import http from "http";
import https from "https";
import net from "net";
import tls from "tls";
import fs from "fs";
import nodePath from "path";
import { lookup } from "dns/promises";
import { fileURLToPath } from "url";
import Database from "better-sqlite3";
import PDFDocument from "pdfkit";
const __dirname = nodePath.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8080;
const MAX_BODY = 1 * 1024 * 1024; // 1 MB
const DIST_DIR = nodePath.join(__dirname, "dist");
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DB_PATH = nodePath.join(DATA_DIR, "miniburp.db");
// ── Database ──────────────────────────────────────────────────────────────────
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS stats (
    key   TEXT PRIMARY KEY,
    value INTEGER DEFAULT 0
  );
  INSERT OR IGNORE INTO stats VALUES ('proxy_hits', 0);
  INSERT OR IGNORE INTO stats VALUES ('scan_hits', 0);
  INSERT OR IGNORE INTO stats VALUES ('fuzz_hits', 0);
  INSERT OR IGNORE INTO stats VALUES ('header_hits', 0);
  INSERT OR IGNORE INTO stats VALUES ('blocked_ssrf', 0);
  INSERT OR IGNORE INTO stats VALUES ('rate_limited', 0);
  CREATE TABLE IF NOT EXISTS scan_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host       TEXT NOT NULL,
    open_ports TEXT,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS proxy_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT NOT NULL,
    method     TEXT DEFAULT 'GET',
    status     INTEGER,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS fuzz_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    url            TEXT NOT NULL,
    payloads_count INTEGER,
    results        TEXT,
    created_at     INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS full_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    report TEXT,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS blocked_hosts (
    host TEXT PRIMARY KEY
  );
`);
const incStat = db.prepare("UPDATE stats SET value = value + 1 WHERE key = ?");
const getStat = db.prepare("SELECT value FROM stats WHERE key = ?");
const allStats = db.prepare("SELECT key, value FROM stats");
function stat(key) { return getStat.get(key)?.value ?? 0; }
// ── SSRF guard ────────────────────────────────────────────────────────────────
const PRIVATE_IP_RE = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|::1$|fc00:|fe80:)/i;
const BLOCKED_HOSTS = new Set(["localhost", "metadata.google.internal", "169.254.169.254"]);
async function isBlockedTarget(hostname) {
  if (!hostname) return true;
  const h = hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(h)) return true;
  if (db.prepare("SELECT host FROM blocked_hosts WHERE host = ?").get(h)) return true;
  if (PRIVATE_IP_RE.test(h)) return true;
  try {
    const addrs = await lookup(h, { all: true });
    for (const { address } of addrs) {
      if (PRIVATE_IP_RE.test(address) || BLOCKED_HOSTS.has(address)) return true;
    }
  } catch {
    return true;
  }
  return false;
}
function isValidUrl(raw) {
  try {
    const u = new URL(raw);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch { return false; }
}
// ── Rate limiter ──────────────────────────────────────────────────────────────
const rateLimits = new Map();
const RATE_WINDOW = 60_000;
const RATE_LIMITS = { "/proxy": 200, "/request": 100, "/portscan": 10, "/headers": 100, "/fuzz": 50, "/ssl": 20 };
function checkRate(ip, route) {
  const limit = RATE_LIMITS[route];
  if (!limit) return false;
  const key = `${ip}:${route}`;
  const now = Date.now();
  const entry = rateLimits.get(key);
  if (!entry || now > entry.resetAt) { rateLimits.set(key, { count: 1, resetAt: now + RATE_WINDOW }); return false; }
  if (entry.count >= limit) return true;
  entry.count++;
  return false;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of rateLimits) if (now > v.resetAt) rateLimits.delete(k); }, 300_000);
// ── Headers ───────────────────────────────────────────────────────────────────
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
function secHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", CORS_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Strict-Transport-Security", "max-age=63072000");
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://*.railway.app; connect-src 'self' https://*.railway.app; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
}
function send(res, status, body) {
  secHeaders(res);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}
// ── Proxy ─────────────────────────────────────────────────────────────────────
const HOP_BY_HOP = new Set(["host", "connection", "keep-alive", "transfer-encoding", "te", "upgrade", "proxy-authorization", "content-length"]);
function proxyRequest(targetUrl, method, reqHeaders, body, res, _redirectCount = 0) {
  if (_redirectCount > 5) {
    send(res, 502, { error: "Too many redirects", url: targetUrl });
    return;
  }
  const parsed = new URL(targetUrl);
  const lib = parsed.protocol === "https:" ? https : http;
  const safeHeaders = {};
  for (const [k, v] of Object.entries(reqHeaders || {})) {
    if (!HOP_BY_HOP.has(k.toLowerCase())) safeHeaders[k] = v;
  }
  const options = {
    hostname: parsed.hostname,
    port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
    path: (parsed.pathname + parsed.search) || "/",
    method: method || "GET",
    headers: { ...safeHeaders, host: parsed.hostname },
    timeout: 15000,
  };
  const preq = lib.request(options, pres => {
    if ([301, 302, 303, 307, 308].includes(pres.statusCode) && pres.headers.location) {
      let nextMethod = method;
      let nextBody = body;
      if ([301, 302, 303].includes(pres.statusCode)) {
        nextMethod = "GET";
        nextBody = null;
      }
      try {
        const redirectUrl = new URL(pres.headers.location, targetUrl).href;
        return proxyRequest(redirectUrl, nextMethod, reqHeaders, nextBody, res, _redirectCount + 1);
      } catch (e) {
        // invalid location header
      }
    }
    secHeaders(res);
    res.writeHead(200, { "Content-Type": "application/json" });
    let data = "";
    pres.on("data", c => (data += c));
    pres.on("end", () => {
      const respHeaders = {};
      Object.keys(pres.headers).forEach(k => (respHeaders[k] = pres.headers[k]));
      res.end(JSON.stringify({ status: pres.statusCode, statusText: pres.statusMessage, headers: respHeaders, body: data, url: targetUrl }));
    });
  });
  preq.on("error", () => send(res, 200, { error: "Request failed", url: targetUrl }));
  preq.on("timeout", () => preq.destroy());
  if (body) preq.write(body);
  preq.end();
}
// ── Port scanner ──────────────────────────────────────────────────────────────
function scanPort(host, port, timeout = 2000) {
  return new Promise(resolve => {
    const sock = new net.Socket();
    sock.setTimeout(timeout);
    sock.on("connect", () => { sock.destroy(); resolve({ port, status: "open" }); });
    sock.on("timeout", () => { sock.destroy(); resolve({ port, status: "closed" }); });
    sock.on("error", () => { sock.destroy(); resolve({ port, status: "closed" }); });
    sock.connect(port, host);
  });
}
function checkTLS(host, port = 443, timeout = 5000) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host,
      port,
      servername: host,
      timeout,
      rejectUnauthorized: false
    }, () => {
      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      const validTo = cert.valid_to ? new Date(cert.valid_to).getTime() : 0;
      const daysLeft = validTo ? Math.floor((validTo - Date.now()) / (1000 * 60 * 60 * 24)) : 0;
      resolve({
        valid: socket.authorized || false,
        protocol,
        cipher: cipher.name,
        issuer: cert.issuer?.O,
        subject: cert.subject?.CN,
        validTo: cert.valid_to,
        daysLeft,
        error: socket.authorizationError
      });
      socket.destroy();
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve({ error: "timeout" });
    });
    socket.on("error", (err) => {
      socket.destroy();
      resolve({ error: err.message });
    });
  });
}
const PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 27017];
// ── Server ────────────────────────────────────────────────────────────────────
http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") { secHeaders(res); res.writeHead(204); res.end(); return; }
  const clientIP = req.socket.remoteAddress || "unknown";
  const parsed = new URL(req.url, "http://localhost");
  const path = parsed.pathname;
  // Basic WAF for explicit XSS payloads in URL
  if (/(%3C|<)script(%3E|>)/i.test(parsed.search) || /javascript:/i.test(parsed.search) || /on\w+=/i.test(parsed.search)) {
    send(res, 403, { error: "WAF: XSS payload detected" });
    return;
  }
  if (checkRate(clientIP, path)) { incStat.run("rate_limited"); send(res, 429, { error: "Too many requests. Try again in a minute." }); return; }
  // Read body with 1 MB limit
  let body = "", bodySize = 0, aborted = false;
  req.on("data", chunk => {
    bodySize += chunk.length;
    if (bodySize > MAX_BODY) { aborted = true; req.destroy(); send(res, 413, { error: "Request body too large (max 1MB)" }); }
    else body += chunk;
  });
  await new Promise(r => req.on("end", r));
  if (aborted) return;
  // GET /proxy?url=...
  if (path === "/proxy") {
    const target = parsed.searchParams.get("url");
    if (!target || !isValidUrl(target)) { send(res, 400, { error: "Invalid or missing url parameter" }); return; }
    if (await isBlockedTarget(new URL(target).hostname)) { incStat.run("blocked_ssrf"); send(res, 403, { error: "Target not allowed" }); return; }
    incStat.run("proxy_hits");
    db.prepare("INSERT INTO proxy_history (url, method) VALUES (?, 'GET')").run(target);
    proxyRequest(target, "GET", {}, null, res);
    return;
  }
  // POST /request
  if (path === "/request" && req.method === "POST") {
    let payload;
    try { payload = JSON.parse(body); } catch { send(res, 400, { error: "Invalid JSON body" }); return; }
    if (!payload.url || !isValidUrl(payload.url)) { send(res, 400, { error: "Invalid or missing url" }); return; }
    if (await isBlockedTarget(new URL(payload.url).hostname)) { incStat.run("blocked_ssrf"); send(res, 403, { error: "Target not allowed" }); return; }
    const SAFE = new Set(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]);
    const method = (payload.method || "GET").toUpperCase();
    if (!SAFE.has(method)) { send(res, 400, { error: "Invalid HTTP method" }); return; }
    incStat.run("proxy_hits");
    db.prepare("INSERT INTO proxy_history (url, method) VALUES (?, ?)").run(payload.url, method);

    const analyzeServerConfig = async (reqData, resData) => {
      try {
        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) return "AI analysis skipped: API key not configured.";
        const { GoogleGenerativeAI } = await import("@google/generative-ai");
        const genAI = new GoogleGenerativeAI(apiKey);
        
        // Let's get the list of models just in case
        let availableModels = [];
        try {
          const fetchObj = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`);
          const resModels = await fetchObj.json();
          availableModels = resModels.models ? resModels.models.map(m => m.name) : [];
          console.log('Available models:', availableModels);
        } catch (e) { console.log('Could not fetch models list:', e); }

        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
        const sysContext = "Ты — эксперт по безопасной настройке веб-серверов. Твоя задача — изучать HTTP-ответы и указывать разработчику на потенциальные утечки информации в заголовках (например, версии ПО) или отсутствие необходимых защитных политик. Ответы должны быть краткими, сугубо техническими и предлагать способы исправления конфигурации.";
        const prompt = `${sysContext}\n\nRequest:\nMethod: ${reqData.method}\nURL: ${reqData.url}\nHeaders: ${JSON.stringify(reqData.headers)}\n\nResponse:\nStatus: ${resData.status}\nHeaders: ${JSON.stringify(resData.headers)}\nBody Sample (first 500 chars): ${String(resData.body).substring(0, 500)}`;
        
        try {
          const result = await model.generateContent(prompt);
          return result.response.text();
        } catch (modelErr) {
          return `AI Analysis Failed: ${modelErr.message}\n\nAvailable Models:\n${availableModels.join("\n")}`;
        }
      } catch (err) {
        return `AI Analysis Failed: ${err.message}`;
      }
    };

    // Use a custom response handler for proxyRequest to inject AI analysis
    const customRes = {
      setHeader: res.setHeader.bind(res),
      writeHead: res.writeHead.bind(res),
      end: async (chunk) => {
        try {
          const resObj = JSON.parse(chunk);
          const aiAnalysis = await analyzeServerConfig({ url: payload.url, method, headers: payload.headers || {} }, resObj);
          resObj.aiAnalysis = aiAnalysis;
          res.end(JSON.stringify(resObj));
        } catch {
          res.end(chunk);
        }
      }
    };

    proxyRequest(payload.url, method, payload.headers || {}, payload.body || null, customRes);
    return;
  }
  // GET /portscan?host=...
  if (path === "/portscan") {
    const host = parsed.searchParams.get("host");
    if (!host) { send(res, 400, { error: "Missing host parameter" }); return; }
    if (await isBlockedTarget(host)) { incStat.run("blocked_ssrf"); send(res, 403, { error: "Target not allowed" }); return; }
    incStat.run("scan_hits");
    secHeaders(res);
    res.writeHead(200, { "Content-Type": "application/json" });
    const results = await Promise.all(PORTS.map(p => scanPort(host, p)));
    const openPorts = results.filter(r => r.status === "open").map(r => r.port);
    db.prepare("INSERT INTO scan_history (host, open_ports) VALUES (?, ?)").run(host, JSON.stringify(openPorts));
    res.end(JSON.stringify({ host, results }));
    return;
  }
  // GET /ssl?host=...
  if (path === "/ssl") {
    const host = parsed.searchParams.get("host");
    if (!host) { send(res, 400, { error: "Missing host parameter" }); return; }
    if (await isBlockedTarget(host)) { send(res, 403, { error: "Target not allowed" }); return; }
    const result = await checkTLS(host);
    send(res, 200, result);
    return;
  }
  // GET /headers?url=...
  if (path === "/headers") {
    const target = parsed.searchParams.get("url");
    if (!target || !isValidUrl(target)) { send(res, 400, { error: "Invalid or missing url parameter" }); return; }
    if (await isBlockedTarget(new URL(target).hostname)) { incStat.run("blocked_ssrf"); send(res, 403, { error: "Target not allowed" }); return; }
    incStat.run("header_hits");
    proxyRequest(target, "HEAD", {}, null, res);
    return;
  }
  // POST /fuzz  { url: "https://target.com/§payload§", payloads: [] }
  if (path === "/fuzz" && req.method === "POST") {
    let payload;
    try { payload = JSON.parse(body); } catch { send(res, 400, { error: "Invalid JSON" }); return; }
    const { url: fuzzUrl, payloads } = payload;
    if (!fuzzUrl || typeof fuzzUrl !== "string") { send(res, 400, { error: "Missing url" }); return; }
    if (!Array.isArray(payloads) || payloads.length === 0) { send(res, 400, { error: "Missing payloads array" }); return; }
    if (payloads.length > 100) { send(res, 400, { error: "Max 100 payloads per request" }); return; }
    // Validate the base URL (with a placeholder substituted)
    const testUrl = fuzzUrl.replace(/§[^§]*§/, "test");
    if (!isValidUrl(testUrl)) { send(res, 400, { error: "Invalid url pattern" }); return; }
    if (await isBlockedTarget(new URL(testUrl).hostname)) { send(res, 403, { error: "Target not allowed" }); return; }
    const results = [];
    for (const p of payloads) {
      const actualUrl = fuzzUrl.replace(/§[^§]*§/g, encodeURIComponent(String(p)));
      if (!isValidUrl(actualUrl)) { results.push({ payload: p, error: "Invalid URL" }); continue; }
      const t = Date.now();
      try {
        await new Promise((resolve, reject) => {
          const parsed2 = new URL(actualUrl);
          const lib2 = parsed2.protocol === "https:" ? https : http;
          const req2 = lib2.request({
            hostname: parsed2.hostname,
            port: parsed2.port || (parsed2.protocol === "https:" ? 443 : 80),
            path: (parsed2.pathname + parsed2.search) || "/",
            method: "GET",
            headers: { host: parsed2.hostname, "User-Agent": "SecurityScanner/1.0" },
            timeout: 8000,
          }, res2 => {
            let data2 = "";
            res2.on("data", c => { if (data2.length < 50000) data2 += c; });
            res2.on("end", () => {
              results.push({ payload: p, status: res2.statusCode, length: data2.length, time: Date.now() - t });
              resolve();
            });
          });
          req2.on("error", () => { results.push({ payload: p, status: 0, length: 0, time: Date.now() - t, error: "Request failed" }); resolve(); });
          req2.on("timeout", () => { req2.destroy(); results.push({ payload: p, status: 0, length: 0, time: Date.now() - t, error: "Timeout" }); resolve(); });
          req2.end();
        });
      } catch { results.push({ payload: p, error: "Exception", status: 0, length: 0, time: 0 }); }
      await new Promise(r => setTimeout(r, 100));
    }
    incStat.run("fuzz_hits");
    db.prepare("INSERT INTO fuzz_history (url, payloads_count, results) VALUES (?, ?, ?)").run(fuzzUrl, payloads.length, JSON.stringify(results));
    send(res, 200, { results });
    return;
  }
  // POST /report
  if (path === "/report" && req.method === "POST") {
    let payload;
    try { payload = JSON.parse(body); } catch { send(res, 400, { error: "Invalid JSON body" }); return; }
    if (!payload.target || !payload.results) { send(res, 400, { error: "Missing target or results" }); return; }

    secHeaders(res);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename=miniburp-report-${payload.target.replace(/\./g, "_")}.pdf`);

    const doc = new PDFDocument({ margin: 50 });
    doc.pipe(res);

    doc.fontSize(20).text("Mini Burp Security Report", { align: "center" });
    doc.moveDown();
    doc.fontSize(12).text(`Target: ${payload.target}`);
    doc.text(`Date: ${new Date().toISOString()}`);
    if (payload.results.score) {
      doc.moveDown(1);
      doc.fontSize(16).fillColor(payload.results.score.severity === "high" ? "red" : payload.results.score.severity === "medium" ? "orange" : "green").text(`Security Score: ${payload.results.score.summary}`);
      doc.fillColor("black").fontSize(12);
    }
    doc.moveDown(2);

    // Add summary graph/stats
    let high = 0, medium = 0, low = 0, info = 0;
    for (const r of Object.values(payload.results)) {
      if (r.severity === "critical" || r.severity === "high") high++;
      else if (r.severity === "medium") medium++;
      else if (r.severity === "low") low++;
      else info++;
    }

    doc.fontSize(14).text("Summary");
    doc.fontSize(10).fillColor("red").text(`Critical/High: ${high}`);
    doc.fillColor("orange").text(`Medium: ${medium}`);
    doc.fillColor("green").text(`Low: ${low}`);
    doc.fillColor("gray").text(`Info: ${info}`);
    doc.fillColor("black");
    doc.moveDown(2);

    for (const [id, r] of Object.entries(payload.results)) {
      doc.fontSize(14).fillColor("black").text(r.label || id);
      const color = (r.severity === "critical" || r.severity === "high") ? "red" : (r.severity === "medium" ? "orange" : (r.severity === "low" ? "green" : "gray"));
      doc.fontSize(10).fillColor(color).text(`Severity: ${r.severity.toUpperCase()} | ${r.summary}`);
      doc.fillColor("black").moveDown(0.5);
      if (r.lines) {
        doc.font("Courier").fontSize(8);
        for (const l of r.lines) doc.text(l.replace(/[\u2713\u2717\u2192\u26A0\u2022]/g, "*")); // Replace problematic unicode chars
        doc.font("Helvetica").fontSize(10);
      }
      if (r.recs && r.recs.length > 0) {
        doc.moveDown(0.5);
        doc.fillColor("blue").text("Recommendations:");
        for (const rec of r.recs) doc.text(`- ${rec}`);
        doc.fillColor("black");
      }
      doc.moveDown();
    }

    doc.end();
    return;
  }

  // POST /report-save
  if (path === "/report-save" && req.method === "POST") {
    let payload;
    try { payload = JSON.parse(body); } catch { send(res, 400, { error: "Invalid JSON" }); return; }
    const { host, report } = payload;
    if (!host || !report) { send(res, 400, { error: "Missing host or report" }); return; }

    const prev = db.prepare("SELECT report, created_at FROM full_reports WHERE host = ? ORDER BY id DESC LIMIT 1").get(host);
    db.prepare("INSERT INTO full_reports (host, report) VALUES (?, ?)").run(host, JSON.stringify(report));

    send(res, 200, { prev: prev ? JSON.parse(prev.report) : null, prev_date: prev ? prev.created_at : null });
    return;
  }

  // GET /history?type=all|scans|proxy|fuzz&limit=50
  if (path === "/history") {
    const type = parsed.searchParams.get("type") || "all";
    const limit = Math.min(parseInt(parsed.searchParams.get("limit") || "50", 10), 200);
    const result = {};
    if (type === "all" || type === "scans") result.scans = db.prepare("SELECT id,host,open_ports,created_at FROM scan_history ORDER BY id DESC LIMIT ?").all(limit);
    if (type === "all" || type === "proxy") result.proxy = db.prepare("SELECT id,url,method,status,created_at FROM proxy_history ORDER BY id DESC LIMIT ?").all(limit);
    if (type === "all" || type === "fuzz") result.fuzz = db.prepare("SELECT id,url,payloads_count,created_at FROM fuzz_history ORDER BY id DESC LIMIT ?").all(limit);
    send(res, 200, result);
    return;
  }

  // ── Admin API ─────────────────────────────────────────────────────────────────
  const adminPass = process.env.ADMIN_PASSWORD || "secret";
  const checkAdmin = (req) => req.headers["x-admin-password"] === adminPass;

  if (path.startsWith("/api/admin")) {
    if (!checkAdmin(req)) {
      send(res, 401, { error: "Unauthorized" });
      return;
    }

    if (path === "/api/admin/stats" && req.method === "GET") {
      const stats = Object.fromEntries(allStats.all().map(r => [r.key, r.value]));
      const recentScans = db.prepare("SELECT * FROM scan_history ORDER BY id DESC LIMIT 100").all();
      const recentReports = db.prepare("SELECT id, host, created_at, length(report) as size, json_extract(report, '$._score') as score FROM full_reports ORDER BY id DESC LIMIT 100").all();

      let sevStats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      let avgScore = 0;
      let totalScore = 0;
      let scoredReports = 0;
      const allReports = db.prepare("SELECT report FROM full_reports").all();
      for (const r of allReports) {
        try {
          const parsed = JSON.parse(r.report);
          if (parsed._score !== undefined) {
            totalScore += parsed._score;
            scoredReports++;
          }
          for (const key of Object.keys(parsed)) {
            if (key === "_score") continue;
            const s = parsed[key].severity;
            if (sevStats[s] !== undefined) sevStats[s]++;
          }
        } catch { }
      }
      if (scoredReports > 0) avgScore = Math.round(totalScore / scoredReports);

      const osData = {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        railway: !!process.env.RAILWAY_PROJECT_ID
      };

      send(res, 200, { stats, recentScans, recentReports, sevStats, osData, avgScore });
      return;
    }

    if (path === "/api/admin/history" && req.method === "DELETE") {
      db.prepare("DELETE FROM scan_history").run();
      db.prepare("DELETE FROM full_reports").run();
      send(res, 200, { ok: true });
      return;
    }

    if (path === "/api/admin/blocks" && req.method === "GET") {
      const blocks = db.prepare("SELECT host FROM blocked_hosts").all();
      send(res, 200, { blocks });
      return;
    }

    if (path === "/api/admin/blocks" && req.method === "POST") {
      let payload;
      try { payload = JSON.parse(body); } catch { send(res, 400, { error: "Invalid JSON" }); return; }
      if (!payload.host) { send(res, 400, { error: "Missing host" }); return; }
      db.prepare("INSERT OR IGNORE INTO blocked_hosts (host) VALUES (?)").run(payload.host.toLowerCase());
      send(res, 200, { ok: true });
      return;
    }

    if (path === "/api/admin/blocks" && req.method === "DELETE") {
      let payload;
      try { payload = JSON.parse(body); } catch { send(res, 400, { error: "Invalid JSON" }); return; }
      if (!payload.host) { send(res, 400, { error: "Missing host" }); return; }
      db.prepare("DELETE FROM blocked_hosts WHERE host = ?").run(payload.host.toLowerCase());
      send(res, 200, { ok: true });
      return;
    }
  }
  // GET /whois?domain=example.com
  if (path === "/whois") {
    const domain = parsed.searchParams.get("domain");
    if (!domain) { send(res, 400, { error: "Missing domain" }); return; }
    const cleanDomain = domain.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
    if (await isBlockedTarget(cleanDomain)) { send(res, 403, { error: "Target not allowed" }); return; }
    // Build candidates: try full hostname, then strip subdomains one by one
    const parts = cleanDomain.split(".");
    const candidates = [];
    for (let i = 0; i <= parts.length - 2; i++) candidates.push(parts.slice(i).join("."));
    const rdapFetch = (d) => new Promise((resolve, reject) => {
      const req2 = https.get({
        hostname: "rdap.org",
        path: `/domain/${encodeURIComponent(d)}`,
        headers: { Accept: "application/json", "User-Agent": "SecurityScanner/1.0" },
        timeout: 8000,
      }, r2 => {
        let data = "";
        r2.on("data", c => { if (data.length < 100000) data += c; });
        r2.on("end", () => resolve({ status: r2.statusCode, body: data }));
      });
      req2.on("error", reject);
      req2.on("timeout", () => { req2.destroy(); reject(new Error("timeout")); });
    });
    try {
      for (const candidate of candidates) {
        const rdapData = await rdapFetch(candidate);
        if (rdapData.status === 200) { send(res, 200, { status: 200, body: rdapData.body, resolvedDomain: candidate }); return; }
      }
      send(res, 200, { error: "WHOIS not found for this domain" });
    } catch {
      send(res, 200, { error: "WHOIS lookup failed" });
    }
    return;
  }
  // GET /health
  if (path === "/health") {
    const s = Object.fromEntries(allStats.all().map(r => [r.key, r.value]));
    const recentScans = db.prepare("SELECT host, open_ports, created_at FROM scan_history  ORDER BY id DESC LIMIT 5").all();
    const recentProxy = db.prepare("SELECT url, method, created_at FROM proxy_history ORDER BY id DESC LIMIT 5").all();
    const recentFuzz = db.prepare("SELECT url, payloads_count, created_at FROM fuzz_history  ORDER BY id DESC LIMIT 5").all();
    send(res, 200, {
      ok: true,
      uptime: Math.floor(process.uptime()),
      stats: s,
      recent: { scans: recentScans, proxy: recentProxy, fuzz: recentFuzz },
    });
    return;
  }
  // Serve static files from dist/
  if (req.method === "GET" && fs.existsSync(DIST_DIR)) {
    const safeSuffix = nodePath.normalize("/" + path.replace(/^\/+/, ""));
    let filePath = nodePath.join(DIST_DIR, safeSuffix);
    // prevent path traversal
    if (!filePath.startsWith(DIST_DIR + nodePath.sep) && filePath !== DIST_DIR) { send(res, 403, { error: "Forbidden" }); return; }
    // Fix false positives: Return 404 for sensitive files/admin paths instead of serving SPA index
    if (/^\/(wp-admin|wp-login\.php|\.env|\.git|\.aws|\.ssh|config\.php|xmlrpc\.php|wp-json|readme\.html)/i.test(path)) {
      if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
        send(res, 404, { error: "Not found" });
        return;
      }
    }
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      filePath = nodePath.join(DIST_DIR, "index.html");
    }
    const ext = nodePath.extname(filePath).toLowerCase();
    const mime = {
      ".html": "text/html", ".js": "application/javascript", ".css": "text/css",
      ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon",
      ".json": "application/json", ".woff2": "font/woff2"
    }[ext] || "application/octet-stream";
    res.writeHead(200, { "Content-Type": mime });
    fs.createReadStream(filePath).pipe(res);
    return;
  }
  send(res, 404, { error: "Not found", routes: ["/proxy?url=", "/request (POST)", "/portscan?host=", "/headers?url=", "/fuzz (POST)", "/health"] });
}).listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Mini Burp running on port ${PORT}`);
  console.log(`   GET  /proxy?url=https://example.com`);
  console.log(`   POST /request  { url, method, headers, body }`);
  console.log(`   GET  /portscan?host=example.com`);
  console.log(`   GET  /headers?url=https://example.com`);
});
process.on("SIGTERM", () => process.exit(0));
process.on("SIGINT", () => process.exit(0));