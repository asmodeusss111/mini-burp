import http  from "http";
import https from "https";
import net   from "net";
import fs    from "fs";
import nodePath from "path";
import { lookup } from "dns/promises";
import { fileURLToPath } from "url";

const __dirname = nodePath.dirname(fileURLToPath(import.meta.url));
const PORT      = process.env.PORT || 8080;
const MAX_BODY  = 1 * 1024 * 1024; // 1 MB
const DIST_DIR  = nodePath.join(__dirname, "dist");

// ── SSRF guard ────────────────────────────────────────────────────────────────
const PRIVATE_IP_RE = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|::1$|fc00:|fe80:)/i;
const BLOCKED_HOSTS = new Set(["localhost", "metadata.google.internal", "169.254.169.254"]);

async function isBlockedTarget(hostname) {
  if (!hostname) return true;
  const h = hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(h)) return true;
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
const rateLimits  = new Map();
const RATE_WINDOW = 60_000;
const RATE_LIMITS = { "/proxy": 200, "/request": 100, "/portscan": 10, "/headers": 100, "/fuzz": 50 };

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
setInterval(() => { const now = Date.now(); for (const [k,v] of rateLimits) if (now > v.resetAt) rateLimits.delete(k); }, 300_000);

// ── Headers ───────────────────────────────────────────────────────────────────
const CORS_ORIGIN = process.env.CORS_ORIGIN || "http://localhost:5173";

function secHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin",  CORS_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept");
  res.setHeader("X-Content-Type-Options",       "nosniff");
  res.setHeader("X-Frame-Options",              "DENY");
  res.setHeader("Referrer-Policy",              "no-referrer");
}

function send(res, status, body) {
  secHeaders(res);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

// ── Proxy ─────────────────────────────────────────────────────────────────────
const HOP_BY_HOP = new Set(["host","connection","keep-alive","transfer-encoding","te","upgrade","proxy-authorization","content-length"]);

function proxyRequest(targetUrl, method, reqHeaders, body, res) {
  const parsed = new URL(targetUrl);
  const lib    = parsed.protocol === "https:" ? https : http;

  const safeHeaders = {};
  for (const [k, v] of Object.entries(reqHeaders || {})) {
    if (!HOP_BY_HOP.has(k.toLowerCase())) safeHeaders[k] = v;
  }

  const options = {
    hostname: parsed.hostname,
    port:     parsed.port || (parsed.protocol === "https:" ? 443 : 80),
    path:     (parsed.pathname + parsed.search) || "/",
    method:   method || "GET",
    headers:  { ...safeHeaders, host: parsed.hostname },
    timeout:  15000,
  };

  const preq = lib.request(options, pres => {
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
    sock.on("error",   () => { sock.destroy(); resolve({ port, status: "closed" }); });
    sock.connect(port, host);
  });
}

const PORTS = [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,8888,27017];

// ── Server ────────────────────────────────────────────────────────────────────
http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") { secHeaders(res); res.writeHead(204); res.end(); return; }

  const clientIP = req.socket.remoteAddress || "unknown";
  const parsed   = new URL(req.url, "http://localhost");
  const path     = parsed.pathname;

  if (checkRate(clientIP, path)) { send(res, 429, { error: "Too many requests. Try again in a minute." }); return; }

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
    if (await isBlockedTarget(new URL(target).hostname)) { send(res, 403, { error: "Target not allowed" }); return; }
    proxyRequest(target, "GET", {}, null, res);
    return;
  }

  // POST /request
  if (path === "/request" && req.method === "POST") {
    let payload;
    try { payload = JSON.parse(body); } catch { send(res, 400, { error: "Invalid JSON body" }); return; }
    if (!payload.url || !isValidUrl(payload.url)) { send(res, 400, { error: "Invalid or missing url" }); return; }
    if (await isBlockedTarget(new URL(payload.url).hostname)) { send(res, 403, { error: "Target not allowed" }); return; }
    const SAFE = new Set(["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"]);
    const method = (payload.method || "GET").toUpperCase();
    if (!SAFE.has(method)) { send(res, 400, { error: "Invalid HTTP method" }); return; }
    proxyRequest(payload.url, method, payload.headers || {}, payload.body || null, res);
    return;
  }

  // GET /portscan?host=...
  if (path === "/portscan") {
    const host = parsed.searchParams.get("host");
    if (!host) { send(res, 400, { error: "Missing host parameter" }); return; }
    if (await isBlockedTarget(host)) { send(res, 403, { error: "Target not allowed" }); return; }
    secHeaders(res);
    res.writeHead(200, { "Content-Type": "application/json" });
    const results = await Promise.all(PORTS.map(p => scanPort(host, p)));
    res.end(JSON.stringify({ host, results }));
    return;
  }

  // GET /headers?url=...
  if (path === "/headers") {
    const target = parsed.searchParams.get("url");
    if (!target || !isValidUrl(target)) { send(res, 400, { error: "Invalid or missing url parameter" }); return; }
    if (await isBlockedTarget(new URL(target).hostname)) { send(res, 403, { error: "Target not allowed" }); return; }
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

    send(res, 200, { results });
    return;
  }

  // GET /health
  if (path === "/health") {
    send(res, 200, { ok: true });
    return;
  }

  // Serve static files from dist/
  if (req.method === "GET" && fs.existsSync(DIST_DIR)) {
    const safeSuffix = nodePath.normalize("/" + path.replace(/^\/+/, ""));
    let filePath = nodePath.join(DIST_DIR, safeSuffix);
    // prevent path traversal
    if (!filePath.startsWith(DIST_DIR + nodePath.sep) && filePath !== DIST_DIR) { send(res, 403, { error: "Forbidden" }); return; }
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      filePath = nodePath.join(DIST_DIR, "index.html");
    }
    const ext = nodePath.extname(filePath).toLowerCase();
    const mime = { ".html": "text/html", ".js": "application/javascript", ".css": "text/css",
                   ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon",
                   ".json": "application/json", ".woff2": "font/woff2" }[ext] || "application/octet-stream";
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
process.on("SIGINT",  () => process.exit(0));
