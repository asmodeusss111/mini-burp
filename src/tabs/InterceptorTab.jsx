import { useState, useRef } from "react";
import { C } from "../lib/constants.js";
import { cleanHost, validateHost } from "../lib/api.js";
import { Panel, Btn, Tag, Inp } from "../components/ui.jsx";

const PROXY_BASE = "";

const PATHS = [
  // Core
  "/", "/favicon.ico", "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
  // Sensitive files
  "/.env", "/.git/config", "/.DS_Store", "/.htaccess", "/web.config",
  "/dump.sql", "/dump.sql.gz", "/db.sql", "/site.sql",
  "/config.json", "/config.yml", "/config.php", "/credentials.json", "/secrets.yaml",
  // WordPress
  "/wp-login.php", "/wp-admin", "/wp-json/wp/v2/users", "/.well-known/security.txt",
  "/xmlrpc.php", "/readme.html",
  // Admin panels
  "/admin", "/administrator", "/admin/login", "/manager", "/console",
  "/phpmyadmin", "/adminer.php", "/cpanel", "/_cpanel",
  // API
  "/api", "/api/v1", "/api/v2", "/api/v3", "/api/admin", "/api/users",
  "/api/config", "/api/health", "/api/status", "/api/debug", "/graphql",
  // Auth
  "/login", "/auth", "/oauth", "/saml", "/sso", "/logout",
  // Dev/debug
  "/debug", "/test", "/staging", "/server-status", "/server-info",
  "/.svn/entries", "/.hg/hgrc",
  // Backups
  "/backup.zip", "/backup.tar.gz", "/old/",
  // DevOps
  "/package.json", "/composer.json", "/Gemfile", "/requirements.txt",
  "/docker-compose.yml", "/.dockerenv",
  // Misc
  "/phpinfo.php", "/login.php", "/search", "/upload", "/health",
];

const INTERESTING_PATHS = new Set([
  "/admin", "/administrator", "/wp-login.php", "/wp-admin", "/wp-json/wp/v2/users",
  "/.env", "/.git/config", "/.DS_Store", "/config.php", "/config.json",
  "/phpinfo.php", "/.htaccess", "/web.config", "/backup.zip", "/dump.sql",
  "/phpmyadmin", "/adminer.php", "/graphql", "/xmlrpc.php",
  "/.svn/entries", "/.hg/hgrc", "/docker-compose.yml", "/credentials.json",
  "/secrets.yaml", "/db.sql", "/_cpanel", "/dump.sql.gz", "/api/admin",
]);

function exportLog(target, log, format = "txt") {
  const ts = new Date().toISOString().slice(0, 19).replace("T", "_").replace(/:/g, "-");
  const filename = `interceptor_${target.replace(/[^a-z0-9]/gi, "_")}_${ts}`;
  let blob;
  if (format === "json") {
    const data = {
      target, generated: new Date().toISOString(),
      total: log.length,
      interesting: log.filter(e => e.interesting).length,
      results: log.map(({ id, body, ...e }) => e),
    };
    blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  } else {
    const lines = [
      `MINI BURP — Interceptor Report`,
      `Target : ${target}`,
      `Date   : ${new Date().toLocaleString("ru-RU")}`,
      `Total  : ${log.length} paths`,
      `Interesting: ${log.filter(e => e.interesting).length}`,
      "─".repeat(60),
      "",
      ...log.map(e =>
        `[${e.ts}] ${e.method} ${e.path}\n` +
        `  Status: ${e.status}  Time: ${e.time}ms  Size: ${(e.size/1024).toFixed(1)}KB` +
        (e.interesting ? "  ⚠ INTERESTING" : "") + "\n" +
        `  URL: ${e.url}`
      ),
    ];
    blob = new Blob([lines.join("\n")], { type: "text/plain" });
  }
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${filename}.${format}`;
  a.click();
  URL.revokeObjectURL(a.href);
}

export default function InterceptorTab({ proxyOnline }) {
  const [target, setTarget] = useState("");
  const [log, setLog] = useState([]);
  const [active, setActive] = useState(false);
  const [sel, setSel] = useState(null);
  const timerRef = useRef(null);
  const indexRef = useRef(0);

  const start = () => {
    if (!target.trim()) return;
    const host = cleanHost(target);
    const err = validateHost(host);
    if (err) {
      alert(`[✗] ${err}`);
      return;
    }
    setActive(true);
    setLog([]);
    indexRef.current = 0;

    const fetchNext = async () => {
      const i = indexRef.current;
      if (i >= PATHS.length) {
        setActive(false);
        return;
      }
      indexRef.current++;
      const path = PATHS[i];
      const url = `https://${host}${path}`;
      const t = Date.now();

      try {
        const r = await (proxyOnline
          ? fetch(`/proxy?url=${encodeURIComponent(url)}`).then(r => r.json())
          : fetch(`https://api.allorigins.win/get?url=${encodeURIComponent(url)}`).then(r => r.json())
        );
        const elapsed = Date.now() - t;
        const status = proxyOnline ? (r?.status || 200) : (r?.status?.http_code || 200);
        const body = proxyOnline ? (r?.body || "") : (r?.contents || "");
        const interesting = INTERESTING_PATHS.has(path);

        setLog(l => [...l, {
          id: crypto.randomUUID(),
          method: "GET", path, status, time: elapsed,
          size: body.length, body, url,
          ts: new Date().toLocaleTimeString(),
          interesting,
          headers: r?.headers || {},
        }]);
      } catch {
        setLog(l => [...l, {
          id: crypto.randomUUID(),
          method: "GET", path, status: "ERR", time: 0,
          size: 0, body: "", url,
          ts: new Date().toLocaleTimeString(),
          interesting: false, headers: {},
        }]);
      }

      // recursive setTimeout instead of setInterval to avoid async overlap
      timerRef.current = setTimeout(fetchNext, proxyOnline ? 500 : 1000);
    };

    timerRef.current = setTimeout(fetchNext, 0);
  };

  const stop = () => {
    clearTimeout(timerRef.current);
    setActive(false);
  };

  const selEntry = log.find(l => l.id === sel);

  return (
    <div style={{ display: "flex", gap: 8, height: "100%", minHeight: 520 }}>
      <Panel style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        {/* Toolbar */}
        <div style={{ padding: "8px 12px", borderBottom: `1px solid ${C.border}`, display: "flex", gap: 8, alignItems: "center" }}>
          <Inp
            value={target}
            onChange={setTarget}
            placeholder="target.com"
            style={{ flex: 1 }}
            onKeyDown={e => e.key === "Enter" && !active && start()}
          />
          <Btn onClick={active ? stop : start} active color={active ? C.red : C.green} small>
            {active ? "■ Stop" : "▶ Start"}
          </Btn>
          {log.length > 0 && !active && <Btn onClick={() => exportLog(cleanHost(target), log, "txt")} small>📥 TXT</Btn>}
          {log.length > 0 && !active && <Btn onClick={() => exportLog(cleanHost(target), log, "json")} small>{"{ }"} JSON</Btn>}
          {log.length > 0 && <Btn onClick={() => setLog([])} small>Clear</Btn>}
        </div>

        {/* Column headers */}
        <div style={{ display: "grid", gridTemplateColumns: "50px 1fr 60px 65px 65px", gap: 8, padding: "4px 12px", borderBottom: `1px solid ${C.border}`, background: C.bg }}>
          {["MTD", "Path", "Status", "Time", "Size"].map(h => (
            <div key={h} style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>{h}</div>
          ))}
        </div>

        {/* Rows */}
        <div style={{ flex: 1, overflowY: "auto" }}>
          {log.length === 0 && (
            <div style={{ padding: 16, color: C.muted, fontFamily: "monospace", fontSize: 12 }}>Enter target and press Start</div>
          )}
          {log.map(e => (
            <div
              key={e.id}
              onClick={() => setSel(e.id)}
              style={{
                display: "grid", gridTemplateColumns: "50px 1fr 60px 65px 65px",
                gap: 8, padding: "5px 12px",
                borderBottom: `1px solid ${C.border}08`,
                cursor: "pointer",
                background: sel === e.id ? C.accent + "15" : e.interesting ? C.yellow + "08" : "transparent",
                borderLeft: e.interesting ? `2px solid ${C.yellow}` : "2px solid transparent",
              }}
            >
              <div style={{ color: C.accent, fontSize: 11, fontFamily: "monospace" }}>{e.method}</div>
              <div style={{ color: e.interesting ? C.yellow : C.text, fontSize: 11, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.path}</div>
              <div style={{ color: e.status < 300 ? C.green : e.status < 400 ? C.blue : e.status === "ERR" ? C.red : C.muted, fontSize: 11, fontFamily: "monospace" }}>{e.status}</div>
              <div style={{ color: C.muted, fontSize: 11, fontFamily: "monospace" }}>{e.time}ms</div>
              <div style={{ color: C.muted, fontSize: 11, fontFamily: "monospace" }}>{(e.size / 1024).toFixed(1)}KB</div>
            </div>
          ))}
          {active && (
            <div style={{ padding: "5px 12px", color: C.accent, fontFamily: "monospace", fontSize: 11 }}>
              █ Intercepting… ({log.length}/{PATHS.length})
            </div>
          )}
        </div>
      </Panel>

      {/* Detail panel */}
      {selEntry && (
        <Panel style={{ width: 340, flexShrink: 0, display: "flex", flexDirection: "column" }}>
          <div style={{ padding: "6px 12px", borderBottom: `1px solid ${C.border}`, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <Tag label={String(selEntry.status)} color={selEntry.status < 300 ? C.green : C.red} />
            {selEntry.interesting && <Tag label="⚠ INTERESTING" color={C.yellow} />}
            <span style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>
              {selEntry.time}ms · {(selEntry.size / 1024).toFixed(1)}KB
            </span>
          </div>
          {proxyOnline && Object.keys(selEntry.headers).length > 0 && (
            <div style={{ padding: "4px 12px", borderBottom: `1px solid ${C.border}`, maxHeight: 90, overflowY: "auto" }}>
              {Object.entries(selEntry.headers).slice(0, 6).map(([k, v]) => (
                <div key={k} style={{ fontFamily: "monospace", fontSize: 10, color: C.muted, lineHeight: 1.7 }}>
                  <span style={{ color: C.blue }}>{k}</span>: {String(v).slice(0, 60)}
                </div>
              ))}
            </div>
          )}
          <div style={{ flex: 1, overflowY: "auto", padding: 10 }}>
            <pre style={{ margin: 0, color: C.text, fontFamily: "monospace", fontSize: 10, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {selEntry.body.slice(0, 4000) || (selEntry.body.length === 0 ? "(empty / 404)" : "")}
            </pre>
          </div>
        </Panel>
      )}
    </div>
  );
}
