import { useState, useRef } from "react";
import { C } from "../lib/constants.js";
import { sendRequest, validateHost } from "../lib/api.js";
import { Panel, Btn, Tag, Inp } from "../components/ui.jsx";

const PRESETS = {
  paths: ["/admin", "/login", "/api", "/.env", "/.git", "/wp-admin", "/backup", "/.env", "/upload", "/dashboard", "/users", "/panel", "/secret", "/test", "/debug", "/status", "/health", "/.git/config", "/phpinfo.php", "/xmlrpc.php"],
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

    for (const payload of payloads) {
      if (ab.cancelled) break;
      const testUrl = baseUrl.replace(/§[^§]*§/g, encodeURIComponent(payload));
      let parsed;
      try { parsed = new URL(testUrl); } catch { continue; }
      if (validateHost(parsed.hostname)) continue;

      const t = Date.now();
      try {
        const r = await sendRequest({ url: testUrl, method: "GET", headers: {} });
        const elapsed = Date.now() - t;
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
      await new Promise(r => setTimeout(r, proxyOnline ? 150 : 800));
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
