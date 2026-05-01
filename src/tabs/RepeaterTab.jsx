import { useState } from "react";
import { C } from "../lib/constants.js";
import { sendRequest, validateHost, cleanHost } from "../lib/api.js";
import { Panel, Btn, Tag, Inp } from "../components/ui.jsx";

function simpleDiff(oldBody, newBody) {
  const oldLines = (oldBody || "").split("\n");
  const newLines = (newBody || "").split("\n");
  const oldSet = new Set(oldLines);
  const newSet = new Set(newLines);
  const result = [];
  for (const l of oldLines) if (!newSet.has(l)) result.push({ type: "removed", text: l });
  for (const l of newLines) if (!oldSet.has(l)) result.push({ type: "added", text: l });
  return result.slice(0, 200);
}

export default function RepeaterTab({ proxyOnline }) {
  const [url, setUrl] = useState("https://example.com");
  const [method, setMethod] = useState("GET");
  const [hdrs, setHdrs] = useState("User-Agent: SecurityScanner/1.0\nAccept: */*");
  const [body, setBody] = useState("");
  const [response, setResp] = useState(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const [savedResponse, setSaved] = useState(null);
  const [diffMode, setDiffMode] = useState(false);

  const send = async () => {
    if (!url.trim()) return;

    // Validate URL format (auto-add https:// if no protocol)
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch {
      try {
        parsedUrl = new URL("https://" + url);
      } catch {
        setResp({ error: "Invalid URL format" });
        return;
      }
    }
    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      setResp({ error: "Only http:// and https:// are allowed" }); return;
    }

    // Block internal targets
    const hostErr = validateHost(parsedUrl.hostname);
    if (hostErr) { setResp({ error: hostErr }); return; }

    setLoading(true);
    const start = Date.now();

    // Sanitise headers — reject header names with special chars (injection guard)
    const HEADER_NAME_RE = /^[a-zA-Z0-9\-_]+$/;
    const HOP_BY_HOP = new Set(["host","connection","keep-alive","transfer-encoding","te","upgrade","content-length"]);
    const headers = {};
    hdrs.split("\n").forEach(l => {
      const [k, ...v] = l.split(":");
      const name = k?.trim();
      if (name && v.length && HEADER_NAME_RE.test(name) && !HOP_BY_HOP.has(name.toLowerCase())) {
        headers[name] = v.join(":").trim();
      }
    });
    try {
      const r = await sendRequest({ url: parsedUrl.href, method, headers, body: body || null });
      const elapsed = Date.now() - start;
      const resp = {
        status: r.status || 200,
        url: r.url || url,
        time: elapsed,
        size: r.body?.length || 0,
        body: r.body || r.contents || "",
        headers: r.headers || {},
        ts: new Date().toLocaleTimeString(),
      };
      setResp(resp);
      setHistory(h => [{ method, url, status: resp.status, time: resp.time }, ...h.slice(0, 9)]);
    } catch (e) {
      setResp({ error: e.message });
    }
    setLoading(false);
  };

  return (
    <div style={{ display: "flex", gap: 8, height: "100%", minHeight: 520 }}>
      {/* History panel */}
      <Panel style={{ width: 180, flexShrink: 0, display: "flex", flexDirection: "column" }}>
        <div style={{ padding: "6px 12px", borderBottom: `1px solid ${C.border}`, color: C.muted, fontSize: 10, letterSpacing: 1 }}>HISTORY</div>
        <div style={{ overflowY: "auto", flex: 1 }}>
          {history.length === 0 && (
            <div style={{ padding: 12, color: C.muted, fontSize: 11, fontFamily: "monospace" }}>No requests yet</div>
          )}
          {history.map((h, i) => (
            <div
              key={i}
              onClick={() => { setUrl(h.url); setMethod(h.method); }}
              style={{ padding: "6px 12px", borderBottom: `1px solid ${C.border}12`, cursor: "pointer" }}
            >
              <div style={{ color: C.accent, fontSize: 10, fontFamily: "monospace" }}>{h.method}</div>
              <div style={{ color: C.text, fontSize: 10, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {h.url.replace(/https?:\/\//, "")}
              </div>
              <div style={{ color: h.status < 400 ? C.green : C.red, fontSize: 10, fontFamily: "monospace" }}>
                {h.status} · {h.time}ms
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 8 }}>
        {/* Request panel */}
        <Panel style={{ flex: 1 }}>
          <div style={{ padding: "6px 12px", borderBottom: `1px solid ${C.border}`, color: C.muted, fontSize: 10, letterSpacing: 1 }}>
            REQUEST {!proxyOnline && <span style={{ color: C.yellow }}>⚠ GET only without proxy</span>}
          </div>
          <div style={{ padding: 12, display: "flex", flexDirection: "column", gap: 8 }}>
            <div style={{ display: "flex", gap: 8 }}>
              <select
                value={method}
                onChange={e => setMethod(e.target.value)}
                style={{ background: C.bg, border: `1px solid ${C.border}`, color: C.accent, borderRadius: 4, padding: "7px 10px", fontFamily: "monospace", fontSize: 12, cursor: "pointer" }}
              >
                {["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].map(m => <option key={m}>{m}</option>)}
              </select>
              <Inp value={url} onChange={setUrl} placeholder="https://target.com/api" style={{ flex: 1 }} />
              <Btn onClick={send} active color={C.accent} disabled={loading}>{loading ? "…" : "Send"}</Btn>
            </div>
            <div>
              <div style={{ color: C.muted, fontSize: 10, letterSpacing: 1, marginBottom: 4 }}>HEADERS</div>
              <Inp value={hdrs} onChange={setHdrs} rows={3} />
            </div>
            {["POST", "PUT", "PATCH"].includes(method) && (
              <div>
                <div style={{ color: C.muted, fontSize: 10, letterSpacing: 1, marginBottom: 4 }}>BODY</div>
                <Inp value={body} onChange={setBody} rows={3} placeholder='{"key":"value"}' />
              </div>
            )}
          </div>
        </Panel>

        {/* Response panel */}
        <Panel style={{ flex: 1, display: "flex", flexDirection: "column" }}>
          <div style={{ padding: "6px 12px", borderBottom: `1px solid ${C.border}`, display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
            <span style={{ color: C.muted, fontSize: 10, letterSpacing: 1 }}>RESPONSE</span>
            {response && !response.error && (
              <>
                <Tag label={String(response.status)} color={response.status < 400 ? C.green : C.red} />
                <span style={{ color: C.muted, fontSize: 11, fontFamily: "monospace" }}>
                  {response.time}ms · {(response.size / 1024).toFixed(1)}KB
                </span>
              </>
            )}
            {response && !response.error && (
              <>
                <Btn onClick={() => setSaved(response)} small>📌 Save</Btn>
                {savedResponse && (
                  <Btn onClick={() => setDiffMode(d => !d)} active={diffMode} small>⇄ Diff</Btn>
                )}
              </>
            )}
          </div>
          {response?.headers && Object.keys(response.headers).length > 0 && (
            <div style={{ padding: "4px 12px", borderBottom: `1px solid ${C.border}`, maxHeight: 80, overflowY: "auto" }}>
              {Object.entries(response.headers).slice(0, 6).map(([k, v]) => (
                <div key={k} style={{ fontFamily: "monospace", fontSize: 10, color: C.muted, lineHeight: 1.7 }}>
                  <span style={{ color: C.blue }}>{k}</span>: {String(v).slice(0, 80)}
                </div>
              ))}
            </div>
          )}
          <div style={{ flex: 1, overflowY: "auto", padding: 12 }}>
            {!response && <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12 }}>Send a request to see response</div>}
            {response?.error && <div style={{ color: C.red, fontFamily: "monospace", fontSize: 12 }}>Error: {response.error}</div>}
            {response?.body && diffMode && savedResponse ? (
              <div style={{ fontFamily: "monospace", fontSize: 11, lineHeight: 1.5 }}>
                {simpleDiff(savedResponse.body, response.body).length === 0 ? (
                  <div style={{ color: C.green }}>✓ No differences</div>
                ) : (
                  simpleDiff(savedResponse.body, response.body).map((line, i) => (
                    <div key={i} style={{ color: line.type === "removed" ? C.red : C.green }}>
                      {line.type === "removed" ? "- " : "+ "}{line.text.slice(0, 100)}
                    </div>
                  ))
                )}
              </div>
            ) : response?.body ? (
              <pre style={{ margin: 0, color: C.text, fontFamily: "monospace", fontSize: 11, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                {response.body.slice(0, 8000)}{response.body.length > 8000 ? "\n[truncated]" : ""}
              </pre>
            ) : null}
          </div>
        </Panel>
      </div>
    </div>
  );
}
