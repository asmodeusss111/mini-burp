import { useState, useEffect } from "react";
import { C } from "../lib/constants.js";
import { Panel, Btn, Tag } from "../components/ui.jsx";

function timeAgo(unix) {
  const diff = Math.floor(Date.now() / 1000) - unix;
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

const TAB_LABELS = [
  { id: "scans", label: "Port Scans",    icon: "▶" },
  { id: "proxy", label: "Proxy Requests", icon: "↺" },
  { id: "fuzz",  label: "Fuzz Jobs",     icon: "⚔" },
];

export default function HistoryTab() {
  const [activeType, setActiveType] = useState("scans");
  const [data, setData]   = useState({ scans: [], proxy: [], fuzz: [] });
  const [loading, setLoading] = useState(false);
  const [sel, setSel]     = useState(null);

  const load = async () => {
    setLoading(true);
    try {
      const r = await fetch("/history?type=all&limit=100").then(r => r.json()).catch(() => null);
      if (r) setData(r);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const rows = data[activeType] || [];
  const selRow = sel !== null ? rows.find(r => r.id === sel) : null;

  return (
    <div style={{ display: "flex", gap: 8, height: "100%", minHeight: 520 }}>
      <Panel style={{ flex: 1, display: "flex", flexDirection: "column" }}>

        {/* Toolbar */}
        <div style={{ padding: "8px 12px", borderBottom: `1px solid ${C.border}`, display: "flex", gap: 8, alignItems: "center" }}>
          {TAB_LABELS.map(t => (
            <button
              key={t.id}
              onClick={() => { setActiveType(t.id); setSel(null); }}
              style={{
                background: activeType === t.id ? C.accent + "20" : "transparent",
                border: activeType === t.id ? `1px solid ${C.accent}40` : `1px solid transparent`,
                color: activeType === t.id ? C.accent : C.muted,
                padding: "4px 12px",
                borderRadius: 4,
                fontFamily: "monospace",
                fontSize: 11,
                cursor: "pointer",
                display: "flex",
                gap: 6,
                alignItems: "center",
              }}
            >
              {t.icon} {t.label}
              <span style={{ color: C.muted, fontSize: 10 }}>({(data[t.id] || []).length})</span>
            </button>
          ))}
          <div style={{ marginLeft: "auto", display: "flex", gap: 6, alignItems: "center" }}>
            {loading && <span style={{ color: C.muted, fontSize: 10 }}>Loading…</span>}
            <Btn onClick={load} small>↻ Refresh</Btn>
          </div>
        </div>

        <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
          {/* List */}
          <div style={{ flex: 1, overflowY: "auto" }}>
            {rows.length === 0 ? (
              <div style={{ padding: 20, color: C.muted, fontFamily: "monospace", fontSize: 12, textAlign: "center" }}>
                No {activeType} history yet
              </div>
            ) : (
              <>
                {/* Header */}
                <div style={{ display: "flex", gap: 8, padding: "5px 12px", borderBottom: `1px solid ${C.border}`, background: C.panel, position: "sticky", top: 0 }}>
                  {activeType === "scans" && <>
                    <div style={{ flex: 1, color: C.muted, fontSize: 9, fontWeight: "bold" }}>HOST</div>
                    <div style={{ width: 120, color: C.muted, fontSize: 9, fontWeight: "bold" }}>OPEN PORTS</div>
                    <div style={{ width: 80, color: C.muted, fontSize: 9, fontWeight: "bold" }}>TIME</div>
                  </>}
                  {activeType === "proxy" && <>
                    <div style={{ width: 50, color: C.muted, fontSize: 9, fontWeight: "bold" }}>METHOD</div>
                    <div style={{ flex: 1, color: C.muted, fontSize: 9, fontWeight: "bold" }}>URL</div>
                    <div style={{ width: 80, color: C.muted, fontSize: 9, fontWeight: "bold" }}>TIME</div>
                  </>}
                  {activeType === "fuzz" && <>
                    <div style={{ flex: 1, color: C.muted, fontSize: 9, fontWeight: "bold" }}>URL</div>
                    <div style={{ width: 80, color: C.muted, fontSize: 9, fontWeight: "bold" }}>PAYLOADS</div>
                    <div style={{ width: 80, color: C.muted, fontSize: 9, fontWeight: "bold" }}>TIME</div>
                  </>}
                </div>

                {rows.map(row => {
                  const openPorts = row.open_ports ? JSON.parse(row.open_ports) : [];
                  return (
                    <div
                      key={row.id}
                      onClick={() => setSel(sel === row.id ? null : row.id)}
                      style={{
                        display: "flex",
                        gap: 8,
                        padding: "7px 12px",
                        borderBottom: `1px solid ${C.border}12`,
                        borderLeft: sel === row.id ? `2px solid ${C.accent}` : "2px solid transparent",
                        cursor: "pointer",
                        alignItems: "center",
                        background: sel === row.id ? C.accent + "08" : "transparent",
                      }}
                    >
                      {activeType === "scans" && <>
                        <div style={{ flex: 1, fontFamily: "monospace", fontSize: 11, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {row.host}
                        </div>
                        <div style={{ width: 120, fontFamily: "monospace", fontSize: 10 }}>
                          {openPorts.length > 0
                            ? openPorts.slice(0, 5).map(p => (
                                <Tag key={p} label={String(p)} color={C.red} style={{ marginRight: 2 }} />
                              ))
                            : <span style={{ color: C.green, fontSize: 10 }}>none open</span>
                          }
                        </div>
                        <div style={{ width: 80, color: C.muted, fontSize: 10, fontFamily: "monospace" }}>{timeAgo(row.created_at)}</div>
                      </>}
                      {activeType === "proxy" && <>
                        <div style={{ width: 50, fontFamily: "monospace", fontSize: 10, color: C.accent }}>{row.method}</div>
                        <div style={{ flex: 1, fontFamily: "monospace", fontSize: 10, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {row.url.replace(/^https?:\/\//, "")}
                        </div>
                        <div style={{ width: 80, color: C.muted, fontSize: 10, fontFamily: "monospace" }}>{timeAgo(row.created_at)}</div>
                      </>}
                      {activeType === "fuzz" && <>
                        <div style={{ flex: 1, fontFamily: "monospace", fontSize: 10, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {row.url.replace(/^https?:\/\//, "")}
                        </div>
                        <div style={{ width: 80, fontFamily: "monospace", fontSize: 10, color: C.blue }}>{row.payloads_count} payloads</div>
                        <div style={{ width: 80, color: C.muted, fontSize: 10, fontFamily: "monospace" }}>{timeAgo(row.created_at)}</div>
                      </>}
                    </div>
                  );
                })}
              </>
            )}
          </div>

          {/* Detail */}
          {selRow && (
            <div style={{ width: 260, borderLeft: `1px solid ${C.border}`, overflowY: "auto", padding: 12 }}>
              <div style={{ color: C.muted, fontSize: 10, letterSpacing: 1, marginBottom: 12 }}>DETAIL</div>
              {activeType === "scans" && (() => {
                const ports = selRow.open_ports ? JSON.parse(selRow.open_ports) : [];
                return <>
                  <div style={{ color: C.muted, fontSize: 10, marginBottom: 4 }}>Host</div>
                  <div style={{ fontFamily: "monospace", fontSize: 12, color: C.text, marginBottom: 12 }}>{selRow.host}</div>
                  <div style={{ color: C.muted, fontSize: 10, marginBottom: 4 }}>Open Ports</div>
                  <div style={{ fontFamily: "monospace", fontSize: 11, color: ports.length ? C.red : C.green, marginBottom: 12 }}>
                    {ports.length ? ports.join(", ") : "None"}
                  </div>
                  <div style={{ color: C.muted, fontSize: 10, marginBottom: 4 }}>Scanned</div>
                  <div style={{ fontFamily: "monospace", fontSize: 11, color: C.text }}>{new Date(selRow.created_at * 1000).toLocaleString()}</div>
                </>;
              })()}
              {activeType === "proxy" && <>
                <div style={{ color: C.muted, fontSize: 10, marginBottom: 4 }}>Method</div>
                <div style={{ fontFamily: "monospace", fontSize: 12, color: C.accent, marginBottom: 12 }}>{selRow.method}</div>
                <div style={{ color: C.muted, fontSize: 10, marginBottom: 4 }}>URL</div>
                <div style={{ fontFamily: "monospace", fontSize: 11, color: C.text, marginBottom: 12, wordBreak: "break-all" }}>{selRow.url}</div>
                <div style={{ color: C.muted, fontSize: 10, marginBottom: 4 }}>Time</div>
                <div style={{ fontFamily: "monospace", fontSize: 11, color: C.text }}>{new Date(selRow.created_at * 1000).toLocaleString()}</div>
              </>}
              {activeType === "fuzz" && <>
                <div style={{ color: C.muted, fontSize: 10, marginBottom: 4 }}>URL</div>
                <div style={{ fontFamily: "monospace", fontSize: 11, color: C.text, marginBottom: 12, wordBreak: "break-all" }}>{selRow.url}</div>
                <div style={{ color: C.muted, fontSize: 10, marginBottom: 4 }}>Payloads count</div>
                <div style={{ fontFamily: "monospace", fontSize: 12, color: C.blue, marginBottom: 12 }}>{selRow.payloads_count}</div>
                <div style={{ color: C.muted, fontSize: 10, marginBottom: 4 }}>Time</div>
                <div style={{ fontFamily: "monospace", fontSize: 11, color: C.text }}>{new Date(selRow.created_at * 1000).toLocaleString()}</div>
              </>}
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}
