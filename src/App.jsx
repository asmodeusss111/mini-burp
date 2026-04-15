import { useState, useEffect } from "react";
import { C } from "./lib/constants.js";
import { checkProxy } from "./lib/api.js";
import { ProxyBadge } from "./components/ui.jsx";
import ScannerTab from "./tabs/ScannerTab.jsx";
import RepeaterTab from "./tabs/RepeaterTab.jsx";
import FuzzerTab from "./tabs/FuzzerTab.jsx";
import InterceptorTab from "./tabs/InterceptorTab.jsx";
import DecoderTab from "./tabs/DecoderTab.jsx";
import HistoryTab from "./tabs/HistoryTab.jsx";

const TABS = [
  { id: "scanner",     label: "Scanner",     icon: "⚡" },
  { id: "repeater",    label: "Repeater",    icon: "↺" },
  { id: "fuzzer",      label: "Fuzzer",      icon: "⚔" },
  { id: "interceptor", label: "Interceptor", icon: "◈" },
  { id: "decoder",     label: "Decoder",     icon: "⇄" },
  { id: "history",     label: "History",     icon: "🕐" },
];

export default function App() {
  const [tab, setTab] = useState("scanner");
  const [proxyOnline, setProxy] = useState(false);

  useEffect(() => {
    const check = async () => setProxy(await checkProxy());
    check();
    const iv = setInterval(check, 5000);
    return () => clearInterval(iv);
  }, []);

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, display: "flex", flexDirection: "column" }}>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        @keyframes pulse { 0%,100%{opacity:.3;transform:scale(.8)} 50%{opacity:1;transform:scale(1.2)} }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        select option { background: ${C.panel}; }
      `}</style>

      {/* Title bar */}
      <div style={{ background: "#0a0e13", borderBottom: `1px solid ${C.border}`, padding: "0 16px", display: "flex", alignItems: "center", gap: 12, height: 38 }}>
        <div style={{ display: "flex", gap: 6 }}>
          {["#ff5f56", "#ffbd2e", "#27c93f"].map((c, i) => (
            <div key={i} style={{ width: 10, height: 10, borderRadius: "50%", background: c }} />
          ))}
        </div>
        <span style={{ color: C.accent, fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>BURP</span>
        <span style={{ color: C.muted, fontFamily: "monospace", fontSize: 12 }}>Security Scanner — Community Edition</span>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>
          <ProxyBadge online={proxyOnline} />
          <span style={{ color: C.muted, fontFamily: "monospace", fontSize: 11 }}>v3.0</span>
        </div>
      </div>

      {/* Tab bar */}
      <div style={{ background: C.panel, borderBottom: `1px solid ${C.border}`, display: "flex", padding: "0 8px", alignItems: "center" }}>
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              background: tab === t.id ? C.bg : "transparent",
              border: "none",
              borderBottom: tab === t.id ? `2px solid ${C.accent}` : "2px solid transparent",
              color: tab === t.id ? C.text : C.muted,
              padding: "8px 18px",
              fontFamily: "monospace",
              fontSize: 12,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: 6,
              transition: "all .15s",
            }}
          >
            <span>{t.icon}</span>{t.label}
          </button>
        ))}
        {!proxyOnline && (
          <span style={{ marginLeft: "auto", color: C.yellow, fontFamily: "monospace", fontSize: 10, padding: "0 12px" }}>
            ⚠ Run <b>node server.cjs</b> for ports + real headers
          </span>
        )}
      </div>

      {/* Tab content — all tabs stay mounted, only active one is visible.
          This preserves state (domain input, results, history) when switching tabs. */}
      <div style={{ flex: 1, overflow: "auto", position: "relative" }}>
        <div style={{ display: tab === "scanner"     ? "block" : "none", padding: 10, height: "100%" }}><ScannerTab     proxyOnline={proxyOnline} /></div>
        <div style={{ display: tab === "repeater"    ? "block" : "none", padding: 10, height: "100%" }}><RepeaterTab    proxyOnline={proxyOnline} /></div>
        <div style={{ display: tab === "fuzzer"      ? "block" : "none", padding: 10, height: "100%" }}><FuzzerTab      proxyOnline={proxyOnline} /></div>
        <div style={{ display: tab === "interceptor" ? "block" : "none", padding: 10, height: "100%" }}><InterceptorTab proxyOnline={proxyOnline} /></div>
        <div style={{ display: tab === "decoder"     ? "block" : "none", padding: 10, height: "100%" }}><DecoderTab /></div>
        <div style={{ display: tab === "history"     ? "block" : "none", padding: 10, height: "100%" }}><HistoryTab /></div>
      </div>

      {/* Status bar */}
      <div style={{ background: C.accent, padding: "2px 12px", display: "flex", gap: 16, alignItems: "center" }}>
        <span style={{ fontFamily: "monospace", fontSize: 10, color: "#fff" }}>
          Proxy: {proxyOnline ? "localhost:8080 ✓" : "offline"}
        </span>
        <span style={{ fontFamily: "monospace", fontSize: 10, color: "#fff", opacity: 0.8 }}>
          Ports/Headers: {proxyOnline ? "real TCP ✓" : "need proxy"}
        </span>
        <span style={{ marginLeft: "auto", fontFamily: "monospace", fontSize: 10, color: "#fff", opacity: 0.8 }}>
          own sites only
        </span>
      </div>
    </div>
  );
}
