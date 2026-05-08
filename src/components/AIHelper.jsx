import { useState, useEffect, useRef } from "react";
import GlobalChat from "./GlobalChat.jsx";
import { C } from "../lib/constants.js";

const MODELS = [
  { id: "google/gemini-2.0-flash-001",            label: "💎 Gemini 2.0 Flash" },
  { id: "anthropic/claude-3.5-haiku",              label: "💎 Claude 3.5 Haiku" },
  { id: "deepseek/deepseek-chat-v3-0324",          label: "💎 DeepSeek V3" },
  { id: "openai/gpt-4o-mini",                      label: "💎 GPT-4o Mini" },
  { id: "openrouter/free",                         label: "🆓 Auto (Free)" },
  { id: "google/gemma-4-31b-it:free",              label: "🆓 Gemma 4 31B" },
  { id: "openai/gpt-oss-120b:free",                label: "🆓 GPT-OSS 120B" },
  { id: "nvidia/nemotron-3-super-120b-a12b:free",  label: "🆓 Nemotron 120B" },
];

export default function AIHelper() {
  const [open, setOpen]         = useState(false);
  const [position, setPosition] = useState("bottom");
  const [size, setSize]         = useState({ w: 520, h: 640 });
  const [model, setModel]       = useState(localStorage.getItem("gc_model") || MODELS[0].id);

  const saveModel = (id) => { setModel(id); localStorage.setItem("gc_model", id); };

  // API key state — read from localStorage, editable here
  const [apiKey, setApiKey]         = useState(localStorage.getItem("openrouter_key") || "");
  const [apiKeyDraft, setApiKeyDraft] = useState(localStorage.getItem("openrouter_key") || "");
  const [showKeyInput, setShowKeyInput] = useState(false);
  const keyInputRef = useRef(null);

  const keySet = Boolean(apiKey);

  const saveKey = () => {
    const v = apiKeyDraft.trim();
    localStorage.setItem("openrouter_key", v);
    setApiKey(v);
    setShowKeyInput(false);
  };

  const clearKey = () => {
    localStorage.removeItem("openrouter_key");
    setApiKey("");
    setApiKeyDraft("");
  };

  // Keyboard shortcut Ctrl+Alt+I
  useEffect(() => {
    const h = (e) => {
      if (e.ctrlKey && e.altKey && e.key.toLowerCase() === "i") {
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  // focus key input when shown
  useEffect(() => {
    if (showKeyInput) setTimeout(() => keyInputRef.current?.focus(), 50);
  }, [showKeyInput]);

  const panelBottom = position === "bottom" ? 76 : "auto";
  const panelTop    = position === "top"    ? 16  : "auto";

  return (
    <>
      <style>{`
        .ai-fab {
          position: fixed; right: 16px; bottom: 16px; z-index: 9999;
          width: 52px; height: 52px; border-radius: 50%;
          background: ${C.accent}; color: #fff; font-size: 22px;
          display: flex; align-items: center; justify-content: center;
          border: none; cursor: pointer;
          box-shadow: 0 6px 24px rgba(0,0,0,.6);
          transition: transform .15s, box-shadow .2s, background .2s;
        }
        .ai-fab.open { background: #333c47; }
        .ai-fab:hover { transform: scale(1.08); box-shadow: 0 8px 32px ${C.accent}60; }

        .ai-panel {
          position: fixed; right: 16px; z-index: 9998;
          border-radius: 10px; overflow: hidden;
          box-shadow: 0 20px 60px rgba(0,0,0,.75), 0 0 0 1px ${C.border};
          background: ${C.panel};
          display: flex; flex-direction: column;
          animation: aiIn .15s ease;
        }
        @keyframes aiIn {
          from { opacity:0; transform: translateY(12px) scale(.97); }
          to   { opacity:1; transform: translateY(0) scale(1); }
        }

        /* panel header */
        .ai-ph {
          display: flex; align-items: center; gap: 6px;
          padding: 0 10px; height: 38px;
          background: #0a0e13; border-bottom: 1px solid ${C.border};
          flex-shrink: 0;
        }
        .ai-ph-title { font-family: monospace; font-size: 12px; font-weight: 700; color: ${C.text}; flex: 1; }
        .ai-ph-btn {
          background: transparent; border: 1px solid ${C.border}50;
          color: ${C.muted}; padding: 2px 8px; border-radius: 4px;
          font-size: 10px; font-family: monospace; cursor: pointer;
          transition: all .15s; white-space: nowrap;
        }
        .ai-ph-btn:hover { color: ${C.accent}; border-color: ${C.accent}; }

        /* key input row */
        .ai-key-row {
          display: flex; align-items: center; gap: 7px;
          padding: 7px 10px; background: ${C.bg};
          border-bottom: 1px solid ${C.border}; flex-shrink: 0;
        }
        .ai-key-input {
          flex: 1; background: ${C.panel}; border: 1px solid ${C.border};
          border-radius: 4px; color: ${C.text}; font-family: monospace;
          font-size: 11px; padding: 5px 8px; outline: none;
        }
        .ai-key-input:focus { border-color: ${C.accent}60; }

        /* resize handles */
        .ai-rh-top  { position:absolute; left:0; top:0; width:100%; height:4px; cursor:ns-resize; z-index:10; }
        .ai-rh-left { position:absolute; left:0; top:0; width:4px; height:100%; cursor:ew-resize; z-index:10; }
      `}</style>

      {/* FAB */}
      <button
        className={`ai-fab${open ? " open" : ""}`}
        onClick={() => setOpen((o) => !o)}
        title="AI Chat (Ctrl+Alt+I)"
      >
        {open ? "✕" : "🤖"}
      </button>

      {/* Panel */}
      {open && (
        <div
          className="ai-panel"
          style={{ bottom: panelBottom, top: panelTop, width: size.w, height: size.h }}
        >
          {/* drag-resize handles */}
          <DragHandle
            className="ai-rh-top"
            onDelta={(dy) => setSize((s) => ({ ...s, h: clamp(s.h - dy, 380, 920) }))}
          />
          <DragHandle
            className="ai-rh-left"
            onDelta={(dy, dx) => setSize((s) => ({ ...s, w: clamp(s.w - dx, 340, 920) }))}
          />

          {/* panel header */}
          <div className="ai-ph">
            <span className="ai-ph-title">🤖 AI Chat</span>
            <select
              value={model}
              onChange={(e) => saveModel(e.target.value)}
              style={{
                background: C.bg, border: `1px solid ${C.border}`, color: C.text,
                fontFamily: "monospace", fontSize: 10, padding: "2px 6px",
                borderRadius: 4, outline: "none", cursor: "pointer", maxWidth: 160,
              }}
            >
              {MODELS.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
            </select>
            <button
              className="ai-ph-btn"
              onClick={() => setShowKeyInput((v) => !v)}
              style={keySet
                ? { color: C.green, borderColor: C.green + "50" }
                : { color: C.yellow, borderColor: C.yellow + "50" }}
            >
              {keySet ? "🔑 Key ✓" : "🔑 Set Key"}
            </button>
            <button
              className="ai-ph-btn"
              onClick={() => setPosition((p) => (p === "bottom" ? "top" : "bottom"))}
              title="Move panel top/bottom"
            >
              {position === "bottom" ? "⬆" : "⬇"}
            </button>
            <button
              className="ai-ph-btn"
              onClick={() => setSize({ w: 520, h: 640 })}
              title="Reset size"
            >
              ⊡
            </button>
            <button
              className="ai-ph-btn"
              onClick={() => setOpen(false)}
              style={{ color: C.red, borderColor: C.red + "40" }}
            >
              ✕
            </button>
          </div>

          {/* API key input row */}
          {showKeyInput && (
            <div className="ai-key-row">
              <span style={{ fontFamily: "monospace", fontSize: 11, color: C.muted, whiteSpace: "nowrap" }}>
                🔑 API Key:
              </span>
              <input
                ref={keyInputRef}
                type="password"
                className="ai-key-input"
                value={apiKeyDraft}
                onChange={(e) => setApiKeyDraft(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && saveKey()}
                placeholder="sk-or-..."
              />
              <button
                className="ai-ph-btn"
                onClick={saveKey}
                style={{ color: C.green, borderColor: C.green + "50" }}
              >Save</button>
              {keySet && (
                <button
                  className="ai-ph-btn"
                  onClick={clearKey}
                  style={{ color: C.red, borderColor: C.red + "40" }}
                >Clear</button>
              )}
              <a
                href="https://openrouter.ai/keys"
                target="_blank" rel="noopener"
                style={{ fontFamily: "monospace", fontSize: 10, color: C.blue, whiteSpace: "nowrap" }}
              >
                Get key →
              </a>
            </div>
          )}

          {/* Chat */}
          <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
            <GlobalChat apiKey={apiKey} model={model} />
          </div>
        </div>
      )}
    </>
  );
}

// ── helpers ──────────────────────────────────────────────────────────────────
function clamp(val, min, max) { return Math.max(min, Math.min(max, val)); }

function DragHandle({ className, onDelta }) {
  const start = useRef(null);
  const onMouseDown = (e) => {
    e.preventDefault();
    start.current = { x: e.clientX, y: e.clientY };
    const move = (ev) => {
      const dx = ev.clientX - start.current.x;
      const dy = ev.clientY - start.current.y;
      start.current = { x: ev.clientX, y: ev.clientY };
      onDelta(dy, dx);
    };
    const up = () => { window.removeEventListener("mousemove", move); window.removeEventListener("mouseup", up); };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  };
  return <div className={className} onMouseDown={onMouseDown} />;
}
