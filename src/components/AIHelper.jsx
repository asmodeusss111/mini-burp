import { useState, useEffect, useRef } from "react";
import AiChatTab from "../tabs/AiChatTab.jsx";
import { C } from "../lib/constants.js";

export default function AIHelper() {
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState("bottom"); // "bottom" | "top"
  const [size, setSize] = useState({ w: 560, h: 620 });
  const [keyError, setKeyError] = useState("");

  // Keyboard shortcut Ctrl+Alt+I
  useEffect(() => {
    const handler = (e) => {
      if (e.ctrlKey && e.altKey && e.key.toLowerCase() === "i") {
        toggleOpen();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open]);

  const toggleOpen = async () => {
    if (open) { setOpen(false); return; }
    try {
      const r = await fetch("/api/ai-key");
      if (!r.ok) throw new Error("check failed");
      const j = await r.json();
      if (j.present) {
        setOpen(true);
        setKeyError("");
      } else {
        setKeyError("Server API key not configured. Set OPENROUTER_API_KEY in Railway environment variables.");
      }
    } catch (err) {
      // Allow opening even if check fails (local dev without backend)
      setOpen(true);
    }
  };

  const panelStyle = {
    position: "fixed",
    right: 16,
    [position === "bottom" ? "bottom" : "top"]: position === "bottom" ? 76 : 16,
    width: size.w,
    height: size.h,
    zIndex: 9999,
    borderRadius: 10,
    overflow: "hidden",
    boxShadow: "0 20px 60px rgba(0,0,0,0.7), 0 0 0 1px " + C.border,
    background: C.panel,
    display: "flex",
    flexDirection: "column",
    animation: "aiPanelIn 0.15s ease",
  };

  return (
    <>
      <style>{`
        @keyframes aiPanelIn {
          from { opacity: 0; transform: translateY(12px) scale(0.97); }
          to   { opacity: 1; transform: translateY(0) scale(1); }
        }
        .ai-fab {
          position: fixed;
          right: 16px;
          bottom: 16px;
          z-index: 9999;
          width: 52px;
          height: 52px;
          border-radius: 50%;
          background: ${open ? C.border : C.accent};
          color: #fff;
          font-size: 22px;
          display: flex;
          align-items: center;
          justify-content: center;
          border: none;
          cursor: pointer;
          box-shadow: 0 6px 24px rgba(0,0,0,0.6);
          transition: background 0.2s, transform 0.15s, box-shadow 0.2s;
          font-family: monospace;
        }
        .ai-fab:hover {
          transform: scale(1.08);
          box-shadow: 0 8px 32px rgba(249,115,22,0.5);
        }
        .ai-panel-toolbar {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 6px 10px;
          background: #0a0e13;
          border-bottom: 1px solid ${C.border};
          flex-shrink: 0;
          gap: 6px;
        }
        .ai-toolbar-btn {
          background: transparent;
          border: 1px solid ${C.border};
          color: ${C.muted};
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 10px;
          font-family: monospace;
          cursor: pointer;
          transition: all 0.15s;
          white-space: nowrap;
        }
        .ai-toolbar-btn:hover {
          color: ${C.accent};
          border-color: ${C.accent};
        }
        .ai-toolbar-label {
          font-family: monospace;
          font-size: 11px;
          color: ${C.muted};
          font-weight: 700;
          letter-spacing: 0.5px;
          flex: 1;
        }
        .ai-resize-handle {
          position: absolute;
          left: 0;
          top: 0;
          width: 100%;
          height: 4px;
          cursor: ns-resize;
          z-index: 10;
        }
        .ai-resize-handle-left {
          position: absolute;
          left: 0;
          top: 0;
          width: 4px;
          height: 100%;
          cursor: ew-resize;
          z-index: 10;
        }
      `}</style>

      {/* Floating Action Button */}
      <button
        className="ai-fab"
        title="AI Assistant (Ctrl+Alt+I)"
        onClick={toggleOpen}
      >
        {open ? "✕" : "🤖"}
      </button>

      {/* Key error toast */}
      {keyError && !open && (
        <div style={{
          position: "fixed", right: 76, bottom: 22, zIndex: 9999,
          background: C.panel, border: `1px solid ${C.red}`,
          color: C.red, fontFamily: "monospace", fontSize: 11,
          padding: "8px 12px", borderRadius: 6, maxWidth: 320,
          boxShadow: "0 4px 16px rgba(0,0,0,0.5)",
        }}>
          ⚠ {keyError}
          <button onClick={() => setKeyError("")} style={{ marginLeft: 10, background: "none", border: "none", color: C.muted, cursor: "pointer", fontFamily: "monospace" }}>✕</button>
        </div>
      )}

      {/* Main panel */}
      {open && (
        <div style={panelStyle}>
          {/* Resize handle top */}
          <ResizeHandle
            onResize={(dy) => setSize(s => ({ ...s, h: Math.max(400, Math.min(900, s.h - dy)) }))}
            cursor="ns-resize"
            style={{ position: "absolute", left: 0, top: 0, width: "100%", height: 4, zIndex: 10, cursor: "ns-resize" }}
          />
          {/* Resize handle left */}
          <ResizeHandle
            onResize={(dy, dx) => setSize(s => ({ ...s, w: Math.max(360, Math.min(900, s.w - dx)) }))}
            cursor="ew-resize"
            style={{ position: "absolute", left: 0, top: 0, width: 4, height: "100%", zIndex: 10, cursor: "ew-resize" }}
            horizontal
          />

          {/* Toolbar */}
          <div className="ai-panel-toolbar">
            <span className="ai-toolbar-label">🤖 AI Assistant</span>
            <button
              className="ai-toolbar-btn"
              title="Toggle position top/bottom"
              onClick={() => setPosition(p => p === "bottom" ? "top" : "bottom")}
            >
              {position === "bottom" ? "⬆ Move Up" : "⬇ Move Down"}
            </button>
            <button
              className="ai-toolbar-btn"
              onClick={() => setSize({ w: 480, h: 600 })}
            >
              ⊡ Reset size
            </button>
            <button
              className="ai-toolbar-btn"
              onClick={() => setOpen(false)}
              style={{ color: C.red, borderColor: C.red + "60" }}
            >
              ✕ Close
            </button>
          </div>

          {/* Full AiChatTab */}
          <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
            <AiChatTab />
          </div>
        </div>
      )}
    </>
  );
}

// Drag-to-resize helper component
function ResizeHandle({ onResize, style, horizontal = false }) {
  const startRef = useRef(null);

  const onMouseDown = (e) => {
    e.preventDefault();
    startRef.current = { x: e.clientX, y: e.clientY };

    const onMove = (ev) => {
      const dx = ev.clientX - startRef.current.x;
      const dy = ev.clientY - startRef.current.y;
      startRef.current = { x: ev.clientX, y: ev.clientY };
      onResize(dy, dx);
    };
    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  return <div style={style} onMouseDown={onMouseDown} />;
}
