import { useState } from "react";
import MinimalChat from "./MinimalChat.jsx";
import { C } from "../lib/constants.js";

export default function AIHelper() {
  const [open, setOpen] = useState(false);

  return (
    <div>
      <script>{`window.addEventListener('keydown', (e) => { if (e.ctrlKey && e.altKey && e.key.toLowerCase() === 'i') { document.querySelector('.ai-helper-fab')?.click(); } });`}</script>
      <style>{`
        .ai-helper-btn {
          position: fixed;
          right: 16px;
          bottom: 16px;
          z-index: 9999;
        }
        .ai-helper-fab {
          width: 52px;
          height: 52px;
          border-radius: 999px;
          background: ${C.accent};
          color: #fff;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 20px;
          box-shadow: 0 8px 24px rgba(0,0,0,0.6);
          border: none;
          cursor: pointer;
          font-family: monospace;
        }
        .ai-helper-panel {
          position: fixed;
          right: 16px;
          bottom: 80px;
          width: 420px;
          height: 560px;
          z-index: 9999;
          border-radius: 8px;
          overflow: hidden;
          box-shadow: 0 12px 40px rgba(0,0,0,0.6);
          background: ${C.panel};
          display: flex;
          flex-direction: column;
        }
        .ai-helper-mini {
          width: 180px;
          height: 44px;
          display:flex;align-items:center;justify-content:space-between;padding:6px 10px;border-radius:6px;border:1px solid ${C.border};background:${C.bg};
        }
        .ai-helper-header {
          display:flex;align-items:center;justify-content:space-between;padding:8px 12px;border-bottom:1px solid ${C.border};background:${C.panel};
        }
        .ai-helper-title { font-family: monospace; color: ${C.text}; font-size: 13px; }
        .ai-helper-close { background: transparent; border: none; color: ${C.muted}; cursor: pointer; font-family: monospace; }
      `}</style>

      <div className="ai-helper-btn">
        {open && (
          <div className="ai-helper-panel" style={{ width: 420 }}>
            <div className="ai-helper-header">
              <div className="ai-helper-title">🤖 AI Assistant</div>
              <div>
                <button className="ai-helper-close" onClick={() => setOpen(false)}>✕</button>
              </div>
            </div>
            <div style={{ flex: 1 }}>
              <MinimalChat />
            </div>
          </div>
        )}

        <button
          className="ai-helper-fab"
          title="AI Assistant"
          onClick={async () => {
            try {
              const r = await fetch('/api/ai-key');
              if (!r.ok) throw new Error('check failed');
              const j = await r.json();
              if (j.present) {
                setOpen(o => !o);
              } else {
                alert('Server API key not configured. Set OPENROUTER_API_KEY or OPENROUTER_API_KEY1 in Railway environment variables.');
              }
            } catch (err) {
              alert('Failed to check server API key: ' + err.message);
            }
          }}
        >
          🤖
        </button>
      </div>
    </div>
  );
}
