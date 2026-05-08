import { useState, useEffect, useRef } from "react";
import { C } from "../lib/constants.js";

// ── helpers ──────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function renderMd(text) {
  if (!text) return "";
  let h = esc(text);
  // code blocks
  h = h.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => `
    <div class="gc-code">
      <div class="gc-code-top">
        <span class="gc-code-lang">${lang || "code"}</span>
        <button class="gc-copy-btn" data-copy="${esc(code.trim())}">Copy</button>
      </div>
      <pre><code>${esc(code.trim())}</code></pre>
    </div>`);
  // inline code
  h = h.replace(/`([^`]+)`/g, '<code class="gc-ic">$1</code>');
  // bold / italic
  h = h.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  h = h.replace(/\*(.+?)\*/g, "<em>$1</em>");
  // headings
  h = h.replace(/^### (.+)$/gm, '<div class="gc-h3">$1</div>');
  h = h.replace(/^## (.+)$/gm,  '<div class="gc-h2">$1</div>');
  h = h.replace(/^# (.+)$/gm,   '<div class="gc-h1">$1</div>');
  // lists
  h = h.replace(/^[-*] (.+)$/gm, '<div class="gc-li">• $1</div>');
  h = h.replace(/^(\d+)\. (.+)$/gm, '<div class="gc-li">$1. $2</div>');
  // newlines
  h = h.replace(/\n\n/g, '<div style="margin-top:10px"></div>');
  h = h.replace(/\n/g, "<br/>");
  return h;
}

const MODELS = [
  { id: "google/gemini-2.0-flash-001",       label: "💎 Gemini 2.0 Flash" },
  { id: "anthropic/claude-3.5-haiku",         label: "💎 Claude 3.5 Haiku" },
  { id: "deepseek/deepseek-chat-v3-0324",     label: "💎 DeepSeek V3" },
  { id: "openai/gpt-4o-mini",                 label: "💎 GPT-4o Mini" },
  { id: "openrouter/free",                    label: "🆓 Auto (Free)" },
  { id: "google/gemma-4-31b-it:free",         label: "🆓 Gemma 4 31B" },
  { id: "openai/gpt-oss-120b:free",           label: "🆓 GPT-OSS 120B" },
  { id: "nvidia/nemotron-3-super-120b-a12b:free", label: "🆓 Nemotron 120B" },
];

const DEFAULT_SYSTEM = "You are a helpful assistant. Answer concisely and accurately. Use markdown for code and structured content.";
const STORAGE_KEY = "gc_messages";
const STORAGE_SYS = "gc_system_prompt";
const STORAGE_MDL = "gc_model";

// ── component ─────────────────────────────────────────────────────────────────
export default function GlobalChat({ apiKey, onClose }) {
  const [messages, setMessages] = useState(() => {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || []; } catch { return []; }
  });
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [model, setModel] = useState(localStorage.getItem(STORAGE_MDL) || MODELS[0].id);
  const [systemPrompt, setSystemPrompt] = useState(localStorage.getItem(STORAGE_SYS) || "");
  const [showSys, setShowSys] = useState(false);
  const [tokenCount, setTokenCount] = useState(0);
  const bottomRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(messages)); } catch {}
  }, [messages]);

  useEffect(() => { localStorage.setItem(STORAGE_SYS, systemPrompt); }, [systemPrompt]);
  useEffect(() => { localStorage.setItem(STORAGE_MDL, model); }, [model]);
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages, loading]);

  // copy buttons in rendered markdown
  useEffect(() => {
    const h = (e) => {
      const btn = e.target.closest(".gc-copy-btn");
      if (!btn) return;
      const text = btn.getAttribute("data-copy");
      if (text) {
        navigator.clipboard.writeText(text);
        const orig = btn.innerHTML;
        btn.innerHTML = "✅";
        setTimeout(() => (btn.innerHTML = orig), 1800);
      }
    };
    document.addEventListener("click", h);
    return () => document.removeEventListener("click", h);
  }, []);

  const send = async (overrideText) => {
    const text = (overrideText ?? input).trim();
    if (!text || loading) return;
    setInput("");
    setError("");
    setLoading(true);

    const userMsg = { role: "user", content: text };
    const history = [...messages, userMsg];
    setMessages(history);

    const sys = systemPrompt.trim() || DEFAULT_SYSTEM;
    const apiMessages = [
      { role: "system", content: sys },
      ...history.map((m) => ({ role: m.role, content: m.content })),
    ];

    try {
      const r = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: apiMessages, model, apiKey: apiKey || "" }),
      });
      if (!r.ok) {
        const j = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
        throw new Error(j.error || `HTTP ${r.status}`);
      }

      // SSE streaming
      const reader = r.body.getReader();
      const dec = new TextDecoder();
      let full = "";
      setMessages((prev) => [...prev, { role: "assistant", content: "" }]);

      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const parts = buf.split("\n\n");
        buf = parts.pop();
        for (const part of parts) {
          for (const line of part.split(/\r?\n/)) {
            if (!line.startsWith("data:")) continue;
            const data = line.slice(5).trim();
            if (data === "[DONE]") continue;
            try {
              const parsed = JSON.parse(data);
              const delta = parsed.choices?.[0]?.delta?.content || "";
              if (delta) {
                full += delta;
                setMessages((prev) => {
                  const next = [...prev];
                  next[next.length - 1] = { role: "assistant", content: full };
                  return next;
                });
              }
              if (parsed.usage) setTokenCount((t) => t + (parsed.usage.total_tokens || 0));
            } catch {}
          }
        }
      }
    } catch (err) {
      setError(err.message);
      setMessages((prev) => [...prev, { role: "assistant", content: `❌ ${err.message}` }]);
    }
    setLoading(false);
    setTimeout(() => inputRef.current?.focus(), 50);
  };

  const regenerate = () => {
    const last = [...messages].reverse().find((m) => m.role === "user");
    if (!last) return;
    setMessages((prev) => (prev[prev.length - 1]?.role === "assistant" ? prev.slice(0, -1) : prev));
    send(last.content);
  };

  const clear = () => { setMessages([]); setTokenCount(0); };

  return (
    <>
      <style>{`
        .gc-wrap { height: 100%; display: flex; flex-direction: column; font-family: monospace; color: ${C.text}; background: ${C.panel}; }

        /* toolbar */
        .gc-toolbar { display: flex; align-items: center; gap: 6px; padding: 0 8px; height: 40px; background: #0a0e13; border-bottom: 1px solid ${C.border}; flex-shrink: 0; }
        .gc-title { font-size: 12px; font-weight: 700; color: ${C.text}; flex: 1; }
        .gc-tb-btn { background: transparent; border: 1px solid ${C.border}40; color: ${C.muted}; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-family: monospace; cursor: pointer; transition: all .15s; white-space: nowrap; }
        .gc-tb-btn:hover { color: ${C.accent}; border-color: ${C.accent}; }

        /* system prompt */
        .gc-sys { padding: 8px 10px; background: ${C.bg}; border-bottom: 1px solid ${C.border}; flex-shrink: 0; }
        .gc-sys-label { font-size: 10px; color: ${C.muted}; margin-bottom: 5px; display: flex; justify-content: space-between; }
        .gc-sys-ta { width: 100%; background: ${C.panel}; border: 1px solid ${C.border}; border-radius: 5px; color: ${C.text}; font-family: monospace; font-size: 11px; padding: 7px 9px; outline: none; resize: vertical; line-height: 1.5; box-sizing: border-box; }

        /* messages */
        .gc-messages { flex: 1; overflow-y: auto; padding: 12px; display: flex; flex-direction: column; gap: 10px; }
        .gc-msg-user { background: ${C.accent}12; border-left: 3px solid ${C.accent}; border-radius: 0 6px 6px 0; padding: 8px 12px; }
        .gc-msg-ai   { background: ${C.blue}0d; border-left: 3px solid ${C.blue}50; border-radius: 0 6px 6px 0; padding: 8px 12px; position: relative; }
        .gc-msg-role { font-size: 10px; color: ${C.muted}; margin-bottom: 5px; }
        .gc-msg-body { font-size: 12px; line-height: 1.65; word-break: break-word; }
        .gc-msg-actions { display: flex; gap: 5px; margin-top: 7px; }
        .gc-action-btn { background: transparent; border: 1px solid ${C.border}; color: ${C.muted}; padding: 1px 7px; border-radius: 3px; font-size: 10px; font-family: monospace; cursor: pointer; transition: all .15s; }
        .gc-action-btn:hover { color: ${C.accent}; border-color: ${C.accent}; }

        /* typing indicator */
        .gc-dot { display: inline-block; width: 5px; height: 5px; border-radius: 50%; background: ${C.accent}; margin: 0 2px; animation: gcDot 1.2s infinite; }
        .gc-dot:nth-child(2) { animation-delay: .2s; }
        .gc-dot:nth-child(3) { animation-delay: .4s; }
        @keyframes gcDot { 0%,60%,100%{opacity:.2;transform:scale(.8)} 30%{opacity:1;transform:scale(1.15)} }

        /* code blocks */
        .gc-code { background: #0d1117; border: 1px solid ${C.border}; border-radius: 5px; margin: 7px 0; overflow: hidden; }
        .gc-code-top { display: flex; justify-content: space-between; align-items: center; background: ${C.border}30; padding: 2px 10px; }
        .gc-code-lang { font-size: 9px; color: ${C.muted}; text-transform: uppercase; }
        .gc-copy-btn { background: transparent; border: 1px solid ${C.muted}40; color: ${C.muted}; padding: 1px 7px; border-radius: 3px; font-size: 9px; font-family: monospace; cursor: pointer; transition: all .15s; }
        .gc-copy-btn:hover { color: ${C.accent}; border-color: ${C.accent}; }
        .gc-code pre { padding: 10px 12px; margin: 0; overflow-x: auto; font-size: 11px; line-height: 1.5; }
        .gc-code code { color: ${C.text}; font-family: 'Cascadia Code','Fira Code',monospace; }
        .gc-ic { background: ${C.border}50; padding: 0 5px; border-radius: 3px; font-size: 11px; color: ${C.accent}; }
        .gc-h1 { font-size: 16px; font-weight: 700; margin: 10px 0 4px; }
        .gc-h2 { font-size: 14px; font-weight: 700; margin: 8px 0 4px; }
        .gc-h3 { font-size: 12px; font-weight: 700; margin: 6px 0 3px; color: ${C.accent}; }
        .gc-li  { padding-left: 10px; margin: 2px 0; }

        /* input */
        .gc-input-area { padding: 10px; border-top: 1px solid ${C.border}; background: ${C.panel}; display: flex; gap: 8px; align-items: flex-end; flex-shrink: 0; }
        .gc-textarea { flex: 1; background: ${C.bg}; border: 1px solid ${C.border}; border-radius: 6px; color: ${C.text}; font-family: monospace; font-size: 12px; padding: 9px 11px; outline: none; resize: none; line-height: 1.5; transition: border-color .15s; }
        .gc-textarea:focus { border-color: ${C.accent}60; }
        .gc-send-btn { background: ${C.accent}; border: none; color: #fff; padding: 9px 16px; border-radius: 6px; font-family: monospace; font-size: 12px; cursor: pointer; transition: opacity .15s; white-space: nowrap; }
        .gc-send-btn:disabled { opacity: .45; cursor: default; }
        .gc-footer { display: flex; justify-content: space-between; padding: 0 10px 4px; font-size: 9px; color: ${C.muted}; }
      `}</style>

      <div className="gc-wrap">
        {/* ── toolbar ── */}
        <div className="gc-toolbar">
          <span className="gc-title">🤖 AI Chat</span>
          <button
            className="gc-tb-btn"
            onClick={() => setShowSys((v) => !v)}
            style={systemPrompt.trim() ? { color: C.accent, borderColor: C.accent + "60" } : {}}
            title="System prompt"
          >
            📝 {showSys ? "Hide" : "Prompt"}
          </button>
          <button className="gc-tb-btn" onClick={clear} title="Clear chat">🗑</button>
        </div>

        {/* ── system prompt ── */}
        {showSys && (
          <div className="gc-sys">
            <div className="gc-sys-label">
              <span>System Prompt {systemPrompt.trim() ? "(custom active)" : "(default)"}</span>
              {systemPrompt.trim() && (
                <button className="gc-tb-btn" onClick={() => setSystemPrompt("")}>Reset</button>
              )}
            </div>
            <textarea
              className="gc-sys-ta"
              rows={4}
              value={systemPrompt}
              onChange={(e) => setSystemPrompt(e.target.value)}
              placeholder={DEFAULT_SYSTEM}
            />
          </div>
        )}

        {/* ── messages ── */}
        <div className="gc-messages">
          {messages.length === 0 && (
            <div style={{ textAlign: "center", color: C.muted, fontSize: 12, marginTop: 60 }}>
              <div style={{ fontSize: 32, marginBottom: 10 }}>🤖</div>
              <div>Напиши что-нибудь — отвечу.</div>
              {!apiKey && (
                <div style={{ marginTop: 10, color: C.yellow, fontSize: 11 }}>
                  ⚠ Ключ не введён — нажми 🔑 Set Key в верхней панели
                </div>
              )}
            </div>
          )}

          {messages.map((msg, i) => (
            <div key={i} className={msg.role === "user" ? "gc-msg-user" : "gc-msg-ai"}>
              <div className="gc-msg-role">
                {msg.role === "user" ? "👤 Ты" : `🤖 AI · ${MODELS.find((m) => m.id === model)?.label || model}`}
              </div>
              <div
                className="gc-msg-body"
                dangerouslySetInnerHTML={{ __html: renderMd(msg.content) }}
              />
              {msg.role === "assistant" && i > 0 && !loading && msg.content && (
                <div className="gc-msg-actions">
                  <button className="gc-action-btn" onClick={() => navigator.clipboard.writeText(msg.content)}>📋 Copy</button>
                  {i === messages.length - 1 && (
                    <button className="gc-action-btn" onClick={regenerate}>🔄 Regenerate</button>
                  )}
                </div>
              )}
            </div>
          ))}

          {/* typing dots — only when loading and last msg is empty placeholder */}
          {loading && !messages[messages.length - 1]?.content && (
            <div className="gc-msg-ai">
              <div className="gc-msg-role">🤖 AI</div>
              <div>
                <span className="gc-dot" />
                <span className="gc-dot" />
                <span className="gc-dot" />
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        {/* ── error ── */}
        {error && (
          <div style={{ padding: "5px 12px", background: C.red + "15", color: C.red, fontSize: 11, flexShrink: 0 }}>
            ⚠ {error}
          </div>
        )}

        {/* ── input ── */}
        <div className="gc-input-area">
          <textarea
            ref={inputRef}
            className="gc-textarea"
            rows={2}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
            placeholder="Напиши сообщение… (Enter — отправить, Shift+Enter — перенос)"
          />
          <button className="gc-send-btn" onClick={() => send()} disabled={loading || !input.trim()}>
            {loading ? "⏳" : "➤ Send"}
          </button>
        </div>

        <div className="gc-footer">
          <span>Shift+Enter — новая строка</span>
          <span>{tokenCount > 0 ? `${tokenCount} tokens` : ""}</span>
        </div>
      </div>
    </>
  );
}
