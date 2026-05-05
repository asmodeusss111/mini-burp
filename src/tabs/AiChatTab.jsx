import { useState, useRef, useEffect } from "react";
import { C } from "../lib/constants.js";
import { Panel, Btn, Inp } from "../components/ui.jsx";

const SYSTEM_PROMPTS = {
  security: `You are a senior penetration tester and security researcher embedded in Mini Burp — a web security scanner with port scanning, HTTP header analysis, SSL/TLS checks, fuzzing, WAF detection, XSS/SQLi/CORS/open redirect vulnerability detection, subdomain enumeration, JS leak analysis, Repeater and Interceptor. You know OWASP Top 10, CVE databases, Burp Suite, Metasploit, nuclei, ffuf, sqlmap and the whole pentesting toolchain. You think like an attacker. When someone shows you a finding — you immediately assess its real exploitability, not just theory. You give payloads, bypass techniques, PoC examples when asked. You explain CVEs with actual impact, not Wikipedia summaries. You use markdown: code blocks with language tags for payloads and commands. Your tone: direct, technical, collegial — like a senior on the red team who actually enjoys this stuff. No corporate tone, no disclaimers on every message, no bullet-point capability lists. If someone says "hi" — just say hi back and ask what's up. If someone asks something with one word like "sqli?" — give a focused answer, not a lecture. Answer in the same language the user writes in. If a scan result is pasted — analyze it immediately, highlight what matters, skip the obvious.`,

  code: `You are a senior full-stack developer embedded in Mini Burp — a security-focused web app built with JavaScript, Node.js, React, and Python. You know the codebase context: port scanners, HTTP analyzers, fuzzing engines, Repeater/Interceptor modules, WebSocket handling, async request pipelines, OpenRouter API integration. When someone asks for code — write it. Clean, working, no filler comments like "// your logic here". If there's a better approach than what they're asking for — say so briefly, then give the solution anyway. Use markdown code blocks with correct language tags always. Don't explain what a for loop is. Don't pad answers. If the fix is one line — give one line. If the architecture needs rethinking — say it plainly. Stack you're fluent in: JS/TS, React, Node.js, Python, REST/WebSocket APIs, Docker, nginx, security tooling integration. Tone: like a senior dev on Slack — helpful, no-nonsense, occasionally blunt if the approach is wrong. Answer in the same language the user writes in. If someone pastes broken code — fix it, don't just describe what's wrong.`,

  general: `You are a smart, no-bullshit assistant embedded in Mini Burp, a web security scanner. You have broad knowledge: tech, security, networking, programming, infrastructure, and general topics. You think clearly and give direct answers. No filler, no "great question!", no capability lists on greeting. If someone says "hi" — say hi and ask what they need. Match the user's energy: if they're brief, be brief; if they need depth, go deep. Use markdown and code blocks when showing technical content. Answer in the same language the user writes in. You're embedded in a security tool, so security and dev questions will be common — handle them naturally without pretending to be a specialized agent. Just be genuinely useful.`,
};

const MODELS = [
  // ── Premium (платные но дешёвые) ──
  { id: "google/gemini-2.0-flash-001", name: "Gemini 2.0 Flash", provider: "Google", tag: "💎" },
  { id: "anthropic/claude-3.5-haiku", name: "Claude 3.5 Haiku", provider: "Anthropic", tag: "💎" },
  { id: "deepseek/deepseek-chat-v3-0324", name: "DeepSeek V3", provider: "DeepSeek", tag: "💎" },
  { id: "openai/gpt-4o-mini", name: "GPT-4o Mini", provider: "OpenAI", tag: "💎" },
  // ── Free (бесплатные, актуальные май 2026) ──
  { id: "openrouter/free", name: "Auto (Free Router)", provider: "OpenRouter", tag: "🆓" },
  { id: "google/gemma-4-31b-it:free", name: "Gemma 4 31B", provider: "Google", tag: "🆓" },
  { id: "nvidia/nemotron-3-super-120b-a12b:free", name: "Nemotron 3 Super 120B", provider: "NVIDIA", tag: "🆓" },
  { id: "openai/gpt-oss-120b:free", name: "GPT-OSS 120B", provider: "OpenAI", tag: "🆓" },
  { id: "minimax/minimax-m2.5:free", name: "MiniMax M2.5", provider: "MiniMax", tag: "🆓" },
];

function renderMarkdown(text) {
  if (!text) return "";
  let html = text;
  // Code blocks with language
  html = html.replace(/```(\w+)?\n([\s\S]*?)```/g, (_, lang, code) => {
    return `<div class="ai-code-block"><div class="ai-code-lang">${lang || "code"}</div><pre><code>${escHtml(code.trim())}</code></pre></div>`;
  });
  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code class="ai-inline-code">$1</code>');
  // Bold
  html = html.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  // Italic
  html = html.replace(/\*(.+?)\*/g, "<em>$1</em>");
  // Headers
  html = html.replace(/^### (.+)$/gm, '<div class="ai-h3">$1</div>');
  html = html.replace(/^## (.+)$/gm, '<div class="ai-h2">$1</div>');
  html = html.replace(/^# (.+)$/gm, '<div class="ai-h1">$1</div>');
  // Unordered lists
  html = html.replace(/^- (.+)$/gm, '<div class="ai-li">• $1</div>');
  html = html.replace(/^\* (.+)$/gm, '<div class="ai-li">• $1</div>');
  // Ordered lists
  html = html.replace(/^(\d+)\. (.+)$/gm, '<div class="ai-li">$1. $2</div>');
  // Line breaks
  html = html.replace(/\n\n/g, '<div style="margin-top:10px"></div>');
  html = html.replace(/\n/g, "<br/>");
  return html;
}

function escHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const WELCOME_MESSAGES = {
  security: "🛡 Режим Security. Спрашивай про уязвимости, пентест, WAF bypass — отвечу по делу.",
  code: "💻 Режим Code. Пиши что нужно закодить, отладить или оптимизировать.",
  general: "💬 Режим General. Задавай любые вопросы.",
};

export default function AiChatTab({ adminPass }) {
  const defaultHistories = {
    security: [{ role: "assistant", content: WELCOME_MESSAGES.security }],
    code: [{ role: "assistant", content: WELCOME_MESSAGES.code }],
    general: [{ role: "assistant", content: WELCOME_MESSAGES.general }],
  };

  const [chatHistories, setChatHistories] = useState(() => {
    try {
      const saved = localStorage.getItem("ai_chat_histories");
      if (saved) return JSON.parse(saved);
    } catch {}
    return defaultHistories;
  });
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [model, setModel] = useState(MODELS[0].id);
  const [mode, setMode] = useState("security");
  const [apiKey, setApiKey] = useState(localStorage.getItem("openrouter_key") || "");
  const [showSettings, setShowSettings] = useState(!localStorage.getItem("openrouter_key"));
  const [error, setError] = useState("");
  const [tokenCount, setTokenCount] = useState(0);
  const chatEndRef = useRef(null);
  const inputRef = useRef(null);

  const messages = chatHistories[mode];
  const setMessages = (updater) => {
    setChatHistories(prev => ({
      ...prev,
      [mode]: typeof updater === "function" ? updater(prev[mode]) : updater,
    }));
  };

  // Save chat histories to localStorage on every change
  useEffect(() => {
    try {
      localStorage.setItem("ai_chat_histories", JSON.stringify(chatHistories));
    } catch {}
  }, [chatHistories]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  const saveApiKey = () => {
    if (apiKey.trim()) {
      localStorage.setItem("openrouter_key", apiKey.trim());
      setShowSettings(false);
      setError("");
    }
  };

  const sendMessage = async () => {
    if (!input.trim() || loading) return;
    if (!apiKey) {
      setError("Сначала введи OpenRouter API ключ в настройках");
      setShowSettings(true);
      return;
    }

    const userMsg = { role: "user", content: input.trim() };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    setLoading(true);
    setError("");

    try {
      // Build conversation history for API (skip the welcome message)
      const apiMessages = [
        { role: "system", content: SYSTEM_PROMPTS[mode] },
        ...newMessages.filter((m, i) => i > 0 || m.role === "user").map(m => ({
          role: m.role,
          content: m.content,
        })),
      ];

      const r = await fetch("/api/admin/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-admin-password": adminPass,
        },
        body: JSON.stringify({
          messages: apiMessages,
          model,
          apiKey: apiKey.trim(),
        }),
      });

      if (!r.ok) {
        const err = await r.json().catch(() => ({ error: "Network error" }));
        throw new Error(err.error || `HTTP ${r.status}`);
      }

      const data = await r.json();

      if (data.error) {
        throw new Error(data.error);
      }

      const assistantMsg = {
        role: "assistant",
        content: data.content || "Пустой ответ от модели",
      };
      setMessages(prev => [...prev, assistantMsg]);

      if (data.usage) {
        setTokenCount(prev => prev + (data.usage.total_tokens || 0));
      }
    } catch (err) {
      setError(err.message);
      setMessages(prev => [...prev, {
        role: "assistant",
        content: `❌ **Ошибка:** ${err.message}`,
      }]);
    }

    setLoading(false);
    setTimeout(() => inputRef.current?.focus(), 100);
  };

  const clearChat = () => {
    setMessages([
      { role: "assistant", content: WELCOME_MESSAGES[mode] }
    ]);
    setTokenCount(0);
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", gap: 0 }}>
      <style>{`
        .ai-code-block {
          background: #0d1117;
          border: 1px solid ${C.border};
          border-radius: 6px;
          margin: 8px 0;
          overflow: hidden;
        }
        .ai-code-lang {
          background: ${C.border};
          padding: 2px 10px;
          font-size: 10px;
          color: ${C.muted};
          font-family: monospace;
          text-transform: uppercase;
        }
        .ai-code-block pre {
          padding: 12px;
          margin: 0;
          overflow-x: auto;
          font-size: 12px;
          line-height: 1.5;
        }
        .ai-code-block code {
          color: ${C.text};
          font-family: 'Cascadia Code', 'Fira Code', monospace;
        }
        .ai-inline-code {
          background: ${C.border}60;
          padding: 1px 6px;
          border-radius: 3px;
          font-size: 12px;
          font-family: monospace;
          color: ${C.accent};
        }
        .ai-h1 { font-size: 18px; font-weight: 700; margin: 12px 0 6px; color: ${C.text}; }
        .ai-h2 { font-size: 15px; font-weight: 700; margin: 10px 0 5px; color: ${C.text}; }
        .ai-h3 { font-size: 13px; font-weight: 700; margin: 8px 0 4px; color: ${C.accent}; }
        .ai-li { padding-left: 12px; margin: 2px 0; }
        .ai-msg-user {
          background: linear-gradient(135deg, ${C.accent}18, ${C.accent}08);
          border-left: 3px solid ${C.accent};
          border-radius: 0 8px 8px 0;
        }
        .ai-msg-assistant {
          background: linear-gradient(135deg, ${C.blue}10, ${C.blue}05);
          border-left: 3px solid ${C.blue}60;
          border-radius: 0 8px 8px 0;
        }
        .ai-typing-dot {
          display: inline-block;
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: ${C.accent};
          margin: 0 2px;
          animation: aiTyping 1.4s infinite;
        }
        .ai-typing-dot:nth-child(2) { animation-delay: 0.2s; }
        .ai-typing-dot:nth-child(3) { animation-delay: 0.4s; }
        @keyframes aiTyping {
          0%, 60%, 100% { opacity: 0.2; transform: scale(0.8); }
          30% { opacity: 1; transform: scale(1.2); }
        }
        .ai-mode-btn {
          border: 1px solid ${C.border};
          background: transparent;
          color: ${C.muted};
          padding: 4px 12px;
          border-radius: 12px;
          font-size: 11px;
          font-family: monospace;
          cursor: pointer;
          transition: all 0.2s;
        }
        .ai-mode-btn.active {
          background: ${C.accent}20;
          border-color: ${C.accent};
          color: ${C.accent};
        }
        .ai-model-select {
          background: ${C.bg};
          border: 1px solid ${C.border};
          color: ${C.text};
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 11px;
          font-family: monospace;
          outline: none;
          cursor: pointer;
        }
        .ai-model-select option {
          background: ${C.panel};
        }
      `}</style>

      {/* Header */}
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "10px 14px",
        borderBottom: `1px solid ${C.border}`,
        background: C.panel,
        flexShrink: 0,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: 18 }}>🤖</span>
          <div>
            <div style={{ fontFamily: "monospace", fontSize: 13, fontWeight: 700, color: C.text }}>
              AI Assistant
            </div>
            <div style={{ fontFamily: "monospace", fontSize: 10, color: C.muted }}>
              OpenRouter • {MODELS.find(m => m.id === model)?.name || "Unknown"}
            </div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {/* Mode buttons */}
          {[
            { id: "security", icon: "🛡", label: "Security" },
            { id: "code", icon: "💻", label: "Code" },
            { id: "general", icon: "💬", label: "General" },
          ].map(m => (
            <button
              key={m.id}
              className={`ai-mode-btn ${mode === m.id ? "active" : ""}`}
              onClick={() => setMode(m.id)}
            >
              {m.icon} {m.label}
            </button>
          ))}

          {/* Model selector */}
          <select
            className="ai-model-select"
            value={model}
            onChange={e => setModel(e.target.value)}
          >
            {MODELS.map(m => (
              <option key={m.id} value={m.id}>
                {m.tag} {m.provider} — {m.name}
              </option>
            ))}
          </select>

          <Btn onClick={() => setShowSettings(!showSettings)} small>⚙</Btn>
          <Btn onClick={clearChat} small color={C.red}>🗑</Btn>
        </div>
      </div>

      {/* Settings panel */}
      {showSettings && (
        <div style={{
          padding: "12px 14px",
          background: `${C.panel}`,
          borderBottom: `1px solid ${C.border}`,
          display: "flex",
          gap: 10,
          alignItems: "center",
          flexShrink: 0,
        }}>
          <span style={{ fontFamily: "monospace", fontSize: 11, color: C.muted, whiteSpace: "nowrap" }}>
            🔑 OpenRouter API Key:
          </span>
          <input
            type="password"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            placeholder="sk-or-..."
            style={{
              flex: 1,
              background: C.bg,
              border: `1px solid ${C.border}`,
              borderRadius: 4,
              color: C.text,
              fontFamily: "monospace",
              fontSize: 12,
              padding: "6px 10px",
              outline: "none",
            }}
            onKeyDown={e => e.key === "Enter" && saveApiKey()}
          />
          <Btn onClick={saveApiKey} small active>Save</Btn>
          <a
            href="https://openrouter.ai/keys"
            target="_blank"
            rel="noopener"
            style={{ color: C.blue, fontSize: 11, fontFamily: "monospace", whiteSpace: "nowrap" }}
          >
            Получить ключ →
          </a>
        </div>
      )}

      {/* Chat messages */}
      <div style={{
        flex: 1,
        overflowY: "auto",
        padding: "14px",
        display: "flex",
        flexDirection: "column",
        gap: 10,
      }}>
        {messages.map((msg, i) => (
          <div
            key={i}
            className={msg.role === "user" ? "ai-msg-user" : "ai-msg-assistant"}
            style={{
              padding: "10px 14px",
              fontFamily: "monospace",
              fontSize: 12,
              lineHeight: 1.6,
              color: C.text,
              maxWidth: "100%",
              wordBreak: "break-word",
            }}
          >
            <div style={{
              fontSize: 10,
              color: C.muted,
              marginBottom: 4,
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}>
              <span>{msg.role === "user" ? "👤 You" : "🤖 AI"}</span>
              {msg.role === "assistant" && i > 0 && (
                <span style={{ opacity: 0.5 }}>
                  • {MODELS.find(m => m.id === model)?.name}
                </span>
              )}
            </div>
            <div dangerouslySetInnerHTML={{ __html: renderMarkdown(msg.content) }} />
          </div>
        ))}

        {loading && (
          <div className="ai-msg-assistant" style={{ padding: "12px 14px" }}>
            <div style={{ fontSize: 10, color: C.muted, marginBottom: 6 }}>🤖 AI</div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span className="ai-typing-dot" />
              <span className="ai-typing-dot" />
              <span className="ai-typing-dot" />
              <span style={{ fontFamily: "monospace", fontSize: 11, color: C.muted, marginLeft: 6 }}>
                Думаю...
              </span>
            </div>
          </div>
        )}

        <div ref={chatEndRef} />
      </div>

      {/* Error */}
      {error && (
        <div style={{
          padding: "6px 14px",
          background: C.red + "15",
          borderTop: `1px solid ${C.red}40`,
          color: C.red,
          fontFamily: "monospace",
          fontSize: 11,
          flexShrink: 0,
        }}>
          ⚠ {error}
        </div>
      )}

      {/* Input area */}
      <div style={{
        padding: "10px 14px",
        borderTop: `1px solid ${C.border}`,
        background: C.panel,
        display: "flex",
        gap: 10,
        alignItems: "flex-end",
        flexShrink: 0,
      }}>
        <textarea
          ref={inputRef}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={
            mode === "security"
              ? "Спроси про уязвимости, пентест, WAF bypass..."
              : mode === "code"
              ? "Попроси написать код, отладить баг..."
              : "Задай любой вопрос..."
          }
          rows={2}
          style={{
            flex: 1,
            background: C.bg,
            border: `1px solid ${C.border}`,
            borderRadius: 6,
            color: C.text,
            fontFamily: "monospace",
            fontSize: 12,
            padding: "10px 12px",
            outline: "none",
            resize: "none",
            lineHeight: 1.5,
          }}
        />
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <Btn onClick={sendMessage} active disabled={loading || !input.trim()}>
            {loading ? "⏳" : "➤"} Send
          </Btn>
          <span style={{ fontFamily: "monospace", fontSize: 9, color: C.muted, textAlign: "center" }}>
            {tokenCount > 0 ? `${tokenCount} tok` : "Enter ↵"}
          </span>
        </div>
      </div>
    </div>
  );
}
