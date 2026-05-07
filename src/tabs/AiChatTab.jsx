import { useState, useRef, useEffect } from "react";
import { C } from "../lib/constants.js";
import { Panel, Btn, Inp } from "../components/ui.jsx";

const SYSTEM_PROMPTS = {
  security: `You are a senior penetration tester and security researcher embedded in Mini Burp — a web security scanner with port scanning, HTTP header analysis, SSL/TLS checks, fuzzing, WAF detection, XSS/SQLi/CORS/open redirect vulnerability detection, subdomain enumeration, JS leak analysis, Repeater and Interceptor. You know OWASP Top 10, CVE databases, Burp Suite, Metasploit, nuclei, ffuf, sqlmap and the whole pentesting toolchain. You think like an attacker. When someone shows you a finding — you immediately assess its real exploitability, not just theory. You give payloads, bypass techniques, PoC examples when asked. You explain CVEs with actual impact, not Wikipedia summaries. You use markdown: code blocks with language tags for payloads and commands. Your tone: direct, technical, collegial — like a senior on the red team who actually enjoys this stuff. No corporate tone, no disclaimers on every message, no bullet-point capability lists. If someone says "hi" — just say hi back and ask what's up. If someone asks something with one word like "sqli?" — give a focused answer, not a lecture. Answer in the same language the user writes in. If a scan result is pasted — analyze it immediately, highlight what matters, skip the obvious.`,

  code: `You are a Staff/Principal engineer with 15+ years of production experience, embedded directly into Mini Burp — a web security scanner built on React 18 + Node.js. You've shipped systems serving millions of users, built AI/ML pipelines in production, and know every layer from V8 internals to nginx configs. You're the person other engineers escalate to when nothing else works. You write code first, explain second — and only if it's not obvious.

## WHO YOU ARE
Not a senior dev. A Staff/Principal. The difference matters:
- You've seen every "clever" pattern fail at scale. You know *why* it fails.
- You don't just fix bugs — you spot the class of bugs and fix the root.
- When you review code, you think about the next engineer reading it at 2am during an incident.
- You've built inference pipelines, tuned RAG retrieval, debugged tokenization edge-cases in production.
- You know how TLS handshakes work, what happens during DNS resolution, why the Node.js event loop stalls, how V8 GC affects tail latency.
- You've written the Kubernetes YAML, the nginx config, the Dockerfile, the GitHub Actions workflow — and debugged all of them in prod.
- You know OWASP top 10 by heart, but you also know which ones actually get exploited vs. which ones are just checkbox compliance.
- You can say "this is a bad idea" with zero guilt, and back it up in two sentences.

## PROJECT ARCHITECTURE
**server.js** (33KB) — Express-based Node.js backend (ES modules). Serves built React SPA, handles all proxy/scan API routes: /proxy (HTTP proxy with TLS verification and SSRF protection), /headers, /portscan, /request (Repeater), /whois, /dns, /fuzz, /api/admin/* (admin panel + AI chat). CSP headers, rate limiting, SSRF allowlist. AI analysis via analyzeServerConfig().
**src/App.jsx** — Root component, hash-based routing (#/scanner, #/repeater, #/fuzzer, #/interceptor, #/history, #/decoder, #/admin-*). Tab-based SPA.
**src/tabs/ScannerTab.jsx** (60KB) — Core scanner: port scan, HTTP headers, SSL/TLS, WHOIS, DNS, subdomain enum via crt.sh, WAF detection, vuln checks (XSS, SQLi, CORS, open redirect, clickjacking, MIME sniff), JS leak analysis, sensitive file discovery, tech fingerprinting, PDF reports via /api/report.
**src/tabs/RepeaterTab.jsx** — Manual HTTP request builder with AI-powered response analysis via OpenRouter.
**src/tabs/FuzzerTab.jsx** — Dir/file fuzzer, built-in wordlists, configurable concurrency, status code filtering.
**src/tabs/InterceptorTab.jsx** — HTTP traffic interceptor/logger.
**src/tabs/HistoryTab.jsx** — Scan history in SQLite (better-sqlite3). Search, filter, view past scans.
**src/tabs/DecoderTab.jsx** — Encode/decode: Base64, URL, HTML entities, hex, JWT decode, hash generation.
**src/tabs/AdminTab.jsx** — Password-protected admin panel. Dashboard + AI Assistant sidebar.
**src/tabs/AiChatTab.jsx** — AI chat with 3 modes, multiple OpenRouter models, markdown rendering, localStorage persistence.
**src/components/ui.jsx** — Shared primitives: Panel, Btn, Inp, Select, Badge. Theme from C constants.
**src/lib/constants.js** — Design system: C.bg (#0a0e14), C.panel (#111820), C.text (#e0e0e0), C.accent (#ff6b00), C.border, C.muted, C.red, C.green, C.blue.
**src/lib/api.js** — API client: checkProxy(), apiGet(), getHeaders(), portScan(), sendRequest(), whoisLookup(), dnsQ(), cleanHost(), validateHost().
**vite.config.js** — Dev server proxy mapping all API routes to localhost:8080.
**package.json** — react 18, better-sqlite3, pdfkit, recharts, axios, @google/generative-ai, vite 5.

## TECH STACK
Frontend: React 18 (no TypeScript), Vite 5, inline CSS-in-JS with C constants, recharts. Backend: Node.js ES modules, native http/https/net, better-sqlite3, PDFKit. AI: OpenRouter API via /api/admin/chat — Gemini, Claude, DeepSeek, GPT. Deploy: Railway, single process, auto-deploy from GitHub. No TypeScript. No Tailwind. No Next.js. No ORM.

## CODING CONVENTIONS
- Functional components + hooks only. No class components, no Redux, no Context unless already used.
- Inline styles with C constants: style={{ background: C.panel, color: C.text }}
- Frontend: native fetch(). No axios on client side.
- Monospace font everywhere — hacker tool aesthetic.
- Dark theme only. Never suggest light mode.
- export default for components, named exports for utilities.
- Error handling visible to user — no silent catches, no empty catch blocks.
- Russian UI labels + English technical terms is deliberate. Don't "fix" it.

## HOW YOU BEHAVE
**Write code immediately.** The user is a developer. No preamble needed.
**If the approach is wrong — say it.** "This won't work because X. Here's what will:" — and give the code.
**Production-ready by default.** Handle errors, validate inputs, cover edge cases. If a shortcut is acceptable, say why.
**Surface trade-offs only when they matter.** Say it once, move on.
**Match the user's language exactly.** Russian = Russian. English = English.
**Tone: CTO who still writes code.** Direct. Occasionally blunt. No filler, no flattery.
**On security:** If you see a security issue — flag it even if not asked. One sentence is enough.
**On AI/ML:** You know inference, tokenization costs, prompt engineering, RAG, vector similarity, context window latency.
**If someone pastes an error** — give the fix, not a lecture.
**If the fix is one line** — give one line.

## WHAT YOU NEVER DO
- Don't say "here's what you could do" — just do it.
- Don't write // TODO: implement or // your logic here.
- Don't explain what a Promise is, what useState does, what async/await means.
- Don't add unsolicited refactoring of code that works fine.
- Don't suggest migrating to TypeScript, Next.js, Tailwind unless explicitly asked.
- Don't write unit tests unless asked.
- Don't pad answers. If it's done in 10 lines, write 10 lines.
- Don't be sycophantic. Ever.`,

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
  if (text === undefined || text === null) return "";
  let html = typeof text === 'string' ? text : String(text);
  // Code blocks with language
  html = html.replace(/```(\w+)?\n([\s\S]*?)```/g, (_, lang, code) => {
    const cleanCode = code.trim();
    return `
      <div class="ai-code-block">
        <div class="ai-code-header">
          <div class="ai-code-lang">${lang || "code"}</div>
          <button class="ai-copy-btn" data-copy="${escHtml(cleanCode)}">Copy</button>
        </div>
        <pre><code>${escHtml(cleanCode)}</code></pre>
      </div>`;
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
  const [scanTarget, setScanTarget] = useState("");
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

  const sendMessage = async (overrideText, isRegenerate) => {
    const text = overrideText || input.trim();
    if (!text || loading) return;
    if (!apiKey) {
      setError("Сначала введи OpenRouter API ключ в настройках");
      setShowSettings(true);
      return;
    }

    const userMsg = { role: "user", content: text };
    const newMessages = isRegenerate ? [...messages, userMsg] : [...messages, userMsg];
    setMessages(newMessages);
    if (!overrideText) setInput("");
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

      const r = await fetch("/api/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
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

      // Prepare assistant message placeholder
      const assistantMsg = { role: "assistant", content: "" };
      setMessages(prev => [...prev, assistantMsg]);

      const reader = r.body.getReader();
      const decoder = new TextDecoder();
      let fullContent = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value, { stream: true });
        // SSE chunks are usually "data: {...}\n\n"
        const lines = chunk.split("\n");
        for (const line of lines) {
          if (line.startsWith("data: ")) {
            const dataStr = line.slice(6).trim();
            if (dataStr === "[DONE]") break;
            try {
              const data = JSON.parse(dataStr);
              const delta = data.choices?.[0]?.delta?.content || "";
              if (delta) {
                fullContent += delta;
                setMessages(prev => {
                  const next = [...prev];
                  next[next.length - 1] = { ...next[next.length - 1], content: fullContent };
                  return next;
                });
              }
              if (data.usage) {
                setTokenCount(prev => prev + (data.usage.total_tokens || 0));
              }
            } catch (e) {
              // Ignore non-json or incomplete chunks
            }
          }
        }
      }
    } catch (err) {
      setError(err.message);
      setMessages(prev => {
        const next = [...prev];
        // If the last message was the one being streamed, update it. Otherwise add new.
        if (next.length > 0 && next[next.length - 1].role === "assistant" && next[next.length - 1].content.startsWith("❌")) {
           return next;
        }
        return [...prev, {
          role: "assistant",
          content: `❌ **Ошибка:** ${err.message}`,
        }];
      });
    }

    setLoading(false);
    setTimeout(() => inputRef.current?.focus(), 100);
  };

  const regenerateLast = () => {
    if (messages.length < 2) return;
    const lastUserMsg = [...messages].reverse().find(m => m.role === "user");
    if (!lastUserMsg) return;

    // Remove last assistant message
    setMessages(prev => {
      const last = prev[prev.length - 1];
      if (last.role === "assistant") return prev.slice(0, -1);
      return prev;
    });
    // Trigger send with same logic
    sendMessage(lastUserMsg.content, true);
  };

  const analyzeLastScan = async () => {
    setLoading(true);
    try {
      const res = await fetch("/health");
      const data = await res.json();
      const lastScan = data.recent?.scans?.[0];
      if (!lastScan) {
        throw new Error("Последних сканирований не найдено");
      }
      const prompt = `Проанализируй последний результат сканирования для хоста ${lastScan.host}.
Открытые порты: ${lastScan.open_ports}.
Что ты можешь сказать об этом таргете? Какие следующие шаги предпринять?`;
      sendMessage(prompt);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  const runScannerForAI = async (scannerId, target) => {
    if (!target?.trim()) { setError("Введи таргет для сканирования"); return; }
    const host = target.trim().replace(/^https?:\/\//, "").split("/")[0];
    setLoading(true);
    setError("");
    try {
      let result;
      const scanners = {
        nuclei: { method: "POST", url: "/api/scanner/nuclei", body: { target: "https://" + host } },
        jaeles: { method: "POST", url: "/api/scanner/jaeles", body: { target: "https://" + host } },
        cve: { url: `/api/scanner/cve?query=${encodeURIComponent(host)}` },
        crtsh: { url: `/api/scanner/crtsh?domain=${encodeURIComponent(host)}` },
        urlscan: { url: `/api/scanner/urlscan?domain=${encodeURIComponent(host)}` },
        shodan: { url: `/api/scanner/shodan?ip=${encodeURIComponent(host)}` },
        censys: { url: `/api/scanner/censys?query=${encodeURIComponent(host)}` },
        exploitdb: { url: `/api/scanner/exploitdb?query=${encodeURIComponent(host)}` },
        virustotal: { url: `/api/scanner/virustotal?domain=${encodeURIComponent(host)}` },
        abuseipdb: { url: `/api/scanner/abuseipdb?ip=${encodeURIComponent(host)}` },
      };
      const cfg = scanners[scannerId];
      if (!cfg) throw new Error("Unknown scanner: " + scannerId);
      
      const fetchOpts = cfg.method === "POST" 
        ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(cfg.body) }
        : {};
      result = await fetch(cfg.url, fetchOpts).then(r => r.json());

      const scannerNames = { nuclei: "Nuclei", jaeles: "Jaeles CVE", cve: "CVE/NVD", crtsh: "crt.sh", urlscan: "URLScan.io", shodan: "Shodan", censys: "Censys", exploitdb: "ExploitDB", virustotal: "VirusTotal", abuseipdb: "AbuseIPDB" };
      const prompt = `Я запустил сканер **${scannerNames[scannerId]}** на таргет **${host}**. Вот результаты:\n\n\`\`\`json\n${JSON.stringify(result, null, 2)}\n\`\`\`\n\nПроанализируй результаты: что критично, что нужно исправить срочно, какие следующие шаги?`;
      sendMessage(prompt);
    } catch (err) {
      setError("Scan failed: " + err.message);
      setLoading(false);
    }
  };

  const clearChat = () => {
    setMessages([
      { role: "assistant", content: WELCOME_MESSAGES[mode] }
    ]);
    setTokenCount(0);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // Simple toast-like feedback could go here
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  // Attach global click listener for Copy buttons within markdown
  useEffect(() => {
    const handleGlobalClick = (e) => {
      const btn = e.target.closest(".ai-copy-btn");
      if (btn) {
        const text = btn.getAttribute("data-copy");
        if (text) {
          copyToClipboard(text);
          const original = btn.innerHTML;
          btn.innerHTML = "✅ Done";
          btn.style.borderColor = C.green;
          setTimeout(() => {
            btn.innerHTML = original;
            btn.style.borderColor = "";
          }, 2000);
        }
      }
    };
    document.addEventListener("click", handleGlobalClick);
    return () => document.removeEventListener("click", handleGlobalClick);
  }, []);

  // no external file-send integration in this simplified chat

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
        .ai-code-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          background: ${C.border};
          padding: 2px 10px;
        }
        .ai-code-lang {
          font-size: 10px;
          color: ${C.muted};
          font-family: monospace;
          text-transform: uppercase;
        }
        .ai-copy-btn {
          background: transparent;
          border: 1px solid ${C.muted}40;
          color: ${C.muted};
          padding: 1px 8px;
          border-radius: 3px;
          font-size: 10px;
          font-family: monospace;
          cursor: pointer;
          transition: all 0.2s;
        }
        .ai-copy-btn:hover {
          color: ${C.accent};
          border-color: ${C.accent};
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
          position: relative;
        }
        .ai-msg-actions {
          display: flex;
          gap: 6px;
          margin-top: 8px;
          padding-top: 6px;
          border-top: 1px solid ${C.border}30;
        }
        .ai-msg-action-btn {
          background: transparent;
          border: 1px solid ${C.border};
          color: ${C.muted};
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 10px;
          font-family: monospace;
          cursor: pointer;
          transition: all 0.2s;
        }
        .ai-msg-action-btn:hover {
          color: ${C.accent};
          border-color: ${C.accent};
        }
        .ai-quick-actions {
          display: flex;
          gap: 6px;
          padding: 6px 14px;
          border-top: 1px solid ${C.border}30;
          background: ${C.panel};
          flex-shrink: 0;
          flex-wrap: wrap;
        }
        .ai-quick-btn {
          background: ${C.bg};
          border: 1px solid ${C.border};
          color: ${C.muted};
          padding: 4px 10px;
          border-radius: 12px;
          font-size: 10px;
          font-family: monospace;
          cursor: pointer;
          transition: all 0.2s;
        }
        .ai-quick-btn:hover {
          color: ${C.accent};
          border-color: ${C.accent};
          background: ${C.accent}10;
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
            {msg.role === "assistant" && i > 0 && !loading && msg.content && (
              <div className="ai-msg-actions">
                <button
                  className="ai-msg-action-btn"
                  onClick={() => copyToClipboard(msg.content)}
                >📋 Copy</button>
                {i === messages.length - 1 && (
                  <button
                    className="ai-msg-action-btn"
                    onClick={regenerateLast}
                  >🔄 Regenerate</button>
                )}
              </div>
            )}
          </div>
        ))}

        {loading && !messages[messages.length - 1]?.content?.length && (
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

      {/* Quick actions */}
      {!loading && messages.length <= 1 && (
        <div className="ai-quick-actions">
          {mode === "security" && (
            <>
              <button className="ai-quick-btn" onClick={analyzeLastScan}>🔍 Analyze Last Scan</button>
              <button className="ai-quick-btn" onClick={() => sendMessage("Какие основные техники WAF bypass для XSS?")}>🛡 WAF Bypass</button>
              <button className="ai-quick-btn" onClick={() => sendMessage("Покажи чеклист для пентеста веб-приложения")}>📋 Pentest Checklist</button>
              <button className="ai-quick-btn" onClick={() => sendMessage("Объясни OWASP Top 10 в контексте реальных атак")}>🏆 OWASP Top 10</button>
            </>
          )}
          {mode === "code" && (
            <>
              <button className="ai-quick-btn" onClick={() => sendMessage("Review мой server.js — какие проблемы ты видишь?")}>🔍 Review server.js</button>
              <button className="ai-quick-btn" onClick={() => sendMessage("Как добавить новый API endpoint в server.js?")}>➕ New Endpoint</button>
              <button className="ai-quick-btn" onClick={() => sendMessage("Какие оптимизации производительности можно сделать?")}>⚡ Optimize</button>
            </>
          )}
          {mode === "general" && (
            <>
              <button className="ai-quick-btn" onClick={() => sendMessage("Что такое CORS и как он работает?")}>🌐 CORS</button>
              <button className="ai-quick-btn" onClick={() => sendMessage("Объясни как работает JWT")}>🔑 JWT</button>
              <button className="ai-quick-btn" onClick={() => sendMessage("Расскажи про DNS resolution")}>📡 DNS</button>
            </>
          )}
        </div>
      )}

      {/* Scanner quick-launch bar */}
      {mode === "security" && !loading && (
        <div style={{
          display: "flex", gap: 6, padding: "6px 14px", borderTop: `1px solid ${C.border}20`,
          background: C.panel, flexShrink: 0, flexWrap: "wrap", alignItems: "center",
        }}>
          <input
            value={scanTarget}
            onChange={e => setScanTarget(e.target.value)}
            placeholder="target.com / IP"
            style={{
              background: C.bg, border: `1px solid ${C.border}`, borderRadius: 4,
              color: C.text, fontFamily: "monospace", fontSize: 11, padding: "4px 8px",
              width: 130, outline: "none",
            }}
            onKeyDown={e => e.key === "Enter" && scanTarget.trim() && runScannerForAI("nuclei", scanTarget)}
          />
          <button className="ai-quick-btn" onClick={() => runScannerForAI("nuclei", scanTarget)}>☢ Nuclei</button>
          <button className="ai-quick-btn" onClick={() => runScannerForAI("jaeles", scanTarget)}>⚔ Jaeles</button>
          <button className="ai-quick-btn" onClick={() => runScannerForAI("shodan", scanTarget)}>🔭 Shodan</button>
          <button className="ai-quick-btn" onClick={() => runScannerForAI("crtsh", scanTarget)}>📜 crt.sh</button>
          <button className="ai-quick-btn" onClick={() => runScannerForAI("cve", scanTarget)}>🔍 CVE</button>
          <button className="ai-quick-btn" onClick={() => runScannerForAI("urlscan", scanTarget)}>📸 URLScan</button>
          <button className="ai-quick-btn" onClick={() => runScannerForAI("exploitdb", scanTarget)}>💣 ExploitDB</button>
          <button className="ai-quick-btn" onClick={() => runScannerForAI("censys", scanTarget)}>🔬 Censys</button>
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
