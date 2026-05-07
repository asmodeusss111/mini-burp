import { useState, useEffect, useRef } from "react";
import { C } from "../lib/constants.js";

function escHtml(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

function renderMarkdown(text) {
  if (text === undefined || text === null) return "";
  let html = typeof text === 'string' ? text : String(text);
  html = escHtml(html);
  html = html.replace(/\n/g, "<br/>");
  return html;
}

export default function MinimalChat() {
  const [messages, setMessages] = useState([{ role: 'assistant', content: 'Привет — вставь OpenRouter ключ при первом открытии, потом пиши.' }]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const chatEnd = useRef(null);

  useEffect(() => { try { const saved = localStorage.getItem('ai_chat_histories_min'); if (saved) setMessages(JSON.parse(saved)); } catch {} }, []);
  useEffect(() => { try { localStorage.setItem('ai_chat_histories_min', JSON.stringify(messages)); } catch {} }, [messages]);
  useEffect(() => chatEnd.current?.scrollIntoView({ behavior: 'smooth' }), [messages]);

  const send = async () => {
    const text = input.trim();
    if (!text || loading) return;
    // Server will use OPENROUTER_API_KEY from env if client does not provide apiKey
    const apiKey = localStorage.getItem('openrouter_key') || '';
    const userMsg = { role: 'user', content: text };
    setMessages(m => [...m, userMsg]);
    setInput('');
    setLoading(true);
    setError('');

    try {
      const apiMessages = [ { role: 'system', content: 'You are a helpful assistant.' }, ...messages.filter(m=>m.role==='user' || m.role==='assistant').map(m=>({ role: m.role, content: m.content })), { role: 'user', content: text } ];
      const r = await fetch('/api/chat', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ messages: apiMessages, model: 'openrouter/free', apiKey }) });
      if (!r.ok) throw new Error('Network');
      const reader = r.body.getReader();
      const dec = new TextDecoder();
      let assistant = '';
      setMessages(m => [...m, { role: 'assistant', content: '' }]);

      // SSE parser: accumulate chunks and split by double-newline which separates events
      let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });

        let parts = buf.split('\n\n');
        // Keep last partial part in buffer
        buf = parts.pop();

        for (const part of parts) {
          const lines = part.split(/\r?\n/).map(l => l.trim());
          for (const line of lines) {
            if (!line) continue;
            if (line.startsWith('data:')) {
              const data = line.slice(5).trim();
              if (data === '[DONE]') continue;
              try {
                const parsed = JSON.parse(data);
                const delta = parsed.choices?.[0]?.delta;
                const chunkText = (delta && (delta.content || delta?.text)) ? (delta.content || delta.text) : '';
                if (chunkText) {
                  assistant += chunkText;
                  setMessages(prev => {
                    const next = [...prev];
                    next[next.length - 1] = { role: 'assistant', content: assistant };
                    return next;
                  });
                }
              } catch (e) {
                // If not JSON, append raw data
                assistant += data;
                setMessages(prev => {
                  const next = [...prev];
                  next[next.length - 1] = { role: 'assistant', content: assistant };
                  return next;
                });
              }
            }
          }
        }
      }
      // flush any remaining buffer if it contains a final data chunk
      if (buf) {
        const m = buf.match(/data:\s*(.*)/s);
        if (m && m[1]) {
          try {
            const parsed = JSON.parse(m[1]);
            const delta = parsed.choices?.[0]?.delta;
            const chunkText = (delta && (delta.content || delta?.text)) ? (delta.content || delta.text) : '';
            if (chunkText) assistant += chunkText;
          } catch {
            assistant += m[1];
          }
          setMessages(prev => {
            const next = [...prev];
            next[next.length - 1] = { role: 'assistant', content: assistant };
            return next;
          });
        }
      }
    } catch (err) {
      setError(err.message);
      setMessages(m => [...m, { role: 'assistant', content: `❌ Ошибка: ${err.message}` }]);
    }

    setLoading(false);
  };

  const handleKey = (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } };

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: 10, borderBottom: `1px solid ${C.border}`, background: C.panel, fontFamily: 'monospace', color: C.text }}>AI Chat</div>
      <div style={{ flex: 1, overflowY: 'auto', padding: 10 }}>
        {messages.map((m, i) => (
          <div key={i} style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 11, color: m.role === 'user' ? C.accent : C.muted, fontFamily: 'monospace' }}>{m.role === 'user' ? 'You' : 'AI'}</div>
            <div style={{ marginTop: 6, fontFamily: 'monospace', fontSize: 13 }} dangerouslySetInnerHTML={{ __html: renderMarkdown(m.content) }} />
          </div>
        ))}
        <div ref={chatEnd} />
      </div>
      {error && <div style={{ padding: 8, color: C.red, fontFamily: 'monospace' }}>{error}</div>}
      <div style={{ padding: 10, borderTop: `1px solid ${C.border}`, background: C.panel, display: 'flex', gap: 8 }}>
        <textarea value={input} onChange={e=>setInput(e.target.value)} onKeyDown={handleKey} rows={2} style={{ flex: 1, background: C.bg, border: `1px solid ${C.border}`, color: C.text, fontFamily: 'monospace', padding: 8, resize: 'none' }} />
        <button onClick={send} disabled={loading} style={{ background: C.accent, border: 'none', color: '#fff', padding: '8px 12px', borderRadius: 6, fontFamily: 'monospace' }}>{loading ? '...' : 'Send'}</button>
      </div>
    </div>
  );
}
