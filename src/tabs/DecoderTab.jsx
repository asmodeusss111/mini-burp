import { useState } from "react";
import { C } from "../lib/constants.js";
import { Panel, Btn, Tag } from "../components/ui.jsx";

// Unicode-safe base64 using TextEncoder/TextDecoder (fixes deprecated escape/unescape)
function encodeBase64(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = "";
  bytes.forEach(b => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

function decodeBase64(str) {
  const binary = atob(str.trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

// Simple MD5 implementation (RFC 1321)
function md5(input) {
  const e = new TextEncoder();
  const msg = e.encode(input);
  const s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
             6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
             6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
             7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22];
  const K = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
             0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
             0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
             0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
             0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
             0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
             0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
             0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391];
  let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
  const bits = msg.length * 8;
  const padded = new Uint8Array(((msg.length + 8) >> 6) * 64 + 64);
  padded.set(msg);
  padded[msg.length] = 0x80;
  new DataView(padded.buffer).setBigUint64(padded.length - 8, BigInt(bits), true);
  for (let i = 0; i < padded.length; i += 64) {
    const x = new Uint32Array(16);
    for (let j = 0; j < 16; j++) x[j] = new DataView(padded.buffer, i + j * 4).getUint32(0, true);
    let aa = a, bb = b, cc = c, dd = d;
    for (let j = 0; j < 64; j++) {
      let f, g;
      if (j < 16) { f = (bb & cc) | ((~bb) & dd); g = j; }
      else if (j < 32) { f = (dd & bb) | ((~dd) & cc); g = (5 * j + 1) % 16; }
      else if (j < 48) { f = bb ^ cc ^ dd; g = (3 * j + 5) % 16; }
      else { f = cc ^ (bb | (~dd)); g = (7 * j) % 16; }
      const temp = dd;
      dd = cc;
      cc = bb;
      bb = bb + (((aa + f + K[j] + x[g]) >>> 0) << s[j] | (aa + f + K[j] + x[g]) >>> (32 - s[j])) >>> 0;
      aa = temp;
    }
    a = (a + aa) >>> 0;
    b = (b + bb) >>> 0;
    c = (c + cc) >>> 0;
    d = (d + dd) >>> 0;
  }
  const toHex = x => ((x >>> 0).toString(16).padStart(8, '0'));
  return (toHex(a) + toHex(b) + toHex(c) + toHex(d)).replace(/(.{8})/g, '$1 ').trim();
}

export default function DecoderTab() {
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [mode, setMode] = useState("decode");
  const [format, setFormat] = useState("base64");
  const [jwt, setJwt] = useState(null);

  const run = async () => {
    try {
      let result = "";
      if (format === "base64") {
        result = mode === "encode" ? encodeBase64(input) : decodeBase64(input);
      } else if (format === "url") {
        result = mode === "encode" ? encodeURIComponent(input) : decodeURIComponent(input);
      } else if (format === "html") {
        if (mode === "encode") {
          result = input.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
        } else {
          const textarea = document.createElement("textarea");
          textarea.innerHTML = input;
          result = textarea.value;
        }
      } else if (format === "hex") {
        if (mode === "encode") {
          result = Array.from(input).map(c => c.charCodeAt(0).toString(16).padStart(2, "0")).join(" ");
        } else {
          result = input.replace(/\s/g, "").match(/.{2}/g)?.map(h => String.fromCharCode(parseInt(h, 16))).join("") || "";
        }
      } else if (format === "binary") {
        if (mode === "encode") {
          result = Array.from(input).map(c => c.charCodeAt(0).toString(2).padStart(8, "0")).join(" ");
        } else {
          result = (input.match(/[01]{8}/g) || []).map(b => String.fromCharCode(parseInt(b, 2))).join("");
        }
      } else if (format === "unicode") {
        if (mode === "encode") {
          result = Array.from(input).map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`).join("");
        } else {
          result = input.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
        }
      } else if (format === "hash") {
        const encoder = new TextEncoder();
        const data = encoder.encode(input);
        const md5Hash = md5(input);
        const sha1 = await crypto.subtle.digest("SHA-1", data).then(b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,"0")).join(""));
        const sha256 = await crypto.subtle.digest("SHA-256", data).then(b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,"0")).join(""));
        result = `MD5:    ${md5Hash}\nSHA-1:  ${sha1}\nSHA-256: ${sha256}`;
      } else if (format === "jwt") {
        const parts = input.trim().split(".");
        if (parts.length === 3) {
          const pad = s => s + "=".repeat((4 - (s.length % 4)) % 4);
          const header = JSON.parse(decodeBase64(pad(parts[0].replace(/-/g, "+").replace(/_/g, "/"))));
          const payload = JSON.parse(decodeBase64(pad(parts[1].replace(/-/g, "+").replace(/_/g, "/"))));
          setJwt({ header, payload, sig: parts[2] });
          return;
        } else {
          result = "Invalid JWT (expected 3 parts separated by '.')";
        }
      }
      setJwt(null);
      setOutput(result);
    } catch (e) {
      setOutput(`Error: ${e.message}`);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8, height: "100%" }}>
      <Panel style={{ padding: 12 }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <span style={{ color: C.muted, fontSize: 11, fontFamily: "monospace" }}>Format:</span>
          {["base64", "url", "html", "hex", "binary", "unicode", "hash", "jwt"].map(f => (
            <Btn key={f} onClick={() => { setFormat(f); setOutput(""); setJwt(null); }} active={format === f} small>
              {f.toUpperCase()}
            </Btn>
          ))}
          <div style={{ width: 1, height: 20, background: C.border }} />
          {format !== "hash" && ["encode", "decode"].map(m => (
            <Btn key={m} onClick={() => setMode(m)} active={mode === m} color={m === "encode" ? C.blue : C.green} small>{m}</Btn>
          ))}
          <Btn onClick={() => run()} active color={C.accent}>▶ Run</Btn>
          <Btn onClick={() => { setInput(output); setOutput(""); setJwt(null); }} small>⇄ Swap</Btn>
        </div>
      </Panel>

      <div style={{ display: "flex", gap: 8, flex: 1, minWidth: 0 }}>
        <Panel style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          <div style={{ padding: "6px 12px", borderBottom: `1px solid ${C.border}`, color: C.muted, fontSize: 10, letterSpacing: 1, flexShrink: 0 }}>INPUT</div>
          <div style={{ flex: 1, padding: 12, minHeight: 0 }}>
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder="Paste text here..."
              spellCheck="false"
              style={{ width: "100%", height: "100%", background: C.bg, border: `1px solid ${C.border}`, color: C.text, fontFamily: "monospace", fontSize: 12, outline: "none", padding: 8, resize: "none", boxSizing: "border-box", borderRadius: 4 }}
            />
          </div>
        </Panel>

        <Panel style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          <div style={{ padding: "6px 12px", borderBottom: `1px solid ${C.border}`, color: C.muted, fontSize: 10, letterSpacing: 1, flexShrink: 0 }}>OUTPUT</div>
          <div style={{ flex: 1, padding: 12, overflowY: "auto", minHeight: 0 }}>
            {jwt ? (
              <div>
                <div style={{ color: C.muted, fontSize: 10, marginBottom: 4 }}>HEADER</div>
                <pre style={{ color: C.blue, fontFamily: "monospace", fontSize: 11, margin: "0 0 12px" }}>{JSON.stringify(jwt.header, null, 2)}</pre>
                <div style={{ color: C.muted, fontSize: 10, marginBottom: 4 }}>PAYLOAD</div>
                <pre style={{ color: C.green, fontFamily: "monospace", fontSize: 11, margin: "0 0 12px" }}>{JSON.stringify(jwt.payload, null, 2)}</pre>
                <div style={{ color: C.muted, fontSize: 10, marginBottom: 4 }}>SIGNATURE</div>
                <div style={{ color: C.red, fontFamily: "monospace", fontSize: 11, wordBreak: "break-all", marginBottom: 12 }}>{jwt.sig}</div>
                {jwt.payload.exp && (
                  <Tag
                    label={new Date(jwt.payload.exp * 1000) < new Date()
                      ? "⚠ TOKEN EXPIRED"
                      : "✓ Valid: " + new Date(jwt.payload.exp * 1000).toLocaleString()}
                    color={new Date(jwt.payload.exp * 1000) < new Date() ? C.red : C.green}
                  />
                )}
              </div>
            ) : (
              <pre style={{ margin: 0, color: output.startsWith("Error") ? C.red : C.green, fontFamily: "monospace", fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                {output || <span style={{ color: C.muted }}>Output appears here</span>}
              </pre>
            )}
          </div>
        </Panel>
      </div>
    </div>
  );
}
