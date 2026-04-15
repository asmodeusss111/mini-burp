// When Vite proxy is active, calls go through /proxy, /headers, etc.
// Falls back to direct localhost:8080 if running outside Vite.
const PROXY = "";  // empty = relative paths, proxied by Vite to localhost:8080

export async function checkProxy() {
  try {
    const r = await fetch(`/health`, {
      signal: AbortSignal.timeout(2000),
    });
    if (!r.ok) return false;
    const data = await r.json();
    return data.ok === true;
  } catch {
    return false;
  }
}

// Normalizes response from proxy or fallback API to consistent format
// Always returns: { status, headers, body, url, error? }
export async function apiGet(url, local) {
  try {
    if (local) {
      const r = await fetch(`/proxy?url=${encodeURIComponent(url)}`).then(r => r.json()).catch(() => null);
      if (!r) return { status: 0, headers: {}, body: "", url, error: "Request failed" };
      return { status: r.status || 200, headers: r.headers || {}, body: r.body || "", url: r.url || url };
    }
    // allorigins.win fallback
    const r = await fetch(`https://api.allorigins.win/get?url=${encodeURIComponent(url)}`).then(r => r.json()).catch(() => null);
    if (!r || r.status === "error") return { status: 0, headers: {}, body: "", url, error: r?.message || "API error" };
    // allorigins returns: { status: "success", contents, status_code, ... }
    return { status: r.status_code || 0, headers: r.headers || {}, body: r.contents || "", url };
  } catch (e) {
    return { status: 0, headers: {}, body: "", url, error: e.message };
  }
}

export async function getHeaders(url, local) {
  if (!local) return null;
  return fetch(`/headers?url=${encodeURIComponent(url)}`).then(r => r.json()).catch(() => null);
}

export async function portScan(host, local) {
  if (local) {
    return fetch(`/portscan?host=${encodeURIComponent(host)}`).then(r => r.json()).catch(() => null);
  }
  const raw = await fetch(`https://api.hackertarget.com/nmap/?q=${encodeURIComponent(host)}`)
    .then(r => r.text())
    .catch(() => null);
  if (!raw || raw.includes("API count exceeded")) return null;
  const results = raw.split("\n").filter(l => l.trim()).map(l => {
    const m = l.match(/(\d+)\/(tcp|udp)\s+(\w+)/);
    return m ? { port: parseInt(m[1]), status: m[3] } : null;
  }).filter(Boolean);
  return { results };
}

export async function sendRequest(payload, local) {
  if (local) {
    return fetch(`/request`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then(r => r.json()).catch(e => ({ error: e.message }));
  }
  const r = await fetch(`https://api.allorigins.win/get?url=${encodeURIComponent(payload.url)}`)
    .then(r => r.json())
    .catch(() => null);
  return { status: 200, headers: {}, body: r?.contents || "", url: payload.url };
}

export const dnsQ = (name, type) =>
  fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`)
    .then(r => r.json())
    .catch(() => null);

export function cleanHost(raw) {
  try {
    return new URL(raw.includes("://") ? raw : "https://" + raw).hostname;
  } catch {
    return raw.trim();
  }
}

// Returns an error string if the host is private/internal, null if safe.
const PRIVATE_RE = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.|::1$|localhost$)/i;

export function validateHost(host) {
  if (!host || host.trim() === "") return "Empty host";
  if (PRIVATE_RE.test(host)) return "Private/internal addresses are not allowed";
  // Must look like a real hostname or IP
  const validHostname = /^[a-z0-9]([a-z0-9\-\.]{0,251}[a-z0-9])?$/i;
  if (!validHostname.test(host)) return "Invalid hostname format";
  return null; // safe
}
