import { useState, useRef, useCallback, useEffect } from "react";
import { C, SEV, CHECKS } from "../lib/constants.js";
import { apiGet, getHeaders, portScan, dnsQ, cleanHost, validateHost, sendRequest, whoisLookup } from "../lib/api.js";
import { Panel, Btn, Tag, Inp } from "../components/ui.jsx";

function exportReport(domain, results, checks, format = "txt") {
  let blob;
  const filename = `burp-report-${domain.replace(/\./g, "_")}`;
  if (format === "json") {
    const data = { target: domain, date: new Date().toISOString(), results: {} };
    for (const c of checks) { if (results[c.id]) data.results[c.id] = results[c.id]; }
    blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  } else {
    const lines = [`Mini Burp Scan Report`, `Target: ${domain}`, `Date: ${new Date().toISOString()}`, `---`];
    for (const c of checks) {
      const r = results[c.id];
      if (!r) continue;
      lines.push(`\n[${r.severity.toUpperCase()}] ${c.label}: ${r.summary}`);
      r.lines?.forEach(l => lines.push(`  ${l}`));
      r.recs?.forEach(rec => lines.push(`  → ${rec}`));
    }
    blob = new Blob([lines.join("\n")], { type: "text/plain" });
  }
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${filename}.${format}`;
  a.click();
  URL.revokeObjectURL(a.href);
}

export default function ScannerTab({ proxyOnline }) {
  const [domain, setDomain] = useState("");
  const [phase, setPhase] = useState("idle");
  const [results, setRes] = useState({});
  const [logs, setLogs] = useState([]);
  const [active, setActive] = useState(new Set());
  const [sel, setSel] = useState(null);
  const [sslProgress, setSslProgress] = useState(0);
  const sslAbort = useRef(null);
  const logRef = useRef(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const log = (text, color = C.muted) =>
    setLogs(l => [...l, { text, color, id: crypto.randomUUID() }]);

  const setR = (id, d) => setRes(p => ({ ...p, [id]: d }));
  const markA = id => setActive(s => new Set([...s, id]));

  const reset = () => {
    sslAbort.current?.abort();
    setPhase("idle"); setRes({}); setLogs([]); setActive(new Set()); setSel(null); setSslProgress(0);
  };

  const runScan = useCallback(async () => {
    if (!domain.trim()) return;
    setPhase("scanning"); setRes({}); setLogs([]); setActive(new Set()); setSel(null); setSslProgress(0);
    const localResults = {};
    const setR = (id, d) => {
      localResults[id] = d;
      setRes(p => ({ ...p, [id]: d }));
    };
    const host = cleanHost(domain);
    const hostErr = validateHost(host);
    if (hostErr) {
      log(`[✗] ${hostErr}`, C.red);
      setPhase("idle");
      return;
    }
    log(`[*] Target: ${host}`, C.accent);
    log(`[*] Proxy: ${proxyOnline ? "localhost:8080 ✓" : "offline → fallback"}`, proxyOnline ? C.green : C.yellow);

    // 1. Redirect
    markA("redirect");
    try {
      const r = await apiGet("http://" + host, proxyOnline);
      if (r.error) {
        setR("redirect", { severity: "info", summary: "Failed", lines: [`[-] ${r.error}`], recs: [] });
        log(`[!] Redirect: ${r.error}`, C.yellow);
      } else {
        const finalUrl = r.url || null;
        const ok = finalUrl?.startsWith("https");
        const status = r.status || 0;
        setR("redirect", {
          severity: ok ? "low" : status === 301 || status === 302 ? "medium" : "high",
          summary: ok ? "HTTPS ✓" : status >= 300 && status < 400 ? `Redirects to ${finalUrl}` : "No redirect",
          lines: [`GET http://${host}`, `Status: ${status}`, ok ? "[+] Redirects to HTTPS" : `[-] Final: ${finalUrl || "Not HTTPS"}`, `[i] URL: ${finalUrl || "n/a"}`],
          recs: ok ? [] : ["Configure 301 redirect", "Add HSTS"],
        });
        log(`[+] Redirect: ${ok ? "OK" : "MISSING"}`, ok ? C.green : C.red);
      }
    } catch { setR("redirect", { severity: "info", summary: "Error", lines: ["[-] Failed"], recs: [] }); }

    // 2. DNS
    markA("dns");
    try {
      const [a, mx, ns] = await Promise.all([dnsQ(host, "A"), dnsQ(host, "MX"), dnsQ(host, "NS")]);
      const ips = a?.Answer?.map(x => x.data) || [];
      setR("dns", {
        severity: "info",
        summary: `${ips.length} IPs, DNSSEC:${a?.AD ? "✓" : "✗"}`,
        lines: [
          `DNS: ${host}`,
          ...ips.map(ip => `[+] A: ${ip}`),
          ...(mx?.Answer?.slice(0, 2).map(m => `[i] MX: ${m.data}`) || []),
          ...(ns?.Answer?.slice(0, 2).map(n => `[i] NS: ${n.data}`) || []),
          a?.AD ? "[+] DNSSEC signed ✓" : "[!] DNSSEC missing",
        ],
        recs: a?.AD ? [] : ["Enable DNSSEC"],
      });
      log(`[+] DNS: ${ips.join(", ")}`, C.blue);
    } catch { setR("dns", { severity: "info", summary: "Error", lines: ["[-] Failed"], recs: [] }); }

    // 3. SSL — with abort + progress
    markA("ssl");
    log("[*] SSL Labs (~60s)...", C.muted);
    sslAbort.current = new AbortController();
    try {
      const ssl = await fetch(`/ssl?host=${encodeURIComponent(host)}`).then(r => r.json());
      if (ssl.error) throw new Error(ssl.error);
      const sev = ssl.valid ? "low" : "high";
      setR("ssl", {
        severity: sev,
        summary: ssl.valid ? `Valid (${ssl.daysLeft}d left)` : "Invalid/Untrusted",
        lines: [
          `TLS: ${host}`,
          `[i] Protocol: ${ssl.protocol}`,
          `[i] Cipher: ${ssl.cipher}`,
          `[i] Issuer: ${ssl.issuer}`,
          `[i] Subject: ${ssl.subject}`,
          ssl.valid ? `[+] Valid for ${ssl.daysLeft} days` : "[-] Untrusted or expired certificate",
        ],
        recs: ssl.valid ? [] : ["Renew SSL certificate", "Check certificate chain"],
      });
      log(`[+] SSL: ${ssl.valid ? "Valid" : "Invalid"}`, ssl.valid ? C.green : C.red);
    } catch (e) {
      setR("ssl", { severity: "info", summary: e.message, lines: [`[-] ${e.message}`], recs: [] });
    }
    setSslProgress(0);

    // 4. Headers
    markA("headers");
    try {
      const r = await getHeaders("https://" + host, proxyOnline);
      if (proxyOnline && r?.headers) {
        const h = r.headers;
        const wanted = [
          { n: "Strict-Transport-Security", k: "strict-transport-security" },
          { n: "Content-Security-Policy", k: "content-security-policy" },
          { n: "X-Frame-Options", k: "x-frame-options" },
          { n: "X-Content-Type-Options", k: "x-content-type-options" },
          { n: "Referrer-Policy", k: "referrer-policy" },
          { n: "Permissions-Policy", k: "permissions-policy" },
        ];
        const present = wanted.filter(c => h[c.k]);
        const missing = wanted.filter(c => !h[c.k]);
        const sev = missing.length === 0 ? "low" : missing.length <= 2 ? "medium" : "high";
        setR("headers", {
          severity: sev,
          summary: `${present.length}/${wanted.length} headers`,
          lines: [
            `HEAD https://${host}`,
            `[i] Server: ${h["server"] || "hidden"}`,
            `[i] X-Powered-By: ${h["x-powered-by"] || "hidden ✓"}`,
            ...present.map(c => `[+] ${c.n}: ${h[c.k]?.slice(0, 50)}`),
            ...missing.map(c => `[-] ${c.n}: MISSING`),
          ],
          recs: missing.map(c => `Add ${c.n}`),
        });
        log(`[+] Headers: ${present.length}/${wanted.length} secure`, sev === "low" ? C.green : C.yellow);
      } else {
        setR("headers", {
          severity: "medium",
          summary: "Start proxy for real scan",
          lines: ["[i] Run: node server.js", "[!] Browser CORS blocks header reading"],
          recs: ["node server.js", "Add CSP, HSTS, X-Frame-Options"],
          link: `https://securityheaders.com/?q=https://${host}`,
        });
        log("[!] Headers: need proxy", C.yellow);
      }
    } catch { setR("headers", { severity: "info", summary: "Error", lines: ["[-] Failed"], recs: [] }); }

    // 5. Email
    markA("email");
    try {
      const [spf, dmarc, dkim] = await Promise.all([
        dnsQ(host, "TXT"),
        dnsQ("_dmarc." + host, "TXT"),
        dnsQ("default._domainkey." + host, "TXT"),
      ]);
      const hasSPF = spf?.Answer?.some(x => x.data.includes("v=spf1"));
      const hasDMARC = dmarc?.Answer?.some(x => x.data.includes("v=DMARC1"));
      const hasDKIM = dkim?.Answer?.some(x => x.data.includes("v=DKIM1"));
      const count = [hasSPF, hasDMARC, hasDKIM].filter(Boolean).length;
      const sev = count === 3 ? "low" : count >= 1 ? "medium" : "critical";
      setR("email", {
        severity: sev,
        summary: `${count}/3 records`,
        lines: [
          `Email: ${host}`,
          hasSPF ? "[+] SPF: found" : "[-] SPF: MISSING",
          hasDMARC ? "[+] DMARC: found" : "[-] DMARC: MISSING",
          hasDKIM ? "[+] DKIM: found" : "[!] DKIM: not found",
        ],
        recs: [
          ...(!hasSPF ? ["Add SPF record"] : []),
          ...(!hasDMARC ? ["Add DMARC"] : []),
          ...(!hasDKIM ? ["Configure DKIM"] : []),
        ],
      });
      log(`[+] Email: SPF:${hasSPF ? "✓" : "✗"} DKIM:${hasDKIM ? "✓" : "✗"} DMARC:${hasDMARC ? "✓" : "✗"}`, sev === "low" ? C.green : C.yellow);
    } catch { setR("email", { severity: "info", summary: "Error", lines: ["[-] DNS error"], recs: [] }); }

    // 6. Subdomains
    markA("subdomains");
    try {
      const data = await fetch(`https://crt.sh/?q=${encodeURIComponent("%" + host)}&output=json`)
        .then(r => r.json()).catch(() => null);
      const unique = data
        ? [...new Set(data.map(e => e.name_value).filter(n => n.includes(host) && !n.includes("*")).sort())]
        : [];
      setR("subdomains", {
        severity: unique.length > 10 ? "medium" : "info",
        summary: `${unique.length} found`,
        lines: [
          `crt.sh: *.${host}`,
          `[i] Total: ${unique.length}`,
          ...unique.slice(0, 10).map(s => `[+] ${s}`),
          unique.length > 10 ? `[i] ...+${unique.length - 10} more` : "",
        ].filter(Boolean),
        recs: unique.length > 5 ? ["Audit each subdomain", "Disable unused"] : [],
      });
      log(`[+] Subdomains: ${unique.length}`, C.blue);
    } catch { setR("subdomains", { severity: "info", summary: "Error", lines: ["[-] crt.sh unavailable"], recs: [] }); }

    // 7. Ports
    markA("ports");
    try {
      const data = await portScan(host, proxyOnline);
      if (data?.results) {
        const NAMES = { 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB" };
        const open = data.results.filter(p => p.status === "open");
        const dangerous = open.filter(p => [21, 23, 25, 110, 143, 3306, 5432, 6379, 27017, 445].includes(p.port));
        setR("ports", {
          severity: dangerous.length > 0 ? "high" : open.length > 3 ? "medium" : "low",
          summary: `${open.length} open, ${dangerous.length} dangerous`,
          lines: [
            proxyOnline ? `[+] Real TCP scan: ${host}` : `[i] HackerTarget: ${host}`,
            `[i] Open: ${open.length}`,
            ...open.map(p => `${dangerous.includes(p) ? "[!!]" : "[+]"} ${p.port}/tcp ${NAMES[p.port] || ""} OPEN`),
            dangerous.length > 0 ? `[!!] Dangerous: ${dangerous.map(p => p.port).join(", ")}` : "[+] No dangerous ports",
          ],
          recs: dangerous.length > 0 ? ["Close ports in firewall", "Block DB ports", "FTP→SFTP"] : [],
        });
        log(`[+] Ports: ${open.length} open, ${dangerous.length} dangerous`, dangerous.length > 0 ? C.red : C.green);
      } else {
        setR("ports", {
          severity: "info",
          summary: proxyOnline ? "Scan failed" : "Need proxy",
          lines: [proxyOnline ? "[-] Scan failed" : "[i] Real port scan needs proxy", "[i] Run: node server.js"],
          recs: ["Run: node server.js"],
        });
        log(`[!] Ports: ${proxyOnline ? "failed" : "need proxy"}`, C.yellow);
      }
    } catch (e) { setR("ports", { severity: "info", summary: e.message, lines: [`[-] ${e.message}`], recs: [] }); }

    // 8. Robots
    markA("robots");
    try {
      const [robots, sitemap] = await Promise.all([
        apiGet("https://" + host + "/robots.txt", proxyOnline),
        apiGet("https://" + host + "/sitemap.xml", proxyOnline),
      ]);
      // Check status code (200 = file exists, not error page)
      const hasR = robots.status === 200 && robots.body.length > 10;
      const hasS = sitemap.status === 200 && (sitemap.body.includes("<?xml") || sitemap.body.includes("<urlset"));
      const sensitive = hasR && (robots.body.includes("Disallow: /admin") || robots.body.includes("Disallow: /private") || robots.body.includes("Disallow: /.env"));
      setR("robots", {
        severity: sensitive ? "medium" : "info",
        summary: `robots:${hasR ? "✓" : "✗"} sitemap:${hasS ? "✓" : "✗"}`,
        lines: [
          `robots.txt: ${host}`,
          hasR ? `[+] Found (${robots.status})` : `[-] Missing (${robots.status})`,
          ...(hasR ? (robots.body.match(/Disallow: (.+)/g) || []).slice(0, 5).map(d => `[i] ${d}`) : []),
          sensitive ? "[!!] Sensitive paths exposed!" : hasR ? "[+] Clean" : "[!] Not found",
          hasS ? `[+] sitemap.xml ✓ (${sitemap.status})` : `[!] sitemap.xml missing (${sitemap.status})`,
        ],
        recs: [...(!hasR ? ["Create robots.txt"] : []), ...(sensitive ? ["Don't expose sensitive paths in robots.txt"] : [])],
      });
      log(`[+] Robots: ${hasR ? "found" : "missing"}`, hasR ? C.green : C.yellow);
    } catch { setR("robots", { severity: "info", summary: "Error", lines: ["[-] Failed"], recs: [] }); }

    // 9. Tech — better detection with regex + version info
    markA("tech");
    try {
      const r = await apiGet("https://" + host, proxyOnline);
      if (r.error) {
        setR("tech", { severity: "info", summary: "Failed", lines: [`[-] ${r.error}`], recs: [] });
      } else {
        const html = r.body.toLowerCase();
        const found = [];

        // Regex patterns with word boundaries to avoid false positives
        if (/wp-content|wp-includes|\/wp-/i.test(html)) found.push({ n: "WordPress", risk: "medium", ver: html.match(/wp_version['":\s]*['"]*(\d+\.\d+)/i)?.[1] });
        if (/__NEXT_DATA__|__NEXT_PAGE__|next\/react/i.test(html)) found.push({ n: "Next.js", risk: "low" });
        if (/__NUXT__|nuxt\/dist/i.test(html)) found.push({ n: "Nuxt.js", risk: "low" });
        if (/(__REACT_DEVTOOLS__|React)/i.test(html) && /react/i.test(html)) found.push({ n: "React", risk: "low" });
        if (/\bvue\b|\/dist\/vue\.|window\.__VUE__/i.test(html)) found.push({ n: "Vue.js", risk: "low" });
        if (/angular\.|ng-app|ng-bind/i.test(html)) found.push({ n: "Angular", risk: "low" });
        if (/jquery['\"]?:['\"]?[\d.]+|jquery-(\d+\.\d+)/i.test(html)) found.push({ n: "jQuery", risk: "low" });
        if (/bootstrap['\"]?:['\"]?[\d.]+|\/bootstrap\//i.test(html)) found.push({ n: "Bootstrap", risk: "low" });
        if (/cdn\.cloudflare|powered by cloudflare/i.test(html)) found.push({ n: "Cloudflare", risk: "low" });
        if (/\.php\?|\.php\s|X-Powered-By.*PHP/i.test(html)) found.push({ n: "PHP", risk: "medium" });
        if (/laravel|artisan|laravel\.js/i.test(html)) found.push({ n: "Laravel", risk: "medium" });
        if (/shopify|myshopify|storefront/i.test(html)) found.push({ n: "Shopify", risk: "low" });

        setR("tech", {
          severity: found.some(t => t.risk === "medium") ? "medium" : "low",
          summary: found.map(t => `${t.n}${t.ver ? ` (${t.ver})` : ""}`).join(", ") || "Hidden",
          lines: [
            `Fingerprint: ${host}`,
            `[i] Found: ${found.length}`,
            ...found.map(t => `${t.risk === "medium" ? "[!]" : "[+]"} ${t.n}${t.ver ? ` v${t.ver}` : ""}`),
            found.length === 0 ? "[+] Well hidden" : "",
          ].filter(Boolean),
          recs: found.some(t => t.n === "WordPress") ? ["Update WordPress to latest", "Hide WP version"] : found.some(t => t.risk === "medium") ? ["Keep software updated"] : [],
        });
        log(`[+] Tech: ${found.map(t => t.n).join(", ") || "hidden"}`, C.blue);
      }
    } catch { setR("tech", { severity: "info", summary: "Error", lines: ["[-] Error"], recs: [] }); }

    // 10. WAF — test with XSS payload + check for blocking patterns
    markA("waf");
    try {
      const wafUrl = new URL(`https://${host}/`);
      wafUrl.searchParams.set("q", "<script>alert(1)</script>");
      const r = await apiGet(wafUrl.toString(), proxyOnline);

      let waf = null;
      const body = r.body?.toLowerCase() || "";
      const status = r.status || 0;
      const h = r.headers || {};
      const serverH = (h["server"] || "").toLowerCase();

      // Check for WAF response patterns via headers
      if (h["cf-ray"] || serverH.includes("cloudflare")) waf = "Cloudflare";
      else if (h["x-sucuri-id"] || h["x-sucuri-cache"] || serverH.includes("sucuri")) waf = "Sucuri";
      else if (h["x-amz-cf-id"] || h["x-waf-event-info"]) waf = "AWS WAF";
      else if (h["x-cdn"]) waf = "Generic CDN/WAF";
      else if (status === 403 || status === 406 || status === 429 || status === 503) {
        // Blocked by WAF (fallback check body)
        if (body.includes("imperva")) waf = "Imperva";
        else if (body.includes("akamai")) waf = "Akamai";
        else if (body.includes("mod_security")) waf = "ModSecurity";
        else waf = "Unknown WAF";
      } else if (body.includes("cloudflare") && (body.includes("error") || body.includes("blocked"))) {
        waf = "Cloudflare";
      }

      const severity = waf ? "low" : (status === 200 ? "high" : "medium");
      setR("waf", {
        severity,
        summary: waf ? `✓ ${waf}` : `Unprotected (${status})`,
        lines: [
          `WAF test: ${host}`,
          `Test payload: <script>alert(1)</script>`,
          `HTTP status: ${status}`,
          waf ? `[+] WAF detected: ${waf}` : status < 400 ? "[-] No WAF protection detected" : "[!] Blocked (potential WAF)",
        ],
        recs: waf ? [] : status === 200 ? ["Install WAF (Cloudflare, AWS Shield, etc.)", "Configure firewall rules"] : ["Verify WAF is properly configured"],
      });
      log(`[+] WAF: ${waf || "NOT DETECTED"}`, waf ? C.green : (status === 200 ? C.red : C.yellow));
    } catch { setR("waf", { severity: "info", summary: "Error", lines: ["[-] Failed"], recs: [] }); }

    // 11. IP Reputation
    markA("ip");
    try {
      const d = await dnsQ(host, "A");
      const ip = d?.Answer?.[0]?.data;
      let rep = null;
      if (ip) {
        const r = await fetch(`/proxy?url=${encodeURIComponent(`http://ip-api.com/json/${ip}?fields=status,country,city,isp,org,as,proxy,hosting`)}`).then(res => res.json()).catch(() => null);
        if (r && r.body) {
          try { rep = JSON.parse(r.body); } catch {}
        }
      }
      setR("ip", {
        severity: rep?.proxy ? "high" : "info",
        summary: `${ip} → ${rep?.country || "?"}`,
        lines: [
          `IP: ${ip}`,
          `[i] ${rep?.country}, ${rep?.city}`,
          `[i] ISP: ${rep?.isp}`,
          `[i] ASN: ${rep?.as}`,
          rep?.proxy ? "[!!] PROXY FLAG!" : "[+] No proxy",
          rep?.hosting ? "[i] Hosting/CDN" : "[+] Regular IP",
        ],
        recs: rep?.proxy ? ["Check traffic — suspicious"] : [],
      });
      log(`[+] IP: ${ip} (${rep?.country || "?"})`, C.blue);
    } catch { setR("ip", { severity: "info", summary: "Error", lines: ["[-] Error"], recs: [] }); }

    // 12. CVE — search by detected technologies, not domain name
    markA("cve");
    try {
      // Get tech detection results (from earlier scan)
      const techResults = localResults["tech"];
      if (!techResults || !techResults.summary || techResults.summary === "Hidden") {
        setR("cve", {
          severity: "info",
          summary: "No techs detected",
          lines: ["[i] CVE check requires technology detection", "[i] Run Tech fingerprinting first"],
          recs: ["Enable Tech check for CVE analysis"],
        });
        log(`[i] CVE: skipped (no tech detected)`, C.muted);
      } else {
        // Extract technology names from summary
        const techs = techResults.summary.match(/[\w\.\s\-]+/g)?.slice(0, 2) || [];
        const kw = techs[0] || "software";
        const data = await fetch(
          `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(kw)}&resultsPerPage=5`,
          { headers: { Accept: "application/json" } }
        ).then(r => r.json()).catch(() => null);
        const items = data?.vulnerabilities || [];
        const crit = items.filter(v => (v.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 0) >= 9);
        setR("cve", {
          severity: crit.length > 0 ? "critical" : items.length > 0 ? "medium" : "low",
          summary: `${items.length} found${crit.length > 0 ? `, ${crit.length} critical` : ""}`,
          lines: [
            `NVD search: "${kw}"`,
            `[i] Total: ${data?.totalResults || 0}`,
            items.length === 0 ? "[+] No known CVEs" : `[!] ${items.length} CVEs found:`,
            ...items.slice(0, 4).map(v => {
              const sc = v.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || "?";
              return `[${sc >= 9 ? "!!" : sc >= 7 ? "!" : "i"}] ${v.cve?.id} (CVSS ${sc})`;
            }),
          ],
          recs: crit.length > 0 ? ["URGENT: Update to patched version", "Apply security patches immediately"] : items.length > 0 ? ["Review and update affected software"] : [],
        });
        log(`[+] CVE: ${items.length}${crit.length > 0 ? `, critical: ${crit.length}` : ""}`, crit.length > 0 ? C.red : C.green);
      }
    } catch { setR("cve", { severity: "info", summary: "Error", lines: ["[-] NVD unavailable"], recs: [] }); }

    // 13. Security.txt
    markA("sectxt");
    try {
      const [root, wk] = await Promise.all([
        apiGet("https://" + host + "/security.txt", proxyOnline),
        apiGet("https://" + host + "/.well-known/security.txt", proxyOnline),
      ]);
      const content = proxyOnline
        ? ((root?.body || "") + (wk?.body || ""))
        : ((root?.contents || "") + (wk?.contents || ""));
      const has = content.includes("Contact:");
      setR("sectxt", {
        severity: has ? "low" : "info",
        summary: has ? "Found ✓" : "Missing",
        lines: [
          `/.well-known/security.txt`,
          has ? "[+] Found ✓" : "[i] Not found",
          has ? `[+] ${(content.match(/Contact: (.+)/) || [])[1] || "contact found"}` : "",
        ].filter(Boolean),
        recs: !has ? ["Create security.txt", "Add bug bounty contact"] : [],
      });
      log(`[+] security.txt: ${has ? "found" : "missing"}`, has ? C.green : C.muted);
    } catch { setR("sectxt", { severity: "info", summary: "Error", lines: ["[-] Error"], recs: [] }); }

    // 14. CORS
    markA("cors");
    try {
      const corsR = await sendRequest({
        url: "https://" + host + "/",
        method: "GET",
        headers: { "Origin": "https://evil.com" },
      }, proxyOnline);
      const acao = corsR?.headers?.["access-control-allow-origin"] || "";
      const acac = corsR?.headers?.["access-control-allow-credentials"] || "";
      const isWild = acao === "*";
      const reflects = acao === "https://evil.com";
      const withCreds = acac.toLowerCase() === "true";
      const sev = !proxyOnline ? "info" : (reflects && withCreds) ? "critical" : (isWild || reflects) ? "high" : "low";
      setR("cors", {
        severity: sev,
        summary: !proxyOnline ? "Need proxy" : isWild ? "Wildcard *" : reflects ? "Reflects Origin" : acao ? `Restricted: ${acao.slice(0,30)}` : "Not set",
        lines: [
          `CORS: ${host}`,
          !proxyOnline ? "[i] Needs proxy for full test" : "",
          `Origin sent: https://evil.com`,
          `ACAO: ${acao || "(not set)"}`,
          `ACAC: ${acac || "(not set)"}`,
          isWild ? "[-] Wildcard * allows any origin" : reflects ? "[-] Server reflects sent Origin" : "[+] CORS restricted",
          (reflects && withCreds) ? "[!!] CRITICAL: Reflects origin + allows credentials!" : "",
        ].filter(Boolean),
        recs: sev === "critical" || sev === "high" ? (reflects && withCreds ? ["CRITICAL: Restrict CORS to known domains", "Never use wildcard with credentials"] : ["Restrict CORS to known domains", "Never use wildcard with credentials"]) : [],
      });
      log(`[+] CORS: ${sev === "critical" ? "CRITICAL" : sev === "high" ? "HIGH" : "OK"}`, sev === "critical" ? C.red : sev === "high" ? "#ff6b35" : C.green);
    } catch { setR("cors", { severity: "info", summary: "Error", lines: ["[-] Error"], recs: [] }); }

    // 15. Clickjacking
    markA("clickjack");
    try {
      const chR = await getHeaders("https://" + host, proxyOnline);
      const h = chR?.headers || {};
      const xfo = h["x-frame-options"] || "";
      const csp = h["content-security-policy"] || "";
      const hasXFO = /deny|sameorigin/i.test(xfo);
      const hasFA = csp.includes("frame-ancestors");
      const protected_ = hasXFO || hasFA;
      const sev = !proxyOnline ? "info" : protected_ ? "low" : "high";
      setR("clickjack", {
        severity: sev,
        summary: !proxyOnline ? "Need proxy" : protected_ ? "Protected ✓" : "Vulnerable",
        lines: [
          `Clickjacking: ${host}`,
          !proxyOnline ? "[i] Needs proxy for header read" : "",
          `X-Frame-Options: ${xfo || "MISSING"}`,
          `CSP frame-ancestors: ${hasFA ? (csp.match(/frame-ancestors[^;]*/)?.[0]?.slice(0,60) || "found") : "MISSING"}`,
          protected_ ? "[+] Clickjacking protection present" : "[-] No clickjacking protection!",
        ].filter(Boolean),
        recs: !protected_ && proxyOnline ? ["Add X-Frame-Options: DENY", "Add CSP frame-ancestors 'none'"] : [],
      });
      log(`[+] Clickjacking: ${sev === "high" ? "VULN" : "OK"}`, sev === "high" ? C.red : C.green);
    } catch { setR("clickjack", { severity: "info", summary: "Error", lines: ["[-] Error"], recs: [] }); }

    // 16. Open Redirect
    markA("openredir");
    try {
      const REDIR_PARAMS = ["url", "redirect", "next", "return"];
      const REDIR_PAYLOAD = "https://evil.com/redirect-test";
      let foundRedirs = [];
      for (const param of REDIR_PARAMS) {
        const testUrl = `https://${host}/?${param}=${encodeURIComponent(REDIR_PAYLOAD)}`;
        const r = await apiGet(testUrl, proxyOnline);
        const loc = r.headers?.["location"] || "";
        if ((r.status >= 300 && r.status < 400) && loc.includes("evil.com")) {
          foundRedirs.push({ param, status: r.status, location: loc });
        }
      }
      const sev = foundRedirs.length > 0 ? "high" : "low";
      setR("openredir", {
        severity: sev,
        summary: foundRedirs.length > 0 ? `${foundRedirs.length} redirect(s) found!` : "Not vulnerable",
        lines: [
          `Open Redirect: ${host}`,
          `Tested params: ${REDIR_PARAMS.join(", ")}`,
          foundRedirs.length === 0 ? "[+] No open redirects found" : `[!!] ${foundRedirs.length} open redirect(s)!`,
          ...foundRedirs.map(f => `[!!] ?${f.param}= → ${f.location.slice(0,60)} (${f.status})`),
        ],
        recs: foundRedirs.length > 0 ? ["Validate redirect URLs against allowlist", "Never redirect to user-supplied URLs"] : [],
      });
      log(`[+] Open Redirect: ${foundRedirs.length > 0 ? "FOUND" : "OK"}`, foundRedirs.length > 0 ? C.red : C.green);
    } catch { setR("openredir", { severity: "info", summary: "Error", lines: ["[-] Error"], recs: [] }); }

    // 17. WordPress
    markA("wordpress");
    try {
      const [wplogin, xmlrpc, wpjson, readme] = await Promise.all([
        apiGet("https://" + host + "/wp-admin/", proxyOnline),
        apiGet("https://" + host + "/xmlrpc.php", proxyOnline),
        apiGet("https://" + host + "/wp-json/wp/v2/users", proxyOnline),
        apiGet("https://" + host + "/readme.html", proxyOnline),
      ]);
      const adminExposed  = wplogin.status === 200 || wplogin.status === 302;
      const xmlrpcEnabled = xmlrpc.status === 200 && xmlrpc.body.includes("XML-RPC");
      const usersLeak     = wpjson.status === 200 && (wpjson.body.includes('"slug"') || wpjson.body.includes('"name"'));
      const readmeExposes = readme.status === 200 && readme.body.toLowerCase().includes("wordpress");
      const ver = readme.body.match(/version\s+([\d.]+)/i)?.[1] || null;
      const issues = [adminExposed, xmlrpcEnabled, usersLeak, readmeExposes].filter(Boolean).length;
      const isWP  = adminExposed || xmlrpcEnabled || usersLeak || readmeExposes;
      const sev   = !isWP ? "info" : issues >= 3 ? "high" : issues >= 2 ? "medium" : "low";
      setR("wordpress", {
        severity: sev,
        summary: !isWP ? "Not WordPress / Not found" : `${issues} issue(s) found`,
        lines: [
          `WordPress: ${host}`,
          !isWP ? "[+] No WordPress indicators found" : `[i] WordPress detected, ${issues} issue(s)`,
          adminExposed   ? `[-] /wp-admin/ exposed (${wplogin.status})` : "[+] /wp-admin/ blocked",
          xmlrpcEnabled  ? "[-] xmlrpc.php enabled (brute-force risk)" : "[+] xmlrpc.php disabled",
          usersLeak      ? "[-] /wp-json/wp/v2/users leaks usernames!" : "[+] Users API protected",
          readmeExposes  ? `[-] readme.html exposes${ver ? ` v${ver}` : " version"}` : "[+] readme.html hidden",
        ],
        recs: [
          ...(adminExposed  ? ["Protect /wp-admin/ with 2FA"] : []),
          ...(xmlrpcEnabled ? ["Disable xmlrpc.php if not needed"] : []),
          ...(usersLeak     ? ["Disable wp-json users endpoint"] : []),
          ...(readmeExposes ? ["Delete readme.html"] : []),
        ],
      });
      log(`[+] WordPress: ${isWP ? "detected" : "not found"}`, isWP ? C.yellow : C.muted);
    } catch { setR("wordpress", { severity: "info", summary: "Error", lines: ["[-] Error"], recs: [] }); }

    // 18. Directory Listing
    markA("dirlisting");
    try {
      const DIR_TARGETS = ["/", "/images/", "/uploads/", "/backup/", "/files/", "/assets/", "/static/"];
      const listingResults = await Promise.all(
        DIR_TARGETS.map(async (p) => {
          const r = await apiGet("https://" + host + p, proxyOnline);
          const body = r.body?.toLowerCase() || "";
          const listing = body.includes("index of") || body.includes("directory listing") || body.includes("<title>index of");
          return { path: p, status: r.status, listing };
        })
      );
      const exposed = listingResults.filter(d => d.listing);
      const sev = exposed.length > 0 ? "high" : "low";
      setR("dirlisting", {
        severity: sev,
        summary: exposed.length > 0 ? `${exposed.length} dir(s) listed!` : "No listing found",
        lines: [
          `Directory Listing: ${host}`,
          ...listingResults.map(d => `${d.listing ? "[-]" : "[+]"} ${d.path} (${d.status})${d.listing ? " ← LISTING ENABLED" : ""}`),
        ],
        recs: exposed.length > 0 ? ["Disable directory listing in webserver config", "Add index.html to each directory"] : [],
      });
      log(`[+] Dir Listing: ${exposed.length > 0 ? "FOUND" : "OK"}`, exposed.length > 0 ? C.red : C.green);
    } catch { setR("dirlisting", { severity: "info", summary: "Error", lines: ["[-] Error"], recs: [] }); }

    // 19. Sensitive Files
    markA("sensitive");
    try {
      const baseReq = await apiGet("https://" + host + "/", proxyOnline);
      const baseSize = baseReq.body?.length || 0;

      const SENS_FILES = [
        "/.env", "/.git/config", "/.htaccess", "/web.config",
        "/phpinfo.php", "/.DS_Store", "/config.php", "/wp-config.php.bak",
      ];
      const sensResults = await Promise.all(
        SENS_FILES.map(async (p) => {
          const r = await apiGet("https://" + host + p, proxyOnline);
          const ctype = r.headers?.["content-type"] || "";
          const isHtml = ctype.toLowerCase().includes("text/html");
          const sizeDiff = Math.abs((r.body?.length || 0) - baseSize);
          const found = r.status === 200 && !isHtml && sizeDiff > 500;
          return { path: p, status: r.status, found };
        })
      );
      const exposed = sensResults.filter(f => f.found);
      const sev = exposed.length > 0 ? "critical" : "low";
      setR("sensitive", {
        severity: sev,
        summary: exposed.length > 0 ? `${exposed.length} file(s) exposed!` : "None exposed",
        lines: [
          `Sensitive Files: ${host}`,
          ...sensResults.map(f => `${f.found ? "[!!]" : "[+]"} ${f.path} (${f.status})${f.found ? " ← EXPOSED!" : ""}`),
        ],
        recs: exposed.length > 0 ? exposed.map(f => `Remove or block access to ${f.path}`) : [],
      });
      log(`[+] Sensitive Files: ${exposed.length > 0 ? "FOUND" : "OK"}`, exposed.length > 0 ? C.red : C.green);
    } catch { setR("sensitive", { severity: "info", summary: "Error", lines: ["[-] Error"], recs: [] }); }

    // 20. WHOIS / RDAP
    markA("whois");
    try {
      const w = await whoisLookup(host);
      if (!w) {
        setR("whois", { severity: "info", summary: "No data", lines: ["[-] RDAP lookup failed or unsupported TLD"], recs: [] });
      } else {
        const registrar  = w.entities?.find(e => e.roles?.includes("registrar"))?.vcardArray?.[1]?.find(v => v[0] === "fn")?.[3] || w.entities?.find(e => e.roles?.includes("registrar"))?.handle || "Unknown";
        const expiry     = w.events?.find(e => e.eventAction === "expiration")?.eventDate;
        const created    = w.events?.find(e => e.eventAction === "registration")?.eventDate;
        const updated    = w.events?.find(e => e.eventAction === "last changed")?.eventDate;
        const nameservers = w.nameservers?.map(ns => ns.ldhName).join(", ") || "—";
        const expiryDate = expiry ? new Date(expiry) : null;
        const daysLeft   = expiryDate ? Math.floor((expiryDate - Date.now()) / 86400000) : null;
        const sev = daysLeft !== null && daysLeft < 30 ? "high" : daysLeft !== null && daysLeft < 90 ? "medium" : "low";
        setR("whois", {
          severity: sev,
          summary: expiry ? `Expires in ${daysLeft}d (${expiryDate.toLocaleDateString()})` : "Registered",
          lines: [
            `Domain: ${w.ldhName || w._resolvedDomain || host}`,
            `Registrar: ${registrar}`,
            `Registered: ${created ? new Date(created).toLocaleDateString() : "—"}`,
            `Expires: ${expiry ? `${new Date(expiry).toLocaleDateString()} (${daysLeft} days)` : "—"}`,
            `Updated: ${updated ? new Date(updated).toLocaleDateString() : "—"}`,
            `Nameservers: ${nameservers}`,
          ],
          recs: daysLeft !== null && daysLeft < 30 ? [`Renew domain immediately — expires in ${daysLeft} days!`] :
                daysLeft !== null && daysLeft < 90 ? [`Consider renewing domain soon — ${daysLeft} days left`] : [],
        });
        log(`[+] WHOIS: expires in ${daysLeft ?? "?"}d`, daysLeft !== null && daysLeft < 30 ? C.red : C.green);
      }
    } catch { setR("whois", { severity: "info", summary: "Error", lines: ["[-] WHOIS error"], recs: [] }); }

    log("[*] Scan complete!", C.accent);
    setPhase("done");
  }, [domain, proxyOnline]);

  const selResult = sel ? results[sel] : null;
  const selCheck = CHECKS.find(c => c.id === sel);

  return (
    <div style={{ display: "flex", gap: 8, height: "100%", minHeight: 520 }}>
      {/* Left panel — module list */}
      <Panel style={{ width: 210, flexShrink: 0, display: "flex", flexDirection: "column" }}>
        <div style={{ padding: "8px 10px", borderBottom: `1px solid ${C.border}`, display: "flex", gap: 6, alignItems: "center" }}>
          <Inp
            value={domain}
            onChange={setDomain}
            placeholder="target.com"
            style={{ flex: 1 }}
            onKeyDown={e => e.key === "Enter" && phase === "idle" && runScan()}
          />
          <Btn
            onClick={phase === "done" ? reset : runScan}
            disabled={phase === "scanning" || (!domain.trim() && phase === "idle")}
            active
            color={phase === "done" ? C.green : C.accent}
            small
          >
            {phase === "idle" ? "▶" : phase === "scanning" ? "…" : "↺"}
          </Btn>
          {phase === "done" && (
            <>
              <Btn onClick={() => exportReport(domain, results, CHECKS, "txt")} small>📥 TXT</Btn>
              <Btn onClick={() => exportReport(domain, results, CHECKS, "json")} small>{ } JSON</Btn>
            </>
          )}
          {phase === "scanning" && (
            <Btn onClick={() => { sslAbort.current?.abort(); setPhase("done"); }} small color={C.red}>✕</Btn>
          )}
        </div>
        <div style={{ overflowY: "auto", flex: 1 }}>
          {CHECKS.map(c => {
            const r = results[c.id];
            const loading = active.has(c.id) && !r;
            const col = r ? SEV[r.severity] : C.border;
            return (
              <div
                key={c.id}
                onClick={() => r && setSel(c.id)}
                style={{
                  padding: "7px 12px",
                  borderBottom: `1px solid ${C.border}12`,
                  display: "flex", alignItems: "center", gap: 8,
                  cursor: r ? "pointer" : "default",
                  background: sel === c.id ? C.accent + "15" : "transparent",
                  borderLeft: sel === c.id ? `2px solid ${C.accent}` : "2px solid transparent",
                }}
              >
                <span style={{ color: C.muted, fontSize: 11, width: 14, textAlign: "center" }}>{c.icon}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ color: r ? C.text : C.muted, fontSize: 11, fontFamily: "monospace" }}>{c.label}</div>
                  {r && <div style={{ color: col, fontSize: 10, fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.summary}</div>}
                  {c.id === "ssl" && phase === "scanning" && sslProgress > 0 && !r && (
                    <div style={{ color: C.muted, fontSize: 10, fontFamily: "monospace" }}>poll {sslProgress}/20…</div>
                  )}
                </div>
                {loading && (
                  <div style={{ display: "flex", gap: 2 }}>
                    {[0, 1, 2].map(i => (
                      <div key={i} style={{ width: 3, height: 3, borderRadius: "50%", background: C.accent, animation: `pulse 1s ease ${i * 0.3}s infinite` }} />
                    ))}
                  </div>
                )}
                {r && <div style={{ width: 6, height: 6, borderRadius: "50%", background: col, flexShrink: 0 }} />}
              </div>
            );
          })}
        </div>
      </Panel>

      {/* Right — detail + log */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 8, minWidth: 0 }}>
        <Panel style={{ flex: 1, display: "flex", flexDirection: "column" }}>
          {selResult ? (
            <>
              <div style={{ padding: "7px 14px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ color: C.muted, fontFamily: "monospace", fontSize: 12 }}>{selCheck?.label}</span>
                <Tag label={selResult.severity} color={SEV[selResult.severity]} />
                {selResult.link && (
                  <a href={selResult.link} target="_blank" rel="noreferrer" style={{ color: C.blue, fontSize: 11, fontFamily: "monospace", marginLeft: "auto", textDecoration: "none" }}>
                    ↗ Full report
                  </a>
                )}
              </div>
              <div style={{ flex: 1, overflowY: "auto", padding: 14, display: "flex", gap: 16 }}>
                <div style={{ flex: 1 }}>
                  {selResult.lines?.map((l, i) => (
                    <div key={i} style={{
                      fontFamily: "monospace", fontSize: 12, lineHeight: 1.9,
                      color: l.startsWith("[+]") ? C.green : l.startsWith("[-]") || l.startsWith("[!!]") ? C.red : l.startsWith("[!]") ? C.yellow : C.muted,
                    }}>{l}</div>
                  ))}
                </div>
                {selResult.recs?.length > 0 && (
                  <div style={{ width: 200, flexShrink: 0 }}>
                    <div style={{ color: C.muted, fontSize: 10, letterSpacing: 1, marginBottom: 8 }}>RECOMMENDATIONS</div>
                    {selResult.recs.map((r, i) => (
                      <div key={i} style={{ fontFamily: "monospace", fontSize: 11, color: C.green, lineHeight: 1.8, paddingLeft: 8, borderLeft: `2px solid ${C.green}40` }}>✓ {r}</div>
                    ))}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 6 }}>
              <div style={{ color: C.muted, fontFamily: "monospace", fontSize: 12 }}>
                {phase === "idle" ? "Enter target and press ▶" : "Click a module to see details"}
              </div>
              {phase === "scanning" && <div style={{ color: C.accent, fontFamily: "monospace", fontSize: 11 }}>Scanning…</div>}
            </div>
          )}
        </Panel>

        {/* Event log */}
        <Panel style={{ height: 110, display: "flex", flexDirection: "column" }}>
          <div style={{ padding: "3px 12px", borderBottom: `1px solid ${C.border}`, color: C.muted, fontSize: 10, letterSpacing: 1 }}>EVENT LOG</div>
          <div ref={logRef} style={{ flex: 1, overflowY: "auto", padding: "4px 12px" }}>
            {logs.map(l => (
              <div key={l.id} style={{ fontFamily: "monospace", fontSize: 11, color: l.color, lineHeight: 1.8 }}>{l.text}</div>
            ))}
            {phase === "scanning" && <span style={{ color: C.accent, animation: "blink 1s infinite" }}>█</span>}
          </div>
        </Panel>
      </div>
    </div>
  );
}
