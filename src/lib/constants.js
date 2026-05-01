export const C = {
  bg: "#0d1117",
  panel: "#161b22",
  border: "#30363d",
  accent: "#f97316",
  text: "#e6edf3",
  muted: "#8b949e",
  green: "#3fb950",
  red: "#f85149",
  yellow: "#d29922",
  blue: "#58a6ff",
};

export const SEV = {
  critical: C.red,
  high: "#ff6b35",
  medium: C.yellow,
  low: C.green,
  info: C.blue,
};

export const CHECKS = [
  { id: "redirect",   icon: "↩",  label: "HTTP→HTTPS",     desc: "Redirect" },
  { id: "dns",        icon: "◆",  label: "DNS/DNSSEC",      desc: "Google DoH" },
  { id: "ssl",        icon: "🔒", label: "SSL/TLS",         desc: "SSL Labs" },
  { id: "headers",    icon: "H",  label: "HTTP Headers",    desc: "Real via proxy" },
  { id: "email",      icon: "@",  label: "SPF/DKIM/DMARC",  desc: "Email security" },
  { id: "subdomains", icon: "⊕",  label: "Subdomains",      desc: "crt.sh" },
  { id: "ports",      icon: "▶",  label: "Port Scan",       desc: "Real TCP via proxy" },
  { id: "robots",     icon: "R",  label: "Robots/Sitemap",  desc: "Structure leak" },
  { id: "tech",       icon: "⚙",  label: "Technologies",    desc: "Fingerprinting" },
  { id: "waf",        icon: "🛡",  label: "WAF",             desc: "Firewall detect" },
  { id: "ip",         icon: "●",  label: "IP Reputation",   desc: "ip-api.com" },
  { id: "cve",        icon: "⚠",  label: "CVE",             desc: "NIST NVD" },
  { id: "sectxt",     icon: "📄", label: "Security.txt",    desc: "Bug bounty" },
  { id: "secrets",    icon: "🔑", label: "JS Secrets",      desc: "Scrape API keys" },
  { id: "cors",       icon: "✈",  label: "CORS Policy",     desc: "Wildcard/reflect" },
  { id: "clickjack",  icon: "⧉",  label: "Clickjacking",    desc: "X-Frame/CSP" },
  { id: "openredir",  icon: "⇢",  label: "Open Redirect",   desc: "?url= params" },
  { id: "wordpress",  icon: "W",  label: "WordPress",       desc: "Admin/xmlrpc/users" },
  { id: "dirlisting", icon: "📂", label: "Dir Listing",     desc: "Common dirs" },
  { id: "sensitive",  icon: "🚨", label: "Sensitive Files", desc: ".env/.git/phpinfo" },
  { id: "whois",      icon: "🌐", label: "WHOIS / RDAP",    desc: "Registrar, expiry" },
];
