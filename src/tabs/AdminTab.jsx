import { useState, useEffect } from "react";
import { C } from "../lib/constants.js";
import { Panel, Btn, Inp } from "../components/ui.jsx";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, CartesianGrid } from "recharts";

export default function AdminTab() {
  const [pass, setPass] = useState(localStorage.getItem("adminPass") || "");
  const [auth, setAuth] = useState(false);
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [newBlock, setNewBlock] = useState("");
  const [blocks, setBlocks] = useState([]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/stats", { headers: { "x-admin-password": pass } });
      if (r.status === 401) {
        setAuth(false);
        setError("Invalid password");
        localStorage.removeItem("adminPass");
      } else if (r.ok) {
        const d = await r.json();
        setData(d);
        setAuth(true);
        localStorage.setItem("adminPass", pass);
        setError("");
        fetchBlocks();
      }
    } catch {
      setError("Network error");
    }
    setLoading(false);
  };

  const fetchBlocks = async () => {
    const r = await fetch("/api/admin/blocks", { headers: { "x-admin-password": pass } });
    if (r.ok) {
      const d = await r.json();
      setBlocks(d.blocks || []);
    }
  };

  useEffect(() => {
    if (pass) fetchData();
  }, []);

  const handleLogin = (e) => {
    e.preventDefault();
    fetchData();
  };

  const clearHistory = async () => {
    if (!confirm("Are you sure? This will delete all scans and reports.")) return;
    await fetch("/api/admin/history", { method: "DELETE", headers: { "x-admin-password": pass } });
    fetchData();
  };

  const addBlock = async () => {
    if (!newBlock) return;
    await fetch("/api/admin/blocks", {
      method: "POST",
      headers: { "x-admin-password": pass, "Content-Type": "application/json" },
      body: JSON.stringify({ host: newBlock })
    });
    setNewBlock("");
    fetchBlocks();
  };

  const removeBlock = async (host) => {
    await fetch("/api/admin/blocks", {
      method: "DELETE",
      headers: { "x-admin-password": pass, "Content-Type": "application/json" },
      body: JSON.stringify({ host })
    });
    fetchBlocks();
  };

  if (!auth) {
    return (
      <div style={{ minHeight: "100vh", background: C.bg, display: "flex", alignItems: "center", justifyContent: "center", color: C.text }}>
        <Panel style={{ padding: 30, width: 350, textAlign: "center" }}>
          <h2 style={{ fontFamily: "monospace", color: C.accent, marginBottom: 20 }}>SECRET ADMIN PORTAL</h2>
          <form onSubmit={handleLogin} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <Inp type="password" value={pass} onChange={setPass} placeholder="Admin Password" />
            <Btn type="submit" active color={C.accent}>Login</Btn>
          </form>
          {error && <div style={{ color: C.red, marginTop: 10, fontSize: 12 }}>{error}</div>}
        </Panel>
      </div>
    );
  }

  if (!data) return <div style={{ padding: 20, color: C.text }}>Loading...</div>;

  const sevData = [
    { name: "Critical", value: data.sevStats.critical || 0, fill: C.red },
    { name: "High", value: data.sevStats.high || 0, fill: "#ff6b35" },
    { name: "Medium", value: data.sevStats.medium || 0, fill: C.yellow },
    { name: "Low", value: data.sevStats.low || 0, fill: C.green },
  ];

  const scanTimeline = data.recentScans.map(s => ({
    time: new Date(s.created_at * 1000).toLocaleTimeString(),
    ports: s.open_ports ? s.open_ports.split(",").length : 0
  })).reverse();

  return (
    <div style={{ minHeight: "100vh", background: C.bg, color: C.text, padding: 20, fontFamily: "monospace" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20, borderBottom: `1px solid ${C.border}`, paddingBottom: 10 }}>
        <h2><span style={{ color: C.accent }}>BURP</span> ADMIN DASHBOARD</h2>
        <div style={{ display: "flex", gap: 10 }}>
          <Btn onClick={() => window.location.hash = ""} small color={C.blue}>🏠 Home</Btn>
          <Btn onClick={() => { setAuth(false); localStorage.removeItem("adminPass"); }} small>Logout</Btn>
        </div>
      </div>

      <div style={{ display: "flex", gap: 20, flexWrap: "wrap", marginBottom: 20 }}>
        <Panel style={{ flex: 1, minWidth: 250, padding: 20 }}>
          <h3 style={{ color: C.muted, marginBottom: 10 }}>Server Status</h3>
          <div style={{ display: "flex", justifyContent: "space-between", margin: "5px 0" }}>
            <span>Environment:</span> <span style={{ color: data.osData.railway ? C.green : C.yellow }}>{data.osData.railway ? "Railway" : "Local"}</span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", margin: "5px 0" }}>
            <span>Uptime:</span> <span>{(data.osData.uptime / 3600).toFixed(2)} hrs</span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", margin: "5px 0" }}>
            <span>Memory (RSS):</span> <span>{(data.osData.memory.rss / 1024 / 1024).toFixed(1)} MB</span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", margin: "5px 0" }}>
            <span>Total Requests:</span> <span>{data.stats.req_count || 0}</span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", margin: "5px 0" }}>
            <span>Blocked Threats:</span> <span style={{ color: C.red }}>{data.stats.waf_hits || 0}</span>
          </div>
        </Panel>

        <Panel style={{ flex: 1, minWidth: 300, padding: 20 }}>
          <h3 style={{ color: C.muted, marginBottom: 10 }}>Vulnerabilities Summary</h3>
          <div style={{ height: 150 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sevData}>
                <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
                <XAxis dataKey="name" stroke={C.muted} fontSize={10} />
                <YAxis stroke={C.muted} fontSize={10} allowDecimals={false} />
                <Tooltip contentStyle={{ background: C.panel, border: `1px solid ${C.border}` }} />
                <Bar dataKey="value" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
        <Panel style={{ flex: 2, minWidth: 400, padding: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
            <h3 style={{ color: C.muted }}>Recent Reports History</h3>
            <Btn onClick={clearHistory} small color={C.red}>Delete All History</Btn>
          </div>
          <div style={{ overflowY: "auto", maxHeight: 300 }}>
            <table style={{ width: "100%", textAlign: "left", fontSize: 12 }}>
              <thead>
                <tr style={{ color: C.muted }}>
                  <th>ID</th>
                  <th>Target Host</th>
                  <th>Date</th>
                  <th>Size</th>
                </tr>
              </thead>
              <tbody>
                {data.recentReports.map(r => (
                  <tr key={r.id} style={{ borderBottom: `1px solid ${C.border}40` }}>
                    <td style={{ padding: "8px 0" }}>#{r.id}</td>
                    <td style={{ color: C.blue }}>{r.host}</td>
                    <td>{new Date(r.created_at * 1000).toLocaleString()}</td>
                    <td>{(r.size / 1024).toFixed(1)} KB</td>
                  </tr>
                ))}
                {data.recentReports.length === 0 && <tr><td colSpan="4" style={{ padding: 10, textAlign: "center", color: C.muted }}>No reports yet</td></tr>}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel style={{ flex: 1, minWidth: 300, padding: 20 }}>
          <h3 style={{ color: C.muted, marginBottom: 10 }}>Global Blocklist (isBlockedTarget)</h3>
          <div style={{ display: "flex", gap: 10, marginBottom: 15 }}>
            <Inp value={newBlock} onChange={setNewBlock} placeholder="example.com" style={{ flex: 1 }} />
            <Btn onClick={addBlock} small active>Block</Btn>
          </div>
          <div style={{ maxHeight: 250, overflowY: "auto" }}>
            {blocks.map(b => (
              <div key={b.host} style={{ display: "flex", justifyContent: "space-between", padding: "6px 10px", background: C.bg, border: `1px solid ${C.border}`, borderRadius: 4, marginBottom: 6, alignItems: "center" }}>
                <span>{b.host}</span>
                <button onClick={() => removeBlock(b.host)} style={{ background: "none", border: "none", color: C.red, cursor: "pointer", fontWeight: "bold" }}>X</button>
              </div>
            ))}
            {blocks.length === 0 && <div style={{ color: C.muted, fontSize: 12, textAlign: "center" }}>No custom blocks</div>}
          </div>
        </Panel>
      </div>
    </div>
  );
}
