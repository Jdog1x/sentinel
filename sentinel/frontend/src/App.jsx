import { useState, useEffect, useRef, useCallback } from "react";

const API = "http://localhost:5000/api";

const SEV = {
  critical: { color: "#ff4444", bg: "#3a0f0f", label: "CRITICAL" },
  high:     { color: "#ff8800", bg: "#3a2000", label: "HIGH"     },
  medium:   { color: "#ffcc00", bg: "#3a3000", label: "MEDIUM"   },
  low:      { color: "#4499ff", bg: "#0f2040", label: "LOW"      },
  info:     { color: "#888888", bg: "#1e2028", label: "INFO"     },
};

const api = {
  getScans:     ()       => fetch(`${API}/scans`).then(r => r.json()),
  getScan:      (id)     => fetch(`${API}/scans/${id}`).then(r => r.json()),
  createScan:   (body)   => fetch(`${API}/scans`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(r => r.json()),
  createReport: (scanId) => fetch(`${API}/scans/${scanId}/report`, { method: "POST" }).then(r => r.json()),
  chat:         (body)   => fetch(`${API}/chat`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(r => r.json()),
  health:       ()       => fetch(`${API}/health`).then(r => r.json()),
};

function timeAgo(iso) {
  if (!iso) return "-";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60)    return `${Math.floor(diff)}s ago`;
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function SeverityBadge({ severity }) {
  const cfg = SEV[severity] || SEV.info;
  return (
    <span style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40`, padding: "2px 8px", borderRadius: 4, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>
      {cfg.label}
    </span>
  );
}

function StatusBadge({ status }) {
  const map = {
    complete:  { color: "#00d4aa", label: "COMPLETE"  },
    running:   { color: "#ffcc00", label: "RUNNING"   },
    analyzing: { color: "#4499ff", label: "ANALYZING" },
    failed:    { color: "#ff4444", label: "FAILED"    },
    pending:   { color: "#888888", label: "PENDING"   },
  };
  const cfg = map[status] || map.pending;
  return <span style={{ color: cfg.color, fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>{cfg.label}</span>;
}

function NewScanModal({ onClose, onCreated }) {
  const [target, setTarget]   = useState("");
  const [backend, setBackend] = useState("ollama");
  const [fast, setFast]       = useState(false);
  const [loading, setLoading] = useState(false);

  async function submit() {
    if (!target.trim()) return;
    setLoading(true);
    try {
      const scan = await api.createScan({ target: target.trim(), llm_backend: backend, fast });
      onCreated(scan);
      onClose();
    } catch (e) { alert("Failed: " + e.message); }
    finally { setLoading(false); }
  }

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.8)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: 12, padding: 32, width: 480, maxWidth: "90vw" }}>
        <h2 style={{ color: "#00d4aa", fontFamily: "monospace", marginTop: 0, fontSize: 18 }}>NEW SCAN</h2>
        <div style={{ marginBottom: 16 }}>
          <label style={{ color: "#8b949e", fontSize: 12, display: "block", marginBottom: 6 }}>TARGET</label>
          <input value={target} onChange={e => setTarget(e.target.value)} onKeyDown={e => e.key === "Enter" && submit()} placeholder="scanme.nmap.org" autoFocus
            style={{ width: "100%", background: "#161b22", border: "1px solid #30363d", color: "#e6edf3", padding: "10px 12px", borderRadius: 8, fontFamily: "monospace", fontSize: 14, boxSizing: "border-box", outline: "none" }} />
        </div>
        <div style={{ marginBottom: 16 }}>
          <label style={{ color: "#8b949e", fontSize: 12, display: "block", marginBottom: 6 }}>LLM BACKEND</label>
          <div style={{ display: "flex", gap: 8 }}>
            {["ollama", "anthropic", "openai"].map(b => (
              <button key={b} onClick={() => setBackend(b)} style={{ flex: 1, padding: "8px 0", background: backend === b ? "#00d4aa20" : "#161b22", border: `1px solid ${backend === b ? "#00d4aa" : "#30363d"}`, color: backend === b ? "#00d4aa" : "#8b949e", borderRadius: 8, cursor: "pointer", fontFamily: "monospace", fontSize: 12, fontWeight: backend === b ? 700 : 400 }}>
                {b.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
        <div style={{ marginBottom: 24, display: "flex", alignItems: "center", gap: 10 }}>
          <input type="checkbox" id="fast" checked={fast} onChange={e => setFast(e.target.checked)} style={{ accentColor: "#00d4aa" }} />
          <label htmlFor="fast" style={{ color: "#8b949e", fontSize: 13, cursor: "pointer" }}>Fast mode (top-100 ports)</label>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button onClick={onClose} style={{ flex: 1, padding: "10px 0", background: "transparent", border: "1px solid #30363d", color: "#8b949e", borderRadius: 8, cursor: "pointer", fontSize: 14 }}>Cancel</button>
          <button onClick={submit} disabled={loading || !target.trim()} style={{ flex: 2, padding: "10px 0", background: loading ? "#00d4aa20" : "#00d4aa", border: "none", color: loading ? "#00d4aa" : "#0d1117", borderRadius: 8, cursor: loading ? "not-allowed" : "pointer", fontWeight: 700, fontSize: 14, fontFamily: "monospace" }}>
            {loading ? "LAUNCHING..." : "LAUNCH SCAN"}
          </button>
        </div>
      </div>
    </div>
  );
}

function ScanDetail({ scan, onClose, onRefresh }) {
  const [activeTab, setActiveTab]     = useState("findings");
  const [reportLoading, setReportLoading] = useState(false);
  const [chatMessages, setChatMessages]   = useState([]);
  const [chatInput, setChatInput]         = useState("");
  const [chatLoading, setChatLoading]     = useState(false);
  const analysis = scan?.raw_results?.analysis || {};

  async function generateReport() {
    setReportLoading(true);
    try { const r = await api.createReport(scan.id); if (r.file_path) { alert(`Report saved: ${r.file_path}`); onRefresh(); } }
    catch (e) { alert("Failed: " + e.message); }
    finally { setReportLoading(false); }
  }

  async function sendChat() {
    if (!chatInput.trim()) return;
    const userMsg = { role: "user", content: chatInput };
    const updated = [...chatMessages, userMsg];
    setChatMessages(updated); setChatInput(""); setChatLoading(true);
    try { const res = await api.chat({ messages: updated, scan_id: scan.id }); setChatMessages([...updated, { role: "assistant", content: res.reply }]); }
    catch (e) { setChatMessages([...updated, { role: "assistant", content: `Error: ${e.message}` }]); }
    finally { setChatLoading(false); }
  }

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)", display: "flex", zIndex: 100 }}>
      <div style={{ marginLeft: "auto", width: 720, maxWidth: "95vw", background: "#0d1117", borderLeft: "1px solid #30363d", display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div style={{ padding: "20px 24px", borderBottom: "1px solid #21262d" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ color: "#8b949e", fontSize: 11, fontFamily: "monospace", marginBottom: 4 }}>SCAN / {scan.id?.slice(0,8).toUpperCase()}</div>
              <h2 style={{ color: "#e6edf3", margin: 0, fontSize: 20, fontFamily: "monospace" }}>{scan.target}</h2>
              <div style={{ marginTop: 8, display: "flex", gap: 16 }}>
                <StatusBadge status={scan.status} />
                {analysis.risk_level && <span style={{ color: { low:"#00d4aa", medium:"#ffcc00", high:"#ff8800", critical:"#ff4444" }[analysis.risk_level] || "#888", fontSize: 11, fontFamily: "monospace", fontWeight: 700 }}>RISK: {analysis.risk_level?.toUpperCase()}</span>}
                <span style={{ color: "#555", fontSize: 11 }}>{timeAgo(scan.created_at)}</span>
              </div>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button onClick={generateReport} disabled={reportLoading || scan.status !== "complete"} style={{ padding: "8px 16px", background: "transparent", border: "1px solid #00d4aa40", color: "#00d4aa", borderRadius: 8, cursor: "pointer", fontSize: 12, fontFamily: "monospace" }}>
                {reportLoading ? "..." : "PDF"}
              </button>
              <button onClick={onClose} style={{ padding: "8px 12px", background: "transparent", border: "1px solid #30363d", color: "#8b949e", borderRadius: 8, cursor: "pointer" }}>x</button>
            </div>
          </div>
          {analysis.executive_summary && <p style={{ margin: "12px 0 0", color: "#8b949e", fontSize: 13, lineHeight: 1.6, background: "#161b22", padding: 12, borderRadius: 8, borderLeft: "3px solid #00d4aa" }}>{analysis.executive_summary}</p>}
        </div>

        <div style={{ display: "flex", borderBottom: "1px solid #21262d" }}>
          {["findings", "raw", "chat"].map(t => (
            <button key={t} onClick={() => setActiveTab(t)} style={{ padding: "12px 20px", background: "transparent", border: "none", borderBottom: `2px solid ${activeTab === t ? "#00d4aa" : "transparent"}`, color: activeTab === t ? "#00d4aa" : "#8b949e", cursor: "pointer", fontFamily: "monospace", fontSize: 12, fontWeight: activeTab === t ? 700 : 400, textTransform: "uppercase" }}>
              {t}{t === "findings" && scan.findings?.length ? ` (${scan.findings.length})` : ""}
            </button>
          ))}
        </div>

        <div style={{ flex: 1, overflow: "auto", padding: 24 }}>
          {activeTab === "findings" && (
            <div>
              {(!scan.findings || scan.findings.length === 0)
                ? <p style={{ color: "#555", textAlign: "center", marginTop: 48 }}>{scan.status === "complete" ? "No findings." : "Scan in progress..."}</p>
                : scan.findings.map(f => (
                  <div key={f.id} style={{ background: "#161b22", border: "1px solid #21262d", borderRadius: 8, padding: 16, marginBottom: 12, borderLeft: `3px solid ${SEV[f.severity]?.color || "#888"}` }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                      <span style={{ color: "#e6edf3", fontWeight: 600, fontSize: 14 }}>{f.title}</span>
                      <SeverityBadge severity={f.severity} />
                    </div>
                    {f.description && <p style={{ color: "#8b949e", fontSize: 13, margin: "0 0 8px", lineHeight: 1.6 }}>{f.description}</p>}
                    {f.evidence && <pre style={{ background: "#0d1117", color: "#79c0ff", fontSize: 11, padding: 10, borderRadius: 6, overflow: "auto", margin: "8px 0", fontFamily: "monospace" }}>{f.evidence}</pre>}
                    {f.remediation && <div style={{ background: "#00d4aa10", border: "1px solid #00d4aa30", borderRadius: 6, padding: "8px 12px", fontSize: 12, color: "#00d4aa" }}><strong>Fix: </strong>{f.remediation}</div>}
                  </div>
                ))
              }
            </div>
          )}
          {activeTab === "raw" && <pre style={{ background: "#0d1117", color: "#8b949e", fontSize: 11, padding: 16, borderRadius: 8, overflow: "auto", fontFamily: "monospace", lineHeight: 1.6 }}>{JSON.stringify(scan.raw_results, null, 2)}</pre>}
          {activeTab === "chat" && (
            <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
              <div style={{ flex: 1, overflow: "auto", marginBottom: 16 }}>
                {chatMessages.length === 0 && <p style={{ color: "#555", fontSize: 13, textAlign: "center", marginTop: 32 }}>Ask SENTINEL to analyze findings or explain vulnerabilities.</p>}
                {chatMessages.map((m, i) => (
                  <div key={i} style={{ marginBottom: 16, display: "flex", flexDirection: m.role === "user" ? "row-reverse" : "row", gap: 10 }}>
                    <div style={{ maxWidth: "85%", background: m.role === "user" ? "#00d4aa20" : "#161b22", border: `1px solid ${m.role === "user" ? "#00d4aa40" : "#21262d"}`, borderRadius: 10, padding: "10px 14px", color: "#e6edf3", fontSize: 13, lineHeight: 1.6, whiteSpace: "pre-wrap" }}>{m.content}</div>
                  </div>
                ))}
                {chatLoading && <div style={{ color: "#00d4aa", fontFamily: "monospace", fontSize: 12 }}>Analyzing...</div>}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <input value={chatInput} onChange={e => setChatInput(e.target.value)} onKeyDown={e => e.key === "Enter" && sendChat()} placeholder="Ask about this scan..." style={{ flex: 1, background: "#161b22", border: "1px solid #30363d", color: "#e6edf3", padding: "10px 14px", borderRadius: 8, fontFamily: "monospace", fontSize: 13, outline: "none" }} />
                <button onClick={sendChat} disabled={chatLoading || !chatInput.trim()} style={{ padding: "10px 18px", background: "#00d4aa", border: "none", color: "#0d1117", borderRadius: 8, cursor: "pointer", fontWeight: 700 }}>Send</button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [scans, setScans]       = useState([]);
  const [selected, setSelected] = useState(null);
  const [showNew, setShowNew]   = useState(false);
  const [health, setHealth]     = useState(null);
  const [loading, setLoading]   = useState(true);
  const pollRef                 = useRef(null);

  const loadScans = useCallback(async () => {
    try { const data = await api.getScans(); setScans(Array.isArray(data) ? data : []); }
    catch {}
    finally { setLoading(false); }
  }, []);

  const refreshSelected = useCallback(async () => {
    if (!selected) return;
    const updated = await api.getScan(selected.id);
    setSelected(updated);
    setScans(prev => prev.map(s => s.id === updated.id ? updated : s));
  }, [selected]);

  useEffect(() => {
    loadScans();
    api.health().then(setHealth).catch(() => {});
    pollRef.current = setInterval(loadScans, 5000);
    return () => clearInterval(pollRef.current);
  }, [loadScans]);

  const sevCounts = scans.flatMap(s => s.findings || []).reduce((a, f) => { a[f.severity] = (a[f.severity] || 0) + 1; return a; }, {});

  return (
    <div style={{ minHeight: "100vh", background: "#010409", color: "#e6edf3", fontFamily: "system-ui, sans-serif" }}>
      <nav style={{ borderBottom: "1px solid #21262d", padding: "0 32px", display: "flex", alignItems: "center", justifyContent: "space-between", height: 56, position: "sticky", top: 0, background: "#010409", zIndex: 50 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ color: "#00d4aa", fontFamily: "monospace", fontWeight: 700, fontSize: 18, letterSpacing: "0.1em" }}>SENTINEL</span>
          <span style={{ color: "#555", fontSize: 13 }}>AI Pentest Platform</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <span style={{ color: health ? "#00d4aa" : "#ff4444", fontSize: 11, fontFamily: "monospace" }}>{health ? `API: ${health.llm_backend?.toUpperCase()}` : "API OFFLINE"}</span>
          <button onClick={() => setShowNew(true)} style={{ padding: "8px 18px", background: "#00d4aa", border: "none", color: "#0d1117", borderRadius: 8, cursor: "pointer", fontWeight: 700, fontSize: 13, fontFamily: "monospace" }}>+ NEW SCAN</button>
        </div>
      </nav>

      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "32px 24px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 32 }}>
          {[
            { label: "Total Scans", value: scans.length,                                              color: "#00d4aa" },
            { label: "Findings",    value: scans.reduce((a, s) => a + (s.findings?.length || 0), 0), color: "#4499ff" },
            { label: "Critical",    value: sevCounts.critical || 0,                                   color: "#ff4444" },
            { label: "High",        value: sevCounts.high     || 0,                                   color: "#ff8800" },
          ].map(s => (
            <div key={s.label} style={{ background: "#0d1117", border: "1px solid #21262d", borderRadius: 10, padding: "16px 20px" }}>
              <div style={{ color: "#555", fontSize: 11, fontFamily: "monospace", marginBottom: 6 }}>{s.label}</div>
              <div style={{ color: s.color, fontSize: 28, fontWeight: 700, fontFamily: "monospace" }}>{s.value}</div>
            </div>
          ))}
        </div>

        <div style={{ background: "#0d1117", border: "1px solid #21262d", borderRadius: 12, overflow: "hidden" }}>
          <div style={{ padding: "16px 24px", borderBottom: "1px solid #21262d", display: "flex", justifyContent: "space-between" }}>
            <h2 style={{ margin: 0, fontSize: 14, fontFamily: "monospace", color: "#8b949e", fontWeight: 400 }}>SCANS — {scans.length} total</h2>
            <button onClick={loadScans} style={{ background: "transparent", border: "1px solid #30363d", color: "#555", padding: "4px 12px", borderRadius: 6, cursor: "pointer", fontSize: 11, fontFamily: "monospace" }}>REFRESH</button>
          </div>
          {scans.length === 0 && !loading
            ? <div style={{ padding: 48, textAlign: "center", color: "#555" }}><p style={{ fontSize: 16, margin: "0 0 8px" }}>No scans yet.</p><p style={{ fontSize: 13, margin: 0 }}>Launch your first scan above.</p></div>
            : <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #21262d" }}>
                    {["Target", "Status", "Risk", "Findings", "LLM", "Started", ""].map(h => (
                      <th key={h} style={{ padding: "10px 20px", textAlign: "left", color: "#555", fontSize: 11, fontFamily: "monospace", fontWeight: 400 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {scans.map(scan => (
                    <tr key={scan.id} style={{ borderBottom: "1px solid #161b22", cursor: "pointer" }}
                      onMouseEnter={e => e.currentTarget.style.background = "#161b22"}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                      onClick={() => setSelected(scan)}>
                      <td style={{ padding: "14px 20px" }}>
                        <div style={{ color: "#e6edf3", fontFamily: "monospace", fontSize: 14 }}>{scan.target}</div>
                        <div style={{ color: "#555", fontSize: 10, marginTop: 2 }}>{scan.id?.slice(0,8)}</div>
                      </td>
                      <td style={{ padding: "14px 20px" }}><StatusBadge status={scan.status} /></td>
                      <td style={{ padding: "14px 20px" }}>
                        {scan.raw_results?.analysis?.risk_level
                          ? <span style={{ color: { low:"#00d4aa", medium:"#ffcc00", high:"#ff8800", critical:"#ff4444" }[scan.raw_results.analysis.risk_level] || "#888", fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>{scan.raw_results.analysis.risk_level.toUpperCase()}</span>
                          : <span style={{ color: "#555" }}>-</span>}
                      </td>
                      <td style={{ padding: "14px 20px", color: "#8b949e", fontSize: 12 }}>{scan.findings?.length || 0}</td>
                      <td style={{ padding: "14px 20px", color: "#555", fontSize: 11, fontFamily: "monospace" }}>{scan.llm_backend || "-"}</td>
                      <td style={{ padding: "14px 20px", color: "#555", fontSize: 12 }}>{timeAgo(scan.created_at)}</td>
                      <td style={{ padding: "14px 20px", color: "#00d4aa", fontSize: 12 }}>view</td>
                    </tr>
                  ))}
                </tbody>
              </table>
          }
        </div>
      </div>

      {showNew && <NewScanModal onClose={() => setShowNew(false)} onCreated={scan => { setScans(prev => [scan, ...prev]); loadScans(); }} />}
      {selected && <ScanDetail scan={selected} onClose={() => setSelected(null)} onRefresh={refreshSelected} />}
    </div>
  );
}