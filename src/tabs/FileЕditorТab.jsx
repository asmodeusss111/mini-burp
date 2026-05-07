import { useState, useEffect, useRef } from "react";
import { C } from "../lib/constants.js";
import { Btn } from "../components/ui.jsx";
 
// ── Language detection ────────────────────────────────────────────────────────
const LANG_MAP = {
  js: "javascript", jsx: "javascript", mjs: "javascript", cjs: "javascript",
  ts: "typescript", tsx: "typescript",
  json: "json", html: "html", css: "css", md: "markdown",
  py: "python", sh: "shell", bash: "shell",
  yml: "yaml", yaml: "yaml", sql: "sql",
  txt: "plaintext", env: "plaintext", lock: "plaintext",
};
function getLang(filename = "") {
  const ext = filename.split(".").pop().toLowerCase();
  return LANG_MAP[ext] || "plaintext";
}
 
// ── File tree component ───────────────────────────────────────────────────────
function FileTree({ nodes, onSelect, selected, depth = 0 }) {
  const [open, setOpen] = useState({});
  const toggle = (path) => setOpen(o => ({ ...o, [path]: !o[path] }));
 
  return (
    <div>
      {nodes.map(node => (
        <div key={node.path}>
          <div
            onClick={() => node.type === "dir" ? toggle(node.path) : onSelect(node)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: `3px 10px 3px ${12 + depth * 14}px`,
              cursor: "pointer",
              fontSize: 12,
              color: selected === node.path ? C.accent : node.type === "dir" ? C.text : C.muted,
              background: selected === node.path ? `${C.accent}18` : "transparent",
              borderLeft: selected === node.path ? `2px solid ${C.accent}` : "2px solid transparent",
              userSelect: "none",
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
              transition: "background 0.1s",
            }}
          >
            <span style={{ fontSize: 11, flexShrink: 0 }}>
              {node.type === "dir" ? (open[node.path] ? "▾" : "▸") : "·"}
            </span>
            <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{node.name}</span>
          </div>
          {node.type === "dir" && open[node.path] && node.children?.length > 0 && (
            <FileTree nodes={node.children} onSelect={onSelect} selected={selected} depth={depth + 1} />
          )}
        </div>
      ))}
    </div>
  );
}
 
// ── Main component ────────────────────────────────────────────────────────────
export default function FileEditorTab({ adminPass }) {
  const [tree, setTree] = useState([]);
  const [treeLoading, setTreeLoading] = useState(true);
  const [selectedFile, setSelectedFile] = useState(null);
  const [savedContent, setSavedContent] = useState("");
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [fileLoading, setFileLoading] = useState(false);
  const [status, setStatus] = useState(null); // { type: "ok"|"err", msg }
  const [monacoReady, setMonacoReady] = useState(false);
 
  const containerRef = useRef(null);
  const editorRef = useRef(null);
  const saveRef = useRef(null); // stable ref to saveFile for Monaco keybind
 
  const h = { "x-admin-password": adminPass };
 
  // Load file tree
  useEffect(() => {
    fetch("/api/admin/files", { headers: h })
      .then(r => r.json())
      .then(d => { setTree(d.tree || []); setTreeLoading(false); })
      .catch(() => setTreeLoading(false));
  }, []);
 
  // Init Monaco
  useEffect(() => {
    if (!containerRef.current) return;
 
    const init = () => {
      window.require.config({
        paths: { vs: "https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs" },
      });
      window.require(["vs/editor/editor.main"], () => {
        if (!containerRef.current) return;
        const editor = window.monaco.editor.create(containerRef.current, {
          value: "// ← Select a file from the tree",
          language: "javascript",
          theme: "vs-dark",
          automaticLayout: true,
          readOnly: true,
          minimap: { enabled: false },
          fontSize: 13,
          fontFamily: "'Fira Code', 'Cascadia Code', 'Consolas', monospace",
          lineNumbers: "on",
          scrollBeyondLastLine: false,
          wordWrap: "off",
          tabSize: 2,
          renderWhitespace: "selection",
          smoothScrolling: true,
        });
 
        // Ctrl+S keybind — uses saveRef so it always has latest saveFile
        editor.addCommand(
          window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.KeyS,
          () => saveRef.current?.()
        );
 
        // Track dirty state
        editor.onDidChangeModelContent(() => {
          setDirty(true);
        });
 
        editorRef.current = editor;
        setMonacoReady(true);
      });
    };
 
    if (window.require) {
      init();
    } else {
      const script = document.createElement("script");
      script.src = "https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs/loader.js";
      script.onload = init;
      document.head.appendChild(script);
    }
 
    return () => { editorRef.current?.dispose(); };
  }, []);
 
  // Open a file
  const openFile = async (node) => {
    if (node.path === selectedFile?.path) return;
    setFileLoading(true);
    setSelectedFile(node);
    setStatus(null);
    setDirty(false);
 
    try {
      const r = await fetch(`/api/admin/file?path=${encodeURIComponent(node.path)}`, { headers: h });
      const d = await r.json();
      const content = d.content ?? "";
      setSavedContent(content);
 
      if (editorRef.current && monacoReady) {
        editorRef.current.setValue(content);
        window.monaco.editor.setModelLanguage(editorRef.current.getModel(), getLang(node.name));
        editorRef.current.updateOptions({ readOnly: false });
        editorRef.current.setScrollPosition({ scrollTop: 0 });
        setDirty(false); // reset dirty after setValue triggers onDidChangeModelContent
        setTimeout(() => setDirty(false), 50); // ensure reset after async
      }
    } catch {
      setStatus({ type: "err", msg: "Failed to load file" });
    }
    setFileLoading(false);
  };
 
  // Save current file
  const saveFile = async () => {
    if (!selectedFile || !editorRef.current || saving) return;
    setSaving(true);
    setStatus(null);
    const content = editorRef.current.getValue();
    try {
      const r = await fetch("/api/admin/file", {
        method: "PUT",
        headers: { ...h, "Content-Type": "application/json" },
        body: JSON.stringify({ path: selectedFile.path, content }),
      });
      if (r.ok) {
        setSavedContent(content);
        setDirty(false);
        setStatus({ type: "ok", msg: "Saved" });
        setTimeout(() => setStatus(null), 2500);
      } else {
        setStatus({ type: "err", msg: "Save failed" });
      }
    } catch {
      setStatus({ type: "err", msg: "Network error" });
    }
    setSaving(false);
  };
 
  // Keep saveRef in sync
  saveRef.current = saveFile;
 
  // Breadcrumb parts
  const pathParts = selectedFile?.path.split("/") || [];
  const fileName = pathParts.pop();
  const dirPath = pathParts.join("/");
 
  return (
    <div style={{ display: "flex", height: "100%", overflow: "hidden", fontFamily: "monospace" }}>
 
      {/* ── File tree sidebar ── */}
      <div style={{
        width: 220,
        background: "#080c10",
        borderRight: `1px solid ${C.border}`,
        display: "flex",
        flexDirection: "column",
        flexShrink: 0,
        overflow: "hidden",
      }}>
        <div style={{
          padding: "8px 12px",
          fontSize: 10,
          fontWeight: 700,
          color: C.muted,
          letterSpacing: "0.1em",
          textTransform: "uppercase",
          borderBottom: `1px solid ${C.border}`,
          flexShrink: 0,
        }}>
          Explorer
        </div>
        <div style={{ flex: 1, overflowY: "auto", padding: "4px 0" }}>
          {treeLoading ? (
            <div style={{ padding: "12px", fontSize: 12, color: C.muted }}>Loading...</div>
          ) : tree.length === 0 ? (
            <div style={{ padding: "12px", fontSize: 12, color: C.muted }}>No files found</div>
          ) : (
            <FileTree nodes={tree} onSelect={openFile} selected={selectedFile?.path} />
          )}
        </div>
      </div>
 
      {/* ── Editor area ── */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", minWidth: 0 }}>
 
        {/* Toolbar */}
        <div style={{
          padding: "6px 14px",
          background: C.panel,
          borderBottom: `1px solid ${C.border}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexShrink: 0,
          gap: 12,
          minHeight: 36,
        }}>
          {/* File path */}
          <div style={{ fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
            {selectedFile ? (
              <>
                {dirPath && <span style={{ color: C.muted }}>{dirPath}/</span>}
                <span style={{ color: dirty ? C.yellow : C.accent, fontWeight: 600 }}>
                  {fileName}{dirty ? " ●" : ""}
                </span>
                <span style={{ color: C.muted, marginLeft: 8, fontSize: 11 }}>
                  {getLang(fileName)}
                </span>
              </>
            ) : (
              <span style={{ color: C.muted }}>No file open</span>
            )}
          </div>
 
          {/* Actions */}
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
            {status && (
              <span style={{
                fontSize: 11,
                color: status.type === "ok" ? C.green : C.red,
                transition: "opacity 0.3s",
              }}>
                {status.type === "ok" ? "✓" : "✗"} {status.msg}
              </span>
            )}
            {selectedFile && (
              <Btn
                onClick={saveFile}
                small
                active={dirty && !saving}
                disabled={saving || !dirty}
                color={dirty ? C.accent : C.muted}
              >
                {saving ? "Saving…" : "Save  Ctrl+S"}
              </Btn>
            )}
          </div>
        </div>
 
        {/* Monaco container */}
        <div style={{ flex: 1, position: "relative", overflow: "hidden" }}>
          <div ref={containerRef} style={{ width: "100%", height: "100%" }} />
          {fileLoading && (
            <div style={{
              position: "absolute", inset: 0,
              display: "flex", alignItems: "center", justifyContent: "center",
              background: "rgba(8,12,16,0.7)",
              color: C.muted, fontSize: 12,
            }}>
              Loading…
            </div>
          )}
          {!monacoReady && (
            <div style={{
              position: "absolute", inset: 0,
              display: "flex", alignItems: "center", justifyContent: "center",
              background: "#080c10",
              color: C.muted, fontSize: 12,
            }}>
              Initialising editor…
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
 