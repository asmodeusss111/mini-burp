import { useState, useEffect, useRef, useMemo } from "react";
import { C } from "../lib/constants.js";
import { Btn } from "../components/ui.jsx";

// ── Language detection & Icons ────────────────────────────────────────────────
const LANG_MAP = {
  js: "javascript", jsx: "javascript", mjs: "javascript", cjs: "javascript",
  ts: "typescript", tsx: "typescript",
  json: "json", html: "html", css: "css", md: "markdown",
  py: "python", sh: "shell", bash: "shell", java: "java",
  yml: "yaml", yaml: "yaml", sql: "sql",
  txt: "plaintext", env: "plaintext", lock: "plaintext",
};

function getLang(filename = "") {
  const ext = filename.split(".").pop().toLowerCase();
  return LANG_MAP[ext] || "plaintext";
}

function getFileIcon(filename = "") {
  const ext = filename.split(".").pop().toLowerCase();
  if (["js", "jsx", "ts", "tsx"].includes(ext)) return "⚡";
  if (ext === "json") return "🔧";
  if (ext === "md") return "📝";
  if (ext === "java") return "☕";
  return "📄";
}

// ── File tree component ───────────────────────────────────────────────────────
function FileTree({ nodes, onSelect, selected, depth = 0, forceOpen = false }) {
  const [open, setOpen] = useState({});
  
  const toggle = (path) => setOpen(o => ({ ...o, [path]: !o[path] }));

  return (
    <div>
      {nodes.map(node => {
        const isOpen = forceOpen || open[node.path];
        return (
          <div key={node.path}>
            <div
              onClick={() => node.type === "dir" ? toggle(node.path) : onSelect(node)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                padding: `4px 10px 4px ${10 + depth * 12}px`,
                cursor: "pointer",
                fontSize: 12,
                color: selected === node.path ? C.accent : node.type === "dir" ? C.text : C.muted,
                background: selected === node.path ? `${C.accent}15` : "transparent",
                userSelect: "none",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
                transition: "background 0.1s, color 0.1s",
              }}
            >
              <span style={{ fontSize: 11, flexShrink: 0, opacity: 0.8, display: "inline-block", width: 14 }}>
                {node.type === "dir" ? (isOpen ? "📂" : "📁") : getFileIcon(node.name)}
              </span>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", fontWeight: selected === node.path ? 600 : 400 }}>
                {node.name}
              </span>
            </div>
            {node.type === "dir" && isOpen && node.children?.length > 0 && (
              <FileTree nodes={node.children} onSelect={onSelect} selected={selected} depth={depth + 1} forceOpen={forceOpen} />
            )}
          </div>
        );
      })}
    </div>
  );
}

// Helper to filter tree
function filterTree(nodes, query) {
  if (!query) return nodes;
  const q = query.toLowerCase();
  return nodes.map(n => {
    if (n.type === "dir") {
      const children = filterTree(n.children || [], query);
      if (children.length > 0) return { ...n, children };
      if (n.name.toLowerCase().includes(q)) return n;
      return null;
    }
    return n.name.toLowerCase().includes(q) ? n : null;
  }).filter(Boolean);
}

// ── Main component ────────────────────────────────────────────────────────────
export default function FileEditorTab({ adminPass }) {
  const [tree, setTree] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
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
  const saveRef = useRef(null); 
  const autoSaveTimerRef = useRef(null); // Timer for auto-saving

  const h = { "x-admin-password": adminPass };

  // Load file tree
  useEffect(() => {
    fetch("/api/admin/files", { headers: h })
      .then(r => r.json())
      .then(d => { setTree(d.tree || []); setTreeLoading(false); })
      .catch(() => setTreeLoading(false));
  }, []);

  const filteredTree = useMemo(() => filterTree(tree, searchQuery), [tree, searchQuery]);

  // Clear auto-save timer when switching files
  useEffect(() => {
    return () => clearTimeout(autoSaveTimerRef.current);
  }, [selectedFile]);

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
          value: "// ← Select a file from the explorer to begin",
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

        // Ctrl+S keybind for manual save
        editor.addCommand(
          window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.KeyS,
          () => {
            clearTimeout(autoSaveTimerRef.current);
            saveRef.current?.();
          }
        );

        // Auto-save logic on type
        editor.onDidChangeModelContent(() => {
          setDirty(true);
          setStatus(null);
          
          clearTimeout(autoSaveTimerRef.current);
          autoSaveTimerRef.current = setTimeout(() => {
            saveRef.current?.();
          }, 800); // 800ms debounce
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
        
        // Prevent onDidChangeModelContent from triggering an auto-save on load
        setTimeout(() => {
          setDirty(false);
          clearTimeout(autoSaveTimerRef.current);
        }, 50);
      }
    } catch {
      setStatus({ type: "err", msg: "Failed to load file" });
    }
    setFileLoading(false);
  };

  const closeFile = () => {
    setSelectedFile(null);
    if (editorRef.current) {
      editorRef.current.setValue("// ← Select a file from the explorer to begin");
      editorRef.current.updateOptions({ readOnly: true });
    }
  }

  // Save current file
  const saveFile = async () => {
    if (!selectedFile || !editorRef.current || saving) return;
    setSaving(true);
    setStatus({ type: "ok", msg: "Saving..." });
    
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
        setStatus({ type: "ok", msg: "Auto-saved ✓" });
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

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden", fontFamily: "monospace", background: C.bg }}>
      
      {/* ── Top IDE Toolbar ── */}
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "8px 16px",
        background: "#080c10",
        borderBottom: `1px solid ${C.border}`,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 15 }}>
          <span style={{ fontWeight: "bold", color: C.text, fontSize: 14 }}>BurpIDE</span>
          <div style={{ display: "flex", gap: 8 }}>
            <Btn small color={C.muted} style={{ padding: "4px 10px", border: "none", background: "transparent" }}>▶ Run</Btn>
            <Btn small color={C.muted} style={{ padding: "4px 10px", border: "none", background: "transparent" }}>🔨 Build</Btn>
            <Btn small color={C.muted} style={{ padding: "4px 10px", border: "none", background: "transparent" }}>🗑 Clean</Btn>
          </div>
        </div>
        
        <div style={{ display: "flex", alignItems: "center", gap: 12, fontSize: 12 }}>
          {status && (
            <span style={{ color: status.type === "ok" ? C.green : C.red, opacity: 0.8 }}>
              {status.msg}
            </span>
          )}
          <Btn 
            onClick={saveFile} 
            small 
            disabled={saving || !dirty}
            color={dirty ? C.accent : C.muted}
            style={{ padding: "4px 12px", borderRadius: 4, background: dirty ? `${C.accent}20` : "transparent" }}
          >
            💾 {saving ? "Saving..." : dirty ? "Unsaved" : "Saved"}
          </Btn>
        </div>
      </div>

      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {/* ── File tree sidebar ── */}
        <div style={{
          width: 240,
          background: "#0a0e13",
          borderRight: `1px solid ${C.border}`,
          display: "flex",
          flexDirection: "column",
          flexShrink: 0,
        }}>
          {/* Search Bar */}
          <div style={{ padding: "10px", borderBottom: `1px solid ${C.border}50` }}>
            <input 
              placeholder="🔍 Search files..." 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: "100%",
                background: C.panel,
                border: `1px solid ${C.border}`,
                color: C.text,
                padding: "6px 10px",
                borderRadius: 4,
                fontSize: 12,
                fontFamily: "inherit",
                outline: "none"
              }}
            />
          </div>

          <div style={{ padding: "8px 12px", fontSize: 10, fontWeight: 700, color: C.muted, letterSpacing: "0.05em", textTransform: "uppercase" }}>
            Project
          </div>

          <div style={{ flex: 1, overflowY: "auto", padding: "0 0 10px 0" }}>
            {treeLoading ? (
              <div style={{ padding: "12px", fontSize: 12, color: C.muted, textAlign: "center" }}>Loading project...</div>
            ) : filteredTree.length === 0 ? (
              <div style={{ padding: "12px", fontSize: 12, color: C.muted, textAlign: "center" }}>No files match</div>
            ) : (
              <FileTree nodes={filteredTree} onSelect={openFile} selected={selectedFile?.path} forceOpen={searchQuery.length > 0} />
            )}
          </div>
        </div>

        {/* ── Editor area ── */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", background: C.panel }}>
          
          {/* Tabs */}
          <div style={{
            display: "flex",
            background: "#080c10",
            borderBottom: `1px solid ${C.border}`,
            overflowX: "auto",
            minHeight: 35
          }}>
            {selectedFile ? (
              <div style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "0 15px",
                background: C.panel,
                borderTop: `2px solid ${C.accent}`,
                borderRight: `1px solid ${C.border}`,
                fontSize: 12,
                color: C.text,
                cursor: "default",
                userSelect: "none"
              }}>
                <span style={{ opacity: 0.8 }}>{getFileIcon(selectedFile.name)}</span>
                <span style={{ fontStyle: dirty ? "italic" : "normal" }}>
                  {selectedFile.name} {dirty ? "•" : ""}
                </span>
                <span 
                  onClick={closeFile}
                  style={{ marginLeft: 5, color: C.muted, cursor: "pointer", padding: "0 4px" }}
                  title="Close file"
                >
                  ×
                </span>
              </div>
            ) : (
              <div style={{ padding: "8px 15px", fontSize: 12, color: C.muted, fontStyle: "italic" }}>
                No file open
              </div>
            )}
          </div>

          {/* Monaco container */}
          <div style={{ flex: 1, position: "relative", overflow: "hidden" }}>
            <div ref={containerRef} style={{ width: "100%", height: "100%" }} />
            {fileLoading && (
              <div style={{
                position: "absolute", inset: 0,
                display: "flex", alignItems: "center", justifyContent: "center",
                background: "rgba(10, 14, 19, 0.7)",
                backdropFilter: "blur(2px)",
                color: C.text, fontSize: 13,
                zIndex: 10
              }}>
                Opening file...
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}