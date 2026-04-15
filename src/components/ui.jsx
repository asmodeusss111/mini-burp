import { C } from "../lib/constants.js";

export function Panel({ children, style }) {
  return (
    <div style={{ background: C.panel, border: `1px solid ${C.border}`, borderRadius: 6, ...style }}>
      {children}
    </div>
  );
}

export function Btn({ children, onClick, active, color, small, disabled }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        background: active ? (color || C.accent) : "transparent",
        border: `1px solid ${active ? (color || C.accent) : C.border}`,
        color: active ? "#fff" : C.muted,
        borderRadius: 4,
        padding: small ? "3px 10px" : "6px 16px",
        fontSize: small ? 11 : 12,
        cursor: disabled ? "not-allowed" : "pointer",
        fontFamily: "monospace",
        opacity: disabled ? 0.5 : 1,
        transition: "all .15s",
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </button>
  );
}

export function Tag({ label, color }) {
  return (
    <span style={{
      background: color + "22",
      color,
      border: `1px solid ${color}44`,
      borderRadius: 3,
      padding: "1px 7px",
      fontSize: 10,
      fontFamily: "monospace",
      textTransform: "uppercase",
      fontWeight: 700,
    }}>
      {label}
    </span>
  );
}

export function Inp({ value, onChange, placeholder, style, rows, onKeyDown }) {
  const s = {
    background: C.bg,
    border: `1px solid ${C.border}`,
    borderRadius: 4,
    color: C.text,
    fontFamily: "monospace",
    fontSize: 12,
    padding: "8px 10px",
    outline: "none",
    width: "100%",
    boxSizing: "border-box",
    ...style,
  };
  return rows ? (
    <textarea
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      rows={rows}
      style={{ ...s, resize: "vertical" }}
    />
  ) : (
    <input
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      style={s}
      onKeyDown={onKeyDown}
    />
  );
}

export function ProxyBadge({ online }) {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 5,
      padding: "2px 10px",
      background: online ? C.green + "15" : C.red + "15",
      border: `1px solid ${online ? C.green : C.red}40`,
      borderRadius: 4,
    }}>
      <div style={{
        width: 6, height: 6, borderRadius: "50%",
        background: online ? C.green : C.red,
        boxShadow: `0 0 6px ${online ? C.green : C.red}`,
      }} />
      <span style={{ fontFamily: "monospace", fontSize: 10, color: online ? C.green : C.red }}>
        {online ? "proxy:8080 ✓" : "proxy offline"}
      </span>
    </div>
  );
}
