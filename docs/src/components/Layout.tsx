import { Outlet, Link, useLocation } from "react-router-dom";

export function Layout() {
  const { pathname } = useLocation();
  const isHome = pathname === "/";

  return (
    <div className="container">
      <header style={{ marginBottom: isHome ? "var(--space-xl)" : "var(--space-md)" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-end",
            paddingBottom: "var(--space-xs)",
            borderBottom: "var(--border-thick)",
          }}
        >
          <Link
            to="/"
            style={{
              fontFamily: "var(--font-display)",
              fontSize: isHome ? "clamp(2.5rem, 7vw, 5.5rem)" : "3rem",
              fontWeight: 700,
              lineHeight: 1,
              textTransform: "uppercase",
              letterSpacing: "-0.02em",
            }}
          >
            Guarantee
          </Link>
          <nav className="mono" style={{ display: "flex", gap: "var(--space-md)", paddingBottom: "0.4rem" }}>
            <Link to="/docs/getting-started" style={{ textDecoration: pathname.startsWith("/docs") ? "underline" : "none", textUnderlineOffset: "4px" }}>
              Docs
            </Link>
            <a href="https://github.com/susruth/guarantee" target="_blank" rel="noopener noreferrer">GitHub ↗</a>
            <a href="https://crates.io/crates/guarantee" target="_blank" rel="noopener noreferrer">Crates.io ↗</a>
          </nav>
        </div>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "var(--space-xs) 0",
            borderBottom: "var(--border-thin)",
            fontSize: "0.78rem",
            textTransform: "uppercase",
            fontFamily: "var(--font-display)",
            letterSpacing: "0.05em",
          }}
        >
          <span>{pathname.startsWith("/docs") ? "API Reference // Documentation" : "Open Source Rust TEE Attestation SDK"}</span>
          <span>v0.1.2</span>
        </div>
      </header>

      <Outlet />

      <footer
        className="mono"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "var(--space-md) 0",
          borderTop: "var(--border-thick)",
          fontSize: "0.78rem",
          textTransform: "uppercase",
          flexWrap: "wrap",
          gap: "var(--space-sm)",
        }}
      >
        <div>Guarantee SDK // 2025</div>
        <div style={{ display: "flex", gap: "var(--space-md)" }}>
          <Link to="/docs/getting-started">Documentation</Link>
          <a href="https://github.com/susruth/guarantee" target="_blank" rel="noopener noreferrer">GitHub ↗</a>
          <a href="https://crates.io/crates/guarantee" target="_blank" rel="noopener noreferrer">Crates.io ↗</a>
          <a href="https://github.com/susruth/guarantee/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">MIT License ↗</a>
        </div>
      </footer>
    </div>
  );
}
