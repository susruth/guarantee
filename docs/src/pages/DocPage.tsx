import { useEffect, useRef } from "react";
import { useParams, Link, useLocation, Navigate } from "react-router-dom";
import { docs } from "./docs-content";

const sections = [
  { label: "Introduction", slugs: ["getting-started", "how-it-works"] },
  { label: "Concepts", slugs: ["attestation", "state", "encryption", "sealing"] },
  {
    label: "SDK Reference",
    slugs: ["attest-macro", "state-macro", "encrypted-derive", "crypto", "enclave-attestor", "ra-tls", "errors"],
  },
  {
    label: "Examples",
    slugs: ["hello-tee", "oracle", "btc-signer", "postgres-encrypted", "redis-cache"],
  },
];

// Flat ordered list of all slugs for prev/next
const allSlugs = sections.flatMap((s) => s.slugs);

export function DocPage() {
  const { slug } = useParams();
  const { pathname } = useLocation();
  const sidebarRef = useRef<HTMLElement>(null);
  const active = slug || "getting-started";

  if (!slug && pathname === "/docs") {
    return <Navigate to="/docs/getting-started" replace />;
  }

  // Scroll active sidebar link into view
  useEffect(() => {
    const el = sidebarRef.current?.querySelector("a.active");
    el?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const doc = docs.find((d) => d.slug === active);
  const sectionLabel = sections.find((s) => s.slugs.includes(active))?.label ?? "";

  // Prev / Next
  const idx = allSlugs.indexOf(active);
  const prevSlug = idx > 0 ? allSlugs[idx - 1] : null;
  const nextSlug = idx < allSlugs.length - 1 ? allSlugs[idx + 1] : null;
  const prevDoc = prevSlug ? docs.find((d) => d.slug === prevSlug) : null;
  const nextDoc = nextSlug ? docs.find((d) => d.slug === nextSlug) : null;

  return (
    <div className="doc-layout">
      <aside className="doc-sidebar" ref={sidebarRef}>
        {sections.map((sec) => (
          <div className="doc-sidebar-section" key={sec.label}>
            <div className="doc-sidebar-title">{sec.label}</div>
            {sec.slugs.map((s) => {
              const d = docs.find((x) => x.slug === s);
              return (
                <Link key={s} to={`/docs/${s}`} className={active === s ? "active" : ""}>
                  {d?.title ?? s}
                </Link>
              );
            })}
          </div>
        ))}
      </aside>

      <main className="doc-content">
        {doc ? (
          <>
            <div className="doc-module-label">
              {sectionLabel.toUpperCase()} // {doc.title.toUpperCase()}
            </div>
            <h1>{doc.title}</h1>
            <p className="doc-lead">{doc.lead}</p>

            {doc.body.map((section, i) => (
              <div className="api-block" key={i}>
                {section.heading && <h2>{section.heading}</h2>}
                {section.text &&
                  section.text.split("\n\n").map((para, j) => (
                    <p key={j} dangerouslySetInnerHTML={{ __html: para }} />
                  ))}
                {section.code && (
                  <div className="code-snippet">
                    <pre>
                      <code>{section.code}</code>
                    </pre>
                  </div>
                )}
                {section.table && (
                  <table className="params-table">
                    <thead>
                      <tr>
                        {section.table.headers.map((h, j) => (
                          <th key={j}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {section.table.rows.map((row, j) => (
                        <tr key={j}>
                          {row.map((cell, k) => (
                            <td key={k} dangerouslySetInnerHTML={{ __html: cell }} />
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {section.list && (
                  <ul>
                    {section.list.map((item, j) => (
                      <li key={j} dangerouslySetInnerHTML={{ __html: item }} />
                    ))}
                  </ul>
                )}
              </div>
            ))}

            {/* Cross-links */}
            <div className="doc-cross-links mono">
              <Link to="/verify">Verify a live response →</Link>
              <a href="https://guarantee.rs" target="_blank" rel="noopener noreferrer">Managed deployment →</a>
            </div>

            {/* Prev / Next */}
            <nav className="doc-nav">
              {prevDoc ? (
                <Link to={`/docs/${prevSlug}`} className="doc-nav-link">
                  <span className="doc-nav-label">← Previous</span>
                  <span className="doc-nav-title">{prevDoc.title}</span>
                </Link>
              ) : (
                <div className="doc-nav-spacer" />
              )}
              {nextDoc ? (
                <Link to={`/docs/${nextSlug}`} className="doc-nav-link" style={{ textAlign: "right" }}>
                  <span className="doc-nav-label">Next →</span>
                  <span className="doc-nav-title">{nextDoc.title}</span>
                </Link>
              ) : (
                <div className="doc-nav-spacer" />
              )}
            </nav>
          </>
        ) : (
          <>
            <h1>Page not found</h1>
            <p>
              No documentation found for <code>{active}</code>.{" "}
              <Link to="/docs/getting-started">Go to Getting Started</Link>.
            </p>
          </>
        )}
      </main>
    </div>
  );
}
