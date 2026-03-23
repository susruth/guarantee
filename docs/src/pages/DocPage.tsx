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

export function DocPage() {
  const { slug } = useParams();
  const { pathname } = useLocation();
  const active = slug || "getting-started";

  if (!slug && pathname === "/docs") {
    return <Navigate to="/docs/getting-started" replace />;
  }

  const doc = docs.find((d) => d.slug === active);
  const sectionLabel = sections.find((s) => s.slugs.includes(active))?.label ?? "";

  return (
    <div className="doc-layout">
      <aside className="doc-sidebar">
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
