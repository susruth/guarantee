import { Link } from "react-router-dom";

export function Home() {
  return (
    <main>
      {/* ── Hero ── */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "var(--space-xl)",
          marginBottom: "var(--space-xl)",
          alignItems: "start",
        }}
      >
        <div>
          <h2>Prove your code runs inside a TEE.</h2>
          <p style={{ fontSize: "1.2rem", maxWidth: 500, marginBottom: "var(--space-md)", lineHeight: 1.6 }}>
            One macro adds hardware-backed Ed25519 signatures to every HTTP response. Callers verify the attestation
            chain without trusting your infrastructure.
          </p>
          <div style={{ display: "flex", gap: "var(--space-sm)", flexWrap: "wrap" }}>
            <Link to="/docs/getting-started" className="btn btn-primary">
              Get Started
            </Link>
            <Link to="/docs/how-it-works" className="btn btn-outline">
              How It Works
            </Link>
          </div>
        </div>
        <div
          className="mono"
          style={{
            padding: "var(--space-md)",
            border: "var(--border-thin)",
            minHeight: 320,
            display: "flex",
            flexDirection: "column",
            justifyContent: "flex-end",
          }}
        >
          <div
            style={{
              flexGrow: 1,
              borderBottom: "var(--border-thin)",
              marginBottom: "1rem",
              position: "relative",
              overflow: "hidden",
            }}
          >
            <div style={{ position: "absolute", bottom: 0, left: 0, width: "40%", height: "60%", borderTop: "var(--border-thin)", borderRight: "var(--border-thin)" }} />
            <div style={{ position: "absolute", top: "20%", right: "10%", width: "50%", height: "50%", border: "var(--border-thin)" }} />
            <div style={{ position: "absolute", top: "8%", left: "15%", width: "25%", height: "30%", borderBottom: "var(--border-thin)", borderLeft: "var(--border-thin)" }} />
          </div>
          <div>STATE: UNTRUSTED_HOST -&gt; SECURE_ENCLAVE</div>
          <div>VERIFICATION: ATTESTED // ED25519</div>
        </div>
      </section>

      {/* ── Core Principles ── */}
      <SectionHeader title="Core Principles" label="01 // Architecture" />
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 1fr)",
          borderBottom: "var(--border-thin)",
          marginBottom: "var(--space-xl)",
        }}
      >
        <GridItem title="Hardware Attestation" text="Every response is signed with an ephemeral Ed25519 key bound to the enclave's hardware measurement via an SGX DCAP quote. Verifiable by anyone, no trust required." />
        <GridItem title="Sealed State" text="Two-tier encrypted persistence. MRENCLAVE state resets per deploy — caches and sessions. MRSIGNER state persists across versions — private keys and master config." />
        <GridItem title="Zero Boilerplate" text="Same binary runs locally in dev mode and inside Gramine SGX in production. No conditional compilation. No SGX expertise. Add one attribute, ship attested responses." last />
      </section>

      {/* ── Quickstart ── */}
      <SectionHeader title="Implementation" label="02 // Quickstart" />
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 2fr",
          borderTop: "var(--border-thin)",
          borderBottom: "var(--border-thin)",
          marginBottom: "var(--space-xl)",
        }}
      >
        <div style={{ padding: "var(--space-md)", borderRight: "var(--border-thin)" }}>
          <p style={{ marginBottom: "var(--space-md)", lineHeight: 1.6 }}>
            Add Guarantee to your Rust project. Annotate any axum handler with <code>#[attest]</code> and every response
            gets a cryptographic signature bound to the enclave identity.
          </p>
          <InstallBox text="$ cargo add guarantee" />
          <InstallBox text="$ cargo run --example hello-tee" />
        </div>
        <div style={{ padding: "var(--space-md)" }}>
          <pre>
            <code>{`// Attested HTTP service in 20 lines
use guarantee::{attest, state};
use axum::{response::Json, routing::get, Router};

state! {
    // Resets on redeploy (new binary = new measurement)
    #[mrenclave]
    AppData,
}

// This is all you add — one attribute
#[attest]
async fn hello() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "message": "hello from TEE" }))
}

#[tokio::main]
async fn main() {
    let state = TeeState::initialize(Path::new("./sealed")).unwrap();
    let app = Router::new()
        .route("/hello", get(hello))
        .layer(Extension(Arc::new(RwLock::new(state))));

    // Every response now includes X-TEE-Attestation header
    axum::serve(listener, app).await.unwrap();
}`}</code>
          </pre>
        </div>
      </section>

      {/* ── How It Works ── */}
      <SectionHeader title="Attestation Chain" label="03 // How It Works" />
      <section style={{ marginBottom: "var(--space-xl)" }}>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, 1fr)",
            borderBottom: "var(--border-thin)",
          }}
        >
          <StepCard num="01" title="Keypair Generated" text="Enclave boots and creates an ephemeral Ed25519 signing key. The private key exists only in enclave memory." />
          <StepCard num="02" title="Startup Quote" text="SGX hardware produces a DCAP quote binding the public key to the enclave measurement (MRENCLAVE)." />
          <StepCard num="03" title="Response Signed" text="The #[attest] macro signs SHA-256(body || ts || req_id) with the enclave key on every response." />
          <StepCard num="04" title="Anyone Verifies" text="Fetch the startup quote once, then verify each response signature. Proof from silicon to JSON." last />
        </div>
      </section>

      {/* ── API Surface ── */}
      <SectionHeader title="API Surface" label="04 // Reference" />
      <section style={{ marginBottom: "var(--space-xl)" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", borderBottom: "var(--border-thin)" }}>
          <thead>
            <tr>
              <th className="mono" style={{ textAlign: "left", padding: "0.75rem var(--space-sm)", borderBottom: "var(--border-thin)", fontWeight: 400, color: "var(--grey-light)", fontSize: "0.72rem", letterSpacing: "0.08em", textTransform: "uppercase" }}>Export</th>
              <th className="mono" style={{ textAlign: "left", padding: "0.75rem var(--space-sm)", borderBottom: "var(--border-thin)", fontWeight: 400, color: "var(--grey-light)", fontSize: "0.72rem", letterSpacing: "0.08em", textTransform: "uppercase" }}>Description</th>
            </tr>
          </thead>
          <tbody>
            {[
              ["#[attest]", "Attribute macro — signs every response with the enclave key"],
              ["state! { }", "Declares two-tier sealed state with auto-generated accessors"],
              ["#[derive(Encrypted)]", "Generates encrypted struct variant with AES-256-GCM"],
              ["EnclaveAttestor", "Core struct — keypair, startup quote, response signing"],
              ["MrEnclave / MrSigner", "32-byte enclave identity value types"],
              ["StartupQuote", "SGX DCAP quote binding key to enclave measurement"],
              ["AttestationHeader", "Per-response signature — parse with from_header_value()"],
              ["seal_to_file()", "Low-level sealing to disk (MRENCLAVE or MRSIGNER mode)"],
              ["encrypt_field()", "AES-256-GCM field encryption with optional key versioning"],
              ["derive_key()", "HKDF-SHA256 purpose-specific key derivation"],
              ["serve_ra_tls()", "HTTPS server with attestation-embedded X.509 certificates"],
            ].map(([exp, desc], i) => (
              <tr key={i}>
                <td className="mono" style={{ padding: "0.6rem var(--space-sm)", borderBottom: "1px solid var(--grey-rule)", fontWeight: 700, fontSize: "0.82rem", whiteSpace: "nowrap" }}>{exp}</td>
                <td style={{ padding: "0.6rem var(--space-sm)", borderBottom: "1px solid var(--grey-rule)", fontSize: "0.88rem", color: "var(--grey)" }}>{desc}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/* ── Examples ── */}
      <SectionHeader title="Examples" label="05 // Use Cases" />
      <section style={{ marginBottom: "var(--space-xl)" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", borderBottom: "var(--border-thin)" }}>
          <ExampleCard slug="hello-tee" tag="Starter" title="Hello TEE" desc="Minimal attested service — one handler, one macro, full attestation chain." />
          <ExampleCard slug="oracle" tag="DeFi" title="Price Oracle" desc="Two-tier state with background price updates. Every price is cryptographically signed." />
          <ExampleCard slug="btc-signer" tag="Custody" title="Bitcoin Signer" desc="Private key custody with MRSIGNER sealing. Key never leaves enclave memory." />
          <ExampleCard slug="postgres-encrypted" tag="Database" title="Encrypted Postgres" desc="Field-level AES-256-GCM before INSERT. Database only ever sees ciphertext." />
          <ExampleCard slug="redis-cache" tag="Cache" title="Encrypted Redis" desc="Conditional encryption for cache values. Sensitive data encrypted, rest stays queryable." />
          <ExampleCard slug="ra-tls" tag="Transport" title="RA-TLS" desc="Remote attestation baked into TLS handshakes. Verify enclave identity at connection time." last />
        </div>
      </section>

      {/* ── Config ── */}
      <SectionHeader title="Configuration" label="06 // Environment" />
      <section style={{ marginBottom: "var(--space-xl)" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", borderBottom: "var(--border-thin)" }}>
          {[
            ["GUARANTEE_ENCLAVE=1", "Enable enclave mode — reads /dev/attestation/* for real SGX quotes"],
            ["(unset)", "Dev mode — mock attestation, same API, no hardware required"],
            ["GUARANTEE_ATTEST_MODE", 'Set to "startup-only" to skip per-response signatures'],
            ["PORT", "HTTP listen port (default 8080)"],
          ].map(([k, v], i) => (
            <div
              key={i}
              style={{
                padding: "var(--space-sm) var(--space-md)",
                borderRight: i % 2 === 0 ? "var(--border-thin)" : "none",
                borderBottom: i < 2 ? "1px solid var(--grey-rule)" : "none",
              }}
            >
              <div className="mono" style={{ fontWeight: 700, fontSize: "0.8rem", marginBottom: "0.25rem" }}>{k}</div>
              <div style={{ fontSize: "0.85rem", color: "var(--grey)" }}>{v}</div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}

/* ── Sub-components ── */

function SectionHeader({ title, label }: { title: string; label: string }) {
  return (
    <div
      style={{
        paddingBottom: "var(--space-sm)",
        borderBottom: "var(--border-thin)",
        marginBottom: 0,
        display: "flex",
        justifyContent: "space-between",
        alignItems: "baseline",
      }}
    >
      <h3>{title}</h3>
      <span className="mono">{label}</span>
    </div>
  );
}

function GridItem({ title, text, last }: { title: string; text: string; last?: boolean }) {
  return (
    <div style={{ padding: "var(--space-md)", borderRight: last ? "none" : "var(--border-thin)" }}>
      <h3 className="mono" style={{ fontSize: "0.9rem", textTransform: "uppercase", letterSpacing: "0.02em" }}>
        {title}
      </h3>
      <p style={{ fontSize: "0.9rem", lineHeight: 1.6 }}>{text}</p>
    </div>
  );
}

function InstallBox({ text }: { text: string }) {
  return (
    <div
      className="mono"
      style={{
        border: "var(--border-thin)",
        padding: "var(--space-sm)",
        marginBottom: "var(--space-sm)",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
      }}
    >
      <span>{text}</span>
      <span
        style={{ cursor: "pointer", userSelect: "none", opacity: 0.5, transition: "opacity 0.15s" }}
        onClick={() => navigator.clipboard.writeText(text.replace("$ ", ""))}
      >
        [COPY]
      </span>
    </div>
  );
}

function StepCard({ num, title, text, last }: { num: string; title: string; text: string; last?: boolean }) {
  return (
    <div style={{ padding: "var(--space-md)", borderRight: last ? "none" : "var(--border-thin)" }}>
      <div
        style={{
          fontFamily: "var(--font-display)",
          fontSize: "2.5rem",
          fontWeight: 700,
          lineHeight: 1,
          marginBottom: "var(--space-sm)",
          opacity: 0.15,
        }}
      >
        {num}
      </div>
      <h4
        style={{
          fontFamily: "var(--font-display)",
          fontSize: "0.85rem",
          textTransform: "uppercase",
          letterSpacing: "0.02em",
          marginBottom: "0.5rem",
        }}
      >
        {title}
      </h4>
      <p style={{ fontSize: "0.85rem", lineHeight: 1.55, color: "#444" }}>{text}</p>
    </div>
  );
}

function ExampleCard({ slug, tag, title, desc, last }: { slug: string; tag: string; title: string; desc: string; last?: boolean }) {
  return (
    <Link
      to={`/docs/${slug}`}
      style={{
        padding: "var(--space-md)",
        borderRight: last ? "none" : "var(--border-thin)",
        display: "block",
        transition: "background 0.15s",
        borderBottom: "var(--border-thin)",
      }}
      onMouseOver={(e) => (e.currentTarget.style.background = "#f8f8f8")}
      onMouseOut={(e) => (e.currentTarget.style.background = "transparent")}
    >
      <span className="mono" style={{ fontSize: "0.68rem", textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--grey-light)", marginBottom: "0.75rem", display: "block" }}>
        {tag}
      </span>
      <h4 style={{ fontFamily: "var(--font-display)", fontSize: "1rem", textTransform: "uppercase", marginBottom: "0.5rem" }}>
        {title}
      </h4>
      <p style={{ fontSize: "0.85rem", color: "var(--grey)", lineHeight: 1.5 }}>{desc}</p>
    </Link>
  );
}
