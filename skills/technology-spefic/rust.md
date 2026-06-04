# Rust Security Audit Guide

> Comprehensive security scanning prompts for Rust codebases: Actix-Web, Axum, Rocket, Warp, Tokio-based services, and systems-level Rust.

---

## 1. Authentication & Session Flow

```
You are an expert security engineer and review below.
Review the entire authentication flow in this Rust codebase. Trace every path from login to session creation to authorization checks. Identify:

- Any Actix-Web / Axum / Rocket route handler missing authentication middleware or extractor
  - Actix: Are all routes in authenticated scope? Can routes be registered outside the middleware chain?
  - Axum: Are all sensitive routes behind a from_fn middleware layer or TypedHeader extractor?
- JWT vulnerabilities:
  - Which library: jsonwebtoken, jwt-simple, frank_jwt? Is the algorithm explicitly pinned?
  - Is the "none" algorithm rejected?
  - Are token claims (exp, iss, aud) validated?
- Session tokens: are they generated with a cryptographically secure RNG (rand::rngs::OsRng)?
- Are secrets compared with constant-time comparison (subtle::ConstantTimeEq or ring::constant_time)?
- OAuth: is the state parameter validated to prevent CSRF?

For each finding, provide the exact file, line number, and a proof-of-concept HTTP request demonstrating the bypass.
```

---

## 2. Database Security (sqlx, Diesel, SeaORM, rusqlite)

```
You are an expert security engineer and review below.
Audit every database interaction in this Rust codebase.

sqlx:
- Any sqlx::query() or sqlx::query_as() with string formatting or concatenation?
  Dangerous: sqlx::query(&format!("SELECT * FROM users WHERE id={}", id))
  Safe: sqlx::query!("SELECT * FROM users WHERE id = $1", id) (compile-time checked macro)
         or sqlx::query("SELECT * FROM users WHERE id = $1").bind(id)
- Are raw strings passed to query() when the macro is available?

Diesel:
- Diesel's type system generally prevents SQL injection through typed DSL
- Are there any .execute(conn) calls with raw SQL via sql() function?
- Are custom SQL queries using diesel::sql_query() parameterized?

SeaORM:
- Any use of sea_query::Expr::cust() with user-controlled strings?
- Are all query builder calls using strongly-typed column references?

rusqlite:
- Any conn.execute() or conn.query_row() with format! in the SQL string?

Second-order Injection:
- Is user data stored and later used in a dynamic query?

Multi-tenancy:
- Are all queries filtered by tenant_id from the authenticated principal — not from the request body?

For each finding, show the full request-to-sink path, a PoC payload, and the parameterized fix.
```

---

## 3. Unsafe Code & Memory Safety

```
You are an expert security engineer and review below.
Audit all unsafe code in this Rust codebase — this is Rust-specific and critical.

unsafe Blocks:
- List every unsafe { } block in the codebase. For each:
  - What invariants must hold for this to be safe?
  - Are those invariants actually enforced?
  - Could user input influence pointer arithmetic, buffer lengths, or type casting inside?
- Are unsafe blocks minimal (smallest possible scope)?
- Is the rationale documented with a // SAFETY: comment?

FFI (Foreign Function Interface):
- Are C function calls (extern "C") provided with correct types and lengths?
- Are C strings (CStr, CString) properly null-terminated and length-validated?
- Is memory allocated in C freed in C, and memory allocated in Rust freed in Rust?
- Could a Rust panic unwind through an FFI boundary? (Should use catch_unwind or #[no_panic])

Raw Pointer Usage:
- Are raw pointer dereferences (*ptr) guarded by null checks and lifetime validation?
- Are pointer arithmetic operations bounds-checked?

Integer Overflow:
- Are arithmetic operations on untrusted numeric input using checked_add(), checked_sub(), checked_mul() or saturating variants?
- Is overflow in release mode (which wraps silently in Rust by default) a concern in security-critical paths?

Transmute:
- Any std::mem::transmute with user-influenced types or values?
- Is transmute being used to reinterpret data from an untrusted source?

From_Raw / From_Parts:
- Any Vec::from_raw_parts(), slice::from_raw_parts() with user-controlled length or pointer?

For each finding, show the unsafe block, explain the soundness risk, and provide the safe alternative.
```

---

## 4. Injection Vulnerabilities

```
You are an expert security engineer and review below.
Find every injection vulnerability in this Rust codebase.

Command Injection:
- Any std::process::Command::new("sh").arg("-c").arg(userInput)?
  (Passing user input to a shell command string — dangerous)
  Safe: std::process::Command::new("binary").arg(userInput) (no shell involved)
- Any use of std::process::Command with args assembled via format! from user input?

Path Traversal:
- Any std::fs::File::open(), std::fs::read(), PathBuf constructed from user-controlled strings?
- Is Path::canonicalize() combined with starts_with(allowed_base) check?
- Are symlinks followed unexpectedly?

SSRF:
- Any reqwest::get(user_url), hyper::Client with user-controlled URLs?
- Is the URL validated against an allowlist before the request?
- Are URL schemes restricted (block file://, ftp://)?

Template Injection:
- Any Tera, Handlebars (handlebars-rust), Askama templates rendering user-supplied template strings?
  Dangerous: Tera::render_str(userInput, &context)
  Askama is compile-time safe; Tera/Handlebars dynamic rendering of user strings is dangerous

XSS (for web applications):
- Is user input passed to HTML responses via format! without HTML escaping?
- Is html-escape crate or askama's auto-escaping used?
- Are CSP headers set?

Regex DoS (ReDoS):
- Are complex regex patterns (using the regex crate) applied to user-supplied strings?
  (The regex crate is linear-time by design — but very large inputs can still exhaust memory)
- Is there an input length limit before regex matching?

Deserialization:
- Any serde_json::from_str() / from_reader() with untrusted input deserializing to untyped Value?
- If deserializing to concrete types, are bounds on Vec, String lengths enforced?
- Any use of bincode, postcard, rkyv deserializing untrusted binary data?

For each finding, show input-to-sink trace, PoC payload, CVSS 3.1 rating, and exact fix.
```

---

## 5. Secrets & Sensitive Data Exposure

```
You are an expert security engineer and review below.
Scan this Rust codebase for secrets and sensitive data exposure.

Hardcoded Secrets:
- Any string literals matching: password, secret, api_key, token, private_key in .rs files
- Credentials in .env, config.toml, or Rocket.toml committed to git
- Are secrets loaded from environment variables (std::env::var) or a secret manager?

Logging:
- Any tracing::info!, log::debug!, println! logging passwords, tokens, PII, or connection strings?
- Are Debug trait implementations for sensitive types (User, Token) exposing secrets?
  Consider using a custom Debug impl or #[derive(Debug)] exclusions
- Does the panic handler log sensitive data from the call stack?

Memory Zeroing:
- Are sensitive values (passwords, keys) zeroed after use?
  Use zeroize crate: #[derive(Zeroize, ZeroizeOnDrop)]
- Are Vec<u8> or String buffers holding secrets cleared before deallocation?

API Response:
- Are Serde-serializable structs with sensitive fields (#[serde(skip)] on PasswordHash, etc.) returning more than intended?
- Is there a separate DTO/view struct for API responses separate from internal domain types?

For each finding, specify file, line, the sensitive data, where it leaks, and remediation.
```

---

## 6. Infrastructure & Configuration

```
You are an expert security engineer and review below.
Review all configuration and infrastructure in this Rust project.

HTTP Security Headers (Actix/Axum):
- Is a security headers middleware (actix-web middleware, tower_http::set_header) in place?
- Are X-Content-Type-Options, X-Frame-Options, HSTS, CSP, and Referrer-Policy set?

TLS:
- Is rustls or native-tls used with TLS 1.2+ minimum?
- Are weak cipher suites excluded?
- Is HTTP→HTTPS redirect configured?

CORS:
- Is actix-cors or tower-http CORS middleware configured with a wildcard allow_any_origin on authenticated routes?
- Are origins explicitly allowlisted?

Rate Limiting:
- Is governor or a custom rate limiter applied to public endpoints (login, registration)?
- Is the rate limiter per-IP?

Dependency Security:
- Run cargo audit — list all known advisories for Cargo.lock dependencies
- Are crates pinned to specific versions in Cargo.lock?
- Are there advisories for yanked or unmaintained crates in the dependency tree?

Docker:
- Is the final image using distroless or scratch with a non-root user?
- Is the Rust binary statically linked (RUSTFLAGS="-C target-feature=+crt-static")?
- Are secrets baked into the Docker image via ENV instructions?

For each issue, specify the file, setting, risk, and corrected code snippet.
```

---

## 7. Business Logic & Concurrency (Async/Tokio)

```
You are an expert security engineer and review below.
Analyze business logic and async patterns in this Rust codebase for logic flaws.

Async Race Conditions:
- Are there check-then-act patterns in async code without database-level locking?
  Example: tokio::spawn reading balance, then writing in two separate await points — another task can interleave
- Are database transactions (BEGIN / COMMIT with sqlx transactions) wrapping all multi-step operations?
- Is SELECT FOR UPDATE used for critical financial operations?

Tokio Concurrency:
- Are Mutex, RwLock from tokio::sync used (not std::sync) for async contexts?
- Is there potential for deadlock (holding a sync Mutex across an await point)?
- Are tokio::select! branches exhaustively handled?

State Machine:
- Are entity state transitions enforced atomically in the database?
- Can concurrent requests bypass state validation (e.g., two simultaneous redemptions of a one-time token)?

Access Control:
- Is resource ownership verified: WHERE id = $1 AND user_id = $2?
- Are expired or revoked tokens checked on every request?

Numeric Handling:
- Are monetary values represented as i64 (cents) or rust_decimal::Decimal — never f64?
- Are arithmetic operations using checked_* to prevent wrapping overflow?

For each finding, describe the full attack scenario and provide the exact async/DB fix.
```

---

## 8. Verification & Re-scan After Patching

```
You are an expert security engineer and review below.
I have applied security patches to this Rust codebase. Perform a verification pass:

1. Re-scan every modified file — did any fix introduce new vulnerabilities?
2. Re-test every confirmed finding — is the vulnerability eliminated?
3. Run cargo audit — check for newly introduced advisories.
4. Run cargo clippy -- -W clippy::all for new warnings introduced by changes.
5. Search for the same vulnerable pattern codebase-wide:
   Example: if a format! in sqlx::query was found, grep all sqlx::query/query_as calls.
6. Re-run cargo-geiger — report on new unsafe usage introduced.
7. Verify that all unsafe blocks retain their SAFETY comments and invariant justifications.

Output per finding:
- Verification status: Confirmed Fixed / Still Vulnerable / New Issue Introduced
- If Still Vulnerable, show what remains exploitable
- Updated CVSS 3.1 score
- Recommended next action
```

---

## Quick Reference: Rust Dangerous Sinks

| Category | Dangerous Pattern | Safe Alternative |
|---|---|---|
| SQL | `sqlx::query(&format!("WHERE id={}", id))` | `sqlx::query!("WHERE id=$1", id)` |
| Command | `Command::new("sh").arg("-c").arg(input)` | `Command::new("binary").arg(input)` |
| Path | `fs::read(base + user_path)` | `canonicalize` + `starts_with` check |
| SSRF | `reqwest::get(user_url).await` | URL allowlist + block private ranges |
| unsafe | `*ptr` without bounds/null check | Use safe abstractions |
| Secret leak | `#[derive(Debug)] struct Token(String)` | Custom Debug impl omitting value |
| Overflow | `a + b` in release mode | `a.checked_add(b).ok_or(Error)?` |
| Zeroize | `let password = String::from(...)` (drop) | `#[derive(ZeroizeOnDrop)]` |

---

*Generated for Rust security audits. Adapt prompts to your specific framework (Actix-Web, Axum, Rocket, Warp, Tonic/gRPC).*

---

## 9. Advanced Validation & Triage (Mythos Workflow)

For high-confidence findings, apply the Mythos advanced validation pipeline:
1. **Cross-Model Corroboration:** Have a skeptic model review the finding.
2. **Dynamic Executable-PoC:** Generate an isolated, executable Proof-of-Concept to confirm the vulnerability.
3. **Variant Hunting:** Search the codebase for similar patterns using the confirmed finding as a signature.
4. **Chain-Severance Proof:** Verify that the proposed patch actively breaks the PoC and critical attack path.
