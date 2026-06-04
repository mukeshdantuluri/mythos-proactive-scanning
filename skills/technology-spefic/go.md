# Go Security Audit Guide

> Comprehensive security scanning prompts for Go codebases: net/http, Gin, Echo, Fiber, Chi, gRPC, and cloud-native Go services.

---

## 1. Authentication & Session Flow

```
You are an expert security engineer and review below.
Review the entire authentication flow in this Go codebase. Trace every path from login to session creation to authorization checks. Identify:

- Any HTTP handler missing authentication middleware
  (Check all router groups — are any routes registered outside the authenticated middleware chain?)
- JWT vulnerabilities:
  - Is the algorithm explicitly verified in jwt.ParseWithClaims? (reject "none" alg)
  - Is the signing key loaded from environment — not hardcoded?
  - Are token expiry claims (exp) validated?
  - Is the dgrijalva/jwt-go package in use? (Deprecated — migrate to golang-jwt/jwt v5)
- Session management: are session IDs regenerated after login?
- CSRF: are state-changing endpoints (POST/PUT/DELETE) protected with gorilla/csrf or equivalent?
- Are API keys or bearer tokens compared with subtle.ConstantTimeCompare (not ==)?
- Are gRPC endpoints protected with interceptors (UnaryInterceptor, StreamInterceptor)?

For each finding, provide the exact file, line number, and a proof-of-concept HTTP request demonstrating the bypass.
```

---

## 2. Database Security (database/sql, GORM, sqlx, pgx)

```
You are an expert security engineer and review below.
Audit every database interaction in this Go codebase.

database/sql:
- Any db.Query() or db.Exec() calls with string concatenation or fmt.Sprintf?
  Dangerous: db.Query("SELECT * FROM users WHERE id=" + id)
  Dangerous: db.Query(fmt.Sprintf("SELECT * FROM users WHERE name='%s'", name))
  Safe: db.Query("SELECT * FROM users WHERE id=$1", id)
- Are all placeholder styles correct? ($1 for PostgreSQL, ? for MySQL/SQLite)

GORM:
- Any db.Raw() or db.Exec() with string-formatted queries?
- GORM Where with map input — is the map sanitized?
  Dangerous: db.Where(req.Body) — can inject GORM query operators
- Are GORM associations loading more data than authorized (preload without filters)?

sqlx:
- Any sqlx.Select() / sqlx.Get() with raw SQL strings assembled from user input?

pgx:
- Any pgx.Conn.Exec() or pgxpool.Pool.Query() with concatenated strings?

Second-order Injection:
- Is user-supplied data stored and later used in a raw query?

Multi-tenancy:
- Are all queries scoped with WHERE tenant_id = $1?
- Can a user change their tenantID claim in a JWT and access other tenants' data?

For each finding, show the full request-to-sink path, a PoC payload, and the parameterized fix.
```

---

## 3. Injection Vulnerabilities

```
You are an expert security engineer and review below.
Find every injection vulnerability in this Go codebase.

Command Injection:
- Any exec.Command() where arguments are assembled via strings.Join or fmt.Sprintf from user input?
  Dangerous: exec.Command("sh", "-c", "convert "+userFilename)
  Safe: exec.Command("convert", userFilename) — argument array, no shell
- Are os.StartProcess, syscall.Exec called with user input?

Path Traversal:
- Any os.Open(), ioutil.ReadFile(), filepath.Join() with user-controlled path segments?
- Is filepath.Clean() combined with strings.HasPrefix(cleanPath, allowedBase) check?
- Can HTTP file servers (http.FileServer, http.ServeFile) serve files outside the intended directory?

SSRF:
- Any http.Get(userURL), http.NewRequest with user-controlled URLs?
- Is the URL validated against an allowlist?
- Can an attacker reach 169.254.169.254 (cloud metadata) or internal services?
- Are URL schemes restricted (block file://, ftp://, gopher://)?

Template Injection:
- Is html/template used (safe) or text/template used to render user content (dangerous — no auto-escaping)?
- Is template.HTML(userInput) used to bypass html/template escaping?
- Is any template parsed from user-supplied strings: template.New("").Parse(userInput)?

XSS:
- Are all HTML responses using html/template (auto-escaped)?
- Is template.HTML(), template.JS(), template.URL() used with user-controlled values?
- Are CSP headers set on all HTML responses?

XML / XXE:
- Any encoding/xml.Unmarshal on user-supplied XML?
- Is an external entity resolver configured that could enable XXE?
- (Note: Go's encoding/xml does not process external entities by default, but verify third-party XML libs)

Open Redirect:
- Any http.Redirect(w, r, userURL, ...) without URL validation?

Header Injection:
- Is user input set directly in response headers via w.Header().Set(key, userInput)?
- Can CRLF characters in the value inject new headers?

For each finding, show input-to-sink trace, PoC payload, CVSS 3.1 rating, and exact fix.
```

---

## 4. Secrets & Sensitive Data Exposure

```
You are an expert security engineer and review below.
Scan this Go codebase for secrets and sensitive data exposure.

Hardcoded Secrets:
- Any string literals matching: password, secret, apiKey, token, privateKey, connectionString in .go files
- Credentials in config.yaml, config.json, or .env files committed to git
- Are all secrets loaded from environment variables or a secret manager (AWS Secrets Manager, HashiCorp Vault)?

Logging:
- Any log.Printf / zap.Info / logrus.Info calls logging passwords, tokens, PII, or connection strings?
- Does the HTTP middleware log request bodies (which may contain credentials)?
- Do error messages returned in API responses include internal details (stack traces, SQL errors)?

API Response Over-fetching:
- Are struct types with sensitive fields (PasswordHash, InternalFlags) returned directly from handlers?
- Are json:"-" tags missing on sensitive struct fields?
- Are there Go structs with omitempty but still-included sensitive fields when set?

Error Handling:
- Do handlers return raw error strings to clients? (err.Error() in JSON response)
- Does a panic in a goroutine go unrecovered and log sensitive context?

Goroutine Leaks:
- Could a slow or malicious client cause goroutine accumulation (missing context cancellation)?
- Are context timeouts set for all outbound HTTP and DB calls?

For each finding, specify file, line, the sensitive data, where it leaks, and remediation.
```

---

## 5. File Upload Security

```
You are an expert security engineer and review below.
Audit all file upload handling in this Go codebase (multipart.Reader, r.FormFile).

Validation:
- Is file type validated by reading magic bytes (using github.com/gabriel-vasile/mimetype or net/http.DetectContentType)?
- Is there a file size limit: r.ParseMultipartForm(maxSize) or http.MaxBytesReader(w, r.Body, maxSize)?
- Are filenames sanitized with filepath.Base() to strip directory traversal?
- Are filenames checked for null bytes?

Storage:
- Are files stored in a directory served by http.FileServer (directly accessible)?
- Is there per-user authorization before serving uploaded files?

Processing:
- If using imaging, resize, or image decoding — is there a decode size limit?
- If processing ZIP files, is zip slip protection in place?
  Validate: header.Name must not start with / or contain ../
- If processing archives, is there a decompression bomb limit?

For each finding, provide the vulnerable endpoint, code path, PoC payload, and fix.
```

---

## 6. Infrastructure & Configuration

```
You are an expert security engineer and review below.
Review all configuration and infrastructure in this Go project.

HTTP Security Headers:
- Are X-Content-Type-Options, X-Frame-Options, HSTS, and Content-Security-Policy headers set?
- Is a security headers middleware (gorilla/handlers, unrolled/secure) used?

CORS:
- Is cors.New() configured with AllowedOrigins: []string{"*"}? (Dangerous for authenticated APIs)
- Are AllowedOrigins explicitly listed?

TLS:
- Is the HTTP server configured with TLS (tls.Config)?
- Is the minimum TLS version set: MinVersion: tls.VersionTLS12?
- Are weak cipher suites excluded?
- Is HTTP/S redirect in place?

Rate Limiting:
- Is golang.org/x/time/rate or tollbooth applied to public endpoints?
- Is the rate limiter per-IP and not per-goroutine (or it defeats the purpose)?

gRPC Security:
- Are gRPC services using TLS (grpc.WithTransportCredentials)?
- Are interceptors enforcing authentication on all RPCs?
- Is gRPC reflection enabled in production (allows enumeration of all services)?

Dependency Security:
- Run govulncheck ./... — list all known CVEs in go.sum dependencies
- Are modules pinned in go.sum?
- Are there known vulnerable modules (old versions of jwt-go, etc.)?

Docker:
- Is the Dockerfile using a non-root user (USER nonroot:nonroot)?
- Is the binary built with CGO_ENABLED=0 for a fully static binary in a scratch/distroless image?

For each issue, specify the file, setting, risk, and corrected code snippet.
```

---

## 7. Business Logic & Race Conditions

```
You are an expert security engineer and review below.
Analyze business logic in this Go codebase for logic flaws.

Race Conditions:
- Are shared in-memory structures (maps, slices, counters) accessed from multiple goroutines without sync.Mutex, sync.RWMutex, or atomic operations?
- Is go test -race clean? (Run the race detector)
- Are database operations atomic? Is there a check-then-act pattern without SELECT FOR UPDATE?
  Example: read balance, check sufficient, deduct — two concurrent goroutines can both pass the check

Channel Safety:
- Are there goroutines that could deadlock (send on nil or closed channel)?
- Are contexts propagated correctly to cancel work on client disconnect?

State Machine:
- Are entity state transitions enforced atomically in the database?
- Can a concurrent API call bypass state validation?

Access Control:
- Is resource ownership verified: WHERE id=$1 AND user_id=$2?
- Are deleted users denied access (soft delete filter in all queries)?

Numeric Handling:
- Is integer overflow possible in quantity or price calculations?
- Are monetary values stored as int64 (cents) or decimal — never float64?

For each finding, describe the full attack scenario, including a goroutine-level PoC, and provide the exact sync/DB fix.
```

---

## 8. Verification & Re-scan After Patching

```
You are an expert security engineer and review below.
I have applied security patches to this Go codebase. Perform a verification pass:

1. Re-scan every modified file — did any fix introduce new vulnerabilities?
2. Re-test every confirmed finding — is the vulnerability eliminated?
3. Run govulncheck ./... — check for newly introduced CVEs.
4. Run go test -race ./... — confirm no data races.
5. Search for the same vulnerable pattern codebase-wide:
   Example: if fmt.Sprintf in db.Query was found, grep all db.Query/Exec/QueryRow calls.
6. Re-run gosec (github.com/securego/gosec) and Semgrep (Go ruleset) across the full codebase.

Output per finding:
- Verification status: Confirmed Fixed / Still Vulnerable / New Issue Introduced
- If Still Vulnerable, show what remains exploitable
- Updated CVSS 3.1 score
- Recommended next action
```

---

## Quick Reference: Go Dangerous Sinks

| Category | Dangerous Pattern | Safe Alternative |
|---|---|---|
| SQL | `db.Query("WHERE id=" + id)` | `db.Query("WHERE id=$1", id)` |
| Command | `exec.Command("sh", "-c", "cmd "+input)` | `exec.Command("cmd", input)` |
| Path | `os.Open(base + userPath)` | `filepath.Clean` + `HasPrefix` check |
| SSRF | `http.Get(userURL)` | URL allowlist + block private ranges |
| Template | `text/template` with user data | `html/template` (auto-escaping) |
| Race | `counter++` in goroutine | `atomic.AddInt64(&counter, 1)` |
| Open Redirect | `http.Redirect(w, r, userURL, ...)` | Validate URL against allowlist |
| Header Injection | `w.Header().Set("X", userInput)` | Strip CRLF from header values |

---

*Generated for Go security audits. Adapt prompts to your specific framework (Gin, Echo, Fiber, Chi, gRPC, go-kit).*

---

## 9. Advanced Validation & Triage (Mythos Workflow)

For high-confidence findings, apply the Mythos advanced validation pipeline:
1. **Cross-Model Corroboration:** Have a skeptic model review the finding.
2. **Dynamic Executable-PoC:** Generate an isolated, executable Proof-of-Concept to confirm the vulnerability.
3. **Variant Hunting:** Search the codebase for similar patterns using the confirmed finding as a signature.
4. **Chain-Severance Proof:** Verify that the proposed patch actively breaks the PoC and critical attack path.
