# 🔐 Proactive Security Scanning Prompts

> A curated set of adversarial security review prompts designed for deep, automated vulnerability scanning using Claude Opus. Each section targets a distinct attack surface and follows a structured methodology for finding, validating, and remediating vulnerabilities.

---

## Table of Contents

1. [Authentication & Authorization](#1-authentication--authorization)
2. [Database & RLS Audit](#2-database--rls-audit)
3. [Input Validation & Injection Vectors](#3-input-validation--injection-vectors)
4. [Secrets & Data Exposure](#4-secrets--data-exposure)
5. [Infrastructure & Configuration](#5-infrastructure--configuration)
6. [Third-Party Integrations](#6-third-party-integrations)
7. [Comprehensive Injection Analysis](#7-comprehensive-injection-analysis)
8. [File Upload Security](#8-file-upload-security)
9. [Business Logic Flaws](#9-business-logic-flaws)
10. [Sensitive Data Lifecycle](#10-sensitive-data-lifecycle)
11. [Configuration & Deployment Security](#11-configuration--deployment-security)
12. [Network Attack Surface Mapping](#12-network-attack-surface-mapping)
13. [Vulnerability Validation](#13-vulnerability-validation)
14. [Attack Chain Analysis](#14-attack-chain-analysis)
15. [Patch Generation](#15-patch-generation)
16. [Post-Fix Verification](#16-post-fix-verification)
17. [Cross-Model Corroboration](#17-cross-model-corroboration)
18. [Dynamic Executable-PoC Verification](#18-dynamic-executable-poc-verification)
19. [Variant Hunting & Known-Issue Dedup](#19-variant-hunting--known-issue-dedup)
20. [Chain-Severance Proof & CI Workflow](#20-chain-severance-proof--ci-workflow)
21. [Behavioral Safety & Self-Monitoring](#21-behavioral-safety--self-monitoring)

---

## 1. Authentication & Authorization

> **Prompt — Paste into Claude Opus to begin this scan.**

```
You are an expert security engineer and review below.
Review the entire authentication flow in this codebase. Trace every path from login
to session creation to authorization checks.
```

### What to Identify

- Any way to **bypass authentication entirely**
- **Race conditions** in session or token handling
- **Missing authorization checks** on any API route
- **Token expiration or refresh** vulnerabilities
- Any path where a user could **escalate privileges**

### Deliverables

For each finding, provide:
- Exact **file** and **line number**
- A **proof-of-concept description** of how the vulnerability could be exploited

---

## 2. Database & RLS Audit

> **Prompt — Paste into Claude Opus to begin this scan.**

```
You are an expert security engineer and review below.
Audit every database interaction in this codebase. For each table and RLS policy,
determine what data is accessible and to whom.
```

### What to Check

| Check | Description |
|---|---|
| User Row Isolation | Can an authenticated user access rows belonging to other users? |
| Anonymous Access | Can an anonymous user access data they shouldn't? |
| SQL Injection | Are there injection vectors, even through ORMs? |
| Security Definer | Are there any `SECURITY DEFINER` functions that bypass RLS? |
| Missing Policies | Are there tables with no RLS policies applied? |
| Edge Function Auth | Can any edge function be called without proper authentication? |

### Deliverables

For each finding, describe the **exact API call or query** that would demonstrate the vulnerability.

---

## 3. Input Validation & Injection Vectors

> **Prompt — Paste into Claude Opus to begin this scan.**

```
You are an expert security engineer and review below.
Find every point in this codebase where user input enters the system — form fields,
URL parameters, headers, file uploads, webhook payloads, API request bodies.
```

### What to Check Per Input Point

- Is input **validated and sanitized**?
- Could it be used for **SQL injection, XSS, SSRF, or command injection**?
- Are **file uploads** restricted by type, size, and content?
- Are **webhook signatures** verified?
- Could malformed input cause a **crash or denial of service**?

---

## 4. Secrets & Data Exposure

> **Prompt — Paste into Claude Opus to begin this scan.**

```
You are an expert security engineer and review below.
Scan this entire codebase for hardcoded secrets, exposed sensitive data,
and debug artifacts left in production code.
```

### What to Find

- **Hardcoded secrets**, API keys, passwords, or tokens
- Secrets that could **leak through error messages or stack traces**
- Sensitive data **exposed in client-side JavaScript bundles**
- **Logging** that captures sensitive user data
- **API responses** that return more data than the client needs
- **Debug endpoints or development code** left in production

---

## 5. Infrastructure & Configuration

> **Prompt — Paste into Claude Opus to begin this scan.**

```
You are an expert security engineer and review below.
Review all infrastructure configuration files (Dockerfile, docker-compose, vercel.json,
cloudflare configs, nginx configs, environment variable handling).
```

### What to Verify

| Config Area | Questions |
|---|---|
| Containers | Are containers running as root? Are unnecessary ports exposed? |
| CORS | Are CORS policies overly permissive? |
| Security Headers | Are CSP, HSTS, and X-Frame-Options configured correctly? |
| Rate Limits | Are rate limits configured on all public endpoints? |
| TLS | Is TLS configured correctly? |

---

## 6. Third-Party Integrations

> **Prompt — Paste into Claude Opus to begin this scan.**

```
You are an expert security engineer and review below.
Review every third-party integration (payment processors, email services,
authentication providers, API connections).
```

### What to Assess Per Integration

- Are **webhook signatures verified** before processing?
- Are **API keys stored securely** with minimal permissions?
- Is **data encrypted in transit** to/from the third party?
- Could a **compromised third-party account** be used to access your system?
- Are there **fallback or retry mechanisms** that could be exploited?

---

## 7. Comprehensive Injection Analysis

> **Prompt — Paste into Claude Opus to begin this scan.**

```
You are an expert security engineer and review below.
Perform a comprehensive injection vulnerability analysis of this codebase.
Trace every path where external input reaches a dangerous sink.
```

**External input includes:** HTTP request parameters, headers, body, cookies, URL path segments, file uploads, webhook payloads, WebSocket messages, and any data read from the database that originated from user input.

### Injection Types to Check

#### SQL Injection
- Any raw SQL with **string concatenation or template literals**?
- Any ORM calls that accept **raw SQL fragments**?
- **Second-order SQL injection** (stored data used in later queries)?
- Are **parameterized queries** used *everywhere*?

#### NoSQL Injection *(if MongoDB, etc.)*
- Can query operators (`$gt`, `$ne`, `$regex`) be **injected via user input**?
- Are object inputs **validated for unexpected keys**?

#### Command Injection
- Any calls to `exec()`, `spawn()`, `system()`, or shell commands?
- Are arguments passed as **arrays (safe)** or **strings (dangerous)**?
- Can **environment variables** be influenced by user input?

#### Path Traversal
- Any file operations (read, write, delete) using **user-controlled paths**?
- Is `../../../etc/passwd` possible?
- Are **symlinks followed**?

#### XSS (Cross-Site Scripting)
- Is user input **rendered in HTML without escaping**?
- Are there `dangerouslySetInnerHTML` / `v-html` / `[innerHTML]` usages?
- Is user input **reflected in JavaScript contexts**?
- Are **CSP headers** properly configured?

#### SSRF (Server-Side Request Forgery)
- Does the server make HTTP requests to **user-provided URLs**?
- Can an attacker reach **internal services** (`169.254.169.254`, `localhost`)?
- Are **URL protocols restricted** (no `file://`, no `gopher://`)?

#### Template Injection
- Are user inputs passed to **template engines**?
- Can server-side template injection achieve **RCE**?

#### Header Injection
- Can user input end up in **HTTP response headers**?
- **CRLF injection** possible?

#### LDAP / XML / XPath Injection *(if applicable)*

### Deliverables Per Finding

1. Exact **code path** from input to dangerous sink
2. A **proof-of-concept payload**
3. **Severity rating**
4. The **specific fix**

---

## 8. File Upload Security

> **Prompt — Paste into Claude Opus to begin this scan.**

```
You are an expert security engineer and review below.
Audit all file upload and file processing functionality.
```

### Upload Validation

- Is file type validated **server-side** (not just client-side)?
- Is validation based on **content inspection** (magic bytes), not just extension?
- Can a `.php`, `.jsp`, `.aspx`, or `.py` file be uploaded and **executed**?
- Is there a **file size limit** enforced server-side?
- Can the **filename be manipulated** (path traversal via filename)?
- Are **null bytes** in filenames handled?

### Storage Security

- Are uploaded files stored **outside the web root**?
- Are files served with `Content-Disposition: attachment`?
- Are files served with the **correct Content-Type** (not guessed)?
- Is there **access control** on who can retrieve uploaded files?
- Can uploaded file URLs be **enumerated**?

### Processing Risks

| Processor | Risk |
|---|---|
| Images (ImageMagick, Sharp, Pillow) | Image parsing vulnerabilities, DoS via huge files |
| Documents (PDF, DOCX) | SSRF or XXE during parsing |
| Archives (ZIP) | Zip bomb or zip slip attacks |

### Metadata Leakage

- Are **EXIF tags stripped** from uploaded images?
- Do uploaded files retain **metadata that could leak user information**?

---

## 9. Business Logic Flaws

> **Prompt — Paste into Claude Opus to begin this scan.**

```
You are an expert security engineer and review below.
Analyze the business logic of this application for logic flaws that automated
scanners would miss. These are bugs that survive years of review because
they aren't simple injection — they're logical errors.
```

### Race Conditions
- Can two concurrent requests cause **double-spending, double-booking, or duplicate resource creation**?
- Are financial operations **atomic**? (check-then-act patterns are vulnerable)
- Is there a **TOCTOU** (time-of-check-to-time-of-use) gap anywhere?

### State Machine Violations
- Can application state transitions be **forced out of order**?
- Can a cancelled order be shipped? Can a refund be **issued twice**?
- Can a user **re-enter a completed workflow**?

### Numeric Handling
- **Integer overflow/underflow** in financial calculations?
- **Floating-point precision** issues in money handling?
- **Negative quantity / negative price** exploitation?
- **Division by zero**?
- **Currency conversion rounding** exploitation?

### Access Control Logic
- Can a user escalate privileges by **modifying their own profile**?
- Can a free-tier user access paid features by **manipulating requests**?
- Can an invited user gain **more access than intended**?
- Can a **deleted/disabled account** still access resources?

### Data Consistency
- Can **partial failures** leave data in an inconsistent state?
- Are **database transactions** used where needed?
- Can **referential integrity** be violated through the API?

### Rate Limiting & Abuse
- Can an attacker **exhaust resources** (email sending, SMS, API calls)?
- Is there rate limiting on **expensive operations**?
- Can **trial/free tier abuse** circumvent payment?

### Information Leakage Through Behavior
- Do error messages **reveal internal state**?
- Can **response timing** reveal whether a resource exists?
- Do different error codes reveal **different internal conditions**?
- Can **enumeration attacks** extract the user list?

### Deliverables

For each logic bug: explain the **full attack scenario from the attacker's perspective** and provide a specific fix.

---

## 10. Sensitive Data Lifecycle

> **Prompt — Paste into Claude Opus to begin this scan.**

```
You are an expert security engineer and review below.
Trace every piece of sensitive data in this application and verify it's protected
at every stage: input, processing, storage, retrieval, display, and deletion.
```

### Data Categories to Trace

- Passwords and password hashes
- API keys and secrets
- Session tokens and JWTs
- **PII**: names, emails, SSN, addresses
- **Financial data**: account numbers, transaction details, tax information
- Health data *(if applicable)*
- Client/customer data

### Protection Checkpoints Per Category

| Stage | What to Verify |
|---|---|
| **In Transit** | Is TLS enforced? Are there any plain HTTP endpoints? |
| **At Rest** | Is sensitive data encrypted in the database? With what algorithm? |
| **In Memory** | Are secrets cleared from memory after use? |
| **In Logs** | Does logging inadvertently capture sensitive data? |
| **In Errors** | Do error messages or stack traces expose sensitive data? |
| **In Backups** | Are backups encrypted? |
| **In URLs** | Is sensitive data ever passed in URL query parameters? |
| **In Client Storage** | Is sensitive data in `localStorage`, `sessionStorage`, or unsecured cookies? |
| **On Deletion** | Is data actually removed from all locations (DB, backups, caches, logs)? |
| **In API Responses** | Are responses over-fetching data beyond what the client needs? |

### Deliverables

Produce a **data flow diagram** for each sensitive data category showing where it enters, where it's stored, and where it exits the system. Flag any point where protection is insufficient.

---

## 11. Configuration & Deployment Security

> **Prompt — Paste into Claude Opus to begin this scan.**

```
You are an expert security engineer and review below.
Review all configuration files, environment variable usage, and deployment
configuration for security issues.
```

### Environment Variables
- Are all secrets in **environment variables** (not hardcoded)?
- Are there any **`.env` files committed to git**? Check git history too.
- Are there **default/fallback values** for secrets that would work in production?
- Do any environment variables contain **connection strings with passwords**?

### CORS Configuration
- Is `Access-Control-Allow-Origin` set to `"*"`? *(dangerous for authenticated APIs)*
- Are credentials allowed with a **wildcard origin**?
- Is the origin **validated against a whitelist**?

### HTTP Security Headers

| Header | Check |
|---|---|
| `Content-Security-Policy` | Present and restrictive? |
| `X-Frame-Options` | Or `frame-ancestors` set? |
| `X-Content-Type-Options` | Set to `nosniff`? |
| `Strict-Transport-Security` | HSTS with appropriate `max-age`? |
| `Referrer-Policy` | Set? |
| `Permissions-Policy` | Set? |

### TLS / SSL
- Is **TLS 1.2+** enforced?
- Are **weak cipher suites** disabled?
- Is **certificate pinning** implemented *(mobile apps)*?

### Docker / Container Security
- Is the container **running as root**?
- Are there **unnecessary capabilities** granted?
- Is the **base image up to date**?
- Are **secrets baked into the image**?

### CI/CD Security
- Are **secrets exposed in build logs**?
- Can a PR **modify CI configuration** to exfiltrate secrets?
- Are deployment credentials scoped to **minimum permissions**?
- Are **GitHub Actions / CI runners** using pinned action versions?

### Database Configuration
- Is the **database accessible from the internet**?
- Are **default credentials** changed?
- Is **SSL required** for database connections?
- Are **connection pool limits** set to prevent DoS?

### Deliverables

For each issue, **rate severity** and provide the specific configuration change needed.

---

## 12. Network Attack Surface Mapping

> **Prompt — Paste into Claude Opus to begin this scan.**

```
You are an expert security engineer and review below.
Based on the deployment configuration and code you've reviewed,
map the complete network attack surface.
```

### For Every Network-Accessible Service

- What **port** does it listen on?
- Is it intended to be **public**?
- What **authentication** is required?
- What's the most damaging action an **unauthenticated attacker** could take?
- What's the most damaging action an **authenticated low-privilege user** could take?

### Specific Checks

- Database ports exposed to the internet (`5432`, `3306`, `6379`, `27017`)
- Admin panels **without VPN/IP restriction**
- Debug endpoints left in production (`/debug`, `/metrics`, `/health` with sensitive data)
- **GraphQL introspection** enabled in production
- **Swagger/OpenAPI docs** exposed in production
- **WebSocket endpoints** without authentication
- **gRPC reflection** enabled in production
- Internal microservice endpoints **reachable from the internet**

### Deliverables

Produce a **network map** showing every listening service, its authentication requirement, and your risk assessment.

---

## 13. Vulnerability Validation

> **Prompt — Use after receiving a security report. Replace placeholder before running.**

```
You are an expert security engineer and review below.
I have received the following security vulnerability report.
Please perform rigorous validation:

[PASTE THE FINDING HERE]
```

### What to Determine

**1. Is this vulnerability real and reproducible?**
- Write the **exact steps to reproduce**, including specific HTTP requests, payloads, or code paths
- If you cannot produce concrete reproduction steps, it may be a **false positive**

**2. Is the severity rating accurate?**
- Consider: Can it be exploited remotely? Does it require authentication? Does it require user interaction? What data is at risk?
- Re-rate using **CVSS 3.1 methodology** if the original rating seems off

**3. Is this actually exploitable in this specific deployment context?**
- A SQL injection behind an admin-only endpoint with MFA is very different from one on a public signup form
- Consider what **compensating controls** exist (WAF, rate limiting, network segmentation)

**4. What is the realistic impact?**
- Best case for the attacker: what's the **maximum damage**?
- Most likely exploitation: what would a **typical attacker achieve**?
- Is **data exfiltration** possible? How much data?

### Deliverables

Rate your **confidence** in this finding:
- `HIGH` — Definitely real
- `MEDIUM` — Likely real but needs manual verification
- `LOW` — Possibly false positive

If confidence is `LOW`, explain what **additional testing** would confirm or deny it.

---

## 14. Attack Chain Analysis

> **Prompt — Use with confirmed findings. Replace placeholder before running.**

```
You are an expert security engineer and review below.
The following Critical/High vulnerabilities have been confirmed in our codebase.

[PASTE ALL CONFIRMED CRITICAL AND HIGH FINDINGS]

Now analyze these findings as an attacker would.
```

### What to Analyze

**Can any of these be chained together?**
> A Medium-severity information disclosure + a Medium-severity IDOR might chain into a Critical data breach. Look for chains.

**What is the worst-case attack scenario?**
> Starting from zero access, what's the most damaging path through these vulnerabilities? Map it step by step.

**What would a sophisticated attacker do first?**
> Not just "exploit the Critical bug" — consider which vulnerability gives the best foothold, what reconnaissance steps come first, and how an attacker would maintain persistence.

**Develop proof-of-concept exploits for each Critical finding.**
> These MUST work in an isolated test environment.
> ⚠️ Do **NOT** test against production.
> The PoC should demonstrate the actual impact, not just crash the service.

### Deliverables Per Exploit

Document exactly what defensive measures would **detect or prevent** it:

| Defense Layer | Would It Stop This? |
|---|---|
| WAF | Would our WAF catch this? |
| Logging | Would our logging capture this? |
| Rate Limiting | Would rate limiting prevent this? |
| Network Segmentation | Would network segmentation contain this? |

---

## 15. Patch Generation

> **Prompt — Use with a confirmed, exploited finding. Replace placeholder before running.**

```
You are an expert security engineer and review below.
Generate a production-ready fix for the following vulnerability:

[PASTE THE CONFIRMED FINDING WITH EXPLOIT]
```

### Fix Requirements

- The fix must be **minimal** — change only what's necessary to eliminate the vulnerability. Do not refactor surrounding code.
- The fix must **not break existing functionality**. If it could, flag what tests should be run.
- The fix must follow the **existing code style and patterns** in this codebase.
- Include a **regression test** that proves:
  - `a.` The vulnerability **existed** *(test would have failed before the fix)*
  - `b.` The vulnerability is now **eliminated** *(test passes after the fix)*
- If the fix requires a **database migration**, provide it.
- If the fix requires **configuration changes**, specify them exactly.

### Deliverables

1. The exact **code changes** *(as a diff)*
2. The **regression test**
3. Any **deployment notes or migration steps**
4. Confirmation that the fix addresses the **root cause**, not just the symptom

---

## 16. Post-Fix Verification

> **Prompt — Run after applying all security patches.**

```
You are an expert security engineer and review below.
I have applied security patches based on our audit findings.
Please perform a verification pass.
```

### What to Verify

- **Re-scan every modified file** — did the fix introduce any new vulnerabilities?
- **Re-test every fixed finding** — is the vulnerability actually eliminated, or just made harder to exploit?
- **Check for regression** — did any fix break an adjacent security control?
  > *Example: fixing an XSS by encoding output might break a CSP that relied on the previous output format*
- **Look for patterns** — if we had one SQL injection, are there similar patterns elsewhere we missed?
  > *The same developer who wrote the vulnerable code likely wrote similar code in other files.*
- **Assess overall posture change** — given the vulnerabilities found and fixed, and the architecture of this application, what's the current risk level? What's the single highest **remaining risk**?

### Deliverables

| Output | Description |
|---|---|
| **Verification Status** | `Confirmed Fixed` / `Still Vulnerable` / `New Issue` — per finding |
| **New Findings** | Any new vulnerabilities discovered during re-scan |
| **Updated Risk Assessment** | Revised overall security posture |
| **Next Actions** | Recommended follow-up steps |

---

## 17. Cross-Model Corroboration

> **Prompt — Use to eliminate false positives by introducing cross-model consensus.**

```
You are an expert security engineer and review below.
I have identified the following potential vulnerabilities. I need you to act as a skeptic.
Please review these findings independently. Do not assume they are correct. 
Provide a critical analysis of why each finding might be a false positive or unexploitable.
Only promote findings where the evidence is undeniable.

[PASTE THE FINDINGS HERE]
```

### Deliverables
- A definitive `CONFIRMED` or `REJECTED` for each finding.
- A technical justification for the rejection.

---

## 18. Dynamic Executable-PoC Verification

> **Prompt — Use to mandate that every vulnerability has a working proof-of-concept.**

```
You are an expert security engineer and review below.
For the confirmed vulnerabilities, generate an executable Python PoC script.
The PoC MUST:
1. Target the vulnerable sink directly.
2. Execute cleanly as a subprocess.
3. Exit with status 0 and output `SINK REACHED` only if successful.
4. Not cause permanent damage or data loss to the target system.
```

### Deliverables
- A self-contained, executable PoC script.
- Instructions on how to run it against the local test environment.

---

## 19. Variant Hunting & Known-Issue Dedup

> **Prompt — Use to scale findings across the codebase.**

```
You are an expert security engineer and review below.
We have confirmed the following bug class/vulnerability exists in the codebase:
[PASTE CONFIRMED VULNERABILITY/BUG SIGNATURE]

Act as a Variant Hunter. Search the entire codebase for other instances of this 
exact same bug class, vulnerable pattern, or similar logical flaws. 
Do not report on the original finding.
```

### Deliverables
- A list of all new variants found.
- An assessment of whether the new variants require a different PoC.

---

## 20. Chain-Severance Proof & CI Workflow

> **Prompt — Use to ensure patches fully break the attack chain.**

```
You are an expert security engineer and review below.
Here is the proposed patch for the following exploit chain:
[PASTE PATCH]
[PASTE COMPOSITE POC]

Verify that this minimal patch severs the longest critical path of the attack graph.
Then, emit a GitHub Actions (or relevant CI) workflow file that will continuously 
scan for this specific regression in future commits.
```

### Deliverables
- Confirmation of chain-severance.
- A CI workflow configuration file (YAML).

---

## 21. Behavioral Safety & Self-Monitoring

> **Prompt — Use to ensure the scanning and patching process remains safe and scoped.**

```
You are an expert security engineer and review below.
Review the proposed engagement plan, patches, and executed actions.
Flag any of the following behavioral pathologies:
1. Deleting or disabling failing tests to make CI pass.
2. Covering up logs or overwriting audit entries.
3. Quietly widening a CI gate or permissions boundary.
4. Scope creep outside the designated target surface.
```

### Deliverables
- A safety audit report on the agent's actions and proposed changes.

---

> **⚠️ Usage Note:** These prompts are designed for use with Claude Opus in an isolated, non-production environment. Always ensure scans are performed against test environments only. Never run active exploitation payloads against production systems.
