# mythos-proactive-scanning
This is a defensive project where mythos preview is not available and we can proactively use these prompts and fix vulnerabilities using opus models up to a certain extent.


# Security Audit Prompt Library — Master Index

> A complete collection of security audit prompt guides, one per technology stack. Each file contains copy-paste-ready prompts for feeding into an AI assistant (e.g. Claude) to systematically audit a codebase or infrastructure component.

---

## How to Use This Library

### Code Auditing Prompts
1. **Select the appropriate file** for the technology you are auditing (see table below).
2. **Copy a prompt section** and paste it into your AI assistant chat along with the relevant code or configuration.
3. **Iterate**: use the follow-up prompts within each file to drill into specific findings, validate them, and generate fixes.
4. **Chain prompts**: for complex systems, combine prompts from multiple files (e.g. ETL + Python + Unix).

### Cybersecurity Operational Playbooks
For general security operations, threat hunting, incident response, and forensic analysis:
1. **Navigate to the `skills/cybersecurity/` directory** to find the playbook topic folder matching your scenario (e.g., AD analysis, memory forensics, cloud logs).
2. **Open the `SKILL.md` file** in that folder to read its metadata, overview, prerequisites, and operational steps.
3. **Follow the step-by-step procedures** to execute the analysis or build detection rules.
4. **Use files in the `scripts/` or `references/` subdirectories** (if available in that playbook's folder) to support your investigation.

## Directory Structure & Usage Scenarios

This repository is organized into distinct directories, each serving a specific phase or type of security audit:

*   **`prompt/`**: Contains the master prompt (`scan.md`). Use this when you want to run a comprehensive, end-to-end security scan across all attack surfaces in a single session. Ideal for initial discovery, smaller codebases, or establishing a baseline.
*   **`skills/app-security/`**: Contains standalone, modular scan segments (e.g., Auth, Injection, Business Logic, Validation, Patching). Use these files when you need to perform deep, targeted audits of specific attack surfaces, or when the codebase is too large for a single scan. These can be run independently or sequenced (Discovery → Validation → Remediation) for a rigorous pipeline.

> **Note:** `prompt/scan.md` and the files in `skills/app-security/` cover the same 21 audit sections. The master prompt is a single monolithic file for running a full scan in one session, while the app-security segments are modular standalone files with additional technology-specific guidance and fine-tuning options. Use whichever format fits your workflow.
*   **`skills/technology-spefic/`**: Contains technology-specific security guides and prompts (e.g., Python, Node.js, .NET, Unix). Use these when you want to focus on framework-specific misconfigurations, known dangerous sinks, and ecosystem-specific vulnerabilities. These are best combined with `app-security` segments for deep, stack-aware scanning.
*   **`skills/cybersecurity/`**: Contains a vast library of specialized cybersecurity operational playbooks, analysis techniques, and threat hunting workflows (e.g., AD analysis, malware reverse engineering, cloud forensics). Use these for specialized security operations, incident response, and advanced red/blue team activities outside of standard application security code scanning.

Each file is self-contained and covers:
- Authentication & Authorization
- Injection Vulnerabilities (SQL, Command, XSS, SSRF, etc.)
- Secrets & Sensitive Data Exposure
- File Upload Security
- Infrastructure & Configuration
- Business Logic & Race Conditions
- Verification & Re-scan After Patching
- Quick Reference: Dangerous Sinks Table

---

## File Index

| Technology | File | Primary Frameworks Covered |
|---|---|---|
| **Java** | `java.md` | Spring Boot, Jakarta EE, Quarkus, Micronaut, Hibernate/JPA |
| **JavaScript / TypeScript** | `javascript.md` | Node.js, Express, NestJS, Next.js, Fastify, React, Vue, Angular, Deno |
| **Python** | `python.md` | Django, FastAPI, Flask, SQLAlchemy, Celery, aiohttp |
| **.NET / C#** | `dotnet.md` | ASP.NET Core, Entity Framework, Blazor, Minimal API, Azure |
| **Go** | `go.md` | Gin, Echo, Fiber, Chi, gRPC, go-kit |
| **Rust** | `rust.md` | Actix-Web, Axum, Rocket, Warp, sqlx, Diesel, Tokio |
| **Unix / Linux** | `unix.md` | Shell scripts, SSH, sudo, PAM, systemd, iptables, SELinux |
| **ETL Pipelines** | `etl.md` | Airflow, dbt, AWS Glue, Azure Data Factory, NiFi, Fivetran |
| **PHP** | `php.md` | Laravel, Symfony, WordPress, CodeIgniter, plain PHP |
| **Apache Spark** | `spark.md` | PySpark, Scala Spark, Databricks, EMR, Spark on Kubernetes |

---

## App-Security Scan Segments

The `skills/app-security/` directory contains 21 modular scan segments. Each is a self-contained prompt file with technology-specific guidance and a fine-tuning section:

| # | File | Scan Focus |
|---|---|---|
| 01 | `01-authentication-authorization.md` | Authentication flow, session management, JWT, privilege escalation |
| 02 | `02-database-rls-audit.md` | Database queries, RLS policies, row isolation, SQL injection |
| 03 | `03-input-validation-injection.md` | Input entry points, validation, sanitization |
| 04 | `04-secrets-data-exposure.md` | Hardcoded secrets, logging of PII, API over-fetching |
| 05 | `05-infrastructure-configuration.md` | Containers, CORS, security headers, TLS, rate limiting |
| 06 | `06-third-party-integrations.md` | Webhook verification, API key storage, third-party attack surface |
| 07 | `07-comprehensive-injection.md` | SQL, NoSQL, command, path traversal, XSS, SSRF, SSTI, XXE |
| 08 | `08-file-upload-security.md` | File type validation, storage, processing risks, metadata leakage |
| 09 | `09-business-logic-flaws.md` | Race conditions, state machines, numeric handling, access control |
| 10 | `10-sensitive-data-lifecycle.md` | Data flow tracing across transit, rest, memory, logs, deletion |
| 11 | `11-configuration-deployment-security.md` | Env vars, CORS, HTTP headers, TLS, Docker, CI/CD, DB config |
| 12 | `12-network-attack-surface.md` | Network service mapping, exposed ports, admin panels, debug endpoints |
| 13 | `13-vulnerability-validation.md` | Triage and validate reported findings, CVSS re-rating |
| 14 | `14-attack-chain-analysis.md` | Chain vulnerabilities, worst-case scenarios, PoC exploits |
| 15 | `15-patch-generation.md` | Production-ready fix generation with regression tests |
| 16 | `16-post-fix-verification.md` | Re-scan after patching, regression checks, posture assessment |
| 17 | `17-cross-model-corroboration.md` | False positive elimination via skeptic review |
| 18 | `18-executable-poc-verification.md` | Executable proof-of-concept script generation |
| 19 | `19-variant-hunting.md` | Codebase-wide search for same bug class / pattern |
| 20 | `20-chain-severance-proof.md` | Verify patches break attack chains, CI regression workflow |
| 21 | `21-behavioral-safety.md` | Safety audit of the scanning/patching process itself |

---

## Universal Security Audit Sections

These topic-specific prompts appear across all technology files. Use them as a checklist to ensure full coverage:

### 1. Authentication & Session Flow
- Bypass paths (missing auth middleware/decorators)
- JWT algorithm confusion attacks (alg:none)
- Session fixation and CSRF
- Password hashing algorithms

### 2. Database Security
- SQL/NoSQL injection via raw queries
- ORM unsafe patterns (raw(), fromSqlRaw(), text())
- Second-order injection
- Multi-tenant data isolation

### 3. Injection Vulnerabilities
- SQL Injection
- Command Injection (exec, shell, subprocess)
- Path Traversal
- XSS (reflected, stored, DOM)
- SSRF (server-side request forgery)
- Template Injection (SSTI)
- XML / XXE
- Deserialization attacks
- Prototype / Object Pollution

### 4. Secrets & Sensitive Data
- Hardcoded credentials
- Secrets in git history
- Logging of PII or tokens
- API response over-fetching
- Client-side secret exposure

### 5. File Upload Security
- Magic-byte validation vs MIME type
- File size limits
- Path traversal via filename
- Execution of uploaded files
- Zip slip vulnerability

### 6. Infrastructure & Configuration
- Security headers (CSP, HSTS, X-Frame-Options)
- CORS policy
- TLS version and cipher suites
- Rate limiting
- Container security (non-root, no secrets in image)
- Dependency CVE scanning

### 7. Business Logic & Race Conditions
- TOCTOU (time-of-check-to-time-of-use)
- Database-level locking for financial operations
- State machine enforcement
- Access control ownership checks
- Numeric handling (decimal vs float for money)

### 8. Verification & Re-scan
- Post-patch regression testing
- Pattern-search for same vulnerability class codebase-wide
- CVSS 3.1 re-rating
- SAST re-run

---

## Recommended Tooling by Technology

| Technology | SAST Tools | Dependency Scanning | Runtime / DAST |
|---|---|---|---|
| Java | SpotBugs + FindSecBugs, Semgrep, SonarQube | OWASP Dependency-Check, Snyk | OWASP ZAP, Burp Suite |
| JavaScript/TS | ESLint (security plugins), Semgrep, NodeJSScan | npm audit, Snyk | OWASP ZAP |
| Python | Bandit, Semgrep, Pylint | pip-audit, safety, Snyk | OWASP ZAP |
| .NET / C# | Security Code Scan, Roslyn Analyzers, Semgrep | dotnet list package --vulnerable | OWASP ZAP |
| Go | gosec, Semgrep, staticcheck | govulncheck, Nancy | OWASP ZAP |
| Rust | cargo-audit, cargo-geiger, Semgrep | cargo audit | N/A (compiled) |
| Unix / Shell | ShellCheck, Semgrep | Lynis, OpenSCAP | Nessus, OpenVAS |
| ETL | Semgrep (custom rules), manual review | pip audit, composer audit | N/A |
| PHP | PHPCS (Security Audit), PHPStan, Psalm, Semgrep | composer audit, Snyk | OWASP ZAP, Nikto |
| Spark | Semgrep (custom rules), manual review | pip audit (PySpark) | N/A |

---

## Severity Rating Reference (CVSS 3.1)

| Score | Severity | Typical Examples |
|---|---|---|
| 9.0 – 10.0 | **Critical** | RCE, unauthenticated SQLi on public endpoint, auth bypass |
| 7.0 – 8.9 | **High** | Authenticated SQLi, SSRF to internal services, privilege escalation |
| 4.0 – 6.9 | **Medium** | Stored XSS, IDOR, path traversal (read-only), insecure deserialization (limited) |
| 0.1 – 3.9 | **Low** | Reflected XSS (requires interaction), info disclosure, missing security header |

---

## Vulnerability Chaining Reference

Common vulnerability chains to look for across all stacks:

| Chain | Components | Impact |
|---|---|---|
| SSRF → Cloud Metadata → Credential Theft | SSRF + cloud IMDS | Full cloud account takeover |
| Info Disclosure + IDOR → Data Breach | User enumeration + missing ownership check | Mass PII exfiltration |
| Insecure Deserialization → RCE | Pickle/PHP unserialize/Java ObjectInputStream | Full server compromise |
| SQLi → Privilege Escalation | SQLi on login + writable user table | Admin access |
| Path Traversal → LFI → RCE | Directory traversal + include/require | Code execution |
| SSTI → RCE | Template injection in Jinja2/Twig/EJS | Full server compromise |
| Prototype Pollution → XSS/RCE | Lodash merge + dangerouslySetInnerHTML | Client or server compromise |

---

*This library is designed for use by security engineers, developers, and AI-assisted code review tools. Always test only on code but donot run on production systems*

---

## Credits

This project draws inspiration and resources from the following repositories, which were of great help:
- [cybersecurity-skills](https://github.com/web3-claw/cybersecurity-skills)
- [claude-mythos-tutorial](https://github.com/az9713/claude-mythos-tutorial)
