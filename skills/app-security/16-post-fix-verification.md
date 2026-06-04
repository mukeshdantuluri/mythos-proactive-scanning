# 🔁 Scan Segment 16 — Post-Fix Verification

> **Standalone prompt segment.** Run after applying all security patches.

---

## Prompt

```
You are an expert security engineer and review below.
I have applied security patches based on our audit findings.
Please perform a verification pass.
```

---

## What to Verify

- **Re-scan every modified file** — did the fix introduce any new vulnerabilities?
- **Re-test every fixed finding** — is the vulnerability actually eliminated, or just made harder to exploit?
- **Check for regression** — did any fix break an adjacent security control?
  > *Example: fixing an XSS by encoding output might break a CSP that relied on the previous output format*
- **Look for patterns** — if we had one SQL injection, are there similar patterns elsewhere we missed?
  > *The same developer who wrote the vulnerable code likely wrote similar code in other files.*
- **Assess overall posture change** — given the vulnerabilities found and fixed, what's the current risk level? What's the single highest **remaining risk**?

---

## Deliverables

| Output | Description |
|---|---|
| **Verification Status** | `Confirmed Fixed` / `Still Vulnerable` / `New Issue` — per finding |
| **New Findings** | Any new vulnerabilities discovered during re-scan |
| **Updated Risk Assessment** | Revised overall security posture |
| **Next Actions** | Recommended follow-up steps |

---

## 🛠 Technology-Specific Verification Commands

### Static Analysis — Run After Every Patch

**Python**
```bash
# Bandit — Python security linter
pip install bandit
bandit -r . -ll -ii --exclude ./tests,./venv

# Semgrep — SAST with OWASP rules
semgrep --config=p/python --config=p/owasp-top-ten .

# Safety — dependency vulnerability check
pip install safety
safety check --full-report
```

**Node.js / JavaScript / TypeScript**
```bash
# npm audit
npm audit --audit-level=moderate

# Semgrep
semgrep --config=p/javascript --config=p/typescript --config=p/owasp-top-ten .

# ESLint security plugin
npm install --save-dev eslint-plugin-security
# Add to .eslintrc: "plugins": ["security"], "extends": ["plugin:security/recommended"]
eslint . --ext .js,.ts
```

**Java**
```bash
# SpotBugs with Find Security Bugs plugin
mvn com.github.spotbugs:spotbugs-maven-plugin:check

# OWASP Dependency Check
mvn org.owasp:dependency-check-maven:check

# Semgrep Java rules
semgrep --config=p/java --config=p/owasp-top-ten .
```

**.NET**
```bash
# dotnet list package --vulnerable
dotnet list package --vulnerable --include-transitive

# SecurityCodeScan (Roslyn analyzer — runs during build)
dotnet add package SecurityCodeScan.VS2019

# OWASP Dependency Check
dependency-check --project "MyApp" --scan . --format HTML

# Semgrep .NET rules
semgrep --config=p/csharp .
```

**Go**
```bash
# govulncheck — official Go vulnerability scanner
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# gosec — Go security checker
go install github.com/securego/gosec/v2/cmd/gosec@latest
gosec ./...

# Semgrep Go rules
semgrep --config=p/golang .
```

**PHP**
```bash
# PHP Security Checker
composer require --dev enlightn/security-checker
./vendor/bin/security-checker security:check composer.lock

# Psalm with Taint Analysis
composer require --dev vimeo/psalm
./vendor/bin/psalm --taint-analysis

# Semgrep PHP rules
semgrep --config=p/php .
```

**Rust**
```bash
# cargo audit — dependency vulnerability check
cargo install cargo-audit
cargo audit

# cargo deny — license and advisory check
cargo install cargo-deny
cargo deny check advisories

# Semgrep Rust rules
semgrep --config=p/rust .
```

### Pattern Search — Find Similar Vulnerabilities

```bash
# If SQLi was found using string concatenation, search for all similar patterns:

# Python
grep -rn "execute.*f\"" --include="*.py" .
grep -rn "execute.*format" --include="*.py" .
grep -rn "execute.*%" --include="*.py" .

# JavaScript / TypeScript
grep -rn "\.query\`\|\.raw\`\|\.execute\`" --include="*.ts" --include="*.js" .

# Java
grep -rn "createQuery.*+\|executeQuery.*+" --include="*.java" .

# If XSS was found via dangerouslySetInnerHTML:
grep -rn "dangerouslySetInnerHTML\|v-html\|\[innerHTML\]" --include="*.tsx" --include="*.vue" --include="*.html" .

# If hardcoded secrets were found:
grep -rn "password\s*=\s*[\"'][^\"']\|api_key\s*=\s*[\"']" --include="*.py" --include="*.js" --include="*.ts" .
```

### Regression Test Execution

```bash
# Run the full security-related test suite
# Python
pytest tests/security/ -v --tb=short

# Node.js
npm test -- --testPathPattern=security

# Java
mvn test -pl security-tests

# .NET
dotnet test --filter Category=Security

# Go
go test ./... -run TestSecurity

# Rust
cargo test security
```

### Dependency Vulnerability Rescan

```bash
# After updating packages, rescan:
npm audit --production          # Node.js
pip-audit                       # Python  (pip install pip-audit)
mvn dependency:resolve          # Java — then run OWASP check
dotnet list package --vulnerable # .NET
cargo audit                     # Rust
composer audit                  # PHP
govulncheck ./...               # Go
```

### Final Security Posture Checklist

```markdown
After all patches applied, confirm:

[ ] All SAST tools run with zero High/Critical findings
[ ] All dependency scanners show no Critical CVEs
[ ] All regression tests pass
[ ] Security headers verified: https://securityheaders.com
[ ] TLS grade verified: https://www.ssllabs.com/ssltest/
[ ] No sensitive data in git history (gitleaks or trufflehog scan)
[ ] Penetration test re-run on patched endpoints
[ ] Changelog / release notes updated with security fixes
[ ] Team notified of changes and any deployment steps
```

```bash
# gitleaks — scan git history for secrets
docker run -v "$(pwd):/path" zricethezav/gitleaks:latest detect --source /path -v

# trufflehog — deep git history secret scan
trufflehog git file://. --since-commit HEAD~50
```

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - List of all patches applied (from Segment 15 output)
# - SAST tools already integrated in your CI pipeline
# - Test framework and how to run security-specific tests
# - Whether a formal re-penetration test is planned
# - Any compliance requirements that need sign-off (SOC 2, PCI DSS, HIPAA)
# - Deployment steps after patch (blue/green, rolling, maintenance window needed?)
# - Who needs to be notified of security fixes (security team, CTO, customers?)
```
