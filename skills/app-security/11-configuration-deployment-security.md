# 🏗️ Scan Segment 11 — Configuration & Deployment Security

> **Standalone prompt segment.** Paste the block below directly into Claude Opus to begin this scan.

---

## Prompt

```
You are an expert security engineer and review below.
Review all configuration files, environment variable usage, and deployment
configuration for security issues.
```

---

## Environment Variables
- Are all secrets in **environment variables** (not hardcoded)?
- Are there any **`.env` files committed to git**? Check git history too.
- Are there **default/fallback values** for secrets that would work in production?
- Do any environment variables contain **connection strings with passwords**?

## CORS Configuration
- Is `Access-Control-Allow-Origin` set to `"*"`? *(dangerous for authenticated APIs)*
- Are credentials allowed with a **wildcard origin**?
- Is the origin **validated against a whitelist**?

## HTTP Security Headers

| Header | Check |
|---|---|
| `Content-Security-Policy` | Present and restrictive? |
| `X-Frame-Options` | Or `frame-ancestors` set? |
| `X-Content-Type-Options` | Set to `nosniff`? |
| `Strict-Transport-Security` | HSTS with appropriate `max-age`? |
| `Referrer-Policy` | Set? |
| `Permissions-Policy` | Set? |

## TLS / SSL
- Is **TLS 1.2+** enforced?
- Are **weak cipher suites** disabled?
- Is **certificate pinning** implemented *(mobile apps)*?

## Docker / Container Security
- Is the container **running as root**?
- Are there **unnecessary capabilities** granted?
- Is the **base image up to date**?
- Are **secrets baked into the image**?

## CI/CD Security
- Are **secrets exposed in build logs**?
- Can a PR **modify CI configuration** to exfiltrate secrets?
- Are deployment credentials scoped to **minimum permissions**?
- Are **GitHub Actions / CI runners** using pinned action versions?

## Database Configuration
- Is the **database accessible from the internet**?
- Are **default credentials** changed?
- Is **SSL required** for database connections?
- Are **connection pool limits** set to prevent DoS?

---

## 🛠 Technology-Specific Guidance

### Python (Django / FastAPI)

```python
# Django — production settings checklist
DEBUG = False                        # MUST be False
ALLOWED_HOSTS = ["yourdomain.com"]  # NEVER ["*"]
SECRET_KEY = os.environ["SECRET_KEY"]  # from env, no fallback
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

# Database — SSL required
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "OPTIONS": {"sslmode": "require"},
    }
}
```

```python
# FastAPI — CORS
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],  # explicit list, not ["*"]
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
```

### Node.js / Express

```javascript
// Helmet.js — sets all security headers
const helmet = require('helmet');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));

// CORS — explicit origins
const cors = require('cors');
app.use(cors({
  origin: ["https://app.example.com"],
  credentials: true,
}));
```

### Java (Spring Boot)

```yaml
# application.properties / application.yml
server:
  ssl:
    enabled: true
    protocol: TLSv1.3
  port: 443

spring:
  datasource:
    url: jdbc:postgresql://host/db?sslmode=require
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://auth.example.com

management:
  endpoints:
    web:
      exposure:
        include: health  # only expose health, nothing else
  endpoint:
    health:
      show-details: never
```

### .NET (ASP.NET Core)

```csharp
// Program.cs — production security pipeline
app.UseHsts();
app.UseHttpsRedirection();
app.UseSecurityHeaders();  // NWebSec or custom middleware

// CORS — specific origins only
builder.Services.AddCors(options => {
    options.AddPolicy("Prod", policy =>
        policy.WithOrigins("https://app.example.com")
              .AllowCredentials()
              .WithMethods("GET","POST")
              .WithHeaders("Authorization","Content-Type"));
});

// Connection string — from env, not appsettings.json
var conn = builder.Configuration["ConnectionStrings__Default"]
           ?? throw new InvalidOperationException("Missing connection string");
```

### Go

```go
// HTTP security headers middleware
func securityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("Content-Security-Policy", "default-src 'self'")
        next.ServeHTTP(w, r)
    })
}

// Env — never hardcode, always os.Getenv with required check
secret := os.Getenv("JWT_SECRET")
if secret == "" {
    log.Fatal("JWT_SECRET not set")
}
```

### Git History — Scan for Committed Secrets

```bash
# Check git history for secrets
git log --all -p | grep -iE "(password|secret|api_key|token)\s*[=:]\s*['\"][^'\"]{6,}"

# Check for .env files ever committed
git log --all --full-history -- "**/.env" "**/.env.*"

# List all files currently tracked that shouldn't be
git ls-files | grep -E "\.(env|key|pem|p12|pfx|secret)$"
```

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - All environment variable names used for secrets (without values)
# - Deployment platform and how env vars are injected
# - CORS origins that should be whitelisted
# - Whether CSP is already in place and its current policy
# - Database connection details (SSL enforced? Connection pooler like PgBouncer?)
# - CI/CD system and secret management approach
# - Whether certificate pinning is needed (mobile clients?)
```
