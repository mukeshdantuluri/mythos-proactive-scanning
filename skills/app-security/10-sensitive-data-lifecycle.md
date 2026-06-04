# 🔒 Scan Segment 10 — Sensitive Data Lifecycle

> **Standalone prompt segment.** Paste the block below directly into Claude Opus to begin this scan.

---

## Prompt

```
You are an expert security engineer and review below.
Trace every piece of sensitive data in this application and verify it's protected
at every stage: input, processing, storage, retrieval, display, and deletion.
```

---

## Data Categories to Trace

- Passwords and password hashes
- API keys and secrets
- Session tokens and JWTs
- **PII**: names, emails, SSN, addresses
- **Financial data**: account numbers, transaction details, tax information
- Health data *(if applicable)*
- Client/customer data

---

## Protection Checkpoints Per Category

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

---

## 🛠 Technology-Specific Guidance

### Password Hashing

```python
# Python — use bcrypt or argon2, never sha256/md5
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
hashed = pwd_context.hash(plain_password)
# Verify: pwd_context.verify(plain_password, hashed)
```

```javascript
// Node.js — bcrypt with cost factor >= 12
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);
```

```java
// Spring Security — BCryptPasswordEncoder
PasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hash = encoder.encode(rawPassword);
```

```csharp
// .NET — ASP.NET Core Identity uses PBKDF2 by default
// Ensure PasswordHasherOptions.IterationCount >= 100_000
services.Configure<PasswordHasherOptions>(o => o.IterationCount = 210_000);
```

### Cookie Security

```python
# FastAPI / Starlette
response.set_cookie(
    key="session",
    value=token,
    httponly=True,    # no JS access
    secure=True,      # HTTPS only
    samesite="strict",
    max_age=3600,
    path="/",
)
```

```javascript
// Express
res.cookie("session", token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  maxAge: 3600000,
});
```

### Field-Level Encryption at Rest

```python
# SQLAlchemy — encrypt PII columns with SQLAlchemy-Utils
from sqlalchemy_utils import StringEncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine

class User(Base):
    ssn = Column(StringEncryptedType(String, SECRET_KEY, AesEngine, "pkcs5"))
```

```java
// Spring — @Convert with AttributeConverter for field encryption
@Convert(converter = EncryptedStringConverter.class)
private String ssn;
```

### Scrubbing Sensitive Fields from Logs

```python
# structlog — filter sensitive keys
import structlog

def drop_sensitive(logger, method, event_dict):
    for key in ("password", "token", "ssn", "credit_card"):
        event_dict.pop(key, None)
    return event_dict

structlog.configure(processors=[drop_sensitive, structlog.dev.ConsoleRenderer()])
```

```javascript
// Winston — filter sensitive keys
const winston = require('winston');
const { combine, printf } = winston.format;

const redact = printf(({ level, message, ...meta }) => {
  ['password','token','ssn'].forEach(k => delete meta[k]);
  return JSON.stringify({ level, message, ...meta });
});
```

### API Response — Return Only What's Needed

```python
# FastAPI — explicit response_model strips extra fields
from pydantic import BaseModel

class UserPublic(BaseModel):
    id: str
    email: str
    # password_hash, role, internal_flags NOT included

@app.get("/users/me", response_model=UserPublic)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user  # extra fields auto-stripped
```

```java
// Spring — use @JsonIgnore on sensitive fields or dedicated DTOs
public class UserDTO {
    private String id;
    private String email;
    // no passwordHash, no internalFlags
}
```

### Token Storage — Client Side

```
# NEVER store JWTs in localStorage (XSS risk)
# PREFER: HttpOnly, Secure, SameSite=Strict cookie

# If localStorage is used, ensure:
# 1. CSP blocks all inline scripts and unknown script-src
# 2. No XSS vulnerabilities exist anywhere in the app
```

### Data Deletion — Right to Erasure

```sql
-- Verify all storage locations are covered:
DELETE FROM users WHERE id = $1;
DELETE FROM audit_logs WHERE user_id = $1;  -- or anonymize?
DELETE FROM sessions WHERE user_id = $1;
-- Also: purge from Redis cache, S3 user data, backup snapshots (check retention policy)
```

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - Password hashing library currently in use
# - Whether PII or health data is stored (triggers GDPR/HIPAA requirements)
# - Database encryption at rest (RDS encryption, TDE, field-level?)
# - Backup solution and whether backups are encrypted
# - Cookie configuration (names, flags, domain scope)
# - Logging platform and what fields are currently captured
# - Any data retention or deletion requirements (GDPR right-to-erasure, CCPA)
# - Whether tokens are stored in cookies or localStorage
```
