# 🔐 Scan Segment 01 — Authentication & Authorization

> **Standalone prompt segment.** Paste the block below directly into Claude Opus to begin this scan. Run independently or as part of the full 16-step audit pipeline.

---

## Prompt

```
You are an expert security engineer and review below.
Review the entire authentication flow in this codebase. Trace every path from login
to session creation to authorization checks.

Identify:
- Any way to bypass authentication entirely
- Race conditions in session or token handling
- Missing authorization checks on any API route
- Token expiration or refresh vulnerabilities
- Any path where a user could escalate privileges

For each finding, provide:
- Exact file and line number
- A proof-of-concept description of how the vulnerability could be exploited
```

---

## What to Identify

- Any way to **bypass authentication entirely**
- **Race conditions** in session or token handling
- **Missing authorization checks** on any API route
- **Token expiration or refresh** vulnerabilities
- Any path where a user could **escalate privileges**

---

## Deliverables

For each finding, provide:
- Exact **file** and **line number**
- A **proof-of-concept description** of how the vulnerability could be exploited

---

## 🛠 Technology-Specific Guidance

### Python (FastAPI / Django / Flask)
- FastAPI: check every route for `Depends(get_current_user)` — any route missing it is unauthenticated
- Django: verify `@login_required` and `permission_classes` on all views; check `AUTH_PASSWORD_VALIDATORS` in `settings.py`
- Flask: check `@jwt_required()` from flask-jwt-extended on every protected route
- JWT: look for `algorithms=["HS256"]` hardcoded vs algorithm confusion (`none` alg)

### JavaScript / Node.js (Express / Next.js)
- Express: verify `passport.authenticate()` or middleware order — middleware applied globally vs per-route
- Next.js: check `getServerSideProps` and API routes for missing `getSession()` calls
- JWT: check `jsonwebtoken.verify()` — is `algorithms` option explicitly set? Is `ignoreExpiration` ever `true`?

### Java (Spring / Quarkus)
- Spring Security: check `SecurityFilterChain` — are all paths covered or is there a catch-all `permitAll()`?
- Verify `@PreAuthorize` annotations and method security is enabled (`@EnableMethodSecurity`)
- Are `ROLE_` prefix checks consistent across the codebase?

### .NET (ASP.NET Core)
- Check every controller/endpoint for `[Authorize]` or `RequireAuthorization()`
- JWT: `ValidateIssuerSigningKey = true`, `ValidateLifetime = true`, `ValidAlgorithms` explicitly set
- Razor Pages: `[ValidateAntiForgeryToken]` or `[AutoValidateAntiforgeryToken]`

### Go (Gin / Echo / Chi)
- Verify middleware is applied to all route groups — not just declared globally but actually attached
- JWT: `jwt.Parse()` with explicit `jwt.WithValidMethods([]string{"HS256"})`

### PHP (Laravel / Symfony)
- Laravel: check `auth:api` or `auth:sanctum` middleware on all route groups in `api.php`
- Symfony: verify `access_control` rules in `security.yaml` cover all paths
- Are sessions regenerated on privilege change (`session_regenerate_id(true)`)?

### Rust (Actix / Axum)
- Check `Extractor` types — are `AuthenticatedUser` or similar types required on every handler?
- Are JWT libraries (jsonwebtoken crate) verifying `exp` and `alg` claims?

---

## 🎯 Fine-Tune This Segment

Add context below to sharpen the scan for your specific stack:

```
# Paste here:
# - Your auth library or framework (e.g., Auth0, Cognito, Clerk, Supabase Auth, Keycloak)
# - Token type used (JWT, opaque, session cookie)
# - Whether OAuth2 / OIDC is in use and which flows
# - Any custom session store (Redis, DB-backed, in-memory)
# - MFA implementation details if applicable
# - Role/permission model (RBAC, ABAC, flat roles, claim-based)
```
