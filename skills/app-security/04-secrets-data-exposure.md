# 🔑 Scan Segment 04 — Secrets & Data Exposure

> **Standalone prompt segment.** Paste the block below directly into Claude Opus to begin this scan. Run independently or as part of the full 16-step audit pipeline.

---

## Prompt

```
You are an expert security engineer and review below.
Scan this entire codebase for hardcoded secrets, exposed sensitive data,
and debug artifacts left in production code.

Find:
- Hardcoded secrets, API keys, passwords, or tokens
- Secrets that could leak through error messages or stack traces
- Sensitive data exposed in client-side JavaScript bundles
- Logging that captures sensitive user data
- API responses that return more data than the client needs
- Debug endpoints or development code left in production
```

---

## What to Find

- **Hardcoded secrets**, API keys, passwords, or tokens
- Secrets that could **leak through error messages or stack traces**
- Sensitive data **exposed in client-side JavaScript bundles**
- **Logging** that captures sensitive user data
- **API responses** that return more data than the client needs
- **Debug endpoints or development code** left in production

---

## 🛠 Technology-Specific Guidance

### Python (FastAPI / Django / Flask)
- Django: is `DEBUG = True` in any production `settings.py`? Is `ALLOWED_HOSTS = ["*"]`?
- FastAPI: is the `/docs` (Swagger) or `/redoc` endpoint disabled in production?
- Logging: does `logging.basicConfig(level=logging.DEBUG)` capture request bodies with passwords?
- Are `.env` files committed to git? Run: `git log --all --full-history -- "**/.env"`
- Django: does `DATABASES['default']` connection string contain a hardcoded password?

### JavaScript / Node.js (Express / Next.js)
- Next.js: are `NEXT_PUBLIC_` env vars leaking secrets to the browser bundle?
- Are `console.log(req.body)` or `console.log(user)` statements in middleware capturing passwords/tokens?
- Are `.env.local` or `.env.production` files gitignored?
- Are any secrets in `package.json` scripts or hardcoded in `config.js`?
- Express: is the `/health` or `/debug` route returning internal connection details?

### Java (Spring / Quarkus)
- Spring Boot Actuator: is `/actuator/env` or `/actuator/heapdump` exposed without authentication?
- Is `spring.jpa.show-sql=true` in production `application.properties` (logs all queries)?
- Are `application.properties` secrets committed — check git history for `password=`, `secret=`, `key=`
- Are exception stack traces returned in HTTP 500 responses to clients?

### .NET (ASP.NET Core)
- Is `app.UseDeveloperExceptionPage()` active outside Development environment?
- Is `appsettings.json` or `appsettings.Development.json` committed with secrets?
- Are EF entity types returned directly from controllers (exposing `PasswordHash`, `SecurityStamp`)?
- Is `ILogger.LogDebug()` capturing `HttpContext.Request.Form` (may contain credentials)?
- Are Swagger/OpenAPI docs (`app.UseSwagger()`) enabled in production?

### Go (Gin / Echo)
- Is `gin.SetMode(gin.DebugMode)` hardcoded rather than read from environment?
- Are `log.Printf("user: %+v", user)` calls logging full structs with sensitive fields?
- Are error responses returning internal error strings directly to clients?

### PHP (Laravel / Symfony)
- Laravel: is `APP_DEBUG=true` in `.env.production`?
- Is `APP_KEY` committed to git?
- Are `dd()` or `dump()` debug calls left in production code?
- Symfony: is `kernel.debug=true` in production?

### Rust
- Are `dbg!()` or `println!()` macros logging sensitive data in release builds?
- Are `.env` files committed?
- Are error responses using `{:?}` debug formatting that exposes internal state?

### Universal Checks
```bash
# Search for common secret patterns in git history:
git log -p | grep -E "(password|secret|api_key|token|private_key)\s*=\s*['\"][^'\"]{8,}"

# Search for .env files in git:
git ls-files | grep -E "\.env"

# Search for TODO/FIXME/HACK comments that may indicate security gaps:
grep -r "TODO\|FIXME\|HACK\|TEMP\|DEBUG" --include="*.py" --include="*.js" --include="*.ts" .
```

---

## 🎯 Fine-Tune This Segment

Add context below to sharpen the scan for your specific stack:

```
# Paste here:
# - Secret management system in use (AWS Secrets Manager, Vault, Azure Key Vault, Doppler, etc.)
# - Cloud provider (AWS, GCP, Azure) — IMDS endpoints differ
# - Logging platform (Datadog, Splunk, CloudWatch, Loki) and what log levels are enabled
# - Whether OpenAPI/Swagger docs are exposed and to whom
# - Frontend framework and bundler (Webpack, Vite, Next.js) — what ends up in the client bundle
# - Any analytics or error-tracking SDK (Sentry, Rollbar) that might capture sensitive data
```
