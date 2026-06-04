# 🧪 Scan Segment 03 — Input Validation & Injection Vectors

> **Standalone prompt segment.** Paste the block below directly into Claude Opus to begin this scan. Run independently or as part of the full 16-step audit pipeline.

---

## Prompt

```
You are an expert security engineer and review below.
Find every point in this codebase where user input enters the system — form fields,
URL parameters, headers, file uploads, webhook payloads, API request bodies.

For each input point:
- Is input validated and sanitized?
- Could it be used for SQL injection, XSS, SSRF, or command injection?
- Are file uploads restricted by type, size, and content?
- Are webhook signatures verified?
- Could malformed input cause a crash or denial of service?
```

---

## What to Check Per Input Point

- Is input **validated and sanitized**?
- Could it be used for **SQL injection, XSS, SSRF, or command injection**?
- Are **file uploads** restricted by type, size, and content?
- Are **webhook signatures** verified?
- Could malformed input cause a **crash or denial of service**?

---

## 🛠 Technology-Specific Guidance

### Python (FastAPI / Django / Flask)
- FastAPI: are Pydantic models used for all request bodies? Are `Field(...)` validators (min_length, max_length, regex) applied?
- Django: are Forms or DRF Serializers validating all input? Any `request.GET.get()` passed directly to queries?
- Flask: check `request.args`, `request.form`, `request.json` — is any value used without validation?
- Webhook: is `hmac.compare_digest()` used for signature verification (not `==`)?

### JavaScript / Node.js (Express / Next.js / NestJS)
- Express: is `express-validator` or `joi`/`zod` applied before any handler logic?
- NestJS: are `@Body()` DTOs annotated with `class-validator` decorators (`@IsString()`, `@MaxLength()`)?
- Next.js API routes: is `req.body` validated before use? Is `req.query` sanitized?
- Webhooks: Stripe — `stripe.webhooks.constructEvent()` with raw body; GitHub — `x-hub-signature-256` HMAC verification

### Java (Spring / Quarkus)
- Spring: are `@Valid` / `@Validated` annotations applied on all `@RequestBody` parameters?
- Are Bean Validation constraints (`@NotNull`, `@Size`, `@Pattern`) on all DTO fields?
- Are `@RequestParam` values sanitized before use in queries or shell calls?
- Quarkus: are `@Valid` and Hibernate Validator constraints applied?

### .NET (ASP.NET Core)
- Are Model Validation attributes (`[Required]`, `[MaxLength]`, `[RegularExpression]`) applied on all DTOs?
- Is `ModelState.IsValid` checked before processing in MVC controllers?
- Minimal APIs: are request bodies bound to typed records with validation?
- Are `[FromQuery]` parameters validated and not passed raw to queries?

### Go (Gin / Echo / Chi)
- Is `binding:"required,max=255"` used with Gin's `ShouldBindJSON`?
- Is the `go-playground/validator` package applied to all input structs?
- Are query parameters parsed and validated before use?

### PHP (Laravel / Symfony)
- Laravel: are `$request->validate([...])` rules applied on every controller method?
- Are custom `FormRequest` classes used for complex validation?
- Symfony: are `Constraints` applied to all form and DTO fields?
- Are `filter_var()` and `htmlspecialchars()` used on all raw input?

### Rust (Actix / Axum)
- Are `serde` deserialization types strict (no `#[serde(flatten)]` with unknown keys)?
- Is the `validator` crate applied to all input structs?
- Are all `String` inputs length-bounded before processing?

---

## 🎯 Fine-Tune This Segment

Add context below to sharpen the scan for your specific stack:

```
# Paste here:
# - Validation library in use (Zod, Joi, Pydantic, class-validator, Bean Validation, etc.)
# - Webhook providers integrated (Stripe, GitHub, Twilio, Shopify, etc.)
# - Whether GraphQL is used (different injection surface than REST)
# - Any custom input sanitization middleware
# - Rate limiting library and configuration
# - Whether WebSockets are used and how messages are validated
```
