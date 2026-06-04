# .NET / C# Security Audit Guide

> Comprehensive security scanning prompts for .NET codebases: ASP.NET Core, .NET 6/7/8, Entity Framework Core, Blazor, minimal APIs, and Azure-hosted services.

---

## 1. Authentication & Session Flow

```
You are an expert security engineer and review below.
Review the entire authentication flow in this .NET codebase. Trace every path from login to session creation to authorization checks. Identify:

- Any controller action or minimal API endpoint missing [Authorize] attribute or RequireAuthorization() call
- Is the Authentication middleware registered before Authorization in Program.cs / Startup.cs?
- JWT vulnerabilities:
  - Is ValidateIssuerSigningKey = true set in JwtBearerOptions?
  - Is ValidAlgorithms explicitly set? Can "alg: none" be exploited?
  - Is token expiration validated (ValidateLifetime = true)?
- Are anti-forgery tokens validated on all state-changing Razor Pages and MVC actions?
  (Missing [ValidateAntiForgeryToken] or [AutoValidateAntiforgeryToken])
- ASP.NET Identity: are password complexity policies enforced? Is lockout configured?
- Are role claims from JWT verified server-side — or trusted from a client-modifiable header?
- Policy-based authorization: are resource-based policies (IAuthorizationHandler) applied where attribute-based auth is insufficient?

For each finding, provide the exact file, line number, and a proof-of-concept HTTP request demonstrating the bypass.
```

---

## 2. Database Security (Entity Framework, Dapper, ADO.NET)

```
You are an expert security engineer and review below.
Audit every database interaction in this .NET codebase.

Entity Framework Core:
- Any use of FromSqlRaw() or ExecuteSqlRaw() with string interpolation?
  Dangerous: context.Users.FromSqlRaw("SELECT * FROM Users WHERE Id=" + id)
  Safe: context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Id={id}")
       (FromSqlInterpolated uses FormattableString, which is parameterized)
- Any EF raw SQL via ExecuteSqlRawAsync() with user-controlled strings?
- Are LINQ queries safe? (EF translates most LINQ safely, but string.Contains() with user input is safe; dynamic OrderBy with column name from user is NOT)

Dapper:
- Any Query<T>("SELECT ... WHERE x='" + val + "'") calls?
- Are all Dapper queries using named parameters: Query<T>("SELECT ... WHERE x=@val", new { val })?

ADO.NET:
- Any SqlCommand with CommandText assembled via string concatenation?
- Are SqlParameter objects used for all inputs?

Second-order Injection:
- Is data read from DB and later concatenated into a new query without sanitization?

Multi-tenancy / Row-Level Access:
- Are all EF queries filtered with .Where(x => x.TenantId == currentTenantId)?
- Is the Global Query Filter (HasQueryFilter) applied for tenant isolation in DbContext?

For each finding, show the full request-to-sink path, a PoC payload, and the parameterized fix.
```

---

## 3. Injection Vulnerabilities

```
You are an expert security engineer and review below.
Find every injection vulnerability in this .NET codebase.

SQL Injection: (see Database section above)

Command Injection:
- Any Process.Start() with user-controlled arguments passed as a single string?
  Dangerous: Process.Start("cmd.exe", "/c " + userInput)
  Safe: Pass arguments as separate ProcessStartInfo.ArgumentList items
- Any use of PowerShell.Create().AddScript(userInput)?

Path Traversal:
- Any File.ReadAllText(), File.Open(), Path.Combine() with user-controlled segments?
- Is Path.GetFullPath() combined with StartsWith(allowedBasePath) check?
- Are null bytes handled? (Path.Combine may be vulnerable in some scenarios)

XSS:
- Razor views: is @Html.Raw(userInput) used instead of @userInput (auto-escaped)?
- Blazor: is MarkupString used with user-controlled content?
- Are Content-Security-Policy headers configured correctly?

SSRF:
- Any HttpClient.GetAsync(userUrl), WebClient, or HttpWebRequest with user-controlled URLs?
- Is the target URL validated against an allowlist?
- Are Azure IMDS endpoints (169.254.169.254) blockable from the application network?

XML / XXE:
- Any XmlDocument, XmlReader, XDocument loading user-supplied XML?
- Is XmlReaderSettings.DtdProcessing set to DtdProcessing.Prohibit?
- Is XmlResolver set to null?

Deserialization:
- Any BinaryFormatter, NetDataContractSerializer, ObjectStateFormatter, JavaScriptSerializer with untrusted data?
  (BinaryFormatter is banned in .NET 7+ by default — is it still enabled?)
- Any Newtonsoft.Json with TypeNameHandling set to All or Auto?
- Any custom ISerializable types that accept untrusted data?

LDAP Injection:
- Any DirectorySearcher with filter assembled from user input?
- Are special LDAP characters (*, (, ), \, NUL) escaped?

Open Redirect:
- Any LocalRedirect() vs Redirect() — is the URL validated?
- Can HttpContext.Request.Query["returnUrl"] contain external URLs?

For each finding, show input-to-sink trace, PoC payload, CVSS 3.1 rating, and exact fix.
```

---

## 4. Secrets & Sensitive Data Exposure

```
You are an expert security engineer and review below.
Scan this .NET codebase for secrets and sensitive data exposure.

Hardcoded Secrets:
- Any connection strings, API keys, or passwords in appsettings.json, web.config, or launchSettings.json committed to git
- Are appsettings.Development.json files excluded from production deployments?
- Are Azure Key Vault, AWS Secrets Manager, or environment variables used for all secrets?
- Are there IConfiguration.GetValue<string>("SomeSecret") calls with fallback hardcoded defaults?

Logging:
- Any ILogger.LogInformation / LogDebug calls capturing passwords, tokens, PII, or connection strings?
- Does the global exception middleware log HttpContext.Request.Form (may contain credentials)?
- Does Serilog / NLog destructure and log sensitive model properties?

API Response Over-fetching:
- Are EF entity types returned directly from controllers without DTOs?
  (This exposes navigation properties, internal flags, password hashes)
- Are [JsonIgnore] attributes missing on sensitive model properties?
- Does any endpoint return a User object with PasswordHash, SecurityStamp, or ConcurrencyStamp?

ASP.NET Developer Exception Page:
- Is app.UseDeveloperExceptionPage() active in non-Development environments?
- Does the production error handler expose stack traces or inner exception details?

Secrets in Client-Side (Blazor WASM):
- Are any secrets or internal API URLs embedded in Blazor WebAssembly bundles?
- Is appsettings.json copied to wwwroot (accessible to all clients)?

For each finding, specify file, line, the sensitive data, where it leaks, and remediation.
```

---

## 5. File Upload Security

```
You are an expert security engineer and review below.
Audit all file upload handling in this .NET codebase (IFormFile, FileStream, BlobClient).

Validation:
- Is file type validated using magic bytes (reading first N bytes) — not just IFormFile.ContentType (user-controlled) or file extension?
- Is there a file size limit enforced: [RequestSizeLimit(X)] or RequestBodySizeLimit middleware?
- Are filenames sanitized with Path.GetFileName() to strip directory traversal?
- Are null bytes in filenames handled?

Storage:
- Are files stored in wwwroot (directly web-accessible)?
- If stored in Azure Blob Storage, is the container private (not public access)?
- Is a SAS token with minimal permissions and short expiry used for file access?
- Is there per-user authorization before serving files via a controller action?

Processing:
- If using System.Drawing (GDI+), ImageSharp, or SkiaSharp for image processing, is there a size limit before decoding?
- If processing DOCX (Open XML SDK) or PDF (PdfSharp, iTextSharp), is SSRF from embedded links possible?
- If extracting ZIP (ZipArchive), is zip slip protection in place?
  Validate: entry.FullName must not contain .. or start with /

For each finding, provide the vulnerable endpoint, code path, PoC payload or filename, and fix.
```

---

## 6. Infrastructure & Configuration

```
You are an expert security engineer and review below.
Review all configuration and infrastructure in this .NET project.

HTTP Security Headers:
- Is UseHsts() called in production (Program.cs)?
- Is UseHttpsRedirection() enforced?
- Are security headers set via middleware or NWebSec (X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy)?
- Is Content-Security-Policy configured and restrictive?

CORS:
- Is app.UseCors() configured with AllowAnyOrigin()? (Dangerous for credentialed APIs)
- Are specific origins allowlisted: WithOrigins("https://trusted.example.com")?
- Is AllowAnyOrigin() combined with AllowCredentials() — this is illegal in spec and some runtimes permit it unsafely?

Rate Limiting:
- Is ASP.NET Core Rate Limiting middleware (AddRateLimiter) configured on public endpoints?
- Are login, registration, password reset endpoints rate-limited?

Dependency Security:
- Run dotnet list package --vulnerable — list all packages with known CVEs
- Are NuGet packages pinned to specific versions?
- Are System.Text.Json, Newtonsoft.Json, and authentication libraries up to date?

Docker / Azure Container:
- Is the Dockerfile using a non-root user (USER app)?
- Are connection strings or API keys in Dockerfile ENV instructions (baked into image)?
- Is the base image (mcr.microsoft.com/dotnet/aspnet) pinned to a specific digest?

Azure-Specific:
- Is Managed Identity used for all Azure resource access (no connection strings with keys)?
- Are App Service authentication settings (EasyAuth) configured correctly?
- Is App Service running with HTTPS only enforced?

For each issue, specify the file, setting, risk, and corrected code snippet.
```

---

## 7. Business Logic & Race Conditions

```
You are an expert security engineer and review below.
Analyze business logic in this .NET codebase for logic flaws.

Race Conditions:
- Are there check-then-act patterns without database-level locking?
  EF Core: Use pessimistic locking via raw SQL SELECT FOR UPDATE, or optimistic concurrency (ConcurrencyToken / RowVersion)
  Are EF transactions (BeginTransactionAsync) wrapping all related operations?
- Are Interlocked.Increment/Decrement used for shared counters rather than non-atomic ++ operations?
- Are background tasks (IHostedService, Hangfire jobs) idempotent for retry scenarios?

State Machine:
- Are entity state transitions validated via domain methods (not just raw property assignment)?
- Can a REST call drive an entity to an invalid state by bypassing the domain layer?

Access Control:
- Is resource ownership verified: context.Orders.FirstOrDefaultAsync(x => x.Id == id && x.UserId == userId)?
- Can users escalate privileges by modifying their own claims via a PATCH /users/me endpoint?
- Are soft-deleted records excluded from all queries (global query filter)?

Numeric Handling:
- Is decimal used for all monetary calculations — not double or float?
- Are negative quantities or prices blocked at the validation layer ([Range(0, int.MaxValue)])?
- Are checked arithmetic contexts used for critical integer operations?

For each finding, describe the full attack scenario and provide the exact EF / locking fix.
```

---

## 8. Verification & Re-scan After Patching

```
You are an expert security engineer and review below.
I have applied security patches to this .NET codebase. Perform a verification pass:

1. Re-scan every modified file — did any fix introduce new vulnerabilities?
2. Re-test every confirmed finding — is the vulnerability eliminated?
3. Run dotnet list package --vulnerable — check for newly introduced CVEs.
4. Search for the same vulnerable pattern codebase-wide:
   Example: if FromSqlRaw with concatenation was found in one repository, search all repositories.
5. Verify middleware pipeline order in Program.cs holistically.
6. Re-run Roslyn Analyzers (SecurityCodeScan, PumaScan), Semgrep (.NET rules), and OWASP Dependency-Check.

Output per finding:
- Verification status: Confirmed Fixed / Still Vulnerable / New Issue Introduced
- If Still Vulnerable, show what remains exploitable
- Updated CVSS 3.1 score
- Recommended next action
```

---

## Quick Reference: .NET Dangerous Sinks

| Category | Dangerous Pattern | Safe Alternative |
|---|---|---|
| SQL (EF) | `FromSqlRaw("WHERE id=" + id)` | `FromSqlInterpolated($"WHERE id={id}")` |
| SQL (Dapper) | `Query("SELECT ... WHERE x='" + val + "'")` | `Query("... WHERE x=@val", new { val })` |
| XSS | `@Html.Raw(userInput)` | `@userInput` (auto-escaped) |
| XXE | `XmlDocument.Load(userStream)` (default) | Set `DtdProcessing.Prohibit` |
| Deser | `BinaryFormatter.Deserialize(stream)` | Use System.Text.Json with strict typing |
| Command | `Process.Start("cmd", "/c " + input)` | `ProcessStartInfo.ArgumentList` |
| Path | `File.ReadAllText(baseDir + userPath)` | `Path.GetFullPath` + `StartsWith` check |
| SSRF | `new HttpClient().GetAsync(userUrl)` | URL allowlist + block private ranges |
| Open Redirect | `Redirect(returnUrl)` | `LocalRedirect(returnUrl)` |

---

*Generated for .NET / C# security audits. Adapt prompts to your specific framework (ASP.NET Core MVC, Minimal API, Blazor, gRPC, Azure Functions).*

---

## 9. Advanced Validation & Triage (Mythos Workflow)

For high-confidence findings, apply the Mythos advanced validation pipeline:
1. **Cross-Model Corroboration:** Have a skeptic model review the finding.
2. **Dynamic Executable-PoC:** Generate an isolated, executable Proof-of-Concept to confirm the vulnerability.
3. **Variant Hunting:** Search the codebase for similar patterns using the confirmed finding as a signature.
4. **Chain-Severance Proof:** Verify that the proposed patch actively breaks the PoC and critical attack path.
