# JavaScript / TypeScript / Node.js Security Audit Guide

> Comprehensive security scanning prompts for JS/TS codebases: Node.js, Express, NestJS, Next.js, Fastify, Deno, browser-side JS, and React/Vue/Angular frontends.

---

## 1. Authentication & Session Flow

```
You are an expert security engineer and review below.
Review the entire authentication flow in this JavaScript/TypeScript codebase. Trace every path from login to session creation to authorization checks. Identify:

- Any Express/Fastify/NestJS routes missing authentication middleware (passport, express-jwt, custom guards)
- JWT vulnerabilities:
  - Is the algorithm explicitly verified? (reject "alg: none" and RS256→HS256 confusion attacks)
  - Is jsonwebtoken's verify() used (not just decode())?
  - Are tokens stored in httpOnly, Secure, SameSite=Strict cookies — or insecurely in localStorage?
- Session fixation: is session.regenerate() called after login (express-session)?
- CSRF protection: are state-changing routes (POST/PUT/DELETE) protected with csurf or double-submit cookie pattern?
- OAuth/OIDC: is the state parameter validated? Is the redirect_uri allowlisted?
- Are Next.js API routes / app router route handlers protected — can middleware.ts be bypassed by direct /api/ calls?

For each finding, provide the exact file, line number, and a proof-of-concept HTTP request demonstrating the bypass.
```

---

## 2. Database Security (SQL, NoSQL, ORMs)

```
You are an expert security engineer and review below.
Audit every database interaction in this JavaScript/TypeScript codebase.

SQL (pg, mysql2, better-sqlite3, Knex, Sequelize, TypeORM, Prisma, Drizzle):
- Any template literals or string concatenation in raw SQL queries?
  Example dangerous pattern: db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)
- Are Knex raw() / Sequelize.literal() / TypeORM query builder createQueryBuilder() calls safe?
- Are Prisma $queryRaw or $executeRaw usages using tagged template literals (safe) or string concatenation (dangerous)?
- Second-order SQL injection: is user-supplied data stored and later interpolated into queries?

NoSQL (MongoDB / Mongoose):
- Can MongoDB query operators ($gt, $ne, $regex, $where) be injected via JSON request bodies?
  Example: { "username": { "$gt": "" }, "password": { "$gt": "" } }
- Is express-mongo-sanitize or similar middleware active?
- Are $where clauses or mapReduce with user input present (server-side JS execution)?

Redis:
- Is user input ever concatenated into Redis commands (EVAL scripts)?

Row-Level Isolation:
- Are multi-tenant queries always scoped with a WHERE tenantId = req.user.tenantId clause?
- Can a user change their tenantId via a profile update and access other tenants' data?

For each finding, show the full request-to-sink path, a PoC payload, and the parameterized fix.
```

---

## 3. Injection Vulnerabilities (XSS, SSRF, Command, Template)

```
You are an expert security engineer and review below.
Find every injection vulnerability in this JavaScript/TypeScript codebase.

XSS:
- Are there any uses of innerHTML, outerHTML, document.write(), insertAdjacentHTML, eval(), setTimeout(string), setInterval(string) with user-controlled data?
- React: is dangerouslySetInnerHTML used? Is user input passed to href / src without validation?
- Vue: are v-html directives used with user data?
- Angular: is bypassSecurityTrustHtml / DomSanitizer.sanitize bypassed?
- Are CSP headers set? Is 'unsafe-inline' or 'unsafe-eval' present in the policy?
- Is DOMPurify or a similar sanitizer used for all rich-text user content?

Server-Side Template Injection (SSTI):
- Is any template engine (Handlebars, EJS, Pug, Nunjucks, Mustache) compiling or rendering user-supplied strings?
  Dangerous: res.render(userInput) or Handlebars.compile(userInput)
- Pug: any pug.render(userInput) calls?
- EJS: any ejs.render(userTemplate)?

Command Injection:
- Any calls to exec(), execSync(), spawn() with string concatenation of user input?
- Are shell: true flags set on spawn/execFile (dangerous)?
- Is child_process being used at all? If so, enumerate all call sites.

SSRF:
- Any fetch(), axios, http.get(), got(), node-fetch, request() with user-controlled URLs?
- Is the URL validated against an allowlist before the request?
- Can an attacker reach 169.254.169.254, 10.0.0.0/8, or ::1?

Path Traversal:
- Any fs.readFile(), fs.createReadStream(), path.join(), res.sendFile() with user-controlled path segments?
- Is path.resolve() combined with a startsWith(allowedDir) check?

Prototype Pollution:
- Are lodash.merge(), _.merge(), jQuery.extend(true), Object.assign with user-supplied nested objects used?
- Is user-controlled JSON parsed and merged into application objects without sanitization?
- Is flatted, qs, or similar deep-merge library in use with unchecked input?

eval() / Function() / vm.runInContext():
- Any eval(userInput), new Function(userInput), or vm.Script(userInput)?
- Is any JSON.parse result passed directly to eval?

For each finding, show input-to-sink trace, PoC payload, CVSS 3.1 rating, and exact fix.
```

---

## 4. Secrets & Sensitive Data Exposure

```
You are an expert security engineer and review below.
Scan this JavaScript/TypeScript codebase for secrets and sensitive data exposure.

Hardcoded Secrets:
- Any string literals matching: password, secret, apiKey, token, PRIVATE_KEY, credentials, connectionString in .js, .ts, .json, .env files committed to git
- Are .env files in .gitignore? Check git history: git log --all --full-history -- .env
- Are there fallback values for secrets that work in production?
  Example: process.env.JWT_SECRET || 'mysecret'

Client-Side Bundle Exposure:
- Are secrets injected into Next.js at build time via NEXT_PUBLIC_ environment variables?
- Does the webpack/Vite bundle include server-side secrets accessible via source maps?
- Is source map generation disabled in production builds (devtool: false)?

API Response Over-fetching:
- Are Mongoose/Prisma models returned directly from API handlers exposing passwordHash, internalFlags, or payment data?
- Are GraphQL resolvers returning more fields than the client needs?
- Is __resolveType or __schema introspection enabled in production?

Logging:
- Are passwords, tokens, or PII logged via console.log, winston, pino, bunyan?
- Does the global Express error handler log req.body (which may contain credentials)?
- Do morgan or other HTTP logging middleware capture Authorization headers?

Client-Side Storage:
- Are JWTs, session tokens, or sensitive data stored in localStorage or sessionStorage?
- Are cookies set with httpOnly, Secure, and SameSite flags?

For each finding, specify file, line, the sensitive data exposed, where it leaks, and remediation.
```

---

## 5. File Upload Security

```
You are an expert security engineer and review below.
Audit all file upload handling in this Node.js codebase (multer, busboy, formidable, multiparty).

Validation:
- Is file type validated using file-type (magic bytes) rather than req.file.mimetype (user-controlled)?
- Is there a file size limit: multer({ limits: { fileSize: X } })?
- Can filenames containing "../", "%2F%2E%2E", or null bytes cause path traversal when saved?
- Are filenames sanitized (sanitize-filename, path.basename) before use?

Storage:
- Are files stored in a publicly accessible directory (public/, static/, uploads/)?
- Can an attacker upload an .html, .svg, or .js file and have it served by the web server?
- Is there per-user authorization when retrieving uploaded files?

Processing:
- If using Sharp, Jimp, or canvas for image processing, are there known CVEs (check npm audit)?
- If processing PDF (pdf-parse, pdfjs-dist) or DOCX (mammoth), is SSRF or path traversal possible?
- If extracting ZIP (adm-zip, unzipper, jszip), is zip slip protection in place?
  (Validate entry path: entry.fileName must not start with / or contain ../)

For each finding, provide the vulnerable endpoint, code path, PoC payload, and fix.
```

---

## 6. Infrastructure & Configuration (Node.js Specific)

```
You are an expert security engineer and review below.
Review all configuration files and runtime settings in this JavaScript project.

HTTP Security Headers (Helmet.js):
- Is helmet() applied to the Express/Fastify app?
- Is Content-Security-Policy configured and restrictive (no 'unsafe-inline', no 'unsafe-eval')?
- Is X-Frame-Options / frame-ancestors set?
- Is HSTS (Strict-Transport-Security) configured with a long max-age?
- Is X-Content-Type-Options: nosniff set?

CORS:
- Is cors({ origin: '*' }) used on authenticated APIs?
- Is cors({ origin: trustedOrigins, credentials: true }) configured correctly?

Rate Limiting:
- Is express-rate-limit or similar applied to: login, registration, password reset, OTP verification, and any expensive operation?
- Is the IP-based rate limit bypassable via X-Forwarded-For header manipulation?
- Is trust proxy configured correctly?

Dependency Security:
- Run npm audit / yarn audit — list all High and Critical CVEs
- Are dependencies pinned to exact versions or using ^ (allows minor updates)?
- Are there known vulnerable packages: lodash <4.17.21, axios <1.6.0, jsonwebtoken <9.0.0, qs <6.10.3?

Next.js / Nuxt.js Specific:
- Are getServerSideProps / server actions properly authenticating requests?
- Is the rewrites() configuration in next.config.js accidentally proxying internal endpoints?
- Are environment variables correctly split between server-only and NEXT_PUBLIC_?

Docker:
- Is the container running as node user (USER node) rather than root?
- Is node_modules/.bin in the PATH inside the container unnecessarily?

For each issue, specify the file, setting, risk, and corrected code snippet.
```

---

## 7. Business Logic & Race Conditions

```
You are an expert security engineer and review below.
Analyze business logic in this JavaScript/TypeScript codebase for logic flaws.

Race Conditions:
- Are there check-then-act patterns in async code without database-level locking?
  Example: const balance = await getBalance(); if (balance >= amount) { await deduct(amount); }
  Two concurrent requests could both pass the check before either deducts.
- Are database transactions used for multi-step financial operations?
- Are Redis INCR / DECR / SETNX used for atomic counters instead of read-modify-write?

Promise / Async Handling:
- Are there unhandled Promise rejections that could leave data in an inconsistent state?
- Are await calls missing in async Express handlers (uncaught rejections crash the process)?
- Is async/await used inside array.forEach() (async iterators ignored)?

Access Control Logic:
- Is ownership verified: const resource = await db.find({ id, userId: req.user.id }) vs just db.find({ id })?
- Can query parameters like ?admin=true or ?role=admin influence authorization?
- Are soft-deleted users (deletedAt: not null) filtered from all queries?

State Machine:
- Are status transitions validated server-side before persisting?
- Can an API call double-trigger a webhook or payment?

For each finding, describe the full attack scenario and provide the exact async/transactional fix.
```

---

## 8. Browser-Side Security (Frontend Specific)

```
You are an expert security engineer and review below.
Review the client-side JavaScript in this frontend codebase.

PostMessage Security:
- Are window.addEventListener('message', handler) listeners validating event.origin before acting?
- Can an attacker iframe this page and send malicious postMessage events?

DOM Clobbering:
- Can user-controlled HTML (e.g., in a forum post) clobber global DOM variables referenced in scripts?

Open Redirect:
- Are there any window.location = userInput or router.push(userInput) calls without URL validation?
- Can an attacker craft a link that redirects to a malicious site after login?

Clickjacking:
- Is X-Frame-Options or Content-Security-Policy frame-ancestors set server-side?

Third-party Scripts:
- Are third-party scripts (analytics, ads, chat widgets) loaded with integrity (SRI) attributes?
- Can a compromised CDN deliver malicious JS?

For each finding, specify component/file, line number, PoC scenario, and remediation.
```

---

## 9. Verification & Re-scan After Patching

```
You are an expert security engineer and review below.
I have applied security patches to this JavaScript/TypeScript codebase. Perform a verification pass:

1. Re-scan every modified file — did any fix introduce new vulnerabilities?
2. Re-test every confirmed finding — is the vulnerability eliminated or only made harder?
3. Run npm audit and check for new CVEs introduced by dependency updates.
4. Search for the same vulnerable pattern across all files not in the original finding list.
   Example: if eval(userInput) was found in one file, grep for all eval() usages codebase-wide.
5. Verify CSP, CORS, and Helmet configuration holistically.
6. Re-run SAST (ESLint security plugins, Semgrep JS rulesets, Snyk Code).

Output per finding:
- Verification status: Confirmed Fixed / Still Vulnerable / New Issue Introduced
- If Still Vulnerable, show what remains exploitable
- Updated CVSS 3.1 score
- Recommended next action
```

---

## Quick Reference: JavaScript Dangerous Sinks

| Category | Dangerous Pattern | Safe Alternative |
|---|---|---|
| SQL | `` db.query(`SELECT * FROM u WHERE id=${id}`) `` | `db.query('SELECT * FROM u WHERE id=$1', [id])` |
| NoSQL | `User.find({ username: req.body.username })` | Validate / sanitize operator keys |
| XSS | `element.innerHTML = userInput` | `element.textContent = userInput` |
| SSTI | `ejs.render(userTemplate)` | Never render user-supplied templates |
| Command | `exec('ls ' + userInput)` | `execFile('ls', [userInput])` |
| Path | `fs.readFile('./uploads/' + filename)` | Canonical path + allowlist check |
| SSRF | `fetch(req.body.url)` | URL allowlist + block private ranges |
| Proto Pollution | `_.merge({}, req.body)` | `JSON.parse(JSON.stringify(req.body))` |
| Open Redirect | `res.redirect(req.query.next)` | Validate against allowlist |

---

*Generated for JavaScript / TypeScript / Node.js security audits. Adapt prompts to your specific framework (Express, NestJS, Next.js, Fastify, Deno, Nuxt).*

---

## 9. Advanced Validation & Triage (Mythos Workflow)

For high-confidence findings, apply the Mythos advanced validation pipeline:
1. **Cross-Model Corroboration:** Have a skeptic model review the finding.
2. **Dynamic Executable-PoC:** Generate an isolated, executable Proof-of-Concept to confirm the vulnerability.
3. **Variant Hunting:** Search the codebase for similar patterns using the confirmed finding as a signature.
4. **Chain-Severance Proof:** Verify that the proposed patch actively breaks the PoC and critical attack path.
