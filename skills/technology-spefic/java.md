# Java Security Audit Guide

> Comprehensive security scanning prompts tailored for Java codebases (Spring Boot, Jakarta EE, Quarkus, Micronaut, plain Java).

---

## 1. Authentication & Session Flow

```
You are an expert security engineer and review below.
Review the entire authentication flow in this Java codebase. Trace every path from login to session creation to authorization checks. Identify:

- Any way to bypass Spring Security / Jakarta Security / custom auth filters entirely
- Race conditions in HttpSession, JWT, or Spring Session handling
- Missing @PreAuthorize / @Secured / @RolesAllowed annotations on @RestController or @Controller methods
- JWT expiration, refresh, and signature-validation vulnerabilities (check for alg:none attacks)
- Any path where a user could escalate privileges through role manipulation

Check specifically:
- SecurityFilterChain configuration — are all routes covered or is there an "antMatchers('/**').permitAll()" catch-all?
- Spring Security method security — is @EnableMethodSecurity / @EnableGlobalMethodSecurity active?
- Custom OncePerRequestFilter implementations — can they be bypassed with URL encoding or double slashes?
- Principal / Authentication object usage — is it ever cast unsafely or trusted from a header?

For each finding, provide the exact file, line number, and a proof-of-concept HTTP request that would demonstrate the bypass.
```

---

## 2. Database & ORM Security (JPA, Hibernate, JDBC)

```
You are an expert security engineer and review below.
Audit every database interaction in this Java codebase. Examine:

JPA / Hibernate:
- Are there any @Query annotations using JPQL/HQL with string concatenation instead of named parameters (:param)?
- Are native queries (@Query(nativeQuery=true)) using string concatenation — classic SQL injection sink?
- Is EntityManager.createQuery() or Session.createQuery() ever called with concatenated user input?
- Are Hibernate Criteria API or JPA CriteriaBuilder usages safe from injection?

Spring Data:
- Are Spring Data derived query methods used safely, or are there custom @Query usages with SpEL expressions ({#param}) that could be exploited?

JDBC:
- Any PreparedStatement usage replaced by Statement with string concatenation?
- Any JdbcTemplate.query() / JdbcTemplate.execute() calls with raw SQL strings built from user input?

Second-order injection:
- Is user-supplied data stored in the DB and later used in a query without re-sanitization?

Row-Level Security:
- Is multi-tenant data isolation enforced in queries, or does one user's ID let them query another's data by modifying request parameters?

For each finding, show the exact code path from HTTP input to the SQL sink, provide a PoC payload, and the parameterized fix.
```

---

## 3. Input Validation & Injection Vulnerabilities

```
You are an expert security engineer and review below.
Find every point in this Java codebase where user input enters the system and trace it to dangerous sinks. Input sources: @RequestParam, @PathVariable, @RequestBody, @RequestHeader, HttpServletRequest, MultipartFile, @RequestPart, WebSocket messages.

Check for:

SQL Injection:
- Any use of String.format() or "+" concatenation inside JDBC, JPA native queries, or QueryDSL
- Spring Data @Query with concatenated parameters

Command Injection:
- Any calls to Runtime.getRuntime().exec(), ProcessBuilder, or Apache Commons Exec with user-controlled arguments
- Are arguments passed as String arrays (safe) or single strings (dangerous)?

Path Traversal:
- Any File(), Paths.get(), or FileInputStream with user-controlled path segments
- Is "../" or URL-encoded "%2F%2E%2E" handled?
- Are canonical path checks (getCanonicalPath().startsWith(baseDir)) in place?

XSS:
- Are Thymeleaf / FreeMarker / JSP templates using unescaped output (th:utext, ${..} in JSP scriptlets)?
- Is OWASP Java HTML Sanitizer or similar used for rich text?
- Are Spring MVC @ResponseBody endpoints returning HTML strings with user content?

SSRF:
- Any use of URL.openConnection(), HttpClient, RestTemplate, WebClient, OkHttpClient with user-controlled URLs?
- Is the target URL validated against an allowlist?
- Can an attacker reach 169.254.169.254 (AWS metadata), localhost, or internal services?

XML / XXE:
- Any DocumentBuilderFactory, SAXParserFactory, XMLInputFactory, JAXB unmarshalling of user-supplied XML?
- Are external entity processing features disabled? (setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true))

Deserialization:
- Any ObjectInputStream.readObject() called on user-supplied data?
- Is the Jackson ObjectMapper configured with default typing enabled (enableDefaultTyping)?
- Is XStream or Kryo deserializing untrusted data?

Expression Injection:
- Any Spring SpEL (ExpressionParser.parseExpression()) evaluated with user input?
- Any Groovy / OGNL / MVEL engine invoked with user-controlled strings?

For each finding, show the full call stack from the @RequestMapping method to the sink, provide a PoC payload, rate severity (CVSS 3.1), and provide the exact fix.
```

---

## 4. Secrets & Sensitive Data Exposure

```
You are an expert security engineer and review below.
Scan this Java codebase and configuration for:

Hardcoded Secrets:
- Any String literals matching patterns: password, secret, apiKey, token, credentials, connectionString
- Any hardcoded values in @Value("hardcoded-string") or direct assignment
- Credentials in application.properties / application.yml / bootstrap.yml committed to source control
- Secrets in logback.xml, log4j2.xml, or other config files

Logging:
- Any log.info/debug/warn/error calls that log passwords, tokens, PII, credit card numbers, or session IDs
- Are MDC (Mapped Diagnostic Context) values ever populated with sensitive data?
- Does the global exception handler log full stack traces to external services?

API Response Over-fetching:
- Are @Entity / @Document objects returned directly from @RestController without a DTO projection?
- Does any User entity expose passwordHash, internalRole, or similar fields in JSON serialization?
- Are Jackson @JsonIgnore / @JsonView annotations used correctly?

Client-side Exposure:
- Are secrets injected into Thymeleaf / JSP templates and rendered in HTML?
- Is any server-side configuration exposed through an Actuator endpoint (/actuator/env, /actuator/configprops) without authentication?

For each finding, specify the file, the exact sensitive field or value, where it leaks, and the remediation.
```

---

## 5. File Upload Security

```
You are an expert security engineer and review below.
Audit all file upload endpoints in this Java codebase. For each MultipartFile / @RequestPart / Part handling:

Validation:
- Is file type validated server-side using Apache Tika content detection (not just extension or MIME type from the request)?
- Is there a file size limit enforced via MultipartConfigElement or spring.servlet.multipart.max-file-size?
- Can a filename containing "../" cause path traversal when saved to disk?

Storage:
- Are uploaded files saved inside the web root (src/main/resources/static or webapp/) — making them directly accessible?
- Is Content-Disposition: attachment set when serving files?
- Is there authorization checking — can User A retrieve User B's uploaded file?

Processing:
- If using ImageIO, Thumbnailator, or ImageMagick (im4java) for image processing, are there known CVEs for the library version in use?
- If processing PDFs (Apache PDFBox, iText), is XXE or SSRF possible?
- If processing ZIP/JAR files (ZipInputStream), is there zip slip protection (validate entry.getName() against output path)?

For each finding, provide the exact endpoint, the vulnerable code path, and a PoC file or filename payload.
```

---

## 6. Infrastructure & Configuration

```
You are an expert security engineer and review below.
Review all infrastructure and configuration files in this Java project:

Spring Boot Actuator:
- Are sensitive endpoints (/actuator/env, /actuator/heapdump, /actuator/shutdown, /actuator/beans) exposed without authentication?
- Is management.endpoints.web.exposure.include=* used in production profiles?

CORS:
- Is @CrossOrigin(origins="*") applied on any @RestController or globally in WebMvcConfigurer?
- Are credentials allowed with wildcard origins?

Security Headers:
- Is Spring Security's headers() configuration enabling HSTS, X-Content-Type-Options, X-Frame-Options, and CSP?
- Is a Content Security Policy defined and restrictive?

TLS:
- Is HTTP (non-HTTPS) redirect configured?
- Are weak cipher suites (DES, RC4, 3DES) disabled in server.ssl configuration?

Docker / Container:
- Is the Dockerfile using a root USER?
- Are secrets passed via ENV in Dockerfile (baked into image layers)?
- Is the base image (openjdk, eclipse-temurin) pinned to a specific digest?

Dependency Security:
- Run OWASP Dependency-Check or Snyk — list all CVEs in pom.xml / build.gradle dependencies
- Are there transitive dependencies with known exploits (Log4Shell, Spring4Shell, etc.)?

For each issue, specify the configuration file, the exact setting, the risk, and the corrected configuration.
```

---

## 7. Business Logic & Race Conditions

```
You are an expert security engineer and review below.
Analyze the business logic in this Java codebase for logic flaws:

Race Conditions:
- Are there check-then-act patterns (read balance, then deduct) without database-level locking (@Lock(LockModeType.PESSIMISTIC_WRITE) or SELECT FOR UPDATE)?
- Are @Transactional boundaries correct — are concurrent transactions using the right isolation level (SERIALIZABLE for financial ops)?
- Are there non-atomic counters (AtomicInteger vs plain int in shared beans)?

State Machine:
- Are entity state transitions validated (@PreUpdate / domain method guards)?
- Can a REST call skip a required state (e.g., mark an order SHIPPED without it being PAID)?

Numeric Handling:
- Is BigDecimal used for all monetary calculations (never double or float)?
- Are there integer overflow risks in quantity * price calculations (use Math.multiplyExact)?
- Can negative quantities or prices be submitted through the API?

Access Control Logic:
- Is ownership checked before returning or mutating a resource (e.g., userRepository.findById(id) without verifying the caller owns it)?
- Can a free-tier user toggle a feature flag by modifying a request parameter?
- Are deleted/soft-deleted user accounts fully denied access (check active flag in UserDetailsService)?

For each finding, describe the full attack scenario and provide the exact @Transactional / locking fix.
```

---

## 8. Verification & Re-scan After Patching

```
You are an expert security engineer and review below.
I have applied security patches to this Java codebase. Perform a verification pass:

1. Re-scan every modified file — did any fix introduce new vulnerabilities?
2. Re-test every finding marked fixed — is the vulnerability eliminated or just harder to exploit?
3. Check for regression — did any fix break an adjacent security control?
4. Pattern search — search for the same vulnerable pattern (e.g., createNativeQuery with concatenation) across all files not in the original finding list.
5. Re-assess Spring Security configuration holistically after all changes.

For each finding:
- Verification status: Confirmed Fixed / Still Vulnerable / New Issue Introduced
- If Still Vulnerable, show what remains exploitable
- Updated CVSS score
- Recommended next action
```

---

## Quick Reference: Java-Specific Dangerous Sinks

| Category | Dangerous Pattern | Safe Alternative |
|---|---|---|
| SQL | `Statement.execute("SELECT * FROM users WHERE id=" + id)` | `PreparedStatement` with `?` |
| JPQL | `@Query("FROM User WHERE name='" + name + "'")` | `@Query("FROM User WHERE name=:name")` |
| Command | `Runtime.exec("convert " + filename)` | `ProcessBuilder` with array args |
| Path | `new File(baseDir + userInput)` | Canonical path check |
| XXE | `DocumentBuilderFactory.newInstance()` (default) | Set `FEATURE_SECURE_PROCESSING` |
| Deser | `new ObjectInputStream(userStream).readObject()` | Use allowlist `ObjectInputFilter` |
| SpEL | `parser.parseExpression(userInput).getValue()` | Never evaluate user input as SpEL |
| SSRF | `new URL(userUrl).openConnection()` | Allowlist + deny internal ranges |

---

*Generated for Java security audits. Adapt prompts to your specific framework (Spring Boot, Quarkus, Micronaut, Jakarta EE).*

---

## 9. Advanced Validation & Triage (Mythos Workflow)

For high-confidence findings, apply the Mythos advanced validation pipeline:
1. **Cross-Model Corroboration:** Have a skeptic model review the finding.
2. **Dynamic Executable-PoC:** Generate an isolated, executable Proof-of-Concept to confirm the vulnerability.
3. **Variant Hunting:** Search the codebase for similar patterns using the confirmed finding as a signature.
4. **Chain-Severance Proof:** Verify that the proposed patch actively breaks the PoC and critical attack path.
