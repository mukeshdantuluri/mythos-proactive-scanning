# Python Security Audit Guide

> Comprehensive security scanning prompts for Python codebases: Django, FastAPI, Flask, SQLAlchemy, Celery, and plain Python services.

---

## 1. Authentication & Session Flow

```
You are an expert security engineer and review below.
Review the entire authentication flow in this Python codebase. Trace every path from login to session creation to authorization checks. Identify:

- Any view/route missing authentication decorators (@login_required, Depends(get_current_user), @jwt_required)
- JWT vulnerabilities:
  - Is the algorithm explicitly set in jwt.decode(algorithms=["HS256"])? (reject "none" algorithm)
  - Is PyJWT's decode() used with verify_exp=True?
- Django: are any views accidentally using @csrf_exempt? Are all state-changing endpoints protected?
- FastAPI: are Depends() auth dependencies applied to all sensitive routers?
- Flask: is Flask-Login's @login_required applied, or are session cookies validated server-side?
- OAuth flows: is the state parameter validated to prevent CSRF?
- Are passwords hashed with bcrypt, argon2-cffi, or Django's PBKDF2 — never MD5, SHA1, or plain SHA256?
- Is there a timing-safe comparison (hmac.compare_digest) for token/secret comparison?

For each finding, provide the exact file, line number, and a proof-of-concept HTTP request demonstrating the bypass.
```

---

## 2. Database Security (SQLAlchemy, Django ORM, psycopg2, raw SQL)

```
You are an expert security engineer and review below.
Audit every database interaction in this Python codebase.

SQLAlchemy:
- Any use of text() with string concatenation or f-strings? text(f"SELECT * FROM users WHERE id={user_id}")
- Any execute() calls with raw SQL strings assembled from user input?
- Are ORM queries using filter() with user-controlled column names or values without sanitization?

Django ORM:
- Any .raw() or connection.cursor().execute() calls with string formatting?
- Are .extra() or .RawSQL() usages safe from injection?
- Are F() expressions, annotate(), or aggregate() usages free from injection?
- Are there missing permission checks before QuerySet operations?

psycopg2 / asyncpg / databases:
- Are all queries using %s placeholders or $1 parameterization — never %-formatting of user input?
- Dangerous: cursor.execute("SELECT * FROM t WHERE x='" + val + "'")
- Safe: cursor.execute("SELECT * FROM t WHERE x=%s", (val,))

Second-order Injection:
- Is user-supplied data stored and later used in a query without re-sanitization?

Multi-tenancy:
- Are all Django QuerySets scoped with .filter(tenant=request.user.tenant)?
- Can a user enumerate another tenant's data by modifying IDs in the URL?

For each finding, show the full request-to-sink path, a PoC payload, and the parameterized fix.
```

---

## 3. Injection Vulnerabilities

```
You are an expert security engineer and review below.
Find every injection vulnerability in this Python codebase.

SQL Injection:
- Any f-string, %-format, or .format() used in SQL queries
- Any Django .extra(where=[user_input]) or .raw(user_input)

Command Injection:
- Any os.system(), subprocess.run(shell=True), subprocess.Popen(shell=True), os.popen() with user-controlled strings?
- Safe: subprocess.run(['ls', user_input]) vs Dangerous: subprocess.run(f'ls {user_input}', shell=True)
- Any use of paramiko exec_command with concatenated strings?

Path Traversal:
- Any open(), pathlib.Path(), os.path.join() with user-controlled segments?
- Is os.path.realpath() combined with a startswith(BASE_DIR) check in place?

Server-Side Template Injection (SSTI):
- Any Jinja2 Template(user_input).render() or Environment().from_string(user_input)?
- Django template engine rendering user-controlled strings?
- Mako or Chameleon rendering user-supplied templates?
- SSTI in Jinja2: {{ 7*7 }} → 49 confirms the vulnerability; {{''.__class__.__mro__[1].__subclasses__()}} for RCE

SSRF:
- Any requests.get(user_url), httpx.get(user_url), urllib.request.urlopen(user_url)?
- Is the URL validated against an allowlist? Can 169.254.169.254 or file:// be reached?

Deserialization:
- Any pickle.loads(), pickle.load() on user-controlled data?
- Any yaml.load() without Loader=yaml.SafeLoader? (PyYAML RCE vector)
- Any marshal.loads() or shelve with user-controlled keys?
- Any jsonpickle.decode() on user data?

XML / XXE:
- Any xml.etree.ElementTree, lxml, minidom parsing user-supplied XML without disabling external entities?
- lxml: is resolve_entities=False set? Is no_network=True set?

Regular Expression DoS (ReDoS):
- Are there complex regular expressions (nested quantifiers) applied to user-supplied strings without timeouts?

eval() / exec():
- Any eval(user_input) or exec(user_input)?
- Any compile(user_input, ...) with execution?

For each finding, show input-to-sink trace, PoC payload, CVSS 3.1 rating, and exact fix.
```

---

## 4. Secrets & Sensitive Data Exposure

```
You are an expert security engineer and review below.
Scan this Python codebase for secrets and sensitive data exposure.

Hardcoded Secrets:
- Any string literals matching: password, secret, api_key, token, AWS_SECRET, DATABASE_URL in .py files
- Credentials in settings.py, config.py, or alembic.ini committed to git
- Django SECRET_KEY hardcoded in settings.py (not loaded from environment)
- Are .env files excluded from git? Check git log --all --full-history -- .env .env.local

Logging:
- Any logging.info/debug calls logging passwords, tokens, or PII
- Does Django's DEBUG=True mode expose full tracebacks with local variables (including secrets) in HTTP responses?
- Does the Celery/RQ task logger log sensitive task arguments?

API Response Over-fetching:
- Are Django model serializers exposing password_hash, internal_flags, or payment fields?
- Are FastAPI Pydantic response models correctly excluding sensitive fields (use response_model with explicit field selection)?
- Are DRF serializers using fields = '__all__' that include sensitive data?

Django DEBUG:
- Is DEBUG=True in production settings? (exposes full stack traces + local vars to anyone)
- Is ALLOWED_HOSTS set correctly? (DEBUG=False with empty ALLOWED_HOSTS causes 400 errors)

Error Handling:
- Do exception handlers return full tracebacks in JSON error responses?
- Does Flask's app.run(debug=True) expose the Werkzeug debugger in production (allows RCE)?

For each finding, specify file, line, the sensitive data exposed, and remediation.
```

---

## 5. File Upload Security

```
You are an expert security engineer and review below.
Audit all file upload handling in this Python codebase (Django, FastAPI, Flask).

Validation:
- Is file type validated using python-magic (libmagic) on file content — not just the filename extension or Content-Type header?
- Is there a file size limit enforced server-side (Django: FILE_UPLOAD_MAX_MEMORY_SIZE, FastAPI: UploadFile size check)?
- Are uploaded filenames sanitized with werkzeug.utils.secure_filename() or equivalent?
- Can filenames containing "../" cause path traversal when saved to disk?

Django-Specific:
- Are media files served through Django (MEDIA_ROOT/MEDIA_URL) without authentication?
- Can an attacker upload a .html or .svg file and have it served with text/html content type?

Storage:
- Are files stored in a publicly accessible web directory?
- Is there per-user authorization when fetching uploaded files?

Processing:
- If using Pillow for image processing, is Image.open() on untrusted files safe? (Check Pillow CVEs, enforce max image size)
- If processing PDFs (PyPDF2, pdfminer), is SSRF from embedded links possible?
- If extracting ZIP files (zipfile module), is zip slip protection in place?
  Validate: member.filename must not start with / or contain ../

For each finding, provide the vulnerable endpoint, code path, PoC payload or filename, and fix.
```

---

## 6. Infrastructure & Configuration (Python Specific)

```
You are an expert security engineer and review below.
Review all configuration and infrastructure files in this Python project.

Django Settings:
- Is SECRET_KEY loaded from environment (not hardcoded)?
- Is DEBUG=False enforced in production? (use django-environ or python-decouple)
- Is SECURE_SSL_REDIRECT=True set?
- Is SECURE_HSTS_SECONDS set to ≥31536000?
- Is SESSION_COOKIE_SECURE=True and SESSION_COOKIE_HTTPONLY=True?
- Is CSRF_COOKIE_SECURE=True?
- Is X_FRAME_OPTIONS='DENY' set?
- Are ALLOWED_HOSTS explicitly listed (not ['*'])?
- Is CONN_MAX_AGE used correctly with connection pooling?

FastAPI / Flask:
- Is CORS configured restrictively? (CORSMiddleware with explicit allow_origins, not allow_origins=["*"] on authenticated APIs)
- Are security headers set via a middleware (starlette-csrf, flask-talisman)?

Celery / Background Tasks:
- Is Celery broker (Redis/RabbitMQ) accessible from the internet?
- Are Celery task arguments sanitized (tasks can be triggered via the broker)?
- Is celery.conf.task_serializer = 'json' (not 'pickle')?

Dependency Security:
- Run pip audit or safety check — list all High and Critical CVEs in requirements.txt / pyproject.toml
- Are dependencies pinned to exact versions?
- Are there known vulnerable packages: Django <4.2.x, Pillow <10.x, cryptography <42.x?

WSGI/ASGI Server:
- Is gunicorn/uvicorn running as a non-root user?
- Are worker timeouts configured to prevent DoS via slow requests?
- Are the number of workers appropriate (no runaway resource exhaustion)?

Docker:
- Is the Dockerfile using USER app (non-root)?
- Are secrets passed via ENV in Dockerfile?

For each issue, specify the configuration file, setting, risk, and corrected snippet.
```

---

## 7. Business Logic & Race Conditions

```
You are an expert security engineer and review below.
Analyze business logic in this Python codebase for logic flaws.

Race Conditions:
- Are there check-then-act patterns without database-level locking?
  Django: use select_for_update() — queryset.select_for_update() inside an atomic() block
  SQLAlchemy: use with_for_update()
- Are @transaction.atomic() or session.begin() boundaries correctly covering all related operations?
- Are Celery tasks idempotent? Can a retried task double-spend or double-create?

Django-Specific:
- Are F() expressions used for atomic increments instead of read-then-write?
  Safe: Model.objects.filter(id=pk).update(balance=F('balance') - amount)
  Unsafe: obj.balance -= amount; obj.save()

State Machine:
- Are model state transitions validated before saving (Django clean(), FSM library)?
- Can a REST call transition a model to an invalid state?

Access Control:
- Is get_object_or_404(Model, pk=pk, user=request.user) used (ownership check) vs just get_object_or_404(Model, pk=pk)?
- Can a user modify their own role or subscription tier via a PATCH /users/{id}/ call?

Numeric Handling:
- Is Decimal used for all monetary values (never float)?
- Are negative amounts blocked at the serializer/validation layer?

For each finding, describe the full attack scenario and provide the exact Django/SQLAlchemy locking fix.
```

---

## 8. Verification & Re-scan After Patching

```
You are an expert security engineer and review below.
I have applied security patches to this Python codebase. Perform a verification pass:

1. Re-scan every modified file — did any fix introduce new vulnerabilities?
2. Re-test every confirmed finding — is the vulnerability eliminated?
3. Run pip audit / safety check for newly introduced CVEs.
4. Search for the same vulnerable pattern codebase-wide:
   Example: if yaml.load() was found, grep for all yaml.load() usages.
   Example: if shell=True subprocess was found, grep all subprocess calls.
5. Verify Django settings holistically for the production environment.
6. Re-run Bandit (bandit -r . -ll) and Semgrep (semgrep --config=p/python) across the full codebase.

Output per finding:
- Verification status: Confirmed Fixed / Still Vulnerable / New Issue Introduced
- If Still Vulnerable, show what remains exploitable
- Updated CVSS 3.1 score
- Recommended next action
```

---

## Quick Reference: Python Dangerous Sinks

| Category | Dangerous Pattern | Safe Alternative |
|---|---|---|
| SQL | `cursor.execute(f"SELECT * WHERE id={id}")` | `cursor.execute("SELECT * WHERE id=%s", (id,))` |
| SSTI | `Template(user_input).render()` | Never render user-supplied template strings |
| Command | `os.system("ls " + path)` | `subprocess.run(["ls", path])` |
| Path | `open(base + user_path)` | `realpath` + `startswith(BASE)` check |
| Deser | `pickle.loads(user_data)` | Use JSON; never pickle untrusted data |
| YAML | `yaml.load(data)` | `yaml.safe_load(data)` |
| SSRF | `requests.get(req.json()['url'])` | URL allowlist + block private ranges |
| ReDoS | `re.match(complex_pattern, user_input)` | Use `re.timeout` (Python 3.11+) or limit input length |
| eval | `eval(user_input)` | Never evaluate user input |

---

*Generated for Python security audits. Adapt prompts to your specific framework (Django, FastAPI, Flask, aiohttp, Tornado).*

---

## 9. Advanced Validation & Triage (Mythos Workflow)

For high-confidence findings, apply the Mythos advanced validation pipeline:
1. **Cross-Model Corroboration:** Have a skeptic model review the finding.
2. **Dynamic Executable-PoC:** Generate an isolated, executable Proof-of-Concept to confirm the vulnerability.
3. **Variant Hunting:** Search the codebase for similar patterns using the confirmed finding as a signature.
4. **Chain-Severance Proof:** Verify that the proposed patch actively breaks the PoC and critical attack path.
