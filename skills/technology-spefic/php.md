# PHP Security Audit Guide

> Comprehensive security scanning prompts for PHP codebases: Laravel, Symfony, WordPress, CodeIgniter, plain PHP, and PHP-FPM deployments.

---

## 1. Authentication & Session Flow

```
You are an expert security engineer and review below.
Review the entire authentication flow in this PHP codebase. Trace every path from login to session creation to authorization checks. Identify:

Session Management:
- Are session IDs regenerated after login? (session_regenerate_id(true))
- Are sessions configured securely in php.ini or ini_set()?
  - session.cookie_httponly = 1
  - session.cookie_secure = 1
  - session.cookie_samesite = "Strict"
  - session.use_strict_mode = 1
  - session.use_only_cookies = 1
- Is session data stored securely (not in a world-readable /tmp)?

Laravel:
- Are all routes requiring auth inside the auth middleware group?
  Can any route in web.php or api.php be accessed without the 'auth' or 'auth:sanctum' middleware?
- Are CSRF tokens validated on all state-changing web routes? (web middleware group applies VerifyCsrfToken)
- Are API tokens (Sanctum/Passport) validated server-side — not just decoded client-side?

Symfony:
- Is the firewall configuration in security.yaml covering all paths?
- Are access_control rules ordering correct? (More specific rules must come before catch-all rules)
- Is remember_me token storage secure?

WordPress:
- Are custom REST API endpoints using permission_callback correctly?
- Are nonces verified in AJAX handlers (check_ajax_referer or wp_verify_nonce)?
- Are capabilities checked (current_user_can) before performing privileged operations?

Password Handling:
- Are passwords hashed with password_hash($pass, PASSWORD_BCRYPT) or PASSWORD_ARGON2ID?
- Is password_verify() used for comparison (constant-time)?
- Are any MD5, SHA1, or unsalted hashes still in use?

For each finding, provide the exact file, line number, and a proof-of-concept HTTP request demonstrating the bypass.
```

---

## 2. SQL Injection

```
You are an expert security engineer and review below.
Audit every database interaction in this PHP codebase for SQL injection vulnerabilities.

Raw PHP / MySQLi / PDO:
- Any queries using string concatenation or variable interpolation?
  Dangerous: mysqli_query($conn, "SELECT * FROM users WHERE id=" . $_GET['id'])
  Dangerous: $pdo->query("SELECT * FROM users WHERE name='" . $name . "'")
  Safe: $stmt = $pdo->prepare("SELECT * FROM users WHERE id=?"); $stmt->execute([$id])
- Are all PDO queries using prepare() + execute() with bound parameters?
- Is PDO::ATTR_EMULATE_PREPARES set to false? (Real prepared statements, not emulated)

Laravel (Eloquent / Query Builder):
- Are whereRaw(), selectRaw(), orderByRaw(), groupByRaw(), havingRaw() calls using parameter bindings?
  Dangerous: DB::select("SELECT * FROM users WHERE name='" . $name . "'")
  Safe: DB::select("SELECT * FROM users WHERE name=?", [$name])
- Are Eloquent where() calls with column names from user input (IDOR via column manipulation)?
- Is DB::statement() used with user input?

Symfony (Doctrine):
- Is DQL constructed with string concatenation of user input?
  Dangerous: $em->createQuery("SELECT u FROM User u WHERE u.name='" . $name . "'")
  Safe: $em->createQuery("SELECT u FROM User u WHERE u.name=:name")->setParameter('name', $name)
- Are native SQL queries via createNativeQuery using named parameters?

WordPress:
- Is $wpdb->prepare() used for ALL custom queries?
  Dangerous: $wpdb->query("SELECT * FROM $wpdb->users WHERE ID=" . $user_id)
  Safe: $wpdb->query($wpdb->prepare("SELECT * FROM $wpdb->users WHERE ID=%d", $user_id))
- Are any $wpdb->get_results() calls using unescaped interpolation?

Second-Order Injection:
- Is user-supplied data stored and later retrieved and used in a raw query without re-sanitization?

For each finding, show the full $_GET/$_POST/$_REQUEST-to-SQL path, a PoC payload, and the parameterized fix.
```

---

## 3. Cross-Site Scripting (XSS)

```
You are an expert security engineer and review below.
Audit all output rendering in this PHP codebase for XSS vulnerabilities.

Plain PHP / Templates:
- Any echo, print, or <?= outputting user input without htmlspecialchars()?
  Dangerous: echo $_GET['name']
  Dangerous: echo "<div>" . $user->name . "</div>"
  Safe: echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8')
- Is htmlspecialchars() used with ENT_QUOTES flag to escape both ' and "?
- Are any user-controlled values output inside JavaScript contexts (not just HTML)?
  Dangerous: var name = "<?= $user_name ?>" — requires json_encode(), not just htmlspecialchars

Blade (Laravel) / Twig (Symfony):
- Is {!! $var !!} (unescaped) or {{ $var|raw }} used with user-controlled values?
  {{ $var }} and {{ var }} auto-escape — safe. {!! !!} and |raw — dangerous.
- Are Rich Text / WYSIWYG outputs sanitized with HTMLPurifier before {!! !!} output?

WordPress:
- Is esc_html(), esc_attr(), esc_url(), esc_js() used appropriately in template output?
- Are echo get_post_meta($id, 'key', true) calls escaped?
- Is wp_kses() or wp_kses_post() used for rich HTML that must allow some tags?

Content Security Policy:
- Are Content-Security-Policy headers set?
- Is 'unsafe-inline' used in the script-src directive?
- Is X-XSS-Protection: 1; mode=block set as a defense-in-depth measure?

For each finding, show the output point, the unescaped user input, a PoC payload, and the fix.
```

---

## 4. Other Injection Vulnerabilities

```
You are an expert security engineer and review below.
Find all remaining injection vulnerabilities in this PHP codebase.

Command Injection:
- Any system(), exec(), shell_exec(), passthru(), proc_open(), popen() with user input?
  Dangerous: exec("convert " . $_FILES['upload']['name'])
  Safe: exec("convert " . escapeshellarg($filename)) — but prefer avoiding shell entirely
- Is escapeshellarg() or escapeshellcmd() used correctly?
  (escapeshellarg wraps the arg in quotes; escapeshellcmd escapes shell metacharacters — use arg for values)

Path Traversal (Local File Inclusion - LFI):
- Any include, require, include_once, require_once with user-controlled filenames?
  Dangerous: include($_GET['page'] . '.php')
  (Can be exploited as LFI, null byte injection on older PHP, or RFI if allow_url_include is on)
- Is allow_url_fopen and allow_url_include disabled in php.ini?
- Any file_get_contents(), fopen(), readfile() with user-controlled paths?

Remote File Inclusion (RFI):
- Is allow_url_include enabled? (Should be disabled — enables RFI via include("http://..."))

SSRF:
- Any file_get_contents(), curl_exec(), fsockopen() with user-controlled URLs?
- Is the URL validated against an allowlist?
- Can an attacker reach 169.254.169.254 (cloud metadata), internal services, or file:// paths?

Object Injection / Deserialization:
- Any unserialize() on user-controlled data?
  (PHP object injection can lead to RCE via POP chains in autoloaded classes)
  Dangerous: unserialize($_COOKIE['session'])
  Dangerous: unserialize(base64_decode($_GET['data']))
- Are there __wakeup(), __destruct(), __toString() magic methods in classes that could be chained?
- Is a serialization allowlist specified in the second parameter of unserialize()?

XML / XXE:
- Any SimpleXML, DOMDocument, XMLReader parsing user-supplied XML?
- Are external entities disabled?
  libxml_disable_entity_loader(true); (PHP < 8.0)
  LIBXML_NONET | LIBXML_NOENT flags on newer PHP
- Is an XML-RPC endpoint exposed? (WordPress xmlrpc.php)

LDAP Injection:
- Any ldap_search() with filter containing user input without ldap_escape()?

For each finding, show input-to-sink trace, PoC payload, CVSS 3.1 rating, and exact fix.
```

---

## 5. File Upload Security

```
You are an expert security engineer and review below.
Audit all file upload handling in this PHP codebase.

Validation:
- Is file type validated using finfo_file() (magic bytes) — not just $_FILES['file']['type'] (user-controlled)?
- Is there a file size limit: upload_max_filesize and post_max_size in php.ini, plus server-side check?
- Are filenames sanitized with basename() to strip directory traversal?
- Are filenames checked for PHP file extensions that could lead to execution?
  Block: .php, .php3, .php4, .php5, .phtml, .phar, .php7

Storage:
- Are uploaded files stored inside the document root (webroot) — making them directly executable?
  Files must be stored outside webroot, or in a directory with PHP execution disabled
- Is the upload directory configured with Options -ExecCGI -Includes in .htaccess (Apache) or try_files with no PHP in Nginx?
- Are files served through a PHP controller that checks authorization — not directly via URL?

Processing:
- If processing images with GD or Imagick, is there a size limit before decoding?
- If processing ZIP (ZipArchive), is zip slip protection in place?
  Validate: $entry->name must not contain ../ and must not start with /

WordPress Uploads:
- Is the WordPress uploads directory correctly configured to not execute PHP?
- Are file type restrictions enforced in wp_check_filetype_and_ext()?

For each finding, provide the upload endpoint, the vulnerable code path, PoC payload/filename, and fix.
```

---

## 6. Infrastructure & PHP Configuration

```
You are an expert security engineer and review below.
Review all PHP configuration and infrastructure settings.

php.ini Security Settings:
- display_errors = Off (never in production — leaks code paths, filenames, DB errors)
- log_errors = On (log instead of display)
- expose_php = Off (hides PHP version from X-Powered-By header)
- allow_url_fopen = Off (prevent remote file reads)
- allow_url_include = Off (prevent RFI)
- open_basedir = /var/www/html (restrict file operations to webroot)
- disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec (if not needed)
- session.use_strict_mode = 1
- session.cookie_httponly = 1
- session.cookie_secure = 1

HTTP Security Headers:
- Are X-Content-Type-Options, X-Frame-Options, HSTS, Referrer-Policy, Content-Security-Policy headers set?
- Is a PHP middleware or web server configuration setting these?

CORS:
- Is Access-Control-Allow-Origin: * set on authenticated API endpoints?
- Are CORS headers set with appropriate Access-Control-Allow-Credentials?

Web Server:
- Is directory listing disabled in Apache (Options -Indexes) / Nginx (autoindex off)?
- Are .git, .env, composer.json, and other sensitive files blocked from web access?
- Is PHP error display disabled at the web server level?

Laravel-Specific:
- Is APP_DEBUG=false in production .env?
- Is APP_KEY set (used for encryption)?
- Are .env files blocked from web access (Laravel places it outside webroot by default — verify)?

Dependency Security:
- Run composer audit — list all packages with known CVEs
- Are dependencies in composer.lock pinned to specific versions?
- Are there known vulnerable packages (old Guzzle, Monolog, etc.)?

For each issue, specify the configuration file, the insecure setting, and the corrected value.
```

---

## 7. Business Logic & Race Conditions

```
You are an expert security engineer and review below.
Analyze business logic in this PHP codebase for logic flaws.

Race Conditions:
- Are there check-then-act patterns in PHP without database-level locking?
  Example: Check user's balance, then deduct — two concurrent requests can both pass the check
  Fix: Use SELECT ... FOR UPDATE inside a transaction (BEGIN/COMMIT)
  Laravel: DB::transaction(function() { ... }) with lockForUpdate()
- Are file-based locks (flock) used correctly with exclusive locking?

State Machine:
- Are model state transitions validated before saving?
- Can a malicious user skip a required step (e.g., confirm an order without paying)?

Access Control:
- Is resource ownership verified before returning or modifying?
  Dangerous: Order::find($request->order_id) — no ownership check
  Safe: Order::where('id', $request->order_id)->where('user_id', Auth::id())->firstOrFail()
- Can a user modify their own role or subscription tier via a profile update endpoint?

WordPress:
- Can a subscriber-role user access Subscriber-Only AND admin-only AJAX actions by guessing action names?
- Are capability checks performed (current_user_can('manage_options')) before admin operations?

Numeric Handling:
- Are monetary values calculated with bcmath (bcadd, bcsub, bcmul) — not floating-point arithmetic?
- Are negative amounts blocked at the validation layer?

For each finding, describe the full attack scenario and provide the exact fix.
```

---

## 8. Verification & Re-scan After Patching

```
You are an expert security engineer and review below.
I have applied security patches to this PHP codebase. Perform a verification pass:

1. Re-scan every modified file — did any fix introduce new vulnerabilities?
2. Re-test every confirmed finding — is the vulnerability eliminated?
3. Run composer audit — check for newly introduced CVEs.
4. Search for the same vulnerable pattern codebase-wide:
   Example: if unserialize($_COOKIE['x']) was found, grep all unserialize() calls.
   Example: if echo $_GET['x'] was found, grep all echo/print without htmlspecialchars.
5. Run PHPStan / Psalm for static analysis on modified files.
6. Run Semgrep with PHP security rules.
7. Run PHPCS with Security Audit sniffs.

Output per finding:
- Verification status: Confirmed Fixed / Still Vulnerable / New Issue Introduced
- If Still Vulnerable, show what remains exploitable
- Updated CVSS 3.1 score
- Recommended next action
```

---

## Quick Reference: PHP Dangerous Sinks

| Category | Dangerous Pattern | Safe Alternative |
|---|---|---|
| SQL | `$pdo->query("WHERE id=" . $id)` | `$stmt->prepare("WHERE id=?")->execute([$id])` |
| XSS | `echo $_GET['name']` | `echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8')` |
| LFI | `include($_GET['page'] . '.php')` | Allowlist of valid pages |
| RFI | `include($url)` + `allow_url_include=On` | Disable `allow_url_include` |
| Deser | `unserialize($_COOKIE['data'])` | Use JSON; never unserialize user data |
| Command | `exec("convert " . $filename)` | `exec("convert " . escapeshellarg($filename))` |
| SSRF | `file_get_contents($userUrl)` | URL allowlist + block private ranges |
| XXE | `simplexml_load_string($xml)` (default) | `libxml_disable_entity_loader(true)` |
| Path | `file_get_contents($base . $path)` | `realpath` + `strpos(base)` check |

---

*Generated for PHP security audits. Adapt prompts to your specific framework (Laravel, Symfony, WordPress, CodeIgniter, Yii, CakePHP).*

---

## 9. Advanced Validation & Triage (Mythos Workflow)

For high-confidence findings, apply the Mythos advanced validation pipeline:
1. **Cross-Model Corroboration:** Have a skeptic model review the finding.
2. **Dynamic Executable-PoC:** Generate an isolated, executable Proof-of-Concept to confirm the vulnerability.
3. **Variant Hunting:** Search the codebase for similar patterns using the confirmed finding as a signature.
4. **Chain-Severance Proof:** Verify that the proposed patch actively breaks the PoC and critical attack path.
