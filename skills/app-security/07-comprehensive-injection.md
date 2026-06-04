# 💉 Scan Segment 07 — Comprehensive Injection Analysis

> **Standalone prompt segment.** Paste the block below directly into Claude Opus to begin this scan. Run independently or as part of the full 16-step audit pipeline.

---

## Prompt

```
You are an expert security engineer and review below.
Perform a comprehensive injection vulnerability analysis of this codebase.
Trace every path where external input reaches a dangerous sink.

External input includes: HTTP request parameters, headers, body, cookies,
URL path segments, file uploads, webhook payloads, WebSocket messages,
and any data read from the database that originated from user input.
```

---

## Injection Types to Check

### SQL Injection
- Any raw SQL with **string concatenation or template literals**?
- Any ORM calls that accept **raw SQL fragments**?
- **Second-order SQL injection** (stored data used in later queries)?
- Are **parameterized queries** used *everywhere*?

### NoSQL Injection *(MongoDB, DynamoDB, Redis)*
- Can query operators (`$gt`, `$ne`, `$regex`) be **injected via user input**?
- Are object inputs **validated for unexpected keys**?

### Command Injection
- Any calls to `exec()`, `spawn()`, `system()`, or shell commands?
- Are arguments passed as **arrays (safe)** or **strings (dangerous)**?
- Can **environment variables** be influenced by user input?

### Path Traversal
- Any file operations using **user-controlled paths**?
- Is `../../../etc/passwd` possible?
- Are **symlinks followed**?

### XSS (Cross-Site Scripting)
- Is user input **rendered in HTML without escaping**?
- Are there `dangerouslySetInnerHTML` / `v-html` / `[innerHTML]` usages?
- Is user input **reflected in JavaScript contexts**?
- Are **CSP headers** properly configured?

### SSRF (Server-Side Request Forgery)
- Does the server make HTTP requests to **user-provided URLs**?
- Can an attacker reach **internal services** (`169.254.169.254`, `localhost`)?
- Are **URL protocols restricted** (no `file://`, no `gopher://`)?

### Template Injection
- Are user inputs passed to **template engines**?
- Can server-side template injection achieve **RCE**?

### Header Injection
- Can user input end up in **HTTP response headers**?
- **CRLF injection** possible?

---

## 🛠 Technology-Specific Guidance

### Python
```python
# Command Injection — DANGEROUS
import subprocess
subprocess.run(f"convert {user_filename} output.png", shell=True)

# SAFE — no shell, args as list
subprocess.run(["convert", user_filename, "output.png"], shell=False)

# Template Injection — DANGEROUS (Jinja2 eval)
from jinja2 import Template
Template(user_input).render()  # RCE if user controls the template string

# SAFE — render user data INTO a static template, never render user data AS a template
template = env.get_template("email.html")
template.render(name=user_input)

# Path Traversal
import os
safe_path = os.path.realpath(os.path.join(BASE_DIR, user_path))
assert safe_path.startswith(BASE_DIR)  # must come after realpath
```

### JavaScript / Node.js
```javascript
// Command Injection — DANGEROUS
const { exec } = require('child_process');
exec(`ffmpeg -i ${userFile} output.mp4`);  // shell injection via filename

// SAFE — execFile with args array, no shell
const { execFile } = require('child_process');
execFile('ffmpeg', ['-i', userFile, 'output.mp4']);

// XSS — DANGEROUS
element.innerHTML = userComment;               // DOM XSS
res.send(`<div>${req.query.name}</div>`);     // Reflected XSS

// SAFE
element.textContent = userComment;
res.send(`<div>${escapeHtml(req.query.name)}</div>`);

// SSRF
const url = new URL(userInput);
const BLOCKED = ['localhost', '127.0.0.1', '169.254.169.254', '::1'];
if (BLOCKED.includes(url.hostname)) throw new Error('Blocked');
```

### Java
```java
// Command Injection — DANGEROUS
Runtime.getRuntime().exec("ls " + userInput);

// SAFE
ProcessBuilder pb = new ProcessBuilder("ls", userInput);

// Template Injection (FreeMarker / Velocity)
// Never pass user input as the template string itself
Template t = cfg.getTemplate("static-template.ftl");  // static name only
t.process(dataModel, out);  // user data goes into dataModel, not template name

// SSTI via Thymeleaf — dangerous if template name is user-controlled:
// modelAndView.setViewName("redirect:" + userInput)  → open redirect + SSTI
```

### .NET
```csharp
// Command Injection — DANGEROUS
Process.Start("cmd.exe", "/c " + userInput);

// SAFE
var psi = new ProcessStartInfo("cmd.exe");
psi.ArgumentList.Add("/c");
psi.ArgumentList.Add(userInput);

// Path Traversal
var fullPath = Path.GetFullPath(Path.Combine(baseDir, userPath));
if (!fullPath.StartsWith(baseDir, StringComparison.OrdinalIgnoreCase))
    throw new UnauthorizedAccessException();

// XXE — SAFE config
var settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};
```

### Go
```go
// Command Injection — DANGEROUS
exec.Command("sh", "-c", "ls "+userInput).Run()

// SAFE
exec.Command("ls", userInput).Run()

// Path Traversal
clean := filepath.Clean(filepath.Join(baseDir, userPath))
if !strings.HasPrefix(clean, baseDir) {
    return errors.New("path traversal detected")
}
```

### PHP
```php
// Command Injection — DANGEROUS
system("convert " . $_GET['file'] . " output.png");

// SAFE — escapeshellarg
system("convert " . escapeshellarg($_POST['file']) . " output.png");

// Template Injection (Twig)
// NEVER: $twig->createTemplate($userInput)->render($data)
// SAFE:  $twig->render('static.html.twig', ['input' => $userInput])
```

---

## Deliverables Per Finding

1. Exact **code path** from input to dangerous sink
2. A **proof-of-concept payload**
3. **Severity rating** (CVSS 3.1)
4. The **specific fix**

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - Template engine in use (Jinja2, Nunjucks, Handlebars, FreeMarker, Twig, Razor, etc.)
# - Whether the app runs shell commands and for what purpose
# - GraphQL endpoint details (introspection enabled? batching? depth limits?)
# - Any LDAP / Active Directory integration
# - Whether XML is parsed anywhere (document upload, SOAP APIs, configuration)
# - NoSQL databases in use (MongoDB operators, Redis Lua scripts, DynamoDB filters)
# - WebSocket usage and message format
```
