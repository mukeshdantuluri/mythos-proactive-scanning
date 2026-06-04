# 🩹 Scan Segment 15 — Patch Generation

> **Standalone prompt segment.** Use with a confirmed, exploited finding. Replace the placeholder before running.

---

## Prompt

```
You are an expert security engineer and review below.
Generate a production-ready fix for the following vulnerability:

[PASTE THE CONFIRMED FINDING WITH EXPLOIT]
```

---

## Fix Requirements

- The fix must be **minimal** — change only what's necessary to eliminate the vulnerability. Do not refactor surrounding code.
- The fix must **not break existing functionality**. If it could, flag what tests should be run.
- The fix must follow the **existing code style and patterns** in this codebase.
- Include a **regression test** that proves:
  - `a.` The vulnerability **existed** *(test would have failed before the fix)*
  - `b.` The vulnerability is now **eliminated** *(test passes after the fix)*
- If the fix requires a **database migration**, provide it.
- If the fix requires **configuration changes**, specify them exactly.

---

## Deliverables

1. The exact **code changes** *(as a diff)*
2. The **regression test**
3. Any **deployment notes or migration steps**
4. Confirmation that the fix addresses the **root cause**, not just the symptom

---

## 🛠 Technology-Specific Patch Templates

### SQL Injection Fix

```python
# Python / SQLAlchemy — BEFORE (vulnerable)
def get_user(username: str):
    return db.execute(f"SELECT * FROM users WHERE username='{username}'").fetchone()

# AFTER (fixed)
def get_user(username: str):
    return db.execute(
        text("SELECT * FROM users WHERE username=:username"),
        {"username": username}
    ).fetchone()

# Regression test
def test_sql_injection_prevented():
    result = get_user("' OR '1'='1")
    assert result is None, "SQL injection should return no results"
```

```javascript
// Node.js / Knex — BEFORE (vulnerable)
const user = await db.raw(`SELECT * FROM users WHERE username='${username}'`);

// AFTER (fixed)
const user = await db.raw('SELECT * FROM users WHERE username = ?', [username]);

// Regression test (Jest)
test('SQL injection is prevented', async () => {
  const result = await getUser("' OR '1'='1");
  expect(result).toBeNull();
});
```

### XSS Fix

```python
# Python / Jinja2 — BEFORE (vulnerable)
return render_template_string(f"<div>{user_input}</div>")

# AFTER (fixed) — auto-escaped Jinja2 template
return render_template("safe_template.html", content=user_input)
# In safe_template.html: <div>{{ content }}</div>  (auto-escaped)

# Regression test
def test_xss_escaped():
    payload = "<script>alert('xss')</script>"
    response = client.get(f"/page?q={payload}")
    assert "<script>" not in response.text
    assert "&lt;script&gt;" in response.text
```

```typescript
// React — BEFORE (vulnerable)
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// AFTER (fixed)
<div>{userContent}</div>  // React auto-escapes

// If HTML rendering is required, use DOMPurify:
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />
```

### IDOR Fix

```python
# FastAPI — BEFORE (vulnerable, no ownership check)
@app.get("/documents/{doc_id}")
async def get_document(doc_id: str, current_user=Depends(get_current_user)):
    return db.query(Document).filter(Document.id == doc_id).first()

# AFTER (fixed — ownership enforced)
@app.get("/documents/{doc_id}")
async def get_document(doc_id: str, current_user=Depends(get_current_user)):
    doc = db.query(Document).filter(
        Document.id == doc_id,
        Document.owner_id == current_user.id  # ← ownership check
    ).first()
    if not doc:
        raise HTTPException(status_code=404)
    return doc

# Regression test
def test_idor_prevented(client, user_a_token, user_b_document_id):
    response = client.get(
        f"/documents/{user_b_document_id}",
        headers={"Authorization": f"Bearer {user_a_token}"}
    )
    assert response.status_code == 404
```

### Command Injection Fix

```python
# BEFORE (vulnerable)
import subprocess
subprocess.run(f"convert {filename} output.png", shell=True)

# AFTER (fixed — no shell, args as list)
import subprocess, os
safe_filename = os.path.basename(filename)  # strip path traversal
subprocess.run(["convert", safe_filename, "output.png"], shell=False)
```

```javascript
// BEFORE (vulnerable)
const { exec } = require('child_process');
exec(`ffmpeg -i ${userFile} output.mp4`);

// AFTER (fixed)
const { execFile } = require('child_process');
const path = require('path');
const safeFile = path.basename(userFile);
execFile('ffmpeg', ['-i', safeFile, 'output.mp4']);
```

### Path Traversal Fix

```python
# BEFORE (vulnerable)
file_path = os.path.join(BASE_DIR, user_path)
with open(file_path) as f:
    return f.read()

# AFTER (fixed)
import os
resolved = os.path.realpath(os.path.join(BASE_DIR, user_path))
if not resolved.startswith(os.path.realpath(BASE_DIR)):
    raise PermissionError("Path traversal detected")
with open(resolved) as f:
    return f.read()

# Regression test
def test_path_traversal_blocked():
    with pytest.raises(PermissionError):
        read_file("../../etc/passwd")
```

### Database Migration Template (If Fix Requires Schema Change)

```sql
-- Migration: add missing index for tenant isolation
-- File: migrations/0042_add_tenant_id_index.sql

BEGIN;

-- Add NOT NULL constraint that was missing
ALTER TABLE documents ALTER COLUMN tenant_id SET NOT NULL;

-- Add index for efficient tenant-scoped queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_tenant_id
ON documents(tenant_id);

-- Verify: no rows with NULL tenant_id
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM documents WHERE tenant_id IS NULL) THEN
    RAISE EXCEPTION 'Data integrity violation: NULL tenant_id rows exist';
  END IF;
END $$;

COMMIT;
```

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - The confirmed vulnerability finding with reproduction steps
# - Existing code style preferences (tabs vs spaces, naming conventions)
# - Test framework in use (pytest, Jest, JUnit, xUnit, Go test, etc.)
# - Whether you need the fix as a PR diff or full file replacement
# - Database migration tool (Alembic, Flyway, Liquibase, Prisma Migrate, EF migrations)
# - Whether any breaking changes are acceptable or zero-downtime is required
# - CI/CD steps to run after applying the patch (test suite, lint, SAST scan)
```
