# ⚙️ Scan Segment 18 — Dynamic Executable-PoC Verification

> **Standalone prompt segment.** Use to mandate that every vulnerability has a working proof-of-concept.

---

## Prompt

```
You are an expert security engineer and review below.
For the confirmed vulnerabilities, generate an executable Python PoC script.
The PoC MUST:
1. Target the vulnerable sink directly.
2. Execute cleanly as a subprocess.
3. Exit with status 0 and output `SINK REACHED` only if successful.
4. Not cause permanent damage or data loss to the target system.

[PASTE THE CONFIRMED FINDINGS HERE]
```

---

## PoC Requirements

- **Self-Contained:** The script should be entirely self-contained (e.g., a single Python file) with minimal external dependencies.
- **Clear Status:** The script must definitively exit with status 0 and output a specific string (like `SINK REACHED`) upon successful exploitation.
- **Safe:** The PoC must be safe to run against a local test environment without causing irreversible damage.
- **Targeted:** The PoC must specifically target the vulnerability identified, proving the exploit path.

---

## Deliverables

For each confirmed finding, provide:
1. The **executable Python PoC script**.
2. **Instructions** on how to set up the local environment and run the script.
3. The expected **stdout/stderr output** upon a successful run.

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - The confirmed findings you want to verify.
# - Instructions on how the local test environment is configured (e.g., base URLs, required headers, test user credentials).
# - Any specific constraints or dependencies for the Python environment.
```
