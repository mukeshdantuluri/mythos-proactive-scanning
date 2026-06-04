# 🔍 Scan Segment 19 — Variant Hunting & Known-Issue Dedup

> **Standalone prompt segment.** Use to scale findings across the codebase.

---

## Prompt

```
You are an expert security engineer and review below.
We have confirmed the following bug class/vulnerability exists in the codebase:

[PASTE CONFIRMED VULNERABILITY/BUG SIGNATURE]

Act as a Variant Hunter. Search the entire codebase for other instances of this 
exact same bug class, vulnerable pattern, or similar logical flaws. 
Do not report on the original finding. Ensure you deduplicate against known issues.
```

---

## What to Look For

**1. Identical Patterns:**
> Search for exact or near-exact copies of the vulnerable code snippet elsewhere in the project (e.g., copied and pasted code).

**2. Similar API Usages:**
> If a specific API call is misused, check all other usages of that API (e.g., all instances of `dangerouslySetInnerHTML`, `eval()`, or `subprocess.run()`).

**3. Related Logical Flaws:**
> If a business logic flaw is found (e.g., missing ownership check), look for other endpoints that perform similar actions on similar resources.

---

## Deliverables

Produce a report including:
- A list of all **new variants found**, specifying file and line numbers.
- An assessment of whether each new variant is exploitable in the same way as the original finding.
- A deduplicated list of findings (do not re-report the original issue).

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - The confirmed vulnerability signature or pattern.
# - Information about code generation tools or common utility libraries used in the project.
# - A list of already known issues or accepted risks to avoid deduplication.
```
