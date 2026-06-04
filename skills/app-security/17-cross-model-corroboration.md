# 🤝 Scan Segment 17 — Cross-Model Corroboration

> **Standalone prompt segment.** Use to eliminate false positives by introducing cross-model consensus.

---

## Prompt

```
You are an expert security engineer and review below.
I have identified the following potential vulnerabilities. I need you to act as a skeptic.
Please review these findings independently. Do not assume they are correct. 
Provide a critical analysis of why each finding might be a false positive or unexploitable.
Only promote findings where the evidence is undeniable.

[PASTE THE FINDINGS HERE]
```

---

## What to Analyze

**1. Is the finding a false positive?**
> Review the finding against the specific context of the codebase and its logic. Look for any mitigating factors that the initial scan might have missed (e.g., input sanitization occurring in a different layer, network boundaries).

**2. Is the finding actually exploitable?**
> A theoretical vulnerability is different from an exploitable one. Does the attacker have a practical way to deliver the payload and reach the vulnerable sink?

**3. Does the finding require a specific condition?**
> Note any prerequisites for the exploit to work (e.g., specific configurations, authenticated user role, user interaction).

---

## Deliverables

For each finding, provide:
- A definitive `CONFIRMED` or `REJECTED` status.
- A technical justification for the rejection or confirmation.
- Any mitigating controls identified that block the exploit.

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - The findings from previous scan segments.
# - Details about the initial model that generated the findings (if relevant).
# - Information about any custom sanitization, validation, or security middleware in place.
```
