# 🛡️ Scan Segment 20 — Chain-Severance Proof & CI Workflow

> **Standalone prompt segment.** Use to ensure patches fully break the attack chain.

---

## Prompt

```
You are an expert security engineer and review below.
Here is the proposed patch for the following exploit chain:
[PASTE PATCH]
[PASTE COMPOSITE POC]

Verify that this minimal patch severs the longest critical path of the attack graph.
Then, emit a GitHub Actions (or relevant CI) workflow file that will continuously 
scan for this specific regression in future commits.
```

---

## Verification Steps

**1. Minimal Patch:**
> Ensure the patch is minimal and doesn't introduce sweeping refactors that could break other functionalities.

**2. Severing the Chain:**
> Confirm that the composite Proof of Concept (PoC) fails against the patched version of the code. The patch must break the critical path of the attack.

**3. Regression Prevention:**
> Develop a strategy (e.g., a specific SAST rule, a custom script, or a test case) to automatically check for this vulnerability in the future.

---

## Deliverables

1. **Confirmation of Chain-Severance:** Explain how the patch breaks the exploit chain and provide evidence that the composite PoC now fails.
2. **CI Workflow Configuration:** A YAML file (e.g., GitHub Actions) or equivalent CI configuration that implements the regression prevention strategy.

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - The proposed patch and the composite PoC.
# - Your preferred CI/CD system (e.g., GitHub Actions, GitLab CI, CircleCI).
# - Existing security scanning tools used in your pipeline (e.g., Semgrep, CodeQL) to integrate the new rule into.
```
