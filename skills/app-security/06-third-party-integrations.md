# 🔌 Scan Segment 06 — Third-Party Integrations

> **Standalone prompt segment.** Paste the block below directly into Claude Opus to begin this scan. Run independently or as part of the full 16-step audit pipeline.

---

## Prompt

```
You are an expert security engineer and review below.
Review every third-party integration (payment processors, email services,
authentication providers, API connections).

For each integration assess:
- Are webhook signatures verified before processing?
- Are API keys stored securely with minimal permissions?
- Is data encrypted in transit to/from the third party?
- Could a compromised third-party account be used to access your system?
- Are there fallback or retry mechanisms that could be exploited?
```

---

## What to Assess Per Integration

- Are **webhook signatures verified** before processing?
- Are **API keys stored securely** with minimal permissions?
- Is **data encrypted in transit** to/from the third party?
- Could a **compromised third-party account** be used to access your system?
- Are there **fallback or retry mechanisms** that could be exploited?

---

## 🛠 Technology-Specific Guidance

### Payment Processors

**Stripe**
```python
# CORRECT — verify signature before trusting payload
import stripe
event = stripe.Webhook.construct_event(
    payload, sig_header, webhook_secret  # uses HMAC-SHA256
)

# WRONG — trusting the payload directly without verification
event = json.loads(request.body)
```
- Is `stripe.webhooks.construct_event()` (or equivalent) called with the raw body?
- Is the Stripe restricted key used (not the full secret key) scoped to minimum permissions?
- Are idempotency keys used on payment creation to prevent duplicate charges?

**PayPal / Braintree / Adyen**
- Is the webhook notification verified via the provider's SDK signature check?
- Are payment amounts validated server-side (never trust client-sent amounts)?

### Email Services (SendGrid / Mailgun / SES / Postmark)
- Are API keys stored in environment variables — never in source code?
- Is inbound email parsing (webhooks) signature-verified?
- Could an attacker trigger bulk email sends by abusing your API (DoS/cost attack)?
- Are email templates rendering user-controlled content safely (no XSS in HTML emails)?

### Authentication Providers (Auth0 / Clerk / Cognito / Supabase Auth / Firebase Auth)
- Are JWTs from the provider verified with the correct JWKS endpoint — not blindly trusted?
- Is the `aud` (audience) claim validated to prevent token reuse across services?
- Are OAuth2 redirect URIs strictly validated (no wildcards or open redirects)?
- Is the `state` parameter used in OAuth2 flows to prevent CSRF?

### Cloud Storage (S3 / GCS / Azure Blob)
- Are pre-signed URLs time-limited (15 minutes or less)?
- Are bucket/container permissions set to private (no public-read by default)?
- Are SAS tokens scoped to minimum permissions (read-only vs write)?
- Is server-side encryption enabled at rest?

### Twilio / SMS / Push Notifications
- Are Twilio webhook signatures verified (`X-Twilio-Signature` HMAC)?
- Could an attacker exhaust your SMS budget by triggering repeated OTP sends?
- Are phone numbers validated before being passed to Twilio APIs?

### Slack / Discord / MS Teams Webhooks (Outbound)
- Are webhook URLs stored securely (not committed to git)?
- Do error messages posted to Slack contain sensitive internal data?

### Node.js / Python / Java — Generic HTTP Client Checks
```javascript
// Check all outbound HTTP calls:
// - Is the base URL hardcoded or from env?
// - Is TLS verification disabled? (rejectUnauthorized: false is dangerous)
// - Are timeouts set to prevent hanging requests?
const response = await axios.get(url, {
  timeout: 5000,
  httpsAgent: new https.Agent({ rejectUnauthorized: true }) // must be true
});
```

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - List every third-party service integrated (payment, email, SMS, auth, storage, etc.)
# - Webhook providers and which endpoints receive their callbacks
# - Whether you use OAuth2 as a client (connecting to Google, GitHub, etc.)
# - Any AI/LLM API integrations (OpenAI, Anthropic) — prompt injection surface
# - Supply chain: any third-party scripts loaded client-side (tag managers, analytics)
# - Any external data feeds or partner APIs consumed
```
