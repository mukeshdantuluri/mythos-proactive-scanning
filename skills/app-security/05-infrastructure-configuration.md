# ⚙️ Scan Segment 05 — Infrastructure & Configuration

> **Standalone prompt segment.** Paste the block below directly into Claude Opus to begin this scan. Run independently or as part of the full 16-step audit pipeline.

---

## Prompt

```
You are an expert security engineer and review below.
Review all infrastructure configuration files (Dockerfile, docker-compose, vercel.json,
cloudflare configs, nginx configs, environment variable handling).
```

---

## What to Verify

| Config Area | Questions |
|---|---|
| Containers | Are containers running as root? Are unnecessary ports exposed? |
| CORS | Are CORS policies overly permissive? |
| Security Headers | Are CSP, HSTS, and X-Frame-Options configured correctly? |
| Rate Limits | Are rate limits configured on all public endpoints? |
| TLS | Is TLS configured correctly? |

---

## 🛠 Technology-Specific Guidance

### Docker & Container Security
```dockerfile
# BAD — runs as root, copies everything, uses latest tag
FROM node:latest
COPY . .
RUN npm install
CMD ["node", "index.js"]

# GOOD — non-root user, .dockerignore, pinned digest
FROM node:20-alpine@sha256:<digest>
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
USER node
CMD ["node", "index.js"]
```
- Is `USER` non-root in every service's Dockerfile?
- Are `ENV` instructions used for secrets (baked into image layers)?
- Is `.dockerignore` excluding `.env`, `*.key`, `node_modules`, `.git`?
- Are ports beyond what's needed exposed in `docker-compose.yml`?

### nginx / Caddy / Traefik
```nginx
# Required security headers in nginx:
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```
- Are all headers above present and not overridden by app-level headers?
- Is `server_tokens off` set (hides nginx version)?
- Is TLS 1.0 and 1.1 disabled (`ssl_protocols TLSv1.2 TLSv1.3`)?
- Are weak cipher suites excluded?

### Vercel / Netlify / Cloudflare Pages
- Are security headers set in `vercel.json` or `netlify.toml` `[[headers]]`?
- Is `CORS` policy in `vercel.json` routes scoped to specific origins?
- Are environment variables set in dashboard (not committed to repo)?
- Cloudflare: is WAF enabled? Are firewall rules blocking known attack patterns?

### Python-Specific (Gunicorn / Uvicorn)
- Is Gunicorn running with `--workers` set to a reasonable number (not unlimited)?
- Is `--timeout` set to prevent slow-loris attacks?
- Is Uvicorn behind a reverse proxy (not directly exposed)?

### Node.js-Specific (PM2 / Docker)
- Is `NODE_ENV=production` set (disables dev-only middleware)?
- Is the app listening on `0.0.0.0` behind a proxy, or directly internet-facing?
- Are `--max-old-space-size` limits set to prevent OOM crashes becoming DoS vectors?

### Java-Specific (Spring Boot / Tomcat)
- Spring Boot Actuator: are `/actuator/*` endpoints protected or disabled?
  ```yaml
  management.endpoints.web.exposure.include: health
  management.endpoint.health.show-details: never
  ```
- Is Tomcat's `server.xml` disabling the `AJP connector` (port 8009)?

### .NET-Specific (Kestrel / IIS)
- Is Kestrel configured with `Limits.MaxRequestBodySize`?
- Is HTTPS redirection enforced and HSTS enabled?
- Are IIS request filtering rules applied?

### CI/CD (GitHub Actions / GitLab CI)
- Are secrets set as `${{ secrets.KEY }}` (never hardcoded in YAML)?
- Are third-party Actions pinned to a full commit SHA (not `@main` or `@v1`)?
- Can a PR author modify `.github/workflows/` to exfiltrate secrets (`pull_request_target` misuse)?
- Are deployment credentials scoped to minimum permissions (OIDC preferred over long-lived keys)?

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - Cloud provider and services used (ECS, EKS, GKE, Azure AKS, Fly.io, Railway, etc.)
# - Reverse proxy / CDN in use (nginx, Caddy, Cloudflare, AWS ALB, etc.)
# - Deployment platform (Vercel, Netlify, Heroku, Render, etc.)
# - CI/CD system (GitHub Actions, GitLab CI, CircleCI, Jenkins, etc.)
# - Whether Kubernetes is used (different attack surface — RBAC, NetworkPolicy, PodSecurity)
# - Any WAF in use and its ruleset
```
