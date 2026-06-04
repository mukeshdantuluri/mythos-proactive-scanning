# 🌐 Scan Segment 12 — Network Attack Surface Mapping

> **Standalone prompt segment.** Paste the block below directly into Claude Opus to begin this scan.

---

## Prompt

```
You are an expert security engineer and review below.
Based on the deployment configuration and code you've reviewed,
map the complete network attack surface.

For every network-accessible service:
- What port does it listen on?
- Is it intended to be public?
- What authentication is required?
- What's the most damaging action an unauthenticated attacker could take?
- What's the most damaging action an authenticated low-privilege user could take?
```

---

## Specific Checks

- Database ports exposed to the internet (`5432`, `3306`, `6379`, `27017`)
- Admin panels **without VPN/IP restriction**
- Debug endpoints left in production (`/debug`, `/metrics`, `/health` with sensitive data)
- **GraphQL introspection** enabled in production
- **Swagger/OpenAPI docs** exposed in production
- **WebSocket endpoints** without authentication
- **gRPC reflection** enabled in production
- Internal microservice endpoints **reachable from the internet**

---

## Deliverables

Produce a **network map** showing every listening service, its authentication requirement, and your risk assessment.

---

## 🛠 Technology-Specific Guidance

### Common Dangerous Exposures by Port

| Port | Service | Risk |
|---|---|---|
| 5432 | PostgreSQL | Full DB access if credentials are weak |
| 3306 | MySQL/MariaDB | Full DB access |
| 6379 | Redis | Unauthenticated by default in many configs |
| 27017 | MongoDB | Unauthenticated by default in many configs |
| 9200 | Elasticsearch | No auth by default in older versions |
| 8080/8443 | Admin/Internal API | Often lacks prod auth controls |
| 2375 | Docker daemon (TCP) | Full host takeover |
| 2379/2380 | etcd (Kubernetes) | Cluster credential exposure |

### Python — Exposing Dangerous Endpoints

```python
# FastAPI — disable docs in production
app = FastAPI(
    docs_url=None if os.getenv("ENV") == "production" else "/docs",
    redoc_url=None if os.getenv("ENV") == "production" else "/redoc",
    openapi_url=None if os.getenv("ENV") == "production" else "/openapi.json",
)

# Django — disable admin in production or restrict by IP
# In urls.py — remove admin URLs entirely or add IP middleware
```

### Node.js — Restrict Dangerous Endpoints

```javascript
// Express — hide X-Powered-By header
app.disable('x-powered-by');

// Restrict /metrics to internal network only
app.get('/metrics', (req, res) => {
  const clientIp = req.ip;
  if (!clientIp.startsWith('10.') && !clientIp.startsWith('172.') && clientIp !== '127.0.0.1') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  // serve metrics
});
```

### GraphQL — Disable Introspection in Production

```javascript
// Apollo Server
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  plugins: [
    // Disable query depth attacks
    {
      requestDidStart() {
        return {
          didResolveOperation({ request, document }) {
            const depth = getMaxDepth(document);
            if (depth > 5) throw new Error('Query too deep');
          }
        };
      }
    }
  ]
});
```

```python
# Strawberry / Graphene — disable introspection
from strawberry.extensions import DisableIntrospection

schema = strawberry.Schema(
    query=Query,
    extensions=[DisableIntrospection] if IS_PRODUCTION else [],
)
```

### Java (Spring Boot) — Actuator Lockdown

```yaml
# application.yml
management:
  server:
    port: 9090           # separate port, firewalled from internet
  endpoints:
    web:
      exposure:
        include: "health"
  endpoint:
    health:
      show-details: "never"
```

### .NET — Swagger in Production

```csharp
// Program.cs — only enable Swagger in Development
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
```

### Redis Security

```bash
# redis.conf — require authentication
requirepass "strong-random-password-here"
# Bind to localhost only (not 0.0.0.0)
bind 127.0.0.1
# Disable dangerous commands
rename-command FLUSHALL ""
rename-command CONFIG ""
rename-command DEBUG ""
```

### gRPC — Disable Reflection in Production

```go
// Go gRPC
import "google.golang.org/grpc/reflection"

if os.Getenv("ENV") != "production" {
    reflection.Register(grpcServer)  // only in dev/staging
}
```

### Docker Compose — Port Exposure Audit

```yaml
# BAD — exposes DB to all interfaces
services:
  postgres:
    ports:
      - "5432:5432"   # accessible from internet if host has no firewall

# GOOD — bind to localhost only
  postgres:
    ports:
      - "127.0.0.1:5432:5432"
    # or better: no ports directive, use internal Docker network only
```

### Network Reachability Test Commands

```bash
# From outside your network — test what's publicly reachable:
nmap -sV -p 22,80,443,3306,5432,6379,8080,8443,9200,27017 your-server-ip

# Check all listening ports on the server itself:
ss -tlnp          # Linux
netstat -tlnp     # older Linux
lsof -i -P -n | grep LISTEN  # macOS
```

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - All services running (list container names or processes)
# - Cloud provider and whether security groups / firewall rules are defined
# - Whether a VPN or bastion host is used for internal services
# - Whether GraphQL is used and if introspection is currently enabled
# - Monitoring/metrics stack (Prometheus, Datadog agent, etc.) and its exposure
# - gRPC services and whether reflection is enabled
# - WebSocket endpoints and their current authentication requirements
```
