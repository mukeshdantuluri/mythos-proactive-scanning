# 🧠 Scan Segment 09 — Business Logic Flaws

> **Standalone prompt segment.** Paste the block below directly into Claude Opus to begin this scan.

---

## Prompt

```
You are an expert security engineer and review below.
Analyze the business logic of this application for logic flaws that automated
scanners would miss. These are bugs that survive years of review because
they aren't simple injection — they're logical errors.

For each logic bug: explain the full attack scenario from the attacker's perspective
and provide a specific fix.
```

---

## What to Analyze

### Race Conditions
- Double-spending, double-booking, or duplicate resource creation via concurrent requests?
- Are financial operations **atomic**? (check-then-act is vulnerable)
- **TOCTOU** gaps anywhere?

### State Machine Violations
- Can state transitions be **forced out of order**?
- Can a cancelled order be shipped or a refund **issued twice**?

### Numeric Handling
- **Integer overflow/underflow** in financial calculations?
- **Floating-point precision** issues in money handling?
- **Negative quantity / negative price** exploitation?

### Access Control Logic
- Privilege escalation via **modifying own profile**?
- Free-tier user accessing paid features by **manipulating requests**?
- **Deleted/disabled account** still accessing resources?

### Rate Limiting & Abuse
- **Resource exhaustion** via email, SMS, or API calls?
- **Trial/free tier abuse** to circumvent payment?

### Information Leakage Through Behavior
- **Response timing** revealing whether a resource exists?
- **Enumeration attacks** extracting the user list?

---

## 🛠 Technology-Specific Guidance

### Race Conditions — Database-Level Fixes

**Python (SQLAlchemy)**
```python
# DANGEROUS — check-then-act
balance = db.query(Account).filter_by(id=account_id).first().balance
if balance >= amount:
    account.balance -= amount  # race: another request passes same check

# SAFE — atomic conditional update
result = db.execute(
    update(Account)
    .where(Account.id == account_id, Account.balance >= amount)
    .values(balance=Account.balance - amount)
    .returning(Account.balance)
)
if result.rowcount == 0:
    raise InsufficientFundsError()
```

**Node.js (Prisma)**
```typescript
// SAFE — transaction with FOR UPDATE lock
await prisma.$transaction(async (tx) => {
  const [account] = await tx.$queryRaw`
    SELECT * FROM accounts WHERE id = ${accountId} FOR UPDATE`;
  if (account.balance < amount) throw new Error('Insufficient funds');
  await tx.account.update({
    where: { id: accountId },
    data: { balance: { decrement: amount } }
  });
});
```

**Java (Spring) — Optimistic Locking**
```java
@Entity
public class Account {
    @Version
    private Long version;  // throws OptimisticLockException on conflict
    private BigDecimal balance;
}
```

**.NET (EF Core) — Row Version**
```csharp
[Timestamp]
public byte[] RowVersion { get; set; }
```

### Money — Always Use Decimal

```python
from decimal import Decimal, ROUND_HALF_UP
amount = Decimal("19.99")
tax = (amount * Decimal("0.08")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
if amount <= 0:
    raise ValueError("Amount must be positive")
```

```java
// Java — BigDecimal always, never double
BigDecimal price = new BigDecimal("19.99");
BigDecimal tax = price.multiply(new BigDecimal("0.08"))
                      .setScale(2, RoundingMode.HALF_UP);
```

### State Machine — Enforce Valid Transitions

```python
ALLOWED_TRANSITIONS = {
    "pending": ["processing", "cancelled"],
    "processing": ["shipped", "cancelled"],
    "shipped": ["delivered"],
    "cancelled": [],
    "delivered": [],
}
def transition_order(order, new_status):
    if new_status not in ALLOWED_TRANSITIONS[order.status]:
        raise ValueError(f"Invalid: {order.status} → {new_status}")
    order.status = new_status
```

### Timing Attacks — Constant-Time Comparison

```python
import hmac
# SAFE
if hmac.compare_digest(user_token.encode(), stored_token.encode()): ...
```

```javascript
const crypto = require('crypto');
if (!crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))) { /* fail */ }
```

---

## 🎯 Fine-Tune This Segment

```
# Paste here:
# - Core business entities and their state machines (order statuses, subscription states, etc.)
# - Financial operations: payments, credits, refunds, subscriptions?
# - Whether multiple concurrent users can modify the same resource
# - Tier/plan system: how are feature limits enforced?
# - Idempotency requirements (payment retries, webhook retries)
# - Background job processing (Celery, Sidekiq, BullMQ, Hangfire, etc.)
# - Soft-delete pattern (deleted_at timestamp, is_deleted flag, etc.)
```
