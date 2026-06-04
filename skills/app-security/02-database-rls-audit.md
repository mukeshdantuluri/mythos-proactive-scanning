# 🗄️ Scan Segment 02 — Database & RLS Audit

> **Standalone prompt segment.** Paste the block below directly into Claude Opus to begin this scan. Run independently or as part of the full 16-step audit pipeline.

---

## Prompt

```
You are an expert security engineer and review below.
Audit every database interaction in this codebase. For each table and RLS policy,
determine what data is accessible and to whom.
```

---

## What to Check

| Check | Description |
|---|---|
| User Row Isolation | Can an authenticated user access rows belonging to other users? |
| Anonymous Access | Can an anonymous user access data they shouldn't? |
| SQL Injection | Are there injection vectors, even through ORMs? |
| Security Definer | Are there any `SECURITY DEFINER` functions that bypass RLS? |
| Missing Policies | Are there tables with no RLS policies applied? |
| Edge Function Auth | Can any edge function be called without proper authentication? |

---

## Deliverables

For each finding, describe the **exact API call or query** that would demonstrate the vulnerability.

---

## 🛠 Technology-Specific Guidance

### Python (SQLAlchemy / Django ORM / psycopg2)
- SQLAlchemy: check for `text()` calls with f-strings or `%` formatting instead of `:param` binding
- Django ORM: look for `.raw()`, `.extra(where=...)`, or `RawSQL()` with user-controlled input
- psycopg2: every `cursor.execute()` must use `%s` parameterization — never string concatenation
- Django multi-tenant: is `get_tenant()` applied as a queryset filter on every model manager?

### JavaScript / Node.js (Prisma / TypeORM / Knex / Supabase)
- Prisma: `$queryRaw` / `$executeRaw` with template literals are safe; backtick string concatenation is not
- TypeORM: `createQueryBuilder().where("user.id = " + id)` is dangerous — use `:id` params
- Knex: `.whereRaw("id = " + id)` — check all `.whereRaw()` and `.raw()` calls
- Supabase RLS: verify `auth.uid()` is referenced in every RLS policy; check for `SECURITY DEFINER` functions that bypass RLS

### Java (Hibernate / JPA / JDBC)
- JPQL: `em.createQuery("FROM User WHERE id=" + id)` is injectable — use named params `:id`
- Native queries: `@Query(nativeQuery=true, value="..."+param+"...")` is dangerous
- JDBC: `Statement.executeQuery(sql)` with concatenation — must be `PreparedStatement`
- Spring Data: are all `@Repository` methods using derived queries or `@Param`?

### .NET (EF Core / Dapper / ADO.NET)
- EF: `FromSqlRaw("SELECT * WHERE id=" + id)` — must use `FromSqlInterpolated($"...{id}...")` or explicit `SqlParameter`
- Dapper: `Query<T>("SELECT ... WHERE x='" + val + "'")` — must use `new { val }` parameter object
- ADO.NET: every `SqlCommand` must use `SqlParameter`, never string concatenation
- Multi-tenant: global query filter `HasQueryFilter(x => x.TenantId == tenantId)` in `DbContext`

### Go (sqlx / GORM / pgx)
- `db.Query("SELECT * WHERE id=" + id)` — must use `$1` positional params
- GORM: `.Where("name = " + name)` is dangerous — use `.Where("name = ?", name)`
- pgx: use `pgx.QueryRow(ctx, sql, args...)` with positional params only

### PHP (Laravel Eloquent / Doctrine / PDO)
- Laravel: `DB::select("SELECT * WHERE id=" . $id)` — use `DB::select("... WHERE id=?", [$id])`
- Eloquent: `User::whereRaw("id=" . $id)` is dangerous — use `whereRaw("id=?", [$id])`
- PDO: every `prepare()` must be followed by `bindParam()` or `execute([$val])`
- Laravel multi-tenant: is `GlobalScope` applied per tenant on all models?

### Supabase / PostgreSQL RLS Specifically
- List all tables: which have `ROW LEVEL SECURITY` enabled?
- For each policy: does it reference `auth.uid()` or `auth.role()`?
- Are any functions `SECURITY DEFINER` — if so, do they re-check permissions internally?
- Can `anon` role access any table without a policy explicitly permitting it?

---

## 🎯 Fine-Tune This Segment

Add context below to sharpen the scan for your specific stack:

```
# Paste here:
# - Database type (PostgreSQL, MySQL, SQLite, MongoDB, DynamoDB, etc.)
# - ORM or query library in use
# - Whether RLS / row-level security is implemented (Supabase, PostgreSQL policies)
# - Multi-tenant architecture details (tenant_id column, schema-per-tenant, etc.)
# - Any database migration tool (Flyway, Alembic, Liquibase, Prisma Migrate)
# - Read replica or sharding configuration
```
