# ETL Pipeline Security Audit Guide

> Comprehensive security scanning prompts for ETL (Extract, Transform, Load) pipelines: Apache Airflow, dbt, Spark, NiFi, Kafka, AWS Glue, Azure Data Factory, Talend, Singer, Fivetran-custom connectors, and custom Python/Scala ETL code.

---

## 1. Authentication & Access to Data Sources

```
You are an expert security engineer and review below.
Review the entire authentication configuration across all ETL components. Trace how credentials are managed from the orchestrator to each source and destination. Identify:

Credential Storage:
- Are database connection strings, API keys, and passwords stored in:
  - Airflow Connections (encrypted in Airflow's secret backend — not plaintext in DAG files)?
  - AWS Secrets Manager, Azure Key Vault, GCP Secret Manager?
  - Environment variables (acceptable) vs hardcoded in pipeline code (dangerous)?
  - dbt profiles.yml — is this file committed to git? Does it contain plaintext passwords?
- Are Airflow Variable values containing secrets encrypted (AIRFLOW__CORE__FERNET_KEY set)?

Service Accounts / IAM:
- Are ETL processes using dedicated service accounts with least-privilege permissions?
- Does the ETL service account have write access to tables it should only read from?
- Are overly broad IAM roles used? (S3: s3:* vs s3:GetObject on specific prefixes)
- Are temporary credentials (STS AssumeRole, Workload Identity) used instead of long-lived keys?

Source System Authentication:
- Are source system credentials rotated regularly?
- Are there shared credentials used by multiple pipelines (rotation affects all at once)?
- Are API tokens scoped to read-only where applicable?

For each finding, provide the component, configuration location, and the remediated credential management approach.
```

---

## 2. SQL Injection in ETL Transformations

```
You are an expert security engineer and review below.
Audit every SQL statement in this ETL codebase for injection vulnerabilities.

Dynamic SQL Construction:
- Are any SQL queries in transformation steps built using string concatenation or f-strings with external data?
  Dangerous (Python/Airflow): sql = f"INSERT INTO {table_name} SELECT * FROM {source} WHERE date='{run_date}'"
  Dangerous if table_name or run_date come from external input (API response, file name, config)
- Are dbt Jinja templates constructing SQL with unsanitized variables?
  Dangerous: {{ "SELECT * FROM " ~ var('user_table') }} where var comes from external input
  Safe: Use dbt ref() and source() for table references, not dynamic string construction
- Are EXECUTE or sp_executesql statements in stored procedures called by ETL pipelines safe?

Airflow SQL Operators:
- Are PostgresOperator, MsSqlOperator, MySqlOperator, BigQueryOperator using parameterized queries or safe templated SQL?
- Is {{ params.table_name }} in Airflow SQL templates validated before use?

External Input in ETL:
- If the ETL pipeline reads filenames, API response fields, or user-provided configuration to determine which tables/columns to process, are those values validated against an allowlist?
- Can a malicious actor inject SQL by uploading a CSV with a specially crafted filename used in a COPY statement?

For each finding, show the pipeline step, the exact code path from external input to SQL, a PoC payload, and the parameterized fix.
```

---

## 3. Data Extraction Security

```
You are an expert security engineer and review below.
Audit the extraction (source) phase of all ETL pipelines.

API Source Security:
- Are webhook payloads from source systems verified with HMAC signatures before processing?
- Are OAuth tokens for source APIs stored securely and refreshed before expiry?
- Can the source API deliver malicious payloads that the ETL pipeline processes unsafely?

File-Based Extraction:
- Are source files (CSV, JSON, Parquet, XML) from external parties validated before processing?
- Is there a file size limit before parsing? Can a decompression bomb (zip, gzip) exhaust resources?
- If processing XML source files, is XXE disabled in the XML parser?
- Are CSV files checked for formula injection? (Values starting with =, +, -, @ that execute in spreadsheets)
  Should not matter for ETL (not opened in Excel), but validate if files are subsequently delivered to end users
- Is the source file path validated to prevent path traversal when constructing file reads?
  Dangerous: open(base_dir + "/" + incoming_filename)
  Safe: use os.path.basename(incoming_filename) and validate against expected pattern

SFTP / S3 / Cloud Storage:
- Are SFTP host keys verified (no StrictHostKeyChecking=no)?
- Are S3 source buckets in the same account, or is cross-account access properly restricted?
- Is S3 bucket versioning and MFA-delete enabled on source data buckets?

Database Source:
- Are source database accounts read-only?
- Is CDC (Change Data Capture) access scoped to only the replicated tables?

For each finding, provide the extraction step, the vulnerability, and the remediation.
```

---

## 4. Data Transformation Security

```
You are an expert security engineer and review below.
Audit the transformation phase for security vulnerabilities.

Code Execution in Transformations:
- If using PythonOperator or custom Python tasks in Airflow, is user-supplied configuration ever passed to eval(), exec(), or subprocess?
- Are dbt macros or Jinja templates rendering user-supplied content that could enable SSTI?
- Are Spark user-defined functions (UDFs) sandboxed? Can a UDF cause SSRF or read local filesystem?
- Can malformed input data cause the transformation to crash (DoS) or produce incorrect results silently?

Schema/Column Injection:
- If column names or table names are derived from source data (schema-on-read), are they validated before use in SQL?
- Can an attacker deliver a source file with a column named "; DROP TABLE production;--"?

Data Validation:
- Is input data validated against expected types, ranges, and formats before transformation?
- Are there data type coercions that could silently corrupt data (implicit casting, truncation)?
- Is null/empty handling correct — could null propagation corrupt downstream aggregations?

Sensitive Data in Transformation:
- Are PII fields (SSN, credit card, email) masked, tokenized, or encrypted before landing in intermediate staging tables?
- Are transformation intermediate outputs (temp tables, S3 staging prefixes) as restricted as the final output?
- Is sensitive data written to logs during transformation (spark.conf.set, print statements)?

For each finding, provide the transformation step, the vulnerability, and the fix.
```

---

## 5. Data Loading Security

```
You are an expert security engineer and review below.
Audit the load (destination) phase of all ETL pipelines.

Destination Permissions:
- Does the ETL service account have DROP TABLE, TRUNCATE, or DDL permissions on destination tables?
  (Should only need INSERT/UPSERT in most cases)
- Can the ETL process modify tables or schemas beyond its intended targets?

Bulk Load Security:
- If using COPY, LOAD DATA INFILE, or bcp, are file paths hardcoded or derived from trusted sources only?
- Is LOAD DATA LOCAL INFILE disabled (MySQL security risk)?
- Are bulk load operations run with minimal database permissions?

Upsert / Merge Logic:
- Are MERGE statements written safely (no injection through dynamic key columns)?
- Is idempotency ensured — can a re-run cause double-loading?

Destination Data Protection:
- Is sensitive data encrypted at rest in the destination (column-level encryption, Transparent Data Encryption)?
- Are destination tables access-restricted (only the BI layer and authorized users can query)?
- Are audit logs (who queried what, when) enabled on the destination warehouse?

For each finding, provide the load step, the vulnerability, and the remediation.
```

---

## 6. Pipeline Orchestration Security (Airflow, Prefect, dbt Cloud)

```
You are an expert security engineer and review below.
Audit the pipeline orchestration layer for security issues.

Airflow-Specific:
- Is the Airflow web UI accessible without authentication (is auth_backend set)?
- Is the Airflow metadata database (postgres/mysql) accessible from the internet?
- Are Airflow DAG files written by users other than the airflow service account?
  (DAG files are executed as Python — a writable DAGs folder is a code execution vulnerability)
- Are Airflow connections stored in the DB encrypted (Fernet key set)?
- Is Airflow running with the least-privilege executor (LocalExecutor on single-node, not unconstrained)?
- Are Airflow REST API endpoints authenticated and rate-limited?
- Is example_dags disabled in production (may expose test DAGs)?

dbt-Specific:
- Are dbt profiles.yml credentials stored in environment variables, not in the file?
- Is dbt source freshness configured to alert on stale data (data quality + availability)?
- Are dbt macros that accept user-defined variables sanitizing input before SQL interpolation?

General Orchestration:
- Are pipeline trigger APIs (webhooks, REST) authenticated?
- Can an unauthorized user trigger a pipeline manually and cause unintended data loads?
- Are pipeline execution logs access-controlled (they may contain connection details)?

For each finding, provide the orchestration component, the vulnerability, and the secure configuration.
```

---

## 7. Secrets & Sensitive Data in Pipelines

```
You are an expert security engineer and review below.
Scan all ETL code and configuration for secrets and sensitive data exposure.

Hardcoded Credentials:
- Are passwords, API keys, or connection strings in DAG files, dbt macros, Spark jobs, or SQL scripts?
- Are .env files or profiles.yml committed to git?
  Check: git log --all --full-history -- dbt/profiles.yml airflow/dags/*.py
- Are there default fallback credentials: os.getenv('DB_PASSWORD', 'admin')?

Logging:
- Do ETL framework logs (Airflow task logs, Spark logs) capture:
  - Full SQL queries (which may contain sensitive data)?
  - Connection strings?
  - Row-level PII from source data?
- Is sensitive data printed in transformation debugging statements?

Data Masking / Pseudonymization:
- Is PII (names, emails, SSNs, credit cards) masked before writing to non-production environments?
- Are test/development pipelines using production data?
- Is tokenization or format-preserving encryption applied to sensitive identifiers?

Intermediate Storage:
- Are S3 staging buckets encrypted (SSE-S3, SSE-KMS)?
- Are staging buckets public-read? (Should be private, accessed only by ETL role)
- Are temporary files on ETL workers deleted after use?
- Are intermediate Spark shuffle files protected?

For each finding, specify the component, the sensitive data exposure, and the remediation.
```

---

## 8. Data Quality & Business Logic Security

```
You are an expert security engineer and review below.
Audit ETL pipelines for business logic vulnerabilities that could corrupt or exfiltrate data.

Data Exfiltration via ETL:
- Can a malicious actor modify a pipeline configuration to redirect data to an unauthorized destination?
- Are destination endpoints (S3 buckets, database connections) validated against an allowlist?
- Can a pipeline operator exfiltrate data by adding an unauthorized destination step?

Data Integrity:
- Are row counts validated between source and destination?
- Are checksums or hash comparisons performed to verify data is not corrupted in transit?
- Are duplicate records detected and handled? Can a replay attack cause double-loading?

Race Conditions:
- Can two concurrent pipeline runs corrupt shared state (same output table, same S3 prefix)?
- Are pipeline runs idempotent? What happens if a run is retried after partial success?
- Are database transactions used for multi-table loads?

Access to Historical Data:
- Can the ETL pipeline access and load historical data ranges a user is not authorized to see?
- Are date-range parameters in backfill jobs validated (no unbounded historical extraction)?

For each finding, describe the attack scenario and provide the pipeline-level fix.
```

---

## 9. Verification & Re-audit After Remediation

```
You are an expert security engineer and review below.
I have applied security patches to these ETL pipelines. Perform a verification pass:

1. Re-scan every modified pipeline, DAG, and transformation — did any fix introduce new issues?
2. Re-test every confirmed finding — is the vulnerability eliminated?
3. Verify no credentials are committed to git: git log --all --full-history -S "password" -- .
4. Run a dbt compile and check all generated SQL for injection patterns.
5. Re-audit Airflow connections for plaintext passwords.
6. Run pip audit / cargo audit on ETL worker dependencies.
7. Verify IAM policies for ETL service accounts are still least-privilege after changes.

Output per finding:
- Verification status: Confirmed Fixed / Still Vulnerable / New Issue Introduced
- If Still Vulnerable, show what remains
- Updated risk rating
- Recommended next action
```

---

## Quick Reference: ETL Security Checklist

| Area | Check | Risk if Violated |
|---|---|---|
| Credentials | No plaintext secrets in DAG/dbt files | Secret exposure |
| SQL | No dynamic SQL with unvalidated external input | SQL injection |
| File parsing | Size + type limits on source files | DoS / path traversal |
| IAM | Read-only source, write-only destination, scoped roles | Data exfiltration |
| Airflow DAGs | DAG folder not writable by untrusted users | RCE |
| Intermediate data | Staging buckets private + encrypted | Data breach |
| Logging | No PII or secrets in pipeline logs | PII exposure |
| Idempotency | Retry-safe pipelines with dedup logic | Data corruption |
| PII masking | Masked before non-prod environments | PII breach |
| Orchestration API | Authenticated + rate-limited trigger endpoints | Unauthorized pipeline execution |

---

*Generated for ETL security audits. Adapt prompts to your specific stack (Airflow, dbt, Spark, NiFi, AWS Glue, Azure Data Factory, Fivetran, Kafka Streams).*

---

## 9. Advanced Validation & Triage (Mythos Workflow)

For high-confidence findings, apply the Mythos advanced validation pipeline:
1. **Cross-Model Corroboration:** Have a skeptic model review the finding.
2. **Dynamic Executable-PoC:** Generate an isolated, executable Proof-of-Concept to confirm the vulnerability.
3. **Variant Hunting:** Search the codebase for similar patterns using the confirmed finding as a signature.
4. **Chain-Severance Proof:** Verify that the proposed patch actively breaks the PoC and critical attack path.
