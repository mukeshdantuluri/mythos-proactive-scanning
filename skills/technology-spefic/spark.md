# Apache Spark Security Audit Guide

> Comprehensive security scanning prompts for Apache Spark deployments: Spark on Kubernetes, YARN, EMR, Databricks, Apache Spark Structured Streaming, Spark SQL, Delta Lake, and PySpark / Scala Spark applications.

---

## 1. Authentication & Authorization

```
You are an expert security engineer and review below.
Review the entire authentication and authorization configuration of this Spark deployment. Identify:

Spark Authentication:
- Is Spark authentication enabled? (spark.authenticate = true)
- Is the Spark authentication secret managed securely (not hardcoded in spark-defaults.conf)?
- Is Spark running on Kerberos-authenticated YARN? Are keytabs stored securely with restricted permissions?
- On Kubernetes: is RBAC configured for the Spark service account?
  - Does the service account have only the minimum required permissions?
  - Is the service account scoped to a specific namespace?

Databricks-Specific:
- Are workspace-level and cluster-level access controls enabled?
- Are personal access tokens (PATs) used with expiry and minimal scope?
- Is Unity Catalog enforcing column-level and row-level access control?
- Are cluster policies restricting what configurations users can apply?

Spark History Server:
- Is the Spark History Server accessible from the internet?
- Is authentication enabled on the History Server? (spark.history.ui.acls.enable)
- Does the History Server expose sensitive data (SQL query text, data samples)?

Spark UI:
- Is the Spark UI (port 4040) exposed to the internet?
- Is Spark UI access restricted by ACLs? (spark.ui.acls.enable = true)
- Does the Spark UI expose sensitive query parameters or data schemas?

For each finding, specify the configuration key, current value, risk, and the corrected setting.
```

---

## 2. Spark SQL Injection

```
You are an expert security engineer and review below.
Audit all Spark SQL usage in this codebase for injection vulnerabilities.

Dynamic SQL Construction:
- Are Spark SQL queries constructed with string concatenation or f-string interpolation of external input?
  Dangerous (PySpark): spark.sql(f"SELECT * FROM {table_name} WHERE date='{run_date}'")
  If table_name or run_date come from external input (API, config, filename), this is injectable
  Safe: Use spark.table(table_name) after validating table_name against an allowlist
         Use DataFrame API: df.filter(col("date") == run_date) instead of raw SQL

Parameter Sources:
- What is the source of values used in Spark SQL strings?
  - Airflow DAG parameters (--conf spark.some.param=user_input)?
  - Command-line arguments (sys.argv, argparse)?
  - Configuration files loaded from S3/ADLS (are those files restricted)?
  - Kafka/stream message content used to determine SQL logic?

Delta Lake / Table Names:
- Are Delta table paths constructed from user input?
  Dangerous: spark.read.format("delta").load(f"s3://bucket/{user_table_name}/")
  Safe: Validate against allowlist of known table paths

Spark Catalog:
- Are catalog operations (CREATE TABLE, DROP TABLE, ALTER TABLE) performed with user-controlled names?
- Is there a risk of a privilege escalation attack by creating a table that shadows an existing one?

For each finding, show the full external-input-to-SQL path, a PoC payload, and the safe DataFrame API rewrite.
```

---

## 3. Data Access Security

```
You are an expert security engineer and review below.
Audit data access controls in this Spark deployment.

Cloud Storage (S3, ADLS, GCS):
- Are IAM roles for Spark execution scoped to only the buckets and prefixes it needs?
- Is the Spark execution role limited to specific operations (s3:GetObject, not s3:*)?
- Can the Spark application access metadata services (169.254.169.254) via credentials in environment?
- Are EMR EC2 instance profiles or Kubernetes service account annotations granting excessive permissions?

Data Lake Access Control:
- Is Apache Ranger or AWS Lake Formation enforcing column-level and row-level security?
- Can a Spark user bypass Lake Formation permissions by reading S3 directly (not via Glue catalog)?
- Are data governance policies enforced at the Spark SQL layer or only at the application layer?

Sensitive Data:
- Does the Spark job process PII (SSN, credit cards, health data)?
  - Is it masked before writing to output?
  - Is it masked before writing to non-production data lakes?
- Are Spark DataFrames with sensitive data persisted to disk (local temp files, shuffle files)?
  - Are shuffle directories encrypted? (spark.io.encryption.enabled = true)
  - Are local disk files encrypted? (spark.io.encryption.enabled)

Cross-Tenant Data:
- In multi-tenant Spark environments, can one job access another tenant's data by manipulating paths or catalog entries?
- Are table access controls enforced per job/user, or is there shared read access?

For each finding, provide the data path, the access control gap, and the remediation (IAM policy, Lake Formation rule, or code change).
```

---

## 4. Code Execution & Injection in Spark

```
You are an expert security engineer and review below.
Find all code execution vulnerabilities in this Spark codebase.

PySpark eval() / exec():
- Any eval(user_input) or exec(user_input) in PySpark transformation functions?
- Are UDFs (user-defined functions) constructed from user-supplied code?
  Dangerous: udf(eval(user_code_string), returnType=StringType())

Arbitrary Python/Scala Code via Notebooks:
- Can end users submit arbitrary notebook code that runs with the Spark cluster's IAM role?
- Are there guardrails (cluster policies, whitelist of allowed commands) on shared clusters?

Shell Commands in Spark:
- Any subprocess, os.system, or sc.parallelize([cmd]).flatMap(lambda x: [subprocess.check_output(x)]) patterns?
- Can a Spark job trigger shell commands on executor nodes?

Spark Serialization / Closures:
- Are Python closures passed to map/filter/flatMap capturing secrets (database passwords, API keys)?
  Closures are serialized and sent to executors — ensure no secrets are captured in closure scope
- Are Java/Scala objects serialized with Kryo or Java serialization? Are they deserialized from untrusted sources?

Dynamic Class Loading:
- Is spark.driver.extraClassPath or spark.executor.extraClassPath set to paths writable by untrusted users?
- Can a user inject a malicious JAR by uploading it to a shared S3 location used as a class path?

For each finding, show the code path, PoC, severity, and fix.
```

---

## 5. Secrets & Sensitive Data in Spark Jobs

```
You are an expert security engineer and review below.
Scan all Spark job code and configuration for secrets and sensitive data exposure.

Hardcoded Credentials:
- Are passwords, API keys, or connection strings hardcoded in PySpark/Scala files?
  Dangerous: jdbc_url = "jdbc:postgresql://host:5432/db?user=admin&password=secret123"
  Safe: Use spark.conf.get("spark.jdbc.password") set via Spark secrets integration, or AWS Secrets Manager
- Are secrets in Spark submit command-line args (visible in process list and job logs)?
  Dangerous: --conf spark.jdbc.password=secret — visible in `ps aux` on executor nodes
  Safe: Use --conf spark.hadoop.fs.s3a.secret.key or Vault integration

Databricks Secrets:
- Are Databricks secret scopes used for all credentials (dbutils.secrets.get)?
- Are secret values printed in notebook output or logs?

Spark Logs:
- Do Spark job logs (on S3, HDFS, or Databricks) contain:
  - Full SQL query text (which may include sensitive filter values)?
  - JDBC connection strings with credentials?
  - Sample data rows from sensitive tables?
- Is spark.eventLog.enabled logging to a restricted location?

Shuffle Files:
- Are shuffle/spill files on executor local disks encrypted?
  spark.io.encryption.enabled = true
  spark.io.encryption.keySizeBits = 256
- Can an attacker on the same executor node access another job's shuffle files?

For each finding, specify the component, the sensitive data exposure, and the remediation.
```

---

## 6. Network & Infrastructure Security

```
You are an expert security engineer and review below.
Review the network configuration and infrastructure of this Spark deployment.

Network Exposure:
- Are Spark driver and executor ports exposed beyond the cluster network?
  Spark driver: 4040 (UI), 7077 (standalone master)
  Block these from public internet access
- Is the Spark REST API (port 6066 on standalone mode) accessible externally? (Allows remote job submission)
- Is YARN ResourceManager UI (8088) or Spark History Server (18080) accessible from the internet?

Encryption in Transit:
- Is RPC encryption enabled? (spark.network.crypto.enabled = true)
- Is SSL enabled for Spark UI? (spark.ssl.ui.enabled = true)
- Are JDBC connections to external databases using SSL/TLS?
  spark.jdbc.url should include sslmode=require for PostgreSQL, useSSL=true for MySQL
- Is data in transit between Spark and S3 / HDFS encrypted (HTTPS for S3, encrypted HDFS RPC)?

Kubernetes Security (if applicable):
- Is the Spark driver pod running as root? (Should use securityContext.runAsNonRoot: true)
- Are unnecessary host namespaces shared? (hostNetwork, hostPID should be false)
- Are resource limits set on driver and executor pods? (Prevent resource exhaustion)
- Is the Kubernetes API server accessible from executor pods? (Check RBAC and network policies)

EMR Security:
- Is EMR cluster running in a public subnet?
- Is the master node security group allowing inbound 0.0.0.0/0?
- Is EMR encryption at rest and in transit enabled?
  (EMR security configuration: encryption provider for EBS and S3)

For each finding, specify the component, network exposure, and the firewall/configuration fix.
```

---

## 7. Structured Streaming Security

```
You are an expert security engineer and review below.
Audit all Spark Structured Streaming applications for security issues.

Kafka Source Security:
- Is Kafka connection using SSL/TLS? (kafka.security.protocol = SSL or SASL_SSL)
- Is SASL authentication configured? (SCRAM-SHA-512 or GSSAPI/Kerberos)
- Are Kafka credentials (keystore passwords, SASL passwords) stored in Spark secrets, not in code?
- Is the Kafka consumer group limited to only the topics it needs?

Malicious Stream Data:
- Is data arriving in the Kafka stream validated and sanitized before processing?
- Can a malicious Kafka producer inject data that causes SQL injection in downstream Spark SQL?
- Can a malicious message cause the stream processor to crash (DoS via malformed Avro/Protobuf)?

State Store Security:
- Is the Structured Streaming state store (checkpoint directory) stored in a restricted S3/HDFS location?
- Can a third party read or corrupt the state store?

Output Sink Security:
- Are output sinks (Delta Lake, JDBC, Kafka) access-controlled to only the Spark job's service account?
- Is Delta Lake output using ACID transactions to prevent partial writes?
- Are output paths validated to prevent data being redirected to unintended locations?

For each finding, provide the streaming component, the vulnerability, and the fix.
```

---

## 8. Verification & Re-audit After Remediation

```
You are an expert security engineer and review below.
I have applied security patches to this Spark deployment. Perform a verification pass:

1. Re-scan every modified Spark configuration file and job code — did any fix introduce new issues?
2. Re-test every confirmed finding — is the vulnerability eliminated?
3. Run a Spark SQL analysis across all jobs: grep for spark.sql( with string concatenation.
4. Re-audit IAM policies for the Spark service account — are they still least-privilege?
5. Re-verify network exposure: are Spark UI, History Server, and REST API still locked down?
6. Confirm shuffle encryption and RPC encryption are active by checking running cluster config.
7. Verify Spark job logs do not contain credentials or sensitive data samples.

Output per finding:
- Verification status: Confirmed Fixed / Still Vulnerable / New Issue Introduced
- If Still Vulnerable, show what remains
- Updated risk rating
- Recommended next action
```

---

## Quick Reference: Spark Security Checklist

| Area | Config Key / Pattern | Secure Value |
|---|---|---|
| Authentication | `spark.authenticate` | `true` |
| RPC Encryption | `spark.network.crypto.enabled` | `true` |
| IO Encryption | `spark.io.encryption.enabled` | `true` |
| UI ACLs | `spark.ui.acls.enable` | `true` |
| Spark SQL injection | `spark.sql(f"...{user_input}...")` | Use DataFrame API / allowlist |
| Credentials in logs | `--conf spark.jdbc.password=secret` | Use Secrets Manager / Vault |
| Exposed ports | Spark UI 4040, REST 6066 | Restrict to VPC/internal network |
| Shuffle files | Local disk, unencrypted | `spark.io.encryption.enabled=true` |
| IAM role | `s3:*` on all buckets | Scoped to specific prefix + operations |
| Kafka auth | `PLAINTEXT` security protocol | `SASL_SSL` with SCRAM |

---

*Generated for Apache Spark security audits. Adapt prompts to your deployment (EMR, Databricks, Spark on Kubernetes, YARN, Spark Standalone).*

---

## 9. Advanced Validation & Triage (Mythos Workflow)

For high-confidence findings, apply the Mythos advanced validation pipeline:
1. **Cross-Model Corroboration:** Have a skeptic model review the finding.
2. **Dynamic Executable-PoC:** Generate an isolated, executable Proof-of-Concept to confirm the vulnerability.
3. **Variant Hunting:** Search the codebase for similar patterns using the confirmed finding as a signature.
4. **Chain-Severance Proof:** Verify that the proposed patch actively breaks the PoC and critical attack path.
