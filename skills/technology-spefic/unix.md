# Unix / Linux Systems Security Audit Guide

> Comprehensive security scanning prompts for Unix/Linux infrastructure: shell scripts, system configuration, services, permissions, and OS-level security controls.

---

## 1. Authentication & Access Controls

```
You are an expert security engineer and review below.
Review the entire authentication and access control configuration on this Unix/Linux system. Identify:

PAM Configuration:
- Is PAM (Pluggable Authentication Modules) properly configured in /etc/pam.d/?
- Is pam_faillock or pam_tally2 configured to lock accounts after N failed attempts?
- Is pam_pwquality or pam_cracklib enforcing strong password requirements?
- Are SUID/SGID bits set only on necessary binaries? (find / -perm -4000 -o -perm -2000)
- Is pam_unix using sha512 for password hashing (not MD5)?

SSH Configuration (/etc/ssh/sshd_config):
- Is PermitRootLogin set to no or prohibit-password?
- Is PasswordAuthentication set to no (key-only)?
- Is Protocol 2 enforced?
- Is AllowUsers or AllowGroups set to restrict which accounts can SSH?
- Is MaxAuthTries ≤ 3?
- Is ClientAliveInterval and ClientAliveCountMax configured?
- Is X11Forwarding disabled?
- Is AllowTcpForwarding disabled or restricted?
- Are HostKey types limited to ed25519 and rsa (no DSA, ECDSA with weak curves)?

sudo Configuration (/etc/sudoers, /etc/sudoers.d/):
- Are there NOPASSWD entries? Who can sudo without a password?
- Are there wildcards in sudo rules that allow privilege escalation?
  Example: /usr/bin/vim * — allows editing /etc/passwd
- Are there sudo rules that allow running arbitrary commands: (ALL) ALL?
- Is !requiretty set (allows sudo from non-interactive shells)?
- Is log_input and log_output enabled for sudo sessions?

User Accounts:
- Are there accounts with UID 0 other than root? (awk -F: '$3==0' /etc/passwd)
- Are there accounts with empty passwords? (awk -F: '$2==""' /etc/shadow)
- Are service accounts (daemon, nobody, etc.) set to nologin or false shell?
- Are there home directories for service accounts that shouldn't have them?

For each finding, specify the configuration file, the insecure setting, and the corrected value.
```

---

## 2. File Permissions & SUID/SGID

```
You are an expert security engineer and review below.
Audit all file permissions and SUID/SGID binaries on this Unix/Linux system.

SUID/SGID Binaries:
- List all SUID binaries: find / -perm -4000 -type f 2>/dev/null
- List all SGID binaries: find / -perm -2000 -type f 2>/dev/null
- For each binary, is it expected to have SUID/SGID? Is it patched?
- Are any non-standard SUID binaries present (not part of base OS packages)?
- Can any SUID binary be exploited for privilege escalation? (Check GTFOBins)

World-Writable Files:
- List all world-writable files: find / -perm -0002 -not -path /proc/* -not -path /sys/* 2>/dev/null
- Are any world-writable files in system directories (/etc, /usr, /bin, /sbin)?
- Are any world-writable scripts executed by root (cron jobs, init scripts)?

Sensitive File Permissions:
- /etc/shadow: must be 640 root:shadow (not world-readable)
- /etc/passwd: must be 644
- /etc/sudoers: must be 440 root:root
- /etc/ssh/sshd_config: must be 600 root:root
- /root: must be 700
- ~/.ssh directories: must be 700; authorized_keys must be 600

Cron Jobs:
- List all cron jobs: crontab -l, /etc/cron.d/, /etc/cron.daily/, /var/spool/cron/
- Are any cron scripts world-writable or in world-writable directories?
- Do any cron jobs run as root and execute user-controlled scripts or paths?
- Are wildcard (* ) usages in cron job commands dangerous? (tar * can be exploited)

Capabilities:
- List all files with capabilities: getcap -r / 2>/dev/null
- Are any capabilities overly broad (cap_sys_admin, cap_net_admin on unexpected binaries)?

For each finding, provide the file path, current permissions, the risk, and the corrected permissions command.
```

---

## 3. Shell Script Security

```
You are an expert security engineer and review below.
Audit all shell scripts in this codebase/system for security vulnerabilities.

Command Injection:
- Are user-supplied values (environment variables, script arguments, read input) ever passed to:
  eval, sh -c, bash -c, xargs without -0, find -exec, awk system(), or backtick expansion?
- Are variables always double-quoted? ("$variable" vs $variable — word splitting and glob expansion)
  Dangerous: rm -rf $user_dir
  Safe: rm -rf "$user_dir"

Path Traversal / Wildcard Injection:
- Are wildcards used in operations on user-controlled paths?
  Dangerous: cp $src/* /dest/ — if src contains --preserve=mode or similar
- Are temporary files created securely: mktemp (not predictable paths like /tmp/script-$$)?

Race Conditions (TOCTOU):
- Is there a check followed by an action on a file (if [ -f "$file" ]; then cat "$file")
  without atomic guarantees? An attacker could replace the file between check and use.
- Are symlinks followed unexpectedly in operations on files in /tmp?

IFS (Internal Field Separator):
- Is IFS explicitly set or restored in scripts that process user input?
- Can IFS manipulation affect how commands are parsed?

Shebang & Shell Options:
- Are scripts using set -euo pipefail?
  -e: exit on error, -u: fail on unset vars, -o pipefail: catch pipeline failures
- Are shellcheck (ShellCheck linter) warnings addressed?

Secret Handling:
- Are passwords or API keys passed as command-line arguments? (Visible in ps aux)
  Dangerous: curl -u "user:$PASSWORD" ...
  Safe: Use --netrc or environment variable read from stdin
- Are secrets echoed to terminal or logs?
- Is set -x (debug mode) enabled in production scripts? (Logs all commands including secrets)

For each finding, provide the script path, line number, the vulnerable pattern, PoC, and the safe rewrite.
```

---

## 4. Network & Service Security

```
You are an expert security engineer and review below.
Audit the network configuration and exposed services on this Unix/Linux system.

Open Ports:
- List all listening services: ss -tlnp or netstat -tlnp
- For each listening port: what service is it? Is it intended to be public?
- Are database ports (5432 PostgreSQL, 3306 MySQL, 6379 Redis, 27017 MongoDB) exposed to the internet?
- Are admin ports (8080 Tomcat manager, 9000 SonarQube, 5601 Kibana) restricted to internal networks?

Firewall:
- Is iptables, nftables, or ufw configured?
- Is there a default-deny policy for inbound connections?
- Are rules reviewed and minimal (not "allow all" rules)?
- Is firewall state persisted across reboots?

Network Services:
- Are unnecessary services running? (telnet, rsh, rlogin, FTP — should be disabled)
- Is xinetd or inetd running with any insecure services?
- Is SNMP configured? Is the community string "public" or "private"?
- Is NFS configured? Are exports restricted by IP? Is no_root_squash used?

TLS/SSL:
- For all HTTPS services, what TLS version is supported? (sslscan, testssl.sh)
- Are TLS 1.0 and 1.1 disabled?
- Are weak cipher suites (DES, RC4, NULL, EXPORT) disabled?
- Is certificate expiry monitored?

For each finding, specify the service, port, the risk, and the firewall rule or configuration change needed.
```

---

## 5. System Hardening & OS Configuration

```
You are an expert security engineer and review below.
Audit the system hardening configuration of this Unix/Linux system.

Kernel Parameters (sysctl):
- Is net.ipv4.ip_forward disabled (unless this is a router)?
- Is net.ipv4.conf.all.accept_redirects = 0?
- Is net.ipv4.conf.all.send_redirects = 0?
- Is net.ipv4.tcp_syncookies = 1 (SYN flood protection)?
- Is kernel.randomize_va_space = 2 (ASLR enabled)?
- Is kernel.dmesg_restrict = 1 (non-root can't read kernel logs)?
- Is fs.suid_dumpable = 0 (prevent SUID core dumps)?

Security Modules:
- Is SELinux (enforcing mode) or AppArmor (enforce mode) enabled?
- Are there disabled SELinux rules that weaken the policy?
- Are any AppArmor profiles in complain mode rather than enforce?

Logging & Auditd:
- Is auditd running and configured?
- Are privileged command executions logged (execve syscall)?
- Are file access events logged for sensitive files (/etc/passwd, /etc/shadow, /etc/sudoers)?
- Are logs sent to a remote syslog server (prevent local log tampering)?
- Is logrotate properly configured?

Filesystem Mounts:
- Is /tmp mounted with noexec, nosuid, nodev options?
- Is /var/tmp similarly restricted?
- Is /home mounted with nosuid, nodev?
- Are removable devices mounted with noexec?

Package Management:
- Is the package manager configured to verify GPG signatures?
- Are automatic security updates enabled (unattended-upgrades, yum-cron)?
- Are there packages installed from untrusted third-party repositories?

For each finding, provide the sysctl key or mount option, the current value, and the required value.
```

---

## 6. Secrets & Sensitive Data on Disk

```
You are an expert security engineer and review below.
Scan this Unix/Linux system for exposed secrets and sensitive data.

Credentials in Files:
- Search for hardcoded credentials: grep -rn "password\|secret\|api_key\|token" /etc /opt /home /var/www 2>/dev/null
- Are .env files world-readable?
- Are application config files (database.yml, wp-config.php, .htpasswd) permission-restricted?
- Are private SSH keys (id_rsa, id_ecdsa) world-readable or in web-accessible directories?

History Files:
- Do shell history files (~/.bash_history, ~/.zsh_history) contain passwords or secrets?
  (Often: mysql -u root -pSECRET, aws configure commands with keys)
- Is HISTFILE=/dev/null or HISTSIZE=0 set for root and service accounts?

Core Dumps:
- Is core dumping enabled? Core dumps can contain secrets from process memory.
  Check: ulimit -c, /etc/security/limits.conf, /proc/sys/kernel/core_pattern
- Is fs.suid_dumpable=0 set?

Temporary Files:
- Are application temp files in /tmp world-readable?
- Are log files in /var/log containing passwords, tokens, or PII?
- Are database backup files (.sql, .dump) left in web-accessible directories?

For each finding, provide the file path, the sensitive content type, and the remediation (restrict permissions, rotate credentials, enable encryption).
```

---

## 7. Cron Jobs, Init Scripts & Service Units

```
You are an expert security engineer and review below.
Audit all scheduled tasks and service management on this Unix/Linux system.

Cron:
- List all cron jobs for all users: for u in $(cut -f1 -d: /etc/passwd); do crontab -u $u -l 2>/dev/null; done
- List system cron: /etc/crontab, /etc/cron.d/, /etc/cron.{daily,weekly,monthly}/
- For each cron job: what user does it run as? What script does it execute?
- Are executed scripts world-writable or in world-writable directories?
- Are absolute paths used in cron commands (not relative paths that depend on PATH)?

Systemd Service Units:
- List all enabled services: systemctl list-units --type=service --state=enabled
- For each service: what user does it run as? (User= in unit file)
  Should service accounts be used — not root?
- Are ExecStart paths absolute and not writable by non-root users?
- Are sensitive environment variables (passwords, tokens) in unit files (visible via systemctl show)?
  Use EnvironmentFile with restricted permissions instead
- Is PrivateTmp=true, NoNewPrivileges=true, ProtectSystem=strict set for services?

Init Scripts (SysV):
- Are /etc/init.d/ scripts world-writable?
- Do init scripts set a clean, restricted PATH?

For each finding, provide the job/unit file, the vulnerable configuration, and the hardened alternative.
```

---

## 8. Verification & Re-audit After Hardening

```
You are an expert security engineer and review below.
I have applied hardening changes to this Unix/Linux system. Perform a verification pass:

1. Re-check every modified configuration file — did any change introduce new issues?
2. Re-test every confirmed finding — is it eliminated?
3. Run Lynis (lynis audit system) and compare the hardening index before/after.
4. Run OpenSCAP against the appropriate STIG/CIS benchmark profile.
5. Re-scan open ports: ss -tlnp — are any new services unexpectedly listening?
6. Re-verify SUID binaries: find / -perm -4000 — were any new SUID binaries created?
7. Test that legitimate services still function after hardening (SSH, web server, database).

Output per finding:
- Verification status: Confirmed Fixed / Still Vulnerable / New Issue Introduced
- If Still Vulnerable, show what remains
- Recommended next action
```

---

## Quick Reference: Unix Security Audit Commands

```bash
# SUID/SGID binaries
find / -perm -4000 -o -perm -2000 2>/dev/null

# World-writable files
find / -perm -0002 -not -path /proc/* 2>/dev/null

# Files with capabilities
getcap -r / 2>/dev/null

# Listening services
ss -tlnp

# Accounts with UID 0
awk -F: '$3==0' /etc/passwd

# Accounts with empty passwords
awk -F: '$2==""' /etc/shadow

# Check sudoers for NOPASSWD
grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

# Run ShellCheck on scripts
shellcheck script.sh

# Run Lynis audit
lynis audit system

# Check failed login attempts
journalctl -u sshd | grep "Failed password"

# Find credentials in files
grep -rn "password\|secret\|api_key" /etc /opt /home 2>/dev/null
```

---

*Generated for Unix/Linux security audits. Adapt prompts to your specific distribution (Ubuntu, RHEL/CentOS, Debian, Amazon Linux, Alpine).*

---

## 9. Advanced Validation & Triage (Mythos Workflow)

For high-confidence findings, apply the Mythos advanced validation pipeline:
1. **Cross-Model Corroboration:** Have a skeptic model review the finding.
2. **Dynamic Executable-PoC:** Generate an isolated, executable Proof-of-Concept to confirm the vulnerability.
3. **Variant Hunting:** Search the codebase for similar patterns using the confirmed finding as a signature.
4. **Chain-Severance Proof:** Verify that the proposed patch actively breaks the PoC and critical attack path.
