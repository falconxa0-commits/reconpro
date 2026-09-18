# ReconPro Security Report

![ReconPro F](https://img.shields.io/badge/ReconPro-F-red?style=for-the-badge&labelColor=000000)

**Target:** `localhost`  
**Score:** 0/100  
**Grade:** F  
**Generated:** 2026-09-18 02:35:37 UTC  
**Scan Started:** 2026-09-18 02:35:36 UTC  
---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 4 |
| Medium | 6 |
| Low | 4 |
| Info | 4 |
| **Total** | **20** |

## Modules Run

`host`, `dev`, `doctor`

## Findings

| # | Severity | Category | Finding | Module | Conf. | Pts |
|---|----------|----------|---------|--------|-------|-----|
| 1 | critical | `kernel_cve` | Kernel potentially vulnerable to Dirty Pipe (CVE-2022-0847) | host | 80% | -15 |
| 2 | critical | `kernel_cve` | Kernel potentially vulnerable to netfilter nf_tables UAF (CVE-2024-1086) | host | 80% | -15 |
| 3 | high | `firewall` | No firewall detected | host | 80% | -10 |
| 4 | high | `env_secrets` | Database URL in environment: DATABASE_URL | host | 80% | -8 |
| 5 | high | `kernel_cve` | Kernel potentially vulnerable to Netfilter UAF (CVE-2021-4039) | host | 80% | -8 |
| 6 | high | `audit_logging` | No logging services detected (rsyslog/journald/auditd) | doctor | 80% | -10 |
| 7 | medium | `file_permissions` | World-readable: User account file (/etc/passwd) | host | 80% | -5 |
| 8 | medium | `mac` | No Mandatory Access Control (SELinux/AppArmor) detected | host | 80% | -5 |
| 9 | medium | `auth_policy` | Password max age is 99999 days (too long) | doctor | 80% | -4 |
| 10 | medium | `auth_policy` | No password complexity requirements configured | doctor | 80% | -5 |
| 11 | medium | `disk_security` | No disk encryption detected | doctor | 80% | -5 |
| 12 | medium | `malware_protection` | No antivirus or security tools detected | doctor | 80% | -5 |
| 13 | low | `ports` | Risky open port: 3000 (Node.js dev server) | host | 80% | -4 |
| 14 | low | `ports` | Risky open port: 8443 (HTTPS alt) | host | 80% | -4 |
| 15 | low | `physical_security` | No auto-lock mechanism detected | doctor | 80% | -3 |
| 16 | low | `uac_sudo` | sudo timestamp_timeout using default (15 min) | doctor | 80% | -2 |
| 17 | info | `os_info` | OS: Linux x86_64 | Kernel: 5.10.134-013.15.kangaroo.al8.x86_64 | host | 80% | -0 |
| 18 | info | `world_writable` | /tmp is world-writable with sticky bit (0o1777) | host | 80% | -0 |
| 19 | info | `world_writable` | /var/tmp is world-writable with sticky bit (0o1777) | host | 80% | -0 |
| 20 | info | `world_writable` | /dev/shm is world-writable with sticky bit (0o1777) | host | 80% | -0 |

### Evidence

1. `Kernel: 5.10.134-013.15.kangaroo.al8.x86_64, CVE range: 5.8.0-5.16.11`
2. `Kernel: 5.10.134-013.15.kangaroo.al8.x86_64, CVE range: 5.1.0-6.7.0`
3. `No firewall found`
4. `DATABASE_URL=file:/...`
5. `Kernel: 5.10.134-013.15.kangaroo.al8.x86_64, CVE range: 5.4.0-5.15.1`
6. `No active logging services found`
7. `Permissions: 0o644`
8. `Neither getenforce nor aa-status succeeded`
9. `PASS_MAX_DAYS=99999`
10. `pwquality.conf not configured`
11. `No encrypted volumes found`
12. `No AV tools found`
13. `Port 3000 found in ss/netstat output`
14. `Port 8443 found in ss/netstat output`
15. `No lock process found`
16. `timestamp_timeout not explicitly set (default=15)`
17. `5.10.134-013.15.kangaroo.al8.x86_64`
18. `Permissions: 0o1777`
19. `Permissions: 0o1777`
20. `Permissions: 0o1777`

## Module Breakdown

### doctor (7 findings)

- **[MEDIUM]** Password max age is 99999 days (too long)
- **[MEDIUM]** No password complexity requirements configured
- **[MEDIUM]** No disk encryption detected
- **[LOW]** No auto-lock mechanism detected
- **[MEDIUM]** No antivirus or security tools detected
- **[HIGH]** No logging services detected (rsyslog/journald/auditd)
- **[LOW]** sudo timestamp_timeout using default (15 min)

### host (13 findings)

- **[INFO]** OS: Linux x86_64 | Kernel: 5.10.134-013.15.kangaroo.al8.x86_64
- **[LOW]** Risky open port: 3000 (Node.js dev server)
- **[LOW]** Risky open port: 8443 (HTTPS alt)
- **[HIGH]** No firewall detected
- **[HIGH]** Database URL in environment: DATABASE_URL
- **[MEDIUM]** World-readable: User account file (/etc/passwd)
- **[MEDIUM]** No Mandatory Access Control (SELinux/AppArmor) detected
- **[HIGH]** Kernel potentially vulnerable to Netfilter UAF (CVE-2021-4039)
- **[CRITICAL]** Kernel potentially vulnerable to Dirty Pipe (CVE-2022-0847)
- **[CRITICAL]** Kernel potentially vulnerable to netfilter nf_tables UAF (CVE-2024-1086)
- **[INFO]** /tmp is world-writable with sticky bit (0o1777)
- **[INFO]** /var/tmp is world-writable with sticky bit (0o1777)
- **[INFO]** /dev/shm is world-writable with sticky bit (0o1777)

## Remediation

- Update kernel: sudo apt dist-upgrade
- Install and enable a firewall: sudo apt install ufw && sudo ufw enable
- Move DATABASE_URL to a secrets manager (AWS Secrets Manager, Vault, .env file with restricted permissions).
- Install and enable logging: sudo apt install rsyslog auditd && sudo systemctl enable --now rsyslog auditd
- Restrict permissions: chmod 0o644 /etc/passwd
- Install AppArmor: sudo apt install apparmor apparmor-profiles
- Set PASS_MAX_DAYS=90 in /etc/login.defs
- Configure /etc/security/pwquality.conf: minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
- Enable full disk encryption: cryptsetup luksFormat /dev/sdX
- Install security tools: sudo apt install clamav rkhunter lynis fail2ban

## Intelligence Analysis

- **Executive Risk Score:** 52.0/100
- **Exposure Score:** 20.7/100
- **Mission Impact Score:** 47.1/100
- **Infrastructure Health Score:** 48.0/100
- **Threat Confidence Index:** 60.0/100

### CVE Matches: CVE-2021-4039, CVE-2022-0847, CVE-2024-1086

### MITRE ATT&CK Techniques

- : Password Spraying
- : Unsecured Credentials
- : Exploits

---
*Generated by ReconPro v11.2.0*
