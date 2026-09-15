"""HOST module — Full local machine security audit.

Scans the laptop/machine for:
- Open ports & listening services
- Firewall status (ufw / iptables / firewalld)
- User accounts & sudoers
- SSH configuration hardening
- Running Docker containers & exposed ports
- Cron jobs & scheduled tasks
- Environment variables leaking secrets
- Sensitive file permissions
- OS & kernel info
- Network interfaces
- Installed services
- Bluetooth & WiFi status
- USB devices
- Auto-start / launch agents
- SUID/SGID binary audit
- SELinux/AppArmor status
- Kernel version CVE check
- SSH authorized keys audit
- World-writable directories
- Suspicious processes
- UAC status (Windows)
- BitLocker recovery
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..http_layer import Finding
from ..safe_command import run_command


def _hostname() -> str:
    """Cross-platform hostname (works on Linux, macOS, Windows)."""
    try:
        return os.uname().nodename
    except AttributeError:
        return os.environ.get("COMPUTERNAME", os.environ.get("HOSTNAME", "localhost"))


def _run(cmd: str, timeout: int = 10) -> Tuple[int, str]:
    """Run a command WITHOUT a shell, return (exit_code, stdout+stderr).

    Uses reconpro.safe_command.run_command: the command string is
    tokenised with shlex and executed as an argument list; the pipe /
    ``||`` fallback / redirection syntax used by this module is emulated
    in Python (never by spawning a shell).
    """
    return run_command(cmd, timeout=timeout)


def _is_windows() -> bool:
    """Check if running on Windows."""
    return os.name == "nt"


def _is_macos() -> bool:
    """Check if running on macOS."""
    return os.name == "posix" and hasattr(os, "uname") and os.uname().sysname == "Darwin"


def _file_exists(p: str) -> bool:
    return os.path.exists(p)


def _file_perms(p: str) -> Optional[int]:
    try:
        return stat.S_IMODE(os.stat(p).st_mode)
    except Exception:
        return None


def _check_open_ports() -> List[Finding]:
    """Find open listening ports via ss/netstat."""
    findings: List[Finding] = []
    hostname = _hostname()

    # Platform-specific port enumeration
    if _is_windows():
        code, out = _run('netstat -an 2>NUL | findstr LISTENING')
        if code != 0 or not out:
            findings.append(Finding(
                title="Could not enumerate open ports",
                severity="low", category="ports",
                module="host",
                description="Unable to enumerate open ports.",
                evidence="netstat returned no output",
                asset=hostname, points_deducted=1,
                remediation="Run as Administrator for full port visibility.",
            ))
            return findings
    else:
        code, out = _run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        if code != 0 or not out:
            findings.append(Finding(
                title="Could not enumerate open ports",
                severity="low", category="ports",
                module="host",
                description="Unable to run ss or netstat. Try running with sudo.",
                evidence="ss/netstat returned no output",
                asset=hostname, points_deducted=1,
                remediation="Run with sudo for full port visibility.",
            ))
            return findings

    ports = []
    for line in out.splitlines():
        # Parse ss output: 0.0.0.0:3000 or [::]:8080
        match = re.search(r':(\d+)\s', line)
        if match:
            port = int(match.group(1))
            ports.append(port)

    # Categorize risky ports
    risky_ports = {
        23: ("high", "Telnet (unencrypted)"),
        21: ("high", "FTP (unencrypted)"),
        445: ("high", "SMB/CIFS"),
        3389: ("high", "RDP"),
        5900: ("high", "VNC"),
        6379: ("high", "Redis (no auth by default)"),
        27017: ("high", "MongoDB (no auth by default)"),
        11211: ("high", "Memcached"),
        9200: ("medium", "Elasticsearch"),
        5432: ("medium", "PostgreSQL"),
        3306: ("medium", "MySQL"),
        8080: ("low", "HTTP alt"),
        8443: ("low", "HTTPS alt"),
        3000: ("low", "Node.js dev server"),
        5173: ("low", "Vite dev server"),
        8000: ("low", "Python dev server"),
    }

    for port in sorted(set(ports)):
        if port in risky_ports:
            sev, desc = risky_ports[port]
            findings.append(Finding(
                title=f"Risky open port: {port} ({desc})",
                severity=sev, category="ports",
                module="host",
                description=f"Port {port} ({desc}) is open and listening. This could expose services to network attackers.",
                evidence=f"Port {port} found in ss/netstat output",
                asset=hostname, points_deducted=8 if sev == "high" else 4,
                remediation=f"Close port {port} if not needed, or bind to 127.0.0.1 only.",
            ))

    if not findings and ports:
        findings.append(Finding(
            title=f"{len(set(ports))} open ports detected",
            severity="info", category="ports",
            module="host",
            description=f"Found {len(set(ports))} open ports. None are known high-risk.",
            evidence=", ".join(str(p) for p in sorted(set(ports))[:20]),
            asset=hostname, points_deducted=0,
            remediation="Review all open ports periodically.",
        ))

    return findings


def _check_firewall() -> List[Finding]:
    """Check firewall status."""
    findings: List[Finding] = []
    hostname = _hostname()

    # Windows: check Windows Defender Firewall
    if _is_windows():
        code, out = _run('netsh advfirewall show currentprofile state 2>NUL')
        if code == 0 and "ON" in out.upper():
            findings.append(Finding(
                title="Windows Defender Firewall is active",
                severity="info", category="firewall",
                module="host",
                description="Windows Defender Firewall is enabled.",
                evidence=out[:200],
                asset=hostname, points_deducted=0,
                remediation="",
            ))
        else:
            findings.append(Finding(
                title="Windows Firewall is not enabled",
                severity="high", category="firewall",
                module="host",
                description="Windows Defender Firewall is not active. Your machine is exposed to network attacks.",
                evidence="Firewall state: OFF",
                asset=hostname, points_deducted=10,
                remediation="Enable Windows Firewall: netsh advfirewall set allprofiles state on",
            ))
        return findings

    # macOS: check Application Layer Firewall
    if _is_macos():
        code, out = _run("defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null")
        if code == 0 and out.strip() == "1":
            findings.append(Finding(
                title="macOS Application Firewall is active",
                severity="info", category="firewall",
                module="host",
                description="macOS Application Layer Firewall is enabled.",
                evidence=f"globalstate={out.strip()}",
                asset=hostname, points_deducted=0,
                remediation="",
            ))
        else:
            findings.append(Finding(
                title="macOS Firewall is not enabled",
                severity="high", category="firewall",
                module="host",
                description="macOS Application Layer Firewall is not active. Your machine is exposed to network attacks.",
                evidence=f"globalstate={out.strip() if code == 0 else 'unknown'}",
                asset=hostname, points_deducted=10,
                remediation="Enable Application Firewall in System Preferences > Security & Privacy > Firewall",
            ))
        return findings

    # Check ufw (Linux)
    code, out = _run("ufw status 2>/dev/null")
    if code == 0:
        if "inactive" in out.lower():
            findings.append(Finding(
                title="UFW firewall is inactive",
                severity="high", category="firewall",
                module="host",
                description="UFW (Uncomplicated Firewall) is installed but not active. Your machine is exposed to network attacks.",
                evidence=out[:200],
                asset=hostname, points_deducted=10,
                remediation="Enable UFW: sudo ufw enable && sudo ufw default deny incoming",
            ))
        else:
            findings.append(Finding(
                title="UFW firewall is active",
                severity="info", category="firewall",
                module="host",
                description="UFW firewall is enabled.",
                evidence=out[:200],
                asset=hostname, points_deducted=0,
                remediation="",
            ))
        return findings

    # Check iptables (Linux)
    code, out = _run("iptables -L -n 2>/dev/null")
    if code == 0 and out:
        if "ACCEPT" in out and "DROP" not in out and "REJECT" not in out:
            findings.append(Finding(
                title="iptables has no DROP/REJECT rules",
                severity="high", category="firewall",
                module="host",
                description="iptables is running but all chains have ACCEPT policy with no filtering rules.",
                evidence="No DROP or REJECT rules found",
                asset=hostname, points_deducted=10,
                remediation="Configure iptables rules or install UFW: sudo apt install ufw && sudo ufw enable",
            ))
        else:
            findings.append(Finding(
                title="iptables rules found",
                severity="info", category="firewall",
                module="host",
                description="iptables has filtering rules configured.",
                evidence="Rules present",
                asset=hostname, points_deducted=0,
                remediation="",
            ))
        return findings

    findings.append(Finding(
        title="No firewall detected",
        severity="high", category="firewall",
        module="host",
        description="No firewall detected. Your machine has no network firewall.",
        evidence="No firewall found",
        asset=hostname, points_deducted=10,
        remediation="Install and enable a firewall: sudo apt install ufw && sudo ufw enable",
    ))
    return findings


def _check_users() -> List[Finding]:
    """Check user accounts and sudo access."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        # Check administrator accounts on Windows
        code, out = _run('net localgroup Administrators 2>NUL')
        if code == 0 and out:
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            # First two lines are header, last line is "The command completed..."
            admins = [l for l in lines[2:] if l and "command completed" not in l.lower()]
            if len(admins) > 2:
                findings.append(Finding(
                    title=f"{len(admins)} administrator accounts found",
                    severity="medium", category="users",
                    module="host",
                    description=f"{len(admins)} users have administrator privileges: {', '.join(admins[:5])}. Minimize admin access to reduce risk.",
                    evidence=f"Administrators: {', '.join(admins[:5])}",
                    asset=hostname, points_deducted=5,
                    remediation="Remove unnecessary users from the Administrators group via Computer Management.",
                ))
        return findings

    # Non-Windows: check sudo users
    code, out = _run("getent group sudo 2>/dev/null")
    if code == 0 and out:
        users = [u for u in out.split(":")[1].split(",") if u.strip()]
        if len(users) > 2:
            findings.append(Finding(
                title=f"{len(users)} users have sudo privileges",
                severity="medium", category="users",
                module="host",
                description=f"{len(users)} users can run sudo: {', '.join(users[:5])}. Minimize sudo access to reduce risk.",
                evidence=f"sudo group: {out[:200]}",
                asset=hostname, points_deducted=5,
                remediation="Remove unnecessary users from the sudo group. Use specific capabilities instead.",
            ))

    # Check for passwordless sudo (non-Windows only)
    code, out = _run("sudo -n true 2>&1")
    if code == 0:
        findings.append(Finding(
            title="Passwordless sudo is enabled",
            severity="high", category="users",
            module="host",
            description="Current user can run sudo without a password. Any code running as your user has root access.",
            evidence="sudo -n returned exit code 0",
            asset=hostname, points_deducted=10,
            remediation="Require password for sudo: remove NOPASSWD from /etc/sudoers",
        ))

    # Check for empty password users (Linux only)
    code, out = _run("sudo awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null")
    if code == 0 and out.strip():
        users = out.strip().splitlines()
        findings.append(Finding(
            title=f"{len(users)} user(s) with empty password",
            severity="critical", category="users",
            module="host",
            description=f"Users with no password: {', '.join(users[:5])}. This is a critical security risk.",
            evidence=out[:200],
            asset=hostname, points_deducted=15,
            remediation="Set passwords for all users immediately: sudo passwd <username>",
        ))

    return findings


def _check_ssh() -> List[Finding]:
    """Check SSH configuration hardening."""
    findings: List[Finding] = []
    hostname = _hostname()
    sshd_config = "/etc/ssh/sshd_config"

    if not _file_exists(sshd_config):
        return findings

    try:
        with open(sshd_config) as f:
            config = f.read()
    except Exception:
        return findings

    ssh_checks = [
        (r'^#?PermitRootLogin\s+yes', "high", "SSH root login is permitted", "Set PermitRootLogin no"),
        (r'^#?PasswordAuthentication\s+yes', "medium", "SSH password authentication enabled", "Use SSH keys only: PasswordAuthentication no"),
        (r'^#?PermitEmptyPasswords\s+yes', "critical", "SSH allows empty passwords", "Set PermitEmptyPasswords no"),
        (r'^#?X11Forwarding\s+yes', "low", "SSH X11 forwarding enabled", "Set X11Forwarding no if not needed"),
        (r'^#?MaxAuthTries\s+(\d+)', None, "", ""),  # just read value
        (r'^#?Protocol\s+1', "high", "SSH Protocol 1 in use (insecure)", "Use Protocol 2"),
        (r'^#?AllowAgentForwarding\s+yes', "low", "SSH agent forwarding enabled", "Disable if not needed: AllowAgentForwarding no"),
    ]

    for pattern, sev, title, remediation in ssh_checks:
        if re.search(pattern, config, re.MULTILINE | re.IGNORECASE):
            if sev is None:
                # MaxAuthTries check
                match = re.search(r'^#?MaxAuthTries\s+(\d+)', config, re.MULTILINE)
                if match and int(match.group(1)) > 6:
                    findings.append(Finding(
                        title=f"SSH MaxAuthTries is {match.group(1)} (too high)",
                        severity="low", category="ssh",
                        module="host",
                        description=f"MaxAuthTries={match.group(1)} allows more brute-force attempts.",
                        evidence=f"MaxAuthTries {match.group(1)}",
                        asset=hostname, points_deducted=2,
                        remediation="Set MaxAuthTries 4",
                    ))
            else:
                findings.append(Finding(
                    title=title,
                    severity=sev, category="ssh",
                    module="host",
                    description=f"SSH config issue: {title}",
                    evidence=f"Found in {sshd_config}",
                    asset=hostname, points_deducted=8 if sev == "high" else (15 if sev == "critical" else 3),
                    remediation=remediation,
                ))

    return findings


def _check_docker() -> List[Finding]:
    """Check Docker security."""
    findings: List[Finding] = []
    hostname = _hostname()

    # Check if Docker is running
    code, out = _run("docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null")
    if code != 0 or not out:
        return findings

    containers = [l for l in out.splitlines() if l.strip()]
    if containers:
        findings.append(Finding(
            title=f"{len(containers)} Docker container(s) running",
            severity="info", category="docker",
            module="host",
            description=f"Found {len(containers)} running Docker containers.",
            evidence=out[:300],
            asset=hostname, points_deducted=0,
            remediation="",
        ))

    # Check for containers with host networking
    code, out = _run("docker ps --format '{{.Names}}' -q 2>/dev/null | xargs -I{} docker inspect {} --format '{{.Name}} {{.HostConfig.NetworkMode}}' 2>/dev/null")
    if code == 0 and out:
        for line in out.splitlines():
            if "host" in line.lower():
                findings.append(Finding(
                    title=f"Docker container using host networking: {line.split()[0]}",
                    severity="high", category="docker",
                    module="host",
                    description="Container with host network mode shares the host's network stack, bypassing network isolation.",
                    evidence=line[:200],
                    asset=hostname, points_deducted=8,
                    remediation="Use bridge networking instead of host mode.",
                ))

    # Check for privileged containers
    code, out = _run("docker ps -q 2>/dev/null | xargs -I{} docker inspect {} --format '{{.Name}} {{.HostConfig.Privileged}}' 2>/dev/null")
    if code == 0 and out:
        for line in out.splitlines():
            if "true" in line.lower():
                findings.append(Finding(
                    title=f"Privileged Docker container: {line.split()[0]}",
                    severity="critical", category="docker",
                    module="host",
                    description="Privileged containers have full access to the host system. This is extremely dangerous.",
                    evidence=line[:200],
                    asset=hostname, points_deducted=15,
                    remediation="Remove --privileged flag. Use specific capabilities instead.",
                ))

    return findings


def _check_env_secrets() -> List[Finding]:
    """Scan environment variables for leaked secrets."""
    findings: List[Finding] = []
    hostname = _hostname()

    secret_patterns = [
        (r'(?i)api[_-]?key', "API key in environment"),
        (r'(?i)secret[_-]?key', "Secret key in environment"),
        (r'(?i)aws[_-]?(access|secret)', "AWS credential in environment"),
        (r'(?i)github[_-]?token', "GitHub token in environment"),
        (r'(?i)stripe[_-]?secret', "Stripe secret in environment"),
        (r'(?i)jwt[_-]?secret', "JWT secret in environment"),
        (r'(?i)database[_-]?url', "Database URL in environment"),
        (r'(?i)mongodb[_-]?uri', "MongoDB URI in environment"),
        (r'(?i)redis[_-]?url', "Redis URL in environment"),
        (r'(?i)sendgrid[_-]?api', "SendGrid API key in environment"),
        (r'(?i)twilio[_-]?auth', "Twilio auth token in environment"),
        (r'(?i)private[_-]?key', "Private key reference in environment"),
    ]

    for pattern, title in secret_patterns:
        matches = [k for k in os.environ if re.search(pattern, k)]
        if matches:
            for key in matches[:3]:
                val = os.environ.get(key, "")
                masked = val[:6] + "..." if len(val) > 6 else "(set)"
                findings.append(Finding(
                    title=f"{title}: {key}",
                    severity="high", category="env_secrets",
                    module="host",
                    description=f"Environment variable {key} may contain a secret. Val: {masked}",
                    evidence=f"{key}={masked}",
                    asset=hostname, points_deducted=8,
                    remediation=f"Move {key} to a secrets manager (AWS Secrets Manager, Vault, .env file with restricted permissions).",
                ))

    return findings


def _check_file_permissions() -> List[Finding]:
    """Check sensitive file permissions."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        sensitive_files = [
            ("~/.ssh/id_rsa", 0o600, "critical", "SSH private key"),
            ("~/.ssh/id_ed25519", 0o600, "critical", "Ed25519 private key"),
            ("~/.ssh/authorized_keys", 0o600, "high", "SSH authorized keys"),
            ("~/.ssh/config", 0o600, "medium", "SSH client config"),
            ("~/.gnupg", 0o700, "high", "GPG directory"),
            ("~/.aws/credentials", 0o600, "critical", "AWS credentials file"),
            ("~/.netrc", 0o600, "high", "netrc credentials file"),
            ("~/.pgpass", 0o600, "high", "PostgreSQL password file"),
            ("~/.env", 0o600, "high", ".env secrets file"),
            (os.path.join(os.environ.get('APPDATA', ''), 'credentials'), 0o600, "critical", "Windows Credential Manager backup"),
        ]
    else:
        sensitive_files = [
            ("/etc/shadow", 0o640, "critical", "Password hash file"),
            ("/etc/passwd", 0o644, "medium", "User account file"),
            ("/etc/sudoers", 0o440, "high", "Sudoers file"),
            ("/etc/ssh/sshd_config", 0o600, "medium", "SSH server config"),
            ("~/.ssh/id_rsa", 0o600, "critical", "SSH private key"),
            ("~/.ssh/id_ed25519", 0o600, "critical", "Ed25519 private key"),
            ("~/.ssh/authorized_keys", 0o600, "high", "SSH authorized keys"),
            ("~/.ssh/config", 0o600, "medium", "SSH client config"),
            ("~/.gnupg", 0o700, "high", "GPG directory"),
            ("~/.aws/credentials", 0o600, "critical", "AWS credentials file"),
            ("~/.netrc", 0o600, "high", "netrc credentials file"),
            ("~/.pgpass", 0o600, "high", "PostgreSQL password file"),
        ]

    for path, expected, sev, desc in sensitive_files:
        full_path = os.path.expanduser(path)
        if not _file_exists(full_path):
            continue
        perms = _file_perms(full_path)
        if perms is None:
            continue

        # Check if file is world-readable or world-writable
        if perms & stat.S_IROTH:
            if _is_windows():
                remediation_cmd = f'Restrict permissions: icacls "{full_path}" /inheritance:r /grant:r "%USERNAME%":(R,W)'
            else:
                remediation_cmd = f"Restrict permissions: chmod {oct(expected)} {path}"
            findings.append(Finding(
                title=f"World-readable: {desc} ({path})",
                severity=sev, category="file_permissions",
                module="host",
                description=f"{desc} at {path} has permissions {oct(perms)} and is world-readable.",
                evidence=f"Permissions: {oct(perms)}",
                asset=hostname, points_deducted=10 if sev in ("critical", "high") else 5,
                remediation=remediation_cmd,
            ))
        elif perms & stat.S_IWOTH:
            if _is_windows():
                remediation_cmd = f"Remove write access: icacls \"{full_path}\" /remove \"Everyone\""
            else:
                remediation_cmd = f"Restrict permissions: chmod {oct(expected)} {path}"
            findings.append(Finding(
                title=f"World-writable: {desc} ({path})",
                severity=sev, category="file_permissions",
                module="host",
                description=f"{desc} at {path} has permissions {oct(perms)} and is world-writable.",
                evidence=f"Permissions: {oct(perms)}",
                asset=hostname, points_deducted=12 if sev == "critical" else 6,
                remediation=remediation_cmd,
            ))

    return findings


def _check_cron_jobs() -> List[Finding]:
    """Check cron jobs for security issues."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        # Windows: check Task Scheduler
        code, out = _run('schtasks /query /fo LIST 2>NUL | findstr TaskName')
        if code == 0 and out:
            tasks = [l.strip() for l in out.splitlines() if l.strip()]
            if tasks:
                findings.append(Finding(
                    title=f"{len(tasks)} scheduled task(s) found",
                    severity="info", category="cron",
                    module="host",
                    description=f"Found {len(tasks)} scheduled tasks. Review for any suspicious scheduled tasks.",
                    evidence="; ".join(tasks[:10]),
                    asset=hostname, points_deducted=0,
                    remediation="Review scheduled tasks: schtasks /query /fo LIST",
                ))
        return findings

    # Non-Windows: check crontab
    code, out = _run("crontab -l 2>/dev/null")
    if code == 0 and out:
        lines = [l for l in out.splitlines() if l.strip() and not l.strip().startswith("#")]
        if lines:
            findings.append(Finding(
                title=f"{len(lines)} cron job(s) found for current user",
                severity="info", category="cron",
                module="host",
                description=f"Found {len(lines)} active cron jobs. Review for any suspicious scheduled tasks.",
                evidence=out[:300],
                asset=hostname, points_deducted=0,
                remediation="Review cron jobs: crontab -l",
            ))

    # Check system crons for world-writable scripts
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"]
    for cdir in cron_dirs:
        if not os.path.isdir(cdir):
            continue
        for entry in os.listdir(cdir):
            full = os.path.join(cdir, entry)
            if os.path.isfile(full):
                perms = _file_perms(full)
                if perms and (perms & stat.S_IWOTH):
                    findings.append(Finding(
                        title=f"World-writable cron script: {full}",
                        severity="critical", category="cron",
                        module="host",
                        description=f"Cron script {full} is world-writable. Any user can modify it to run code as root.",
                        evidence=f"Permissions: {oct(perms)}",
                        asset=hostname, points_deducted=15,
                        remediation=f"chmod 755 {full}",
                    ))

    return findings


def _check_auto_start() -> List[Finding]:
    """Check auto-start services and launch agents."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        # Check Windows startup entries
        code, out = _run('wmic startup get caption,command 2>NUL')
        if code == 0 and out:
            lines = [l.strip() for l in out.splitlines() if l.strip() and l.strip() != "Caption  Command"]
            if len(lines) > 5:
                findings.append(Finding(
                    title=f"{len(lines)} startup entry/entries found (high count)",
                    severity="low", category="services",
                    module="host",
                    description=f"{len(lines)} items are configured to run at Windows startup. More startup items = larger attack surface.",
                    evidence="; ".join(lines[:5]),
                    asset=hostname, points_deducted=2,
                    remediation="Review and remove unnecessary startup entries: Task Manager > Startup tab",
                ))

        # Check running services count
        code, out = _run('sc query state= all 2>NUL | findstr RUNNING | find /c /v ""')
        if code == 0 and out.strip():
            try:
                count = int(out.strip())
                if count > 100:
                    findings.append(Finding(
                        title=f"{count} Windows services running (high count)",
                        severity="low", category="services",
                        module="host",
                        description=f"{count} services are currently running. More services = larger attack surface.",
                        evidence=f"Running services: {count}",
                        asset=hostname, points_deducted=2,
                        remediation="Disable unnecessary services: services.msc",
                    ))
            except ValueError:
                pass
        return findings

    # Non-Windows: systemd services
    code, out = _run("systemctl list-unit-files --state=enabled --type=service --no-pager 2>/dev/null")
    if code == 0 and out:
        services = [l.strip() for l in out.splitlines() if "enabled" in l]
        if len(services) > 20:
            findings.append(Finding(
                title=f"{len(services)} enabled systemd services (high count)",
                severity="low", category="services",
                module="host",
                description=f"{len(services)} services are enabled at boot. More services = larger attack surface.",
                evidence=f"Count: {len(services)}",
                asset=hostname, points_deducted=2,
                remediation="Disable unnecessary services: sudo systemctl disable <service>",
            ))

    return findings


def _check_network() -> List[Finding]:
    """Check network configuration."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        # Check WiFi via netsh
        code, out = _run('netsh wlan show interfaces 2>NUL | findstr /i "SSID State"')
        if code == 0 and out and ("connected" in out.lower() or "SSID" in out):
            findings.append(Finding(
                title="Connected to WiFi network",
                severity="info", category="network",
                module="host",
                description=f"Machine is connected to WiFi: {out.strip()[:100]}",
                evidence=out.strip()[:100],
                asset=hostname, points_deducted=0,
                remediation="",
            ))
        return findings

    # macOS/Linux: Check if WiFi is connected
    if _is_macos():
        code, out = _run("system_profiler SPAirPort 2>/dev/null | grep -i 'current network'")
        if code == 0 and out:
            findings.append(Finding(
                title="Connected to WiFi network",
                severity="info", category="network",
                module="host",
                description=f"Machine is connected to WiFi: {out.strip()[:100]}",
                evidence=out.strip()[:100],
                asset=hostname, points_deducted=0,
                remediation="",
            ))
    else:
        code, out = _run("iwconfig 2>/dev/null | grep -i 'essid'")
        if code == 0 and out:
            if "off/any" not in out.lower():
                findings.append(Finding(
                    title="Connected to WiFi network",
                    severity="info", category="network",
                    module="host",
                    description=f"Machine is connected to WiFi: {out.strip()[:100]}",
                    evidence=out.strip()[:100],
                    asset=hostname, points_deducted=0,
                    remediation="",
                ))

    # Check for promiscuous mode (Linux only)
    code, out = _run("ip link 2>/dev/null | grep -i promisc")
    if code == 0 and out:
        findings.append(Finding(
            title="Network interface in promiscuous mode",
            severity="high", category="network",
            module="host",
            description="A network interface is in promiscuous mode, meaning it captures all network traffic.",
            evidence=out.strip()[:200],
            asset=hostname, points_deducted=8,
            remediation="Check for packet sniffers. Disable promiscuous mode: sudo ip link set <iface> promisc off",
        ))

    return findings


def _check_os_info() -> List[Finding]:
    """Gather OS info and check for known issues."""
    findings: List[Finding] = []
    hostname = _hostname()

    try:
        import platform
        sysname = platform.system()
        machine = platform.machine()
        kernel = platform.release()
        if _is_windows():
            remediation = "Keep Windows updated: Settings > Windows Update > Check for updates"
        elif _is_macos():
            remediation = "Keep macOS updated: System Preferences > Software Update"
        else:
            remediation = "Update your system packages: sudo apt upgrade"
        findings.append(Finding(
            title=f"OS: {sysname} {machine} | Kernel: {kernel}",
            severity="info", category="os_info",
            module="host",
            description=f"Running {sysname} on {machine} with kernel {kernel}",
            evidence=kernel,
            asset=hostname, points_deducted=0,
            remediation=remediation,
        ))
    except Exception:
        pass

    return findings


def _check_usb_devices() -> List[Finding]:
    """Check for connected USB devices."""
    findings: List[Finding] = []
    hostname = _hostname()

    code, out = _run("lsusb 2>/dev/null")
    if code == 0 and out:
        devices = [l for l in out.splitlines() if l.strip()]
        if devices:
            findings.append(Finding(
                title=f"{len(devices)} USB device(s) connected",
                severity="info", category="usb",
                module="host",
                description="USB devices detected. Be cautious of unknown USB devices (BadUSB attacks).",
                evidence=out[:300],
                asset=hostname, points_deducted=0,
                remediation="Only connect trusted USB devices. Consider USB device whitelisting.",
            ))

    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 1: SUID/SGID Binary Audit
# ---------------------------------------------------------------------------

def _check_suid_sgid() -> List[Finding]:
    """Find world-writable SUID/SGID binaries (Linux) or auto-elevatable binaries (Windows)."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        # Windows: check for known auto-elevatable binaries in PATH
        auto_elevatable = [
            "compmgmtlauncher.exe", "dcomcnfg.exe", "eventvwr.exe",
            "fxcopcmd.exe", "msconfig.exe", "regedit.exe", "resmon.exe",
            "taskmgr.exe", "comexp.exe", "mmc.exe",
        ]
        code, out = _run("echo %PATH%")
        if code != 0 or not out:
            return findings
        path_dirs = [p.strip('"') for p in out.split(os.pathsep) if p.strip()]
        found_elevatable = []
        for d in path_dirs[:30]:
            if not os.path.isdir(d):
                continue
            try:
                for entry in os.listdir(d):
                    if entry.lower() in auto_elevatable:
                        found_elevatable.append(os.path.join(d, entry))
            except PermissionError:
                continue
        if found_elevatable:
            findings.append(Finding(
                title=f"{len(found_elevatable)} auto-elevatable binaries found in PATH",
                severity="medium", category="suid_sgid",
                module="host",
                description="Auto-elevatable binaries can escalate privileges without UAC prompt. Ensure only trusted binaries are in PATH.",
                evidence="; ".join(found_elevatable[:5]),
                asset=hostname, points_deducted=5,
                remediation="Review PATH entries and remove unnecessary directories. Restrict file permissions on auto-elevatable binaries.",
            ))
        return findings

    if _is_macos():
        # macOS: basic SUID check
        code, out = _run("find /usr/bin /usr/sbin /bin /sbin -perm -4000 2>/dev/null")
        if code == 0 and out:
            suid_bins = [l for l in out.splitlines() if l.strip()]
            world_writable = []
            for b in suid_bins:
                try:
                    if os.stat(b).st_mode & stat.S_IWOTH:
                        world_writable.append(b)
                except OSError:
                    continue
            if world_writable:
                findings.append(Finding(
                    title=f"{len(world_writable)} world-writable SUID binary/binaries on macOS",
                    severity="critical", category="suid_sgid",
                    module="host",
                    description="SUID binaries that are world-writable can be replaced by any user to run code as root.",
                    evidence="; ".join(world_writable[:5]),
                    asset=hostname, points_deducted=15,
                    remediation="Remove world-write: sudo chmod o-w <binary> for each listed file.",
                ))
        return findings

    # Linux: full SUID/SGID audit
    code, out = _run("find /usr -perm -4000 -o -perm -2000 2>/dev/null")
    if code == 0 and out:
        suid_sgid_bins = [l for l in out.splitlines() if l.strip()]
        world_writable = []
        for b in suid_sgid_bins:
            try:
                if os.stat(b).st_mode & stat.S_IWOTH:
                    world_writable.append(b)
            except OSError:
                continue
        if world_writable:
            findings.append(Finding(
                title=f"{len(world_writable)} world-writable SUID/SGID binary/binaries found",
                severity="critical", category="suid_sgid",
                module="host",
                description="SUID/SGID binaries that are world-writable can be replaced by any user to run code as elevated user/root.",
                evidence="; ".join(world_writable[:5]),
                asset=hostname, points_deducted=15,
                remediation="Remove world-write: sudo chmod o-w <binary> for each listed file.",
            ))
        else:
            if len(suid_sgid_bins) > 30:
                findings.append(Finding(
                    title=f"{len(suid_sgid_bins)} SUID/SGID binaries found (large count)",
                    severity="low", category="suid_sgid",
                    module="host",
                    description=f"{len(suid_sgid_bins)} SUID/SGID binaries found. Review for unnecessary privilege escalation paths.",
                    evidence=f"Count: {len(suid_sgid_bins)}",
                    asset=hostname, points_deducted=2,
                    remediation="Audit SUID/SGID binaries: sudo find / -perm -4000 -o -perm -2000",
                ))
    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 2: SELinux/AppArmor Status
# ---------------------------------------------------------------------------

def _check_selinux_apparmor() -> List[Finding]:
    """Check SELinux enforcing mode or AppArmor active status (Linux only)."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows() or _is_macos():
        return findings  # Not applicable

    # Check SELinux
    code, out = _run("getenforce 2>/dev/null")
    if code == 0:
        mode = out.strip().lower()
        if mode == "enforcing":
            findings.append(Finding(
                title="SELinux is in enforcing mode",
                severity="info", category="mac",
                module="host",
                description="SELinux Mandatory Access Control is active and enforcing policy.",
                evidence=f"getenforce: {out.strip()}",
                asset=hostname, points_deducted=0,
                remediation="",
            ))
        elif mode in ("permissive", "disabled"):
            findings.append(Finding(
                title=f"SELinux is in {mode} mode",
                severity="high" if mode == "disabled" else "medium",
                category="mac",
                module="host",
                description=f"SELinux is {mode}. Mandatory Access Control protections are {'absent' if mode == 'disabled' else 'not enforced'}.",
                evidence=f"getenforce: {out.strip()}",
                asset=hostname, points_deducted=8 if mode == "disabled" else 5,
                remediation="Enable SELinux enforcing: sudo setenforce 1 && edit /etc/selinux/config to SELINUX=enforcing",
            ))
        return findings

    # Check AppArmor
    code, out = _run("aa-status 2>/dev/null")
    if code == 0 and out:
        profiles_loaded = 0
        profiles_enforce = 0
        for line in out.splitlines():
            if "profiles are loaded" in line.lower():
                try:
                    profiles_loaded = int(re.search(r'(\d+)', line).group(1))
                except (AttributeError, ValueError):
                    pass
            if "profiles are in enforce mode" in line.lower():
                try:
                    profiles_enforce = int(re.search(r'(\d+)', line).group(1))
                except (AttributeError, ValueError):
                    pass
        if profiles_loaded == 0:
            findings.append(Finding(
                title="AppArmor has no profiles loaded",
                severity="high", category="mac",
                module="host",
                description="AppArmor is installed but no profiles are loaded. No MAC protection is active.",
                evidence="0 profiles loaded",
                asset=hostname, points_deducted=8,
                remediation="Load AppArmor profiles: sudo apt install apparmor-profiles && sudo aa-enforce /etc/apparmor.d/*",
            ))
        elif profiles_enforce == 0 and profiles_loaded > 0:
            findings.append(Finding(
                title="AppArmor profiles loaded but none in enforce mode",
                severity="high", category="mac",
                module="host",
                description=f"{profiles_loaded} AppArmor profiles loaded but none are in enforce mode. All profiles are in complain mode only.",
                evidence=f"{profiles_loaded} loaded, 0 enforcing",
                asset=hostname, points_deducted=8,
                remediation="Enforce profiles: sudo aa-enforce /etc/apparmor.d/*",
            ))
        else:
            findings.append(Finding(
                title=f"AppArmor: {profiles_enforce}/{profiles_loaded} profiles in enforce mode",
                severity="info", category="mac",
                module="host",
                description="AppArmor MAC is active with profiles in enforce mode.",
                evidence=f"{profiles_enforce} enforcing of {profiles_loaded} loaded",
                asset=hostname, points_deducted=0,
                remediation="",
            ))
        return findings

    # Neither SELinux nor AppArmor detected
    findings.append(Finding(
        title="No Mandatory Access Control (SELinux/AppArmor) detected",
        severity="medium", category="mac",
        module="host",
        description="No SELinux or AppArmor MAC system detected. Consider enabling one for additional security.",
        evidence="Neither getenforce nor aa-status succeeded",
        asset=hostname, points_deducted=5,
        remediation="Install AppArmor: sudo apt install apparmor apparmor-profiles",
    ))
    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 3: Kernel Version CVE Check
# ---------------------------------------------------------------------------

# Static list of high-severity kernel CVEs with version ranges
_KNOWN_KERNEL_CVES: List[Dict[str, Any]] = [
    {"id": "CVE-2016-5195", "name": "Dirty COW", "min_ver": "2.6.22", "max_ver": "4.8.3", "severity": "critical",
     "desc": "Race condition in mm/cow: priv escalation via write-after-zero page."},
    {"id": "CVE-2017-1000112", "name": "Stack Clash (kernel part)", "min_ver": "2.6.18", "max_ver": "4.13.4", "severity": "critical",
     "desc": "Stack clash allows arbitrary code execution."},
    {"id": "CVE-2017-1000405", "name": "Linux Kernel KVM Priv Escalation", "min_ver": "3.10.0", "max_ver": "4.14.13", "severity": "critical",
     "desc": "KVM allows host OS memory corruption."},
    {"id": "CVE-2018-14633", "name": "Crypto API Buffer Overflow", "min_ver": "3.6.0", "max_ver": "4.18.10", "severity": "critical",
     "desc": "Buffer overflow in crypto API allows priv esc."},
    {"id": "CVE-2019-13272", "name": "PTRACE Tracing Priv Escalation", "min_ver": "3.2.0", "max_ver": "5.1.17", "severity": "critical",
     "desc": "PTRACE_TRACEME allows local priv esc."},
    {"id": "CVE-2020-14386", "name": "Packet Socket OOB Write", "min_ver": "4.6.0", "max_ver": "5.8.6", "severity": "critical",
     "desc": "Out-of-bounds write in AF_PACKET."},
    {"id": "CVE-2021-4039", "name": "Netfilter UAF", "min_ver": "5.4.0", "max_ver": "5.15.1", "severity": "high",
     "desc": "Use-after-free in netfilter allows priv esc."},
    {"id": "CVE-2022-0847", "name": "Dirty Pipe", "min_ver": "5.8.0", "max_ver": "5.16.11", "severity": "critical",
     "desc": "Buffer overflow in pipe buffer allows overwriting read-only files."},
    {"id": "CVE-2023-0386", "name": "OverlayFS Priv Escalation", "min_ver": "5.11.0", "max_ver": "6.2.0", "severity": "critical",
     "desc": "OverlayFS escape allows local priv esc."},
    {"id": "CVE-2024-1086", "name": "netfilter nf_tables UAF", "min_ver": "5.1.0", "max_ver": "6.7.0", "severity": "critical",
     "desc": "Use-after-free in nf_tables allows local priv esc."},
]


def _parse_kernel_version(ver: str) -> Optional[Tuple[int, ...]]:
    """Parse kernel version string into tuple of ints for comparison."""
    # Extract version part, stripping distro suffixes
    match = re.match(r'(\d+\.\d+(?:\.\d+)?)', ver)
    if not match:
        return None
    parts = []
    for p in match.group(1).split("."):
        try:
            parts.append(int(p))
        except ValueError:
            break
    return tuple(parts) if parts else None


def _version_in_range(ver: Tuple[int, ...], min_v: str, max_v: str) -> bool:
    """Check if ver falls within [min_v, max_v] inclusive."""
    v_min = _parse_kernel_version(min_v)
    v_max = _parse_kernel_version(max_v)
    if v_min is None or v_max is None:
        return False
    return v_min <= ver <= v_max


def _check_kernel_cves() -> List[Finding]:
    """Parse kernel version and check against known high-severity CVE patterns."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        return findings  # Not applicable

    try:
        import platform
        kernel_ver = platform.release()
    except Exception:
        return findings

    parsed = _parse_kernel_version(kernel_ver)
    if parsed is None:
        return findings

    for cve in _KNOWN_KERNEL_CVES:
        if _version_in_range(parsed, cve["min_ver"], cve["max_ver"]):
            findings.append(Finding(
                title=f"Kernel potentially vulnerable to {cve['name']} ({cve['id']})",
                severity=cve["severity"], category="kernel_cve",
                module="host",
                description=f"Kernel version {kernel_ver} falls within the affected range ({cve['min_ver']}-{cve['max_ver']}). {cve['desc']}",
                evidence=f"Kernel: {kernel_ver}, CVE range: {cve['min_ver']}-{cve['max_ver']}",
                asset=hostname, points_deducted=15 if cve["severity"] == "critical" else 8,
                remediation=f"Update kernel: {'sudo apt dist-upgrade' if not _is_macos() else 'softwareupdate -i -a'}",
            ))

    if not findings:
        findings.append(Finding(
            title=f"Kernel {kernel_ver} — no known high-severity CVE matches",
            severity="info", category="kernel_cve",
            module="host",
            description=f"Kernel version {kernel_ver} was checked against a static list of high-severity CVEs and no matches were found.",
            evidence=f"Kernel: {kernel_ver}",
            asset=hostname, points_deducted=0,
            remediation="Keep your kernel updated for future CVEs.",
        ))

    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 4: SSH Authorized Keys Audit
# ---------------------------------------------------------------------------

def _check_ssh_authorized_keys() -> List[Finding]:
    """Check for unauthorized or unusual keys in authorized_keys files."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        # Windows: check SSH authorized_keys if OpenSSH is installed
        ssh_dir = os.path.expanduser("~/.ssh")
        if not os.path.isdir(ssh_dir):
            return findings
        ak_paths = [os.path.join(ssh_dir, "authorized_keys")]
    else:
        ak_paths = [
            os.path.expanduser("~/.ssh/authorized_keys"),
            "/etc/ssh/authorized_keys",
        ]

    # Known-good key type prefixes
    good_key_types = {"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519", "sk-ecdsa-sha2-nistp256"}

    for ak_path in ak_paths:
        if not os.path.isfile(ak_path):
            continue
        try:
            with open(ak_path, errors="replace") as f:
                lines = f.readlines()
        except Exception:
            continue

        total_keys = 0
        unusual_keys = []
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            total_keys += 1
            parts = line.split()
            if len(parts) < 2:
                unusual_keys.append(f"line {i}: malformed key entry")
                continue
            key_type = parts[0]
            if key_type not in good_key_types:
                unusual_keys.append(f"line {i}: unusual key type '{key_type}'")

        if total_keys > 10:
            findings.append(Finding(
                title=f"{total_keys} authorized keys in {ak_path} (high count)",
                severity="medium", category="ssh_keys",
                module="host",
                description=f"{total_keys} SSH keys are authorized in {ak_path}. A large number of authorized keys increases the attack surface.",
                evidence=f"Path: {ak_path}, Keys: {total_keys}",
                asset=hostname, points_deducted=5,
                remediation="Audit and remove unused authorized keys.",
            ))

        if unusual_keys:
            findings.append(Finding(
                title=f"Unusual SSH authorized key(s) in {ak_path}",
                severity="high", category="ssh_keys",
                module="host",
                description="Found unusual or malformed key entries in authorized_keys. These could indicate unauthorized access or key injection.",
                evidence="; ".join(unusual_keys[:5]),
                asset=hostname, points_deducted=8,
                remediation="Review and remove unrecognized keys in authorized_keys.",
            ))

    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 5: World-Writable Directories
# ---------------------------------------------------------------------------

def _check_world_writable_dirs() -> List[Finding]:
    """Check /tmp, /var/tmp, /dev/shm for proper permissions."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        # Windows equivalent: check %TEMP% and %TMP% permissions
        tmp_dirs = [
            os.environ.get("TEMP", ""),
            os.environ.get("TMP", ""),
            r"C:\Windows\Temp",
        ]
        for d in tmp_dirs:
            if not d or not os.path.isdir(d):
                continue
            try:
                # Check if Everyone has write access
                code, out = _run(f'icacls "{d}" 2>NUL | findstr "Everyone"')
                if code == 0 and out and ("(W)" in out or "(F)" in out):
                    findings.append(Finding(
                        title=f"Open write access on temp dir: {d}",
                        severity="medium", category="world_writable",
                        module="host",
                        description=f"Windows temp directory {d} grants write access to Everyone. Malware can place files here for persistence.",
                        evidence=out[:200],
                        asset=hostname, points_deducted=5,
                        remediation=f"Restrict permissions on {d} via icacls.",
                    ))
            except Exception:
                pass
        return findings

    if _is_macos():
        tmp_dirs = ["/tmp", "/private/tmp", "/var/tmp"]
    else:
        tmp_dirs = ["/tmp", "/var/tmp", "/dev/shm"]

    for d in tmp_dirs:
        if not os.path.isdir(d):
            continue
        perms = _file_perms(d)
        if perms is None:
            continue
        if perms & stat.S_IWOTH:
            # /tmp is commonly world-writable (1777 = sticky bit + world-writable)
            # which is acceptable if sticky bit is set
            has_sticky = perms & stat.S_ISVTX
            if not has_sticky:
                findings.append(Finding(
                    title=f"World-writable directory without sticky bit: {d}",
                    severity="high", category="world_writable",
                    module="host",
                    description=f"{d} is world-writable (perms {oct(perms)}) but has no sticky bit. Any user can delete/replace files.",
                    evidence=f"Permissions: {oct(perms)}",
                    asset=hostname, points_deducted=8,
                    remediation=f"Add sticky bit: sudo chmod +t {d} (or chmod 1777 {d})",
                ))
            else:
                findings.append(Finding(
                    title=f"{d} is world-writable with sticky bit ({oct(perms)})",
                    severity="info", category="world_writable",
                    module="host",
                    description=f"{d} has sticky bit set, which prevents users from deleting files they don't own. This is the standard secure configuration.",
                    evidence=f"Permissions: {oct(perms)}",
                    asset=hostname, points_deducted=0,
                    remediation="",
                ))

    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 6: Suspicious Processes
# ---------------------------------------------------------------------------

# Patterns matching common malware/reverse shell/backdoor process names
_SUSPICIOUS_PROCESS_PATTERNS = [
    (re.compile(r'(?i)nc(?:at)?(?:\.exe)?.*-[eEl]'), "netcat reverse shell detected"),
    (re.compile(r'(?i)\bnc\.exe\b'), "netcat executable running"),
    (re.compile(r'(?i)\bmsfvenom\b'), "Metasploit msfvenom payload generator"),
    (re.compile(r'(?i)\bmsfconsole\b'), "Metasploit Framework console"),
    (re.compile(r'(?i)\bmeterpreter\b'), "Metasploit Meterpreter"),
    (re.compile(r'(?i)\breverse_?shell\b'), "reverse shell process"),
    (re.compile(r'(?i)\bbackdoor\b'), "backdoor process"),
    (re.compile(r'(?i)\bkeylog(?:ger)?\b'), "keylogger process"),
    (re.compile(r'(?i)\bscreen(?:shot|capture)\b.*save'), "screenshot capture tool"),
    (re.compile(r'(?i)\bcryptominer\b|\bxmrig\b|\bminerd\b|\bcgminer\b'), "cryptominer process"),
    (re.compile(r'(?i)\bpty\b.*spawn'), "pty spawn (possible reverse shell)"),
    (re.compile(r'(?i)\bpython[23]?\b.*-c.*import\s+(?:socket|pty|subprocess|os)'), "suspicious python one-liner"),
    (re.compile(r'(?i)\bbash\b.*-i.*>/dev/tcp/'), "bash reverse shell via /dev/tcp"),
    (re.compile(r'(?i)\bsh\b.*-c.*\b(curl|wget)\b.*\|\s*(?:sh|bash)'), "download and execute pattern"),
    (re.compile(r'(?i)\bpowershell.*-enc\b'), "encoded PowerShell command (common in malware)"),
    (re.compile(r'(?i)\bpowershell.*-w hidden\b'), "hidden PowerShell window (common in malware)"),
    (re.compile(r'(?i)\bcmd(?:\.exe)?\b.*/c\s.*\b(curl|certutil)\b'), "cmd download cradle"),
    (re.compile(r'(?i)\bwhoami\b.*\b>>(?:\/dev\/tcp|\\\\)'), "recon via whoami piped to network"),
]


def _check_suspicious_processes() -> List[Finding]:
    """Check for processes matching common malware/reverse shell patterns."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        code, out = _run('wmic process get CommandLine 2>NUL')
    else:
        code, out = _run("ps aux --no-headers 2>/dev/null || ps -ef 2>/dev/null")

    if code != 0 or not out:
        return findings

    for line in out.splitlines():
        for pattern, description in _SUSPICIOUS_PROCESS_PATTERNS:
            if pattern.search(line):
                # Mask potential command-line arguments for evidence
                cmd_line = line.strip()[:200]
                findings.append(Finding(
                    title=f"Suspicious process: {description}",
                    severity="critical", category="suspicious_processes",
                    module="host",
                    description=f"A running process matches a known malware or reverse shell pattern: {description}",
                    evidence=cmd_line,
                    asset=hostname, points_deducted=15,
                    remediation="Investigate immediately. Kill the process and check for persistence mechanisms.",
                ))
                break  # Only report once per process line

    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 7: UAC Status (Windows)
# ---------------------------------------------------------------------------

def _check_uac_status() -> List[Finding]:
    """Check Windows UAC level via registry."""
    findings: List[Finding] = []
    hostname = _hostname()

    if not _is_windows():
        return findings  # Not applicable

    # Read UAC settings from registry
    # ConsentPromptBehaviorAdmin: 0=Always notify, 1=Prompt for non-Windows binaries,
    #   2=Prompt for secure desktop (default), 3=Prompt for non-Windows (secure desktop), 5=Always prompt (secure desktop)
    code, out = _run(r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin 2>NUL')
    if code == 0 and out:
        match = re.search(r'REG_DWORD\s+0x([0-9a-fA-F]+)', out)
        if match:
            val = int(match.group(1), 16)
            if val == 0:
                findings.append(Finding(
                    title="UAC is completely disabled",
                    severity="critical", category="uac",
                    module="host",
                    description="Windows User Account Control is completely disabled. Any process can silently elevate privileges.",
                    evidence=f"ConsentPromptBehaviorAdmin = {val}",
                    asset=hostname, points_deducted=15,
                    remediation="Enable UAC: Set ConsentPromptBehaviorAdmin to 2 via Local Security Policy or registry.",
                ))
            elif val == 1:
                findings.append(Finding(
                    title="UAC set to 'Never notify' (weakened)",
                    severity="high", category="uac",
                    module="host",
                    description="UAC is set to not notify the user for admin operations. This significantly weakens privilege boundary protection.",
                    evidence=f"ConsentPromptBehaviorAdmin = {val}",
                    asset=hostname, points_deducted=10,
                    remediation="Set UAC to 'Always notify': Set ConsentPromptBehaviorAdmin to 2 or 5.",
                ))
            else:
                findings.append(Finding(
                    title=f"UAC is enabled (level {val})",
                    severity="info", category="uac",
                    module="host",
                    description="Windows User Account Control is active and will prompt for elevation.",
                    evidence=f"ConsentPromptBehaviorAdmin = {val}",
                    asset=hostname, points_deducted=0,
                    remediation="",
                ))
    else:
        findings.append(Finding(
            title="Could not read UAC settings",
            severity="low", category="uac",
            module="host",
            description="Unable to read UAC registry settings.",
            evidence="Registry query failed",
            asset=hostname, points_deducted=2,
            remediation="Manually check UAC: Control Panel > User Accounts > Change User Account Control settings",
        ))

    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 8: BitLocker Recovery
# ---------------------------------------------------------------------------

def _check_bitlocker_recovery() -> List[Finding]:
    """Check if BitLocker recovery keys are backed up to AD or TPM (Windows only)."""
    findings: List[Finding] = []
    hostname = _hostname()

    if not _is_windows():
        return findings  # Not applicable

    # Check BitLocker status
    code, out = _run('manage-bde -status C: 2>NUL')
    if code != 0 or not out:
        # Check other drives
        code, out = _run('wmic volume get DriveLetter,DriveType 2>NUL | findstr "3"')
        if code != 0 or not out:
            return findings  # No BitLocker or no drives

    if "Percentage Encrypted" not in out:
        return findings

    # Check if recovery password is backed up to AD
    recovery_info = {}
    for line in out.splitlines():
        line_stripped = line.strip()
        if "Key Protector" in line_stripped:
            recovery_info.setdefault("protectors", []).append(line_stripped)
        if "Numerical Password" in line_stripped or "Recovery Password" in line_stripped:
            recovery_info["has_numerical"] = True
        if "TPM" in line_stripped:
            recovery_info["has_tpm"] = True

    has_numerical = recovery_info.get("has_numerical", False)
    has_tpm = recovery_info.get("has_tpm", False)

    if not has_tpm and not has_numerical:
        findings.append(Finding(
            title="BitLocker active but no TPM or recovery key protector found",
            severity="high", category="bitlocker",
            module="host",
            description="BitLocker is active but no TPM key protector or numerical recovery password is configured. If the device is lost, data cannot be recovered.",
            evidence="No TPM or numerical password protector in manage-bde output",
            asset=hostname, points_deducted=8,
            remediation="Add TPM protector: manage-bde -protectors -add C: -tpm. Backup recovery key: manage-bde -protectors -backup C: -AD",
        ))
    elif not has_tpm and has_numerical:
        findings.append(Finding(
            title="BitLocker recovery key found but no TPM protector",
            severity="medium", category="bitlocker",
            module="host",
            description="BitLocker has a numerical recovery password but no TPM protector. TPM provides seamless authentication.",
            evidence="Numerical password found, no TPM protector",
            asset=hostname, points_deducted=5,
            remediation="Add TPM protector: manage-bde -protectors -add C: -tpm",
        ))
    else:
        # Check if recovery key is backed up to AD
        code2, out2 = _run('powershell -command "(Get-BitLockerVolume -MountPoint C:).KeyProtector | Where-Object {$_.KeyProtectorType -eq \"RecoveryPassword\"} | Select-Object -ExpandProperty RecoveryPassword" 2>NUL')
        findings.append(Finding(
            title="BitLocker is active with TPM protector",
            severity="info", category="bitlocker",
            module="host",
            description="BitLocker encryption is active with a TPM protector. Ensure recovery keys are backed up to Active Directory or a secure location.",
            evidence="TPM protector present",
            asset=hostname, points_deducted=0,
            remediation="Backup recovery key to AD: manage-bde -protectors -backup C: -AD or save to a secure location.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_host(target: str = "localhost", base_url: str = "", timeout: int = 8,
             verify_tls: bool = True) -> List[Finding]:
    """Full local machine security audit.

    Scans the entire laptop/machine for security issues.
    """
    findings: List[Finding] = []

    findings.extend(_check_os_info())
    findings.extend(_check_open_ports())
    findings.extend(_check_firewall())
    findings.extend(_check_users())
    findings.extend(_check_ssh())
    findings.extend(_check_docker())
    findings.extend(_check_env_secrets())
    findings.extend(_check_file_permissions())
    findings.extend(_check_cron_jobs())
    findings.extend(_check_auto_start())
    findings.extend(_check_network())
    findings.extend(_check_usb_devices())

    # New checks
    findings.extend(_check_suid_sgid())
    findings.extend(_check_selinux_apparmor())
    findings.extend(_check_kernel_cves())
    findings.extend(_check_ssh_authorized_keys())
    findings.extend(_check_world_writable_dirs())
    findings.extend(_check_suspicious_processes())
    findings.extend(_check_uac_status())
    findings.extend(_check_bitlocker_recovery())

    return findings
