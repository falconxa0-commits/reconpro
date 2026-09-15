"""DOCTOR module — Security health check with actionable fixes.

Provides a quick security health check with:
- Overall security posture score
- Category breakdown (network, auth, files, deps, env)
- Actionable fix commands the user can copy-paste
- Color-coded severity
- Quick wins section
- NTP time sync verification
- Firewall deep audit (rules, default policy)
- Audit/logging verification
- UAC/Sudo timeout check
- SSH key strength analysis
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


def _run(cmd: str, timeout: int = 8) -> Tuple[int, str]:
    """Run a command WITHOUT a shell, return (exit_code, output).

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


def _check_password_policy() -> List[Finding]:
    """Check password and authentication policies."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        # Windows: check password policy via net accounts
        code, out = _run('net accounts 2>NUL')
        if code == 0 and out:
            max_age = None
            min_len = None
            for line in out.splitlines():
                line_lower = line.lower().strip()
                if "maximum password age" in line_lower:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        try:
                            val = parts[-1].strip()
                            max_age = int(val) if val.lower() != "unlimited" else 99999
                        except (ValueError, IndexError):
                            pass
                elif "minimum password length" in line_lower:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        try:
                            min_len = int(parts[-1].strip())
                        except (ValueError, IndexError):
                            pass
            if max_age is not None and max_age > 90:
                findings.append(Finding(
                    title=f"Password max age is {max_age} days (too long)",
                    severity="medium", category="auth_policy",
                    module="doctor",
                    description=f"Password expiration is set to {max_age} days. NIST recommends 90 days or less.",
                    evidence=f"Maximum password age: {max_age}",
                    asset=hostname, points_deducted=4,
                    remediation="Set password expiration: net accounts /maxpwage:90",
                ))
            if min_len is not None and min_len < 12:
                findings.append(Finding(
                    title=f"Minimum password length is {min_len} (too short)",
                    severity="medium", category="auth_policy",
                    module="doctor",
                    description="Minimum password length is less than 12 characters. Longer passwords are more secure.",
                    evidence=f"Minimum password length: {min_len}",
                    asset=hostname, points_deducted=5,
                    remediation="Set minimum password length: net accounts /minpwlen:12",
                ))
        return findings

    # Non-Windows: check Linux password policies
    # Check if password aging is configured
    code, out = _run("cat /etc/login.defs 2>/dev/null")
    if code == 0 and out:
        max_days = 99999
        for line in out.splitlines():
            if line.strip().startswith("PASS_MAX_DAYS"):
                try:
                    max_days = int(line.split()[1])
                except (ValueError, IndexError):
                    pass
        if max_days > 90:
            findings.append(Finding(
                title=f"Password max age is {max_days} days (too long)",
                severity="medium", category="auth_policy",
                module="doctor",
                description=f"Password expiration is set to {max_days} days. NIST recommends 90 days or less.",
                evidence=f"PASS_MAX_DAYS={max_days}",
                asset=hostname, points_deducted=4,
                remediation="Set PASS_MAX_DAYS=90 in /etc/login.defs",
            ))

    # Check minimum password length
    code, out = _run("cat /etc/security/pwquality.conf 2>/dev/null || cat /etc/pam.d/common-password 2>/dev/null")
    if code == 0 and out:
        if "minlen" not in out.lower() and "pam_pwquality" not in out and "pam_cracklib" not in out:
            findings.append(Finding(
                title="No password complexity requirements configured",
                severity="medium", category="auth_policy",
                module="doctor",
                description="No minimum password length or complexity requirements found.",
                evidence="pwquality.conf not configured",
                asset=hostname, points_deducted=5,
                remediation="Configure /etc/security/pwquality.conf: minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1",
            ))

    return findings


def _check_disk_encryption() -> List[Finding]:
    """Check if disk encryption is active."""
    findings: List[Finding] = []
    hostname = _hostname()

    # Windows: check BitLocker
    if _is_windows():
        code, out = _run('manage-bde -status C: 2>NUL')
        if code == 0 and out and "Percentage Encrypted" in out:
            pct_match = re.search(r'Percentage Encrypted[:\s]+(\d+)%', out)
            if pct_match and int(pct_match.group(1)) > 0:
                return findings  # BitLocker is active
        findings.append(Finding(
            title="No disk encryption detected",
            severity="medium", category="disk_security",
            module="doctor",
            description="No BitLocker encryption found on the system drive. Laptop data is at risk if stolen.",
            evidence="BitLocker not active or not detected",
            asset=hostname, points_deducted=5,
            remediation="Enable BitLocker: Settings > System > BitLocker or manage-bde -on C:",
        ))
        return findings

    # macOS: check FileVault
    if _is_macos():
        code, out = _run("fdesetup status 2>/dev/null")
        if code == 0 and "On" in (out or ""):
            return findings  # FileVault is active
        findings.append(Finding(
            title="No disk encryption detected",
            severity="medium", category="disk_security",
            module="doctor",
            description="No FileVault encryption found. Laptop data is at risk if stolen.",
            evidence="FileVault not active",
            asset=hostname, points_deducted=5,
            remediation="Enable FileVault: System Preferences > Security & Privacy > FileVault",
        ))
        return findings

    # Linux: check LUKS / ecryptfs
    code, out = _run("lsblk -o NAME,FSTYPE,TYPE -n 2>/dev/null | grep -i crypt")
    if code != 0 or not out:
        # Check for ecryptfs
        code2, out2 = _run("mount | grep -i ecryptfs")
        if code2 != 0 or not out2:
            findings.append(Finding(
                title="No disk encryption detected",
                severity="medium", category="disk_security",
                module="doctor",
                description="No LUKS or ecryptfs encryption found. Laptop data is at risk if stolen.",
                evidence="No encrypted volumes found",
                asset=hostname, points_deducted=5,
                remediation="Enable full disk encryption: cryptsetup luksFormat /dev/sdX",
            ))
    return findings


def _check_auto_lock() -> List[Finding]:
    """Check screen lock / auto-lock settings."""
    findings: List[Finding] = []
    hostname = _hostname()

    # Windows: check screen saver lock via registry
    if _is_windows():
        code, out = _run('reg query "HKCU\\Control Panel\\Desktop" /v ScreenSaveActive 2>NUL')
        if code == 0 and out:
            if "REG_SZ" in out and "1" in out.split("REG_SZ")[-1]:
                return findings  # Screen saver with lock is active
        findings.append(Finding(
            title="Screen lock may not be enabled",
            severity="medium", category="physical_security",
            module="doctor",
            description="Windows screen lock does not appear to be active. Your machine can be accessed when unattended.",
            evidence="ScreenSaveActive not set to 1",
            asset=hostname, points_deducted=5,
            remediation="Enable screen lock: Settings > Personalization > Lock screen > Screen timeout",
        ))
        return findings

    # macOS: check screen saver idle time
    if _is_macos():
        code, out = _run("defaults read com.apple.screensaver idleTime 2>/dev/null")
        if code == 0 and out.strip():
            try:
                seconds = int(out.strip())
                if seconds > 0 and seconds <= 300:  # 5 minutes or less
                    return findings  # Auto-lock is configured
            except ValueError:
                pass
        findings.append(Finding(
            title="Screen lock may not be configured",
            severity="medium", category="physical_security",
            module="doctor",
            description="macOS screen lock idle time is not set or too long. Your machine can be accessed when unattended.",
            evidence=f"idleTime: {out.strip() if code == 0 else 'not set'}",
            asset=hostname, points_deducted=5,
            remediation="Enable screen lock: System Preferences > Desktop & Screen Saver > Start After",
        ))
        return findings

    # Linux: check gnome screensaver or xautolock
    code, out = _run("gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null")
    if code == 0:
        if "false" in out.lower():
            findings.append(Finding(
                title="Screen lock is disabled",
                severity="medium", category="physical_security",
                module="doctor",
                description="GNOME screen lock is disabled. Your machine can be accessed when unattended.",
                evidence="lock-enabled: false",
                asset=hostname, points_deducted=5,
                remediation="Enable screen lock: gsettings set org.gnome.desktop.screensaver lock-enabled true",
            ))
    else:
        # Check xautolock or xscreensaver
        code2, out2 = _run("pgrep -x xautolock 2>/dev/null || pgrep -x xscreensaver 2>/dev/null")
        if code2 != 0 or not out2:
            findings.append(Finding(
                title="No auto-lock mechanism detected",
                severity="low", category="physical_security",
                module="doctor",
                description="No screen locker daemon (xautolock/xscreensaver) is running.",
                evidence="No lock process found",
                asset=hostname, points_deducted=3,
                remediation="Install xautolock: sudo apt install xautolock && xautolock -time 5 -locker lock",
            ))

    return findings


def _check_antivirus() -> List[Finding]:
    """Check for antivirus / malware protection."""
    findings: List[Finding] = []
    hostname = _hostname()

    # Windows: check Windows Defender and common third-party AV
    if _is_windows():
        found_av = []
        code, out = _run('sc query WinDefend 2>NUL')
        if code == 0 and "RUNNING" in out:
            found_av.append("Windows Defender")
        # Check for common third-party AV processes
        third_party_av = [
            ("Malwarebytes", "where mbamtray 2>NUL"),
            ("Kaspersky", "where avpui 2>NUL"),
            ("Norton", "where ccSvcHst 2>NUL"),
            ("Sophos", "where SophosUI 2>NUL"),
        ]
        for name, cmd in third_party_av:
            c, _ = _run(cmd)
            if c == 0:
                found_av.append(name)
        if found_av:
            findings.append(Finding(
                title=f"Security tools installed: {', '.join(found_av)}",
                severity="info", category="malware_protection",
                module="doctor",
                description=f"Found security tools: {', '.join(found_av)}.",
                evidence=str(found_av),
                asset=hostname, points_deducted=0,
                remediation="",
            ))
        else:
            findings.append(Finding(
                title="No antivirus or security tools detected",
                severity="medium", category="malware_protection",
                module="doctor",
                description="No Windows Defender or third-party antivirus found. Your system has no malware detection.",
                evidence="No AV tools found",
                asset=hostname, points_deducted=5,
                remediation="Enable Windows Defender: Settings > Update & Security > Windows Security",
            ))
        return findings

    # Non-Windows: check common Linux AV tools
    av_tools = [
        ("clamav", "clamdscan --version"),
        ("rkhunter", "rkhunter --version"),
        ("chkrootkit", "chkrootkit -V 2>/dev/null | head -1"),
        ("lynis", "lynis version 2>/dev/null"),
        ("fail2ban", "fail2ban-client --version"),
    ]

    found_av = []
    for name, cmd in av_tools:
        code, out = _run(cmd)
        if code == 0 and out:
            found_av.append(name)

    if found_av:
        findings.append(Finding(
            title=f"Security tools installed: {', '.join(found_av)}",
            severity="info", category="malware_protection",
            module="doctor",
            description=f"Found security tools: {', '.join(found_av)}.",
            evidence=str(found_av),
            asset=hostname, points_deducted=0,
            remediation="",
        ))
    else:
        findings.append(Finding(
            title="No antivirus or security tools detected",
            severity="medium", category="malware_protection",
            module="doctor",
            description="No ClamAV, rkhunter, chkrootkit, Lynis, or fail2ban found. Your system has no malware detection.",
            evidence="No AV tools found",
            asset=hostname, points_deducted=5,
            remediation="Install security tools: sudo apt install clamav rkhunter lynis fail2ban",
        ))

    return findings


def _check_system_updates() -> List[Finding]:
    """Check for pending system updates."""
    findings: List[Finding] = []
    hostname = _hostname()

    # Windows: check last update date via PowerShell
    if _is_windows():
        code, out = _run('powershell -command "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn" 2>NUL')
        if code == 0 and out.strip():
            findings.append(Finding(
                title=f"Last Windows update: {out.strip()[:30]}",
                severity="info", category="updates",
                module="doctor",
                description=f"Last system update was installed on {out.strip()[:30]}. Check Windows Update regularly.",
                evidence=out.strip()[:50],
                asset=hostname, points_deducted=0,
                remediation="Update Windows: Settings > Windows Update",
            ))
        else:
            findings.append(Finding(
                title="Could not determine last Windows update",
                severity="low", category="updates",
                module="doctor",
                description="Unable to check when Windows was last updated.",
                evidence="Get-HotFix failed",
                asset=hostname, points_deducted=2,
                remediation="Update Windows: Settings > Windows Update",
            ))
        return findings

    # macOS: check for pending updates
    if _is_macos():
        code, out = _run("softwareupdate -l 2>&1 | grep -c 'restart' 2>/dev/null")
        if code == 0 and out.strip():
            try:
                count = int(out.strip())
                if count > 0:
                    findings.append(Finding(
                        title=f"{count} pending macOS update(s) requiring restart",
                        severity="medium", category="updates",
                        module="doctor",
                        description=f"{count} macOS updates are available and require a restart. Unpatched software is a common attack vector.",
                        evidence=f"{count} updates pending",
                        asset=hostname, points_deducted=3 + count,
                        remediation="Update macOS: System Preferences > Software Update",
                    ))
            except ValueError:
                pass
        return findings

    # Linux: Ubuntu/Debian
    code, out = _run("apt list --upgradable 2>/dev/null | grep -c 'upgradable'")
    if code == 0 and out.strip():
        try:
            count = int(out.strip())
            if count > 0:
                sev = "high" if count > 20 else ("medium" if count > 5 else "low")
                findings.append(Finding(
                    title=f"{count} pending system updates",
                    severity=sev, category="updates",
                    module="doctor",
                    description=f"{count} packages have updates available. Unpatched packages are a common attack vector.",
                    evidence=f"{count} upgradable packages",
                    asset=hostname, points_deducted=3 + count,
                    remediation="Update system: sudo apt update && sudo apt upgrade -y",
                ))
        except ValueError:
            pass

    return findings


def _check_shared_memory() -> List[Finding]:
    """Check /dev/shm is mounted noexec (Linux only)."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows() or _is_macos():
        return findings  # Not applicable on Windows/macOS

    code, out = _run("mount | grep /dev/shm")
    if code == 0 and out:
        if "noexec" not in out:
            findings.append(Finding(
                title="/dev/shm is not mounted with noexec",
                severity="medium", category="hardening",
                module="doctor",
                description="/dev/shm allows execution of files. Attackers can use this to run malware from shared memory.",
                evidence=out.strip()[:200],
                asset=hostname, points_deducted=5,
                remediation="Add to /etc/fstab: tmpfs /dev/shm tmpfs defaults,noexec,nosuid 0 0",
            ))

    return findings


def _check_core_dumps() -> List[Finding]:
    """Check if core dumps are restricted (Linux only)."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        # Windows: check via WMI (Windows Error Reporting / crash dumps)
        code, out = _run('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting" /v Disabled 2>NUL')
        if code == 0 and "REG_DWORD" in out and "0x1" in out:
            findings.append(Finding(
                title="Windows Error Reporting is enabled",
                severity="info", category="hardening",
                module="doctor",
                description="Windows Error Reporting may write crash dumps containing sensitive data.",
                evidence="WER not disabled",
                asset=hostname, points_deducted=1,
                remediation="Disable WER if crash dumps are a concern: Settings > Privacy > Diagnostics & feedback",
            ))
        return findings

    if _is_macos():
        return findings  # macOS core dump handling is internal

    code, out = _run("ulimit -c")
    if code == 0 and out.strip() not in ("0", "unlimited"):
        pass  # some limit set
    elif code == 0 and out.strip() == "unlimited":
        findings.append(Finding(
            title="Core dumps are unlimited",
            severity="low", category="hardening",
            module="doctor",
            description="Core dumps can contain sensitive data from memory (keys, passwords, etc.).",
            evidence="ulimit -c: unlimited",
            asset=hostname, points_deducted=2,
            remediation="Set ulimit -c 0 or add 'fs.suid_dumpable=0' to /etc/sysctl.conf",
        ))

    return findings


def _check_browser_security() -> List[Finding]:
    """Check for browser security extensions/configs."""
    findings: List[Finding] = []
    hostname = _hostname()

    # This is informational - we can check if common privacy/security browsers are installed
    browsers_found = []
    browser_checks = []
    if _is_windows():
        browser_checks = [
            ("firefox", "where firefox 2>NUL"),
            ("chrome", "where chrome 2>NUL"),
            ("brave", "where brave 2>NUL"),
        ]
    else:
        browser_checks = [
            ("firefox", "which firefox 2>/dev/null"),
            ("chromium", "which chromium-browser 2>/dev/null || which chromium 2>/dev/null"),
            ("brave", "which brave-browser 2>/dev/null"),
        ]

    for name, cmd in browser_checks:
        code, _ = _run(cmd)
        if code == 0:
            browsers_found.append(name)

    if browsers_found:
        findings.append(Finding(
            title=f"Browsers installed: {', '.join(browsers_found)}",
            severity="info", category="browser_security",
            module="doctor",
            description="Consider installing privacy extensions: uBlock Origin, HTTPS Everywhere, Privacy Badger.",
            evidence=str(browsers_found),
            asset=hostname, points_deducted=0,
            remediation="Install security extensions: uBlock Origin, Privacy Badger, HTTPS Everywhere",
        ))

    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 1: NTP Time Sync
# ---------------------------------------------------------------------------

def _check_ntp_sync() -> List[Finding]:
    """Check if system clock is synchronized via NTP."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        # Windows: use w32tm
        code, out = _run('w32tm /query /status 2>NUL')
        if code == 0 and out:
            # Look for "Source" and "Last Successful Sync" lines
            source = ""
            synced = False
            for line in out.splitlines():
                line_stripped = line.strip()
                if "Source:" in line_stripped:
                    source = line_stripped.split("Source:", 1)[1].strip()
                if "Last Successful Sync Time" in line_stripped:
                    # Check if sync happened recently (not "(none)" or very old)
                    sync_val = line_stripped.split(":", 1)[1].strip().lower() if ":" in line_stripped else ""
                    if sync_val and sync_val not in ("(none)", ""):
                        synced = True
            if not source or source.lower() in ("local cmos clock", "free-running system clock"):
                findings.append(Finding(
                    title="Windows NTP not configured (using local CMOS clock)",
                    severity="medium", category="ntp",
                    module="doctor",
                    description="System is not synchronizing with an NTP server. Time drift can break certificate validation and log correlation.",
                    evidence=f"NTP Source: {source or 'not found'}",
                    asset=hostname, points_deducted=5,
                    remediation="Configure NTP: w32tm /config /manualpeerlist:pool.ntp.org /syncfromflags:manual /reliable:yes /update && w32tm /resync",
                ))
            elif not synced:
                findings.append(Finding(
                    title="Windows NTP configured but no recent sync",
                    severity="low", category="ntp",
                    module="doctor",
                    description="NTP source is configured but clock has not synchronized recently.",
                    evidence=f"Source: {source}",
                    asset=hostname, points_deducted=3,
                    remediation="Force NTP sync: w32tm /resync",
                ))
            else:
                findings.append(Finding(
                    title=f"Windows NTP synchronized (source: {source})",
                    severity="info", category="ntp",
                    module="doctor",
                    description="System clock is synchronized via NTP.",
                    evidence=f"Source: {source}",
                    asset=hostname, points_deducted=0,
                    remediation="",
                ))
        else:
            findings.append(Finding(
                title="Could not query Windows NTP status",
                severity="low", category="ntp",
                module="doctor",
                description="Unable to query Windows Time service.",
                evidence="w32tm query failed",
                asset=hostname, points_deducted=2,
                remediation="Ensure Windows Time service is running: sc query w32time",
            ))
        return findings

    if _is_macos():
        # macOS: use systemsetup
        code, out = _run("systemsetup -getusingnetworktime 2>/dev/null")
        if code == 0:
            if "on" in out.lower():
                # Get the NTP server
                code2, out2 = _run("systemsetup -getnetworktimeserver 2>/dev/null")
                server = out2.strip().split(":", 1)[1].strip() if code2 == 0 and ":" in out2 else "unknown"
                findings.append(Finding(
                    title=f"macOS NTP enabled (server: {server})",
                    severity="info", category="ntp",
                    module="doctor",
                    description="System clock is set to synchronize via network time.",
                    evidence=f"Server: {server}",
                    asset=hostname, points_deducted=0,
                    remediation="",
                ))
            else:
                findings.append(Finding(
                    title="macOS network time synchronization is OFF",
                    severity="medium", category="ntp",
                    module="doctor",
                    description="macOS is not synchronizing clock via network time. Time drift can break certificate validation.",
                    evidence=out.strip()[:200],
                    asset=hostname, points_deducted=5,
                    remediation="Enable NTP: sudo systemsetup -setusingnetworktime on -setnetworktimeserver time.apple.com",
                ))
        return findings

    # Linux: use timedatectl
    code, out = _run("timedatectl status 2>/dev/null")
    if code == 0 and out:
        synced = False
        ntp_service = ""
        for line in out.splitlines():
            line_stripped = line.strip()
            if "synchronized:" in line_stripped and "yes" in line_stripped.lower():
                synced = True
            if "NTP service:" in line_stripped:
                ntp_service = line_stripped.split(":", 1)[1].strip() if ":" in line_stripped else ""
        if not synced:
            findings.append(Finding(
                title="System clock is NOT synchronized via NTP",
                severity="medium", category="ntp",
                module="doctor",
                description="The system clock is not synchronized. Time drift can break TLS certificate validation and log forensics.",
                evidence=out.strip()[:200],
                asset=hostname, points_deducted=5,
                remediation="Enable NTP: sudo timedatectl set-ntp true",
            ))
        else:
            findings.append(Finding(
                title=f"System clock is synchronized via NTP (service: {ntp_service})",
                severity="info", category="ntp",
                module="doctor",
                description="System clock is synchronized via NTP.",
                evidence=f"NTP service: {ntp_service}",
                asset=hostname, points_deducted=0,
                remediation="",
            ))
    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 2: Firewall Deep Audit
# ---------------------------------------------------------------------------

def _check_firewall_deep() -> List[Finding]:
    """Deep audit of firewall rules: default policy, blocked inbound ports."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        # Check default inbound/outbound action
        code, out = _run('netsh advfirewall show currentprofile 2>NUL')
        if code == 0 and out:
            inbound_action = ""
            outbound_action = ""
            for line in out.splitlines():
                line_l = line.strip().lower()
                if "inbound" in line_l and ("allow" in line_l or "block" in line_l):
                    inbound_action = line.strip()
                if "outbound" in line_l and ("allow" in line_l or "block" in line_l):
                    outbound_action = line.strip()
            if "allow" in inbound_action.lower():
                findings.append(Finding(
                    title="Windows Firewall default inbound policy: ALLOW",
                    severity="high", category="firewall_deep",
                    module="doctor",
                    description="Default inbound firewall action is Allow. Unconfigured inbound connections are permitted.",
                    evidence=inbound_action,
                    asset=hostname, points_deducted=8,
                    remediation="Set default inbound to Block: netsh advfirewall set currentprofile firewallpolicy blockinbound,allowoutbound",
                ))
            else:
                findings.append(Finding(
                    title=f"Windows Firewall default inbound policy: BLOCK",
                    severity="info", category="firewall_deep",
                    module="doctor",
                    description="Default inbound firewall action is Block (secure).",
                    evidence=inbound_action,
                    asset=hostname, points_deducted=0,
                    remediation="",
                ))

        # Check for specific port rules allowing inbound
        code2, out2 = _run('netsh advfirewall firewall show rule name=all dir=in 2>NUL | findstr /i "Rule Name LocalPort"')
        if code2 == 0 and out2:
            lines = out2.splitlines()
            allowed_inbound_ports = []
            current_rule = ""
            for line in lines:
                if "Rule Name" in line:
                    current_rule = line.strip()
                elif "LocalPort" in line:
                    port = line.strip().split(":", 1)[1].strip() if ":" in line else ""
                    if port:
                        allowed_inbound_ports.append(f"{port} ({current_rule})")
            if len(allowed_inbound_ports) > 10:
                findings.append(Finding(
                    title=f"{len(allowed_inbound_ports)} inbound firewall rules with open ports",
                    severity="medium", category="firewall_deep",
                    module="doctor",
                    description=f"A large number of inbound port rules increases attack surface. Review these rules.",
                    evidence="; ".join(allowed_inbound_ports[:8]),
                    asset=hostname, points_deducted=5,
                    remediation="Review and remove unnecessary inbound rules: Windows Defender Firewall > Inbound Rules",
                ))
        return findings

    if _is_macos():
        # macOS: check pf (packet filter) rules
        code, out = _run("sudo pfctl -sr 2>/dev/null")
        if code == 0 and out:
            block_rules = [l for l in out.splitlines() if "block" in l.lower()]
            if not block_rules:
                findings.append(Finding(
                    title="macOS pf has no block rules",
                    severity="medium", category="firewall_deep",
                    module="doctor",
                    description="macOS packet filter (pf) is loaded but has no block rules. All traffic is permitted by default.",
                    evidence="No block rules in pf",
                    asset=hostname, points_deducted=5,
                    remediation="Configure pf with block rules: /etc/pf.conf",
                ))
            else:
                findings.append(Finding(
                    title=f"macOS pf has {len(block_rules)} block rule(s)",
                    severity="info", category="firewall_deep",
                    module="doctor",
                    description="macOS packet filter has block rules configured.",
                    evidence=f"{len(block_rules)} block rules",
                    asset=hostname, points_deducted=0,
                    remediation="",
                ))
        return findings

    # Linux: deep audit
    # Check UFW default policies
    code, out = _run("ufw status verbose 2>/dev/null")
    if code == 0 and "Status: active" in out:
        has_default_deny_in = "Default: deny (incoming)" in out
        has_default_deny_out = "Default: deny (outgoing)" in out
        if not has_default_deny_in:
            findings.append(Finding(
                title="UFW default incoming policy is NOT deny",
                severity="high", category="firewall_deep",
                module="doctor",
                description="UFW is active but the default incoming policy is not 'deny'. Unsolicited inbound connections may be allowed.",
                evidence=out[:200],
                asset=hostname, points_deducted=8,
                remediation="Set default deny: sudo ufw default deny incoming",
            ))
        else:
            findings.append(Finding(
                title="UFW default incoming policy: deny (good)",
                severity="info", category="firewall_deep",
                module="doctor",
                description="UFW default incoming policy is deny.",
                evidence="Default: deny (incoming)",
                asset=hostname, points_deducted=0,
                remediation="",
            ))
        return findings

    # iptables deep audit
    code, out = _run("iptables -L INPUT -n --line-numbers 2>/dev/null")
    if code == 0 and out:
        # Check default INPUT policy
        policy_match = re.search(r'Chain INPUT \(policy (\w+)', out)
        if policy_match:
            policy = policy_match.group(1)
            if policy == "ACCEPT":
                # Count DROP/REJECT rules
                drop_count = len([l for l in out.splitlines() if "DROP" in l or "REJECT" in l])
                if drop_count == 0:
                    findings.append(Finding(
                        title="iptables INPUT policy is ACCEPT with no DROP rules",
                        severity="high", category="firewall_deep",
                        module="doctor",
                        description="iptables INPUT chain has a default ACCEPT policy and no DROP/REJECT rules. All inbound traffic is allowed.",
                        evidence=out[:200],
                        asset=hostname, points_deducted=10,
                        remediation="Set default DROP: sudo iptables -P INPUT DROP && add rules for needed traffic",
                    ))
                else:
                    findings.append(Finding(
                        title=f"iptables INPUT policy ACCEPT but {drop_count} DROP/REJECT rule(s) present",
                        severity="medium", category="firewall_deep",
                        module="doctor",
                        description="Default policy is ACCEPT but some filtering rules exist. Consider changing default to DROP.",
                        evidence=f"Policy: ACCEPT, {drop_count} drop rules",
                        asset=hostname, points_deducted=4,
                        remediation="Set default DROP: sudo iptables -P INPUT DROP",
                    ))
            else:
                findings.append(Finding(
                    title=f"iptables INPUT policy is {policy} (good)",
                    severity="info", category="firewall_deep",
                    module="doctor",
                    description="iptables INPUT chain has a restrictive default policy.",
                    evidence=f"Policy: {policy}",
                    asset=hostname, points_deducted=0,
                    remediation="",
                ))
    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 3: Audit Logging
# ---------------------------------------------------------------------------

def _check_audit_logging() -> List[Finding]:
    """Check if audit/logging is enabled."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        # Check Windows Event Log service
        code, out = _run('sc query EventLog 2>NUL')
        if code != 0 or "RUNNING" not in out:
            findings.append(Finding(
                title="Windows Event Log service is not running",
                severity="high", category="audit_logging",
                module="doctor",
                description="Windows Event Log service is not running. Security events and audit logs are not being recorded.",
                evidence="EventLog service not RUNNING",
                asset=hostname, points_deducted=8,
                remediation="Start Event Log: sc start EventLog. Set to Automatic: sc config EventLog start= auto",
            ))
        else:
            # Check if Security audit log has events
            code2, out2 = _run('wevtutil qe Security /c:1 /rd:true /f:text 2>NUL | findstr "Event ID"')
            if code2 == 0 and out2:
                findings.append(Finding(
                    title="Windows Event Log is active (Security log has events)",
                    severity="info", category="audit_logging",
                    module="doctor",
                    description="Windows Event Log is running and recording security events.",
                    evidence="Security log active",
                    asset=hostname, points_deducted=0,
                    remediation="",
                ))
            else:
                findings.append(Finding(
                    title="Windows Event Log running but Security log may be empty",
                    severity="medium", category="audit_logging",
                    module="doctor",
                    description="Event Log service is running but the Security audit log appears empty. Audit policy may not be configured.",
                    evidence="No events found in Security log",
                    asset=hostname, points_deducted=5,
                    remediation="Configure audit policy: secpol.msc > Local Policies > Audit Policy. Enable: Logon, Privilege Use, Object Access.",
                ))
        return findings

    if _is_macos():
        # macOS: check unified logging / ASL
        # Check if logging is active by looking at recent log entries
        code, out = _run("log show --last 1m --style compact 2>/dev/null | wc -l")
        if code == 0 and out.strip():
            try:
                count = int(out.strip())
                if count > 0:
                    findings.append(Finding(
                        title=f"macOS unified logging is active ({count} recent entries)",
                        severity="info", category="audit_logging",
                        module="doctor",
                        description="macOS unified logging is recording events.",
                        evidence=f"{count} log entries in last minute",
                        asset=hostname, points_deducted=0,
                        remediation="",
                    ))
                else:
                    findings.append(Finding(
                        title="macOS unified logging appears inactive",
                        severity="medium", category="audit_logging",
                        module="doctor",
                        description="No log entries found in the last minute. Unified logging may be disabled or misconfigured.",
                        evidence="0 log entries in last minute",
                        asset=hostname, points_deducted=5,
                        remediation="Check logging configuration: sudo log config --status",
                    ))
            except ValueError:
                pass
        return findings

    # Linux: check rsyslog / journald / auditd
    logging_found = []

    # Check rsyslog
    code, out = _run("systemctl is-active rsyslog 2>/dev/null")
    if code == 0 and out.strip() == "active":
        logging_found.append("rsyslog")

    # Check systemd-journald
    code, out = _run("systemctl is-active systemd-journald 2>/dev/null")
    if code == 0 and out.strip() == "active":
        logging_found.append("systemd-journald")

    # Check auditd
    code, out = _run("systemctl is-active auditd 2>/dev/null")
    if code == 0 and out.strip() == "active":
        logging_found.append("auditd")

    if not logging_found:
        findings.append(Finding(
            title="No logging services detected (rsyslog/journald/auditd)",
            severity="high", category="audit_logging",
            module="doctor",
            description="No standard logging services are running. Security events are not being recorded.",
            evidence="No active logging services found",
            asset=hostname, points_deducted=10,
            remediation="Install and enable logging: sudo apt install rsyslog auditd && sudo systemctl enable --now rsyslog auditd",
        ))
    else:
        # Check if auditd has rules
        if "auditd" in logging_found:
            code, out = _run("sudo auditctl -l 2>/dev/null")
            if code == 0 and not out.strip():
                findings.append(Finding(
                    title="auditd is running but has NO audit rules",
                    severity="medium", category="audit_logging",
                    module="doctor",
                    description="auditd is active but no audit rules are configured. It is not monitoring anything.",
                    evidence="auditctl -l returned empty",
                    asset=hostname, points_deducted=5,
                    remediation="Add audit rules: sudo auditctl -w /etc/passwd -p wa -k identity && sudo apt install auditd-rules",
                ))
        findings.append(Finding(
            title=f"Logging services active: {', '.join(logging_found)}",
            severity="info", category="audit_logging",
            module="doctor",
            description=f"Logging services are running: {', '.join(logging_found)}.",
            evidence=str(logging_found),
            asset=hostname, points_deducted=0,
            remediation="",
        ))

    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 4: UAC/Sudo Timeout
# ---------------------------------------------------------------------------

def _check_uac_sudo_timeout() -> List[Finding]:
    """Check UAC prompt behavior (Windows) and sudo timestamp_timeout (Linux)."""
    findings: List[Finding] = []
    hostname = _hostname()

    if _is_windows():
        # Check UAC Secure Desktop prompt setting
        code, out = _run('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v PromptOnSecureDesktop 2>NUL')
        if code == 0 and out:
            match = re.search(r'REG_DWORD\s+0x([0-9a-fA-F]+)', out)
            if match:
                val = int(match.group(1), 16)
                if val == 0:
                    findings.append(Finding(
                        title="UAC Secure Desktop prompt is DISABLED",
                        severity="high", category="uac_sudo",
                        module="doctor",
                        description="UAC no longer dims the desktop when prompting. Malware can automate UAC prompts more easily.",
                        evidence=f"PromptOnSecureDesktop = {val}",
                        asset=hostname, points_deducted=8,
                        remediation="Enable Secure Desktop: Set PromptOnSecureDesktop to 1 in registry.",
                    ))
                else:
                    findings.append(Finding(
                        title="UAC Secure Desktop prompt is enabled",
                        severity="info", category="uac_sudo",
                        module="doctor",
                        description="UAC prompts on a secure desktop (dimmed), making automation more difficult.",
                        evidence="PromptOnSecureDesktop = 1",
                        asset=hostname, points_deducted=0,
                        remediation="",
                    ))

        # Check if admin approval mode is enabled for built-in admin
        code2, out2 = _run('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v FilterAdministratorToken 2>NUL')
        if code2 == 0 and out2:
            match2 = re.search(r'REG_DWORD\s+0x([0-9a-fA-F]+)', out2)
            if match2 and int(match2.group(1), 16) == 0:
                findings.append(Finding(
                    title="Built-in Administrator account bypasses UAC",
                    severity="medium", category="uac_sudo",
                    module="doctor",
                    description="The built-in Administrator account does not receive UAC prompts for admin operations.",
                    evidence="FilterAdministratorToken = 0",
                    asset=hostname, points_deducted=5,
                    remediation="Enable FilterAdministratorToken: Set to 1 in registry. Avoid using the built-in admin account.",
                ))
        return findings

    if _is_macos():
        # macOS doesn't have a direct equivalent to sudo timestamp_timeout in the same way,
        # but check if sudo is configured
        code, out = _run("sudo -n true 2>&1")
        if code == 0:
            findings.append(Finding(
                title="macOS: sudo can run without password (NOPASSWD)",
                severity="high", category="uac_sudo",
                module="doctor",
                description="Current user can run sudo without a password. Any process running as this user can gain root access.",
                evidence="sudo -n returned 0",
                asset=hostname, points_deducted=10,
                remediation="Remove NOPASSWD from /etc/sudoers. Use: visudo",
            ))
        return findings

    # Linux: check sudo timestamp_timeout
    code, out = _run("sudo cat /etc/sudoers 2>/dev/null | grep -i timestamp_timeout")
    if code == 0 and out.strip():
        match = re.search(r'timestamp_timeout=(\d+)', out)
        if match:
            try:
                timeout_val = int(match.group(1))
                if timeout_val <= 0:
                    findings.append(Finding(
                        title=f"sudo timestamp_timeout is {timeout_val} (always asks for password)",
                        severity="info", category="uac_sudo",
                        module="doctor",
                        description="sudo always asks for password. This is the most secure setting.",
                        evidence=f"timestamp_timeout={timeout_val}",
                        asset=hostname, points_deducted=0,
                        remediation="",
                    ))
                elif timeout_val <= 5:
                    findings.append(Finding(
                        title=f"sudo timestamp_timeout is {timeout_val} minutes (reasonable)",
                        severity="info", category="uac_sudo",
                        module="doctor",
                        description=f"sudo remembers credentials for {timeout_val} minutes. This is a reasonable balance of security and usability.",
                        evidence=f"timestamp_timeout={timeout_val}",
                        asset=hostname, points_deducted=0,
                        remediation="",
                    ))
                elif timeout_val > 15:
                    findings.append(Finding(
                        title=f"sudo timestamp_timeout is {timeout_val} minutes (too long)",
                        severity="medium", category="uac_sudo",
                        module="doctor",
                        description=f"sudo remembers credentials for {timeout_val} minutes. An attacker with brief access has a long window for privilege escalation.",
                        evidence=f"timestamp_timeout={timeout_val}",
                        asset=hostname, points_deducted=5,
                        remediation="Reduce timeout in /etc/sudoers: Defaults timestamp_timeout=5",
                    ))
            except ValueError:
                pass
    else:
        # Default sudo timestamp_timeout is 15 minutes — check for NOPASSWD instead
        code2, out2 = _run("sudo -n true 2>&1")
        if code2 == 0:
            findings.append(Finding(
                title="sudo can run without password (NOPASSWD)",
                severity="high", category="uac_sudo",
                module="doctor",
                description="Current user can run sudo without a password. Any process running as this user can gain root access.",
                evidence="sudo -n returned 0",
                asset=hostname, points_deducted=10,
                remediation="Remove NOPASSWD from /etc/sudoers. Use: sudo visudo",
            ))
        else:
            findings.append(Finding(
                title="sudo timestamp_timeout using default (15 min)",
                severity="low", category="uac_sudo",
                module="doctor",
                description="sudo uses the default 15-minute credential cache. Consider reducing it for better security.",
                evidence="timestamp_timeout not explicitly set (default=15)",
                asset=hostname, points_deducted=2,
                remediation="Add to /etc/sudoers: Defaults timestamp_timeout=5",
            ))

    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 5: SSH Key Strength
# ---------------------------------------------------------------------------

def _check_ssh_key_strength() -> List[Finding]:
    """Check SSH key types and lengths in ~/.ssh/."""
    findings: List[Finding] = []
    hostname = _hostname()

    ssh_dir = os.path.expanduser("~/.ssh")
    if not os.path.isdir(ssh_dir):
        return findings

    # Known key type patterns and minimum bit lengths
    # Format: (file_glob_pattern, key_type_regex, recommended_min_bits, severity_if_short, description)
    key_files = []
    for entry in os.listdir(ssh_dir):
        full = os.path.join(ssh_dir, entry)
        if not os.path.isfile(full):
            continue
        # Check for private keys (no .pub extension, and known key file names)
        if entry.endswith(".pub"):
            continue  # We'll read the .pub to check key type
        if entry.startswith("id_") and not entry.endswith(".pub"):
            key_files.append((full, entry, os.path.join(ssh_dir, entry + ".pub")))

    for priv_path, priv_name, pub_path in key_files:
        # Read the public key for key type and bit length
        if not os.path.isfile(pub_path):
            continue
        try:
            with open(pub_path, errors="replace") as f:
                content = f.read().strip()
        except Exception:
            continue

        # Parse: ssh-rsa AAAA... comment  OR  ssh-ed25519 AAAA... comment
        parts = content.split()
        if len(parts) < 2:
            continue

        key_type = parts[0]
        key_data_b64 = parts[1]

        # Decode base64 key data to get bit length
        import base64
        try:
            key_bytes = base64.b64decode(key_data_b64)
            bit_length = len(key_bytes) * 8
        except Exception:
            bit_length = 0

        if key_type == "ssh-rsa":
            # RSA keys: minimum 3072 bits recommended, 2048 is bare minimum
            if bit_length < 2048:
                findings.append(Finding(
                    title=f"Weak RSA SSH key: {priv_name} (~{bit_length} bits)",
                    severity="high", category="ssh_key_strength",
                    module="doctor",
                    description=f"RSA key {priv_name} is approximately {bit_length} bits. RSA keys should be at least 3072 bits.",
                    evidence=f"Key type: {key_type}, ~{bit_length} bits",
                    asset=hostname, points_deducted=8,
                    remediation=f"Generate a new key: ssh-keygen -t ed25519 -C 'your@email.com'. Or use RSA 4096: ssh-keygen -t rsa -b 4096",
                ))
            elif bit_length < 3072:
                findings.append(Finding(
                    title=f"RSA SSH key could be stronger: {priv_name} (~{bit_length} bits)",
                    severity="medium", category="ssh_key_strength",
                    module="doctor",
                    description=f"RSA key {priv_name} is approximately {bit_length} bits. NIST recommends 3072+ bits for RSA.",
                    evidence=f"Key type: {key_type}, ~{bit_length} bits",
                    asset=hostname, points_deducted=4,
                    remediation=f"Consider regenerating: ssh-keygen -t ed25519 -C 'your@email.com'",
                ))
            else:
                findings.append(Finding(
                    title=f"SSH key {priv_name}: RSA {bit_length} bits (good)",
                    severity="info", category="ssh_key_strength",
                    module="doctor",
                    description=f"RSA key {priv_name} has sufficient bit length.",
                    evidence=f"{key_type} ~{bit_length} bits",
                    asset=hostname, points_deducted=0,
                    remediation="",
                ))
        elif key_type == "ssh-dss":
            # DSA keys are deprecated
            findings.append(Finding(
                title=f"Deprecated DSA SSH key: {priv_name}",
                severity="high", category="ssh_key_strength",
                module="doctor",
                description="DSA (ssh-dss) keys are deprecated and disabled by default in modern OpenSSH. They provide weak security.",
                evidence=f"Key type: {key_type}",
                asset=hostname, points_deducted=8,
                remediation=f"Generate a new key: ssh-keygen -t ed25519 -C 'your@email.com'",
            ))
        elif key_type == "ecdsa-sha2-nistp256":
            findings.append(Finding(
                title=f"SSH key {priv_name}: ECDSA P-256 (acceptable)",
                severity="info", category="ssh_key_strength",
                module="doctor",
                description="ECDSA P-256 provides ~128-bit security. Consider Ed25519 for better performance and security.",
                evidence=f"Key type: {key_type}",
                asset=hostname, points_deducted=0,
                remediation="Consider migrating to ed25519: ssh-keygen -t ed25519 -C 'your@email.com'",
            ))
        elif key_type in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
            findings.append(Finding(
                title=f"SSH key {priv_name}: Ed25519 (strong)",
                severity="info", category="ssh_key_strength",
                module="doctor",
                description="Ed25519 keys provide excellent security and performance. This is a modern, recommended key type.",
                evidence=f"Key type: {key_type}",
                asset=hostname, points_deducted=0,
                remediation="",
            ))
        else:
            findings.append(Finding(
                title=f"Unrecognized SSH key type: {key_type} in {priv_name}",
                severity="low", category="ssh_key_strength",
                module="doctor",
                description=f"SSH key type '{key_type}' is not a standard recognized type. Verify this key is legitimate.",
                evidence=f"Key type: {key_type}",
                asset=hostname, points_deducted=3,
                remediation="Verify the key is legitimate. Consider replacing with ed25519.",
            ))

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_doctor(target: str = "localhost", base_url: str = "", timeout: int = 8,
               verify_tls: bool = True) -> List[Finding]:
    """Security health check with actionable fixes.

    Runs a comprehensive health check and provides
    copy-paste fix commands for every issue found.
    """
    findings: List[Finding] = []

    findings.extend(_check_password_policy())
    findings.extend(_check_disk_encryption())
    findings.extend(_check_auto_lock())
    findings.extend(_check_antivirus())
    findings.extend(_check_system_updates())
    findings.extend(_check_shared_memory())
    findings.extend(_check_core_dumps())
    findings.extend(_check_browser_security())

    # New checks
    findings.extend(_check_ntp_sync())
    findings.extend(_check_firewall_deep())
    findings.extend(_check_audit_logging())
    findings.extend(_check_uac_sudo_timeout())
    findings.extend(_check_ssh_key_strength())

    return findings
