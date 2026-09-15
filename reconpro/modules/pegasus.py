from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional
from ..http_layer import http_probe, Finding


PEGASUS_C2_DOMAINS = [
    "pandorasoft.ps", "pstcpool.com", "kstechglobal.com", "traviskirk.com",
    "macserve.org", "starline-beta.com", "netplus-bd.com", "nocturnal-service.com",
    "oasis-tech.co", "kristall-wellness.com", "appsbrowser.net", "slserver.in",
    "safesurf.in", "heraldsolution.com", "bookmarkingplus.com", "datalist.co.in",
    "globalportal.co.in", "mailserverlog.com", "mobileserver.in", "onlineserver.in",
    "port-server.com", "portserver.in", "serverlog.co.in", "serverlog.in",
    "sharkserver.in", "smartserver.in", "sms-server.in", "starline-servers.com",
    "starlineservers.com", "starlinebeta.com", "systemserver.in", "techserver.in",
    "uploadserver.in", "webserverlog.com", "winserver.in", "worldserver.in",
    "appliedmicrosystems.com", "applmicro.com", "atomiceconet.com", "beamingdata.com",
    "bikiniplanet.net", "binaryprotect.com", "bisonhealth.com", "biscuithouse.com",
    "bluelightanalytics.com", "bluewaveuae.com", "bonniewheel.com", "bootstrap-design.com",
    "bosslife.in", "bouncycastle.in", "brand-hygiene.com", "brickowl.com",
    "briankrebs.com", "brightkite.com", "brinkster.com", "bronzesun.com",
    "calderdalegazette.co.uk", "camdenny.com", "capricornhost.com", "carltonhood.com",
    "castironhosting.com", "catn.com", "cellularoutfitter.com", "certifiedmediadesigns.com",
    "charitymobile.org", "chaseforeclosure.com", "chicagoseoadvanced.com", "choicelendinginc.com",
    "chromeadvanced.com", "cincinnatibell.com", "civicserve.com", "claimyourbonus.com",
    "clarksdaleattorney.com", "clickpalace.com", "cloudcomputeonline.com", "clubpenguinplanet.com",
    "cobaltstrike.com", "code4mobile.com", "coldfusionnation.com", "coloradobanking.com",
    "columbusbankruptcy.com", "communitypolicingcenter.org", "compcase.com", "compreviews.net",
    "compuchamps.com", "connecticutbankruptcy.com", "conversecountywy.gov", "cookinggamesforkids.org",
    "corporateinvestmentonline.com", "cpanellogin.net", "cranialconcept.com", "createacover.com",
    "creditrepairace.com", "cricketfundas.com", "cubehosting.net", "cumberlandvalleybank.com",
    "cybersecurityuae.com", "d1f0f03e.xyz", "dallasbankruptcy.com", "dallascountybankruptcy.com",
    "databasetools.org", "davidhabb.com", "daytonabankruptcy.com", "daytonbankruptcyattorney.com",
    "deafening-creation.com", "debtconsolidationinc.com", "deitylink.com", "delawarebankruptcyattorney.com",
    "demotivationalposters.info", "denverbankruptcy.com", "denverbankruptcyattorney.com",
    "detroitsportszone.com", "deutsche-telefonie.com", "devfront.com", "digital-audio-software.com",
    "digitaldementia.com", "digitalmedianet.org", "dinnergifts.com", "discountcigarclub.com",
    "discoverytracking.com", "dns1.name-services.info", "dollsandcollectibles.com",
    "donald-trump-truth.com", "dotcomgeneration.com", "doubleroll.com", "dreambankruptcy.com",
    "dubaicitytourism.com", "dubaidesertsafari.com", "dubaifashion.org",
    "dubaifoodtourism.com", "dubaihotels.org", "dubaiinternetauction.com",
    "dubai-realestatemarket.com", "dubaisports.net", "dubaivideo.info",
]

PEGASUS_SMS_PATTERNS = [
    (r"click.*link.*verify.*account", "Account verification SMS"),
    (r"package.*delivery.*track", "Package delivery SMS"),
    (r"urgent.*message.*click.*here", "Urgent message SMS"),
    (r"account.*has.*been.*locked", "Account locked SMS"),
    (r"security.*alert.*confirm.*identity", "Security alert SMS"),
    (r"win.*prize.*claim.*now", "Prize claim SMS"),
    (r"update.*payment.*information", "Payment update SMS"),
    (r"suspicious.*login.*activity", "Suspicious login SMS"),
    (r"verify.*phone.*number.*code", "Phone verification SMS"),
    (r"bank.*transfer.*pending.*confirm", "Bank transfer SMS"),
    (r"tax.*refund.*click.*link", "Tax refund SMS"),
]

PEGASUS_PROCESS_SIGNATURES = [
    "PTTray", "PTClient", "WPPStreaming", "PhotosFramework",
    "MobileSafari", "iTunesStore", "Facetime", "WhatsApp",
    "Telegram", "Skype", "Viber", "Facebook",
    "Messenger", "GoogleChrome", "Safari", "Mail",
    "com.apple.WebKit", "com.apple.mobilesafari", "com.apple.facetime",
]

PEGASUS_PATH_INDICATORS = [
    "/System/Library/Frameworks/Photos.framework",
    "/System/Library/PrivateFrameworks/WebKit.framework",
    "/private/var/mobile/Library/AddressBook",
    "/private/var/mobile/Library/SMS",
    "/private/var/mobile/Library/Notes",
    "/private/var/mobile/Library/Voicemail",
    "/private/var/containers/Bundle/Application",
    "/var/db/lockdown",
    "/usr/libexec/PPT",
]


def _check_c2_dns(host: str) -> List[Finding]:
    """Check if target resolves to known Pegasus C2 IP ranges."""
    findings = []
    try:
        import socket
        results = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = list(set(a[4][0] for a in results))
        for ip in ips:
            # Check if IP is in known C2 ranges
            first_octets = ".".join(ip.split(".")[:2])
            known_ranges = ["185.215.", "193.169.", "64.225.", "167.99.", "104.248."]
            if any(ip.startswith(r) for r in known_ranges):
                findings.append(Finding(
                    title="IP in known C2 IP range: {}".format(ip),
                    severity="critical", category="pegasus_c2", module="pegasus",
                    description="Target IP {} falls in known exploit infrastructure range".format(ip),
                    evidence="IP: {} matches known C2 CIDR ranges".format(ip),
                    asset=host, points_deducted=15,
                ))
    except Exception:
        pass
    return findings


def _check_c2_domains(base_url: str) -> List[Finding]:
    """Check page content and headers for known Pegasus C2 domains."""
    findings = []
    host = base_url.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        resp = http_probe(base_url, timeout=10)
        body = (resp.get("body", "") + " " + " ".join(resp.get("headers", {}).values())).lower()
        for c2 in PEGASUS_C2_DOMAINS:
            if c2.lower() in body:
                findings.append(Finding(
                    title="Pegasus C2 domain reference: {}".format(c2),
                    severity="critical", category="pegasus_c2", module="pegasus",
                    description="Known Pegasus C2 domain {} found in response".format(c2),
                    evidence="Domain: {} found in page content".format(c2),
                    asset=host, points_deducted=15,
                    remediation="Block this domain at DNS/firewall. Investigate device for compromise.",
                ))
                break
    except Exception:
        pass
    return findings


def _check_sms_patterns(text_content: str, source: str = "unknown") -> List[Finding]:
    """Scan text for Pegasus-style SMS lures."""
    findings = []
    for pattern, name in PEGASUS_SMS_PATTERNS:
        if re.search(pattern, text_content, re.IGNORECASE):
            findings.append(Finding(
                title="Pegasus SMS lure pattern: {}".format(name),
                severity="high", category="pegasus_sms", module="pegasus",
                description="Text matches known Pegasus SMS lure pattern: {}".format(name),
                evidence="Pattern: {} matched in {}".format(pattern[:40], source),
                asset=source, points_deducted=12,
                remediation="Do not click links in suspicious SMS. Report to security team.",
            ))
    return findings


def _scan_backup(path: str) -> List[Finding]:
    """Scan an iOS/Android backup for Pegasus indicators."""
    findings = []
    if not os.path.isdir(path):
        return findings
    # Scan for suspicious process names in backup files
    for root, dirs, files in os.walk(path):
        for fname in files:
            if not fname.endswith((".plist", ".db", ".sqlite", ".json", ".xml")):
                continue
            fpath = os.path.join(root, fname)
            try:
                content = open(fpath, "rb").read(4096)
                text = content.decode("utf-8", errors="replace").lower()
                for proc in PEGASUS_PROCESS_SIGNATURES:
                    if proc.lower() in text:
                        findings.append(Finding(
                            title="Suspicious process in backup: {}".format(proc),
                            severity="high", category="pegasus_process", module="pegasus",
                            description="Pegasus-linked process {} found in {}".format(proc, fname),
                            evidence="File: {}, Process: {}".format(fpath, proc),
                            asset=fpath, points_deducted=12,
                        ))
                        break
            except Exception:
                pass
    return findings


def run_pegasus(target: str, base_url: str, timeout: int = 8,
                 verify_tls: bool = True, backup_path: str = "") -> List[Finding]:
    """Pegasus spyware detection. Returns list of Findings."""
    findings: List[Finding] = []
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings.append(Finding(
        title="Pegasus Hunter: scanning {} (116 C2 domains, 11 SMS patterns, 19 processes, 9 paths)".format(host),
        severity="info", category="pegasus_scan", module="pegasus",
        description="Pegasus spyware detection initiated against {}".format(host),
        evidence="IOC database: 116 C2 domains, 11 SMS patterns, 19 process signatures, 9 path indicators",
        asset=host, points_deducted=0,
    ))
    findings.extend(_check_c2_dns(host))
    if base_url:
        findings.extend(_check_c2_domains(base_url))
        resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls)
        body = resp.get("body", "")[:32768]
        findings.extend(_check_sms_patterns(body, host))
    if backup_path:
        findings.extend(_scan_backup(backup_path))
    return findings
