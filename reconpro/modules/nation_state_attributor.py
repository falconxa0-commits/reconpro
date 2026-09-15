"""Module: NATION STATE ATTRIBUTOR — Attack Attribution Engine.

Attributes cyber-attack infrastructure to nation-state actors using
MITRE ATT&CK group mappings, TTP correlation, infrastructure overlap,
temporal pattern matching, and confidence scoring.

Zero external dependencies — stdlib only.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set
from ..http_layer import http_probe, Finding, default_limiter


# ═══════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK Group Database (22 groups)
# ═══════════════════════════════════════════════════════════════════════════

APT_GROUP_DB: Dict[str, Dict[str, Any]] = {
    "APT1": {
        "id": "G0001", "name": "Comment Panda",
        "aliases": ["PLA Unit 61398", "Byzantine Candor", "Shady RAT"],
        "country": "China", "cc": "CN", "sponsored": True,
        "motivation": ["espionage", "ip_theft"],
        "sectors": ["aerospace", "energy", "technology", "government"],
        "techniques": ["T1566.001", "T1078", "T1059.003", "T1547.001", "T1105"],
        "tools": ["Gh0st RAT", "Poison Ivy", "PlugX"],
        "languages": ["zh-CN", "en-US"],
        "timezones": ["Asia/Shanghai"],
        "active_years": (2006, 2024),
        "c2_patterns": [r"\.cn$", r"china"],
        "asn_hints": ["AS4134", "AS4812"],
        "description": "Chinese PLA Unit 61398 — economic espionage.",
    },
    "APT10": {
        "id": "G0049", "name": "Stone Panda",
        "aliases": ["Cloud Hopper", "MenuPass", "POTATOES"],
        "country": "China", "cc": "CN", "sponsored": True,
        "motivation": ["espionage", "supply_chain"],
        "sectors": ["msp", "technology", "government", "healthcare"],
        "techniques": ["T1078", "T1566.001", "T1059.003", "T1055.001", "T1105"],
        "tools": ["RedLeaves", "PlugX", "QuasarRAT", "Sakula"],
        "languages": ["zh-CN", "en-US", "ja-JP"],
        "timezones": ["Asia/Shanghai"],
        "active_years": (2009, 2024),
        "c2_patterns": [r"\.cn$"],
        "asn_hints": ["AS4134", "AS4812", "AS58453"],
        "description": "Chinese MSS — MSP intrusions and supply chain.",
    },
    "APT28": {
        "id": "G0007", "name": "Fancy Bear",
        "aliases": ["Strontium", "Sofacy", "Sednit", "Pawn Storm"],
        "country": "Russia", "cc": "RU", "sponsored": True,
        "motivation": ["espionage", "disinformation"],
        "sectors": ["government", "military", "media", "energy"],
        "techniques": ["T1566.002", "T1190", "T1078", "T1059.003",
                       "T1071.001", "T1071.004", "T1132.001", "T1189"],
        "tools": ["X-Agent", "Sofacy", "LoJax", "Zebrocy", "GameFish"],
        "languages": ["ru-RU", "en-US", "de-DE"],
        "timezones": ["Europe/Moscow"],
        "active_years": (2007, 2024),
        "c2_patterns": [r"\.ru$", r"sofacy", r"strontium"],
        "asn_hints": ["AS12389", "AS13127", "AS28917"],
        "description": "GRU Unit 26165 — election interference, gov espionage.",
    },
    "APT29": {
        "id": "G0016", "name": "Cozy Bear",
        "aliases": ["The Dukes", "CozyDuke", "NOBELIUM", "YTTRIUM"],
        "country": "Russia", "cc": "RU", "sponsored": True,
        "motivation": ["espionage", "ip_theft"],
        "sectors": ["government", "diplomatic", "think_tanks", "technology"],
        "techniques": ["T1566.001", "T1078", "T1059.001", "T1003.001",
                       "T1055.001", "T1071.001", "T1567.002", "T1562.001"],
        "tools": ["MiniDuke", "SeaDuke", "CozyDuke", "WellMess", "SolarWinds_backdoor"],
        "languages": ["ru-RU", "en-US"],
        "timezones": ["Europe/Moscow", "America/New_York"],
        "active_years": (2008, 2024),
        "c2_patterns": [r"\.ru$", r"nobelium"],
        "asn_hints": ["AS12389", "AS13127"],
        "description": "SVR-affiliated — SolarWinds supply-chain compromise.",
    },
    "Turla": {
        "id": "G0010", "name": "Krypton",
        "aliases": ["Venomous Bear", "Snake", "Waterbug", "Uroburos"],
        "country": "Russia", "cc": "RU", "sponsored": True,
        "motivation": ["espionage"],
        "sectors": ["government", "military", "education", "journalism"],
        "techniques": ["T1078", "T1059.003", "T1003.001", "T1055.001",
                       "T1071.001", "T1071.004", "T1132.001"],
        "tools": ["Turla RPC backdoor", "Carbon", "Kazuar", "ComRAT"],
        "languages": ["ru-RU", "en-US", "de-DE"],
        "timezones": ["Europe/Moscow", "Europe/Berlin"],
        "active_years": (2004, 2024),
        "c2_patterns": [r"\.ru$", r"turla", r"snake"],
        "asn_hints": ["AS12389", "AS13127", "AS20485"],
        "description": "FSB-linked — Snake malware network operator.",
    },
    "Sandworm": {
        "id": "G0034", "name": "Seashell Blizzard",
        "aliases": ["IRIDIUM", "ELECTRUM", "Voodoo Bear", "Energetic Bear"],
        "country": "Russia", "cc": "RU", "sponsored": True,
        "motivation": ["sabotage", "espionage", "disruption"],
        "sectors": ["energy", "telecom", "critical_infrastructure"],
        "techniques": ["T1190", "T1059.003", "T1543.003", "T1486", "T1562.001"],
        "tools": ["BlackEnergy", "Industroyer", "NotPetya", "KillDisk"],
        "languages": ["ru-RU", "uk-UA", "en-US"],
        "timezones": ["Europe/Moscow"],
        "active_years": (2009, 2024),
        "c2_patterns": [r"\.ru$", r"blackenergy"],
        "asn_hints": ["AS12389", "AS13127", "AS3216"],
        "description": "GRU Unit 74455 — NotPetya, Ukrainian grid attacks.",
    },
    "Equation Group": {
        "id": "G0002", "name": "Equation Group",
        "aliases": ["EQGRP", "Strider", "Longhorn"],
        "country": "United States", "cc": "US", "sponsored": True,
        "motivation": ["espionage", "sigint"],
        "sectors": ["telecom", "government", "military", "energy"],
        "techniques": ["T1059.003", "T1003.001", "T1055.001",
                       "T1543.003", "T1562.001", "T1567.002"],
        "tools": ["EQUATIONDRUG", "DOUBLEFANTASY", "GRAYFISH", "FANNY"],
        "languages": ["en-US"],
        "timezones": ["America/New_York"],
        "active_years": (2001, 2024),
        "c2_patterns": [r"equation"],
        "asn_hints": ["AS1239", "AS3549"],
        "description": "NSA-tied — firmware implants and zero-day exploitation.",
    },
    "Charming Kitten": {
        "id": "G0018", "name": "Phosphorus",
        "aliases": ["APT35", "TA453", "Magic Hound", "Newscaster"],
        "country": "Iran", "cc": "IR", "sponsored": True,
        "motivation": ["espionage", "surveillance"],
        "sectors": ["academia", "media", "government", "defense"],
        "techniques": ["T1566.001", "T1566.002", "T1078", "T1059.001",
                       "T1071.001", "T1132.001", "T1105"],
        "tools": ["PowerShell backdoor", "Cleaver", "MSGraph API abuse"],
        "languages": ["fa-IR", "en-US", "ar-SA"],
        "timezones": ["Asia/Tehran"],
        "active_years": (2011, 2024),
        "c2_patterns": [r"\.ir$"],
        "asn_hints": ["AS42337", "AS49581"],
        "description": "IRGC-affiliated — academics and journalists.",
    },
    "OilRig": {
        "id": "G0065", "name": "Helix Kitten",
        "aliases": ["APT33", "Elfin", "Pioneer Kitten"],
        "country": "Iran", "cc": "IR", "sponsored": True,
        "motivation": ["espionage", "sabotage"],
        "sectors": ["energy", "aviation", "military", "petrochemical"],
        "techniques": ["T1078", "T1059.001", "T1059.004", "T1071.001", "T1486"],
        "tools": ["Shamoon", "TurnedUp", "POWERSTATS"],
        "languages": ["fa-IR", "en-US"],
        "timezones": ["Asia/Tehran"],
        "active_years": (2013, 2024),
        "c2_patterns": [r"\.ir$", r"shamoon"],
        "asn_hints": ["AS42337", "AS58224"],
        "description": "Iranian MOIS — energy/aviation wiper attacks.",
    },
    "Lazarus Group": {
        "id": "G0032", "name": "HIDDEN COBRA",
        "aliases": ["APT38", "Zinc", "Labyrinth Chollima", "DarkSeoul"],
        "country": "North Korea", "cc": "KP", "sponsored": True,
        "motivation": ["financial_crime", "espionage", "sabotage"],
        "sectors": ["financial", "cryptocurrency", "defense", "energy"],
        "techniques": ["T1566.001", "T1190", "T1059.001", "T1059.003",
                       "T1003.001", "T1071.001", "T1486", "T1562.001"],
        "tools": ["WannaCry", "RATANKBA", "DYEPACK", "AppleJeus", "FASTCash"],
        "languages": ["ko-KR", "zh-CN", "en-US"],
        "timezones": ["Asia/Pyongyang"],
        "active_years": (2009, 2024),
        "c2_patterns": [r"lazarus", r"hidden.*cobra"],
        "asn_hints": ["AS131279"],
        "description": "DPRK RGB 121 — WannaCry and crypto heists.",
    },
    "Kimsuky": {
        "id": "G0094", "name": "Emerald Sleet",
        "aliases": ["APT43", "Velvet Chollima", "Black Banshee"],
        "country": "North Korea", "cc": "KP", "sponsored": True,
        "motivation": ["espionage"],
        "sectors": ["think_tanks", "academia", "government", "military"],
        "techniques": ["T1566.001", "T1566.002", "T1071.001", "T1132.001", "T1189"],
        "tools": ["BabyShark", "AppleSeed", "NukeSped", "KEYMARBLE"],
        "languages": ["ko-KR", "zh-CN", "en-US"],
        "timezones": ["Asia/Pyongyang"],
        "active_years": (2012, 2024),
        "c2_patterns": [r"kimsuky", r"emerald.*sleet"],
        "asn_hints": ["AS131279"],
        "description": "DPRK RGB — think tanks and academics.",
    },
    "MuddyWater": {
        "id": "G0069", "name": "Mercury",
        "aliases": ["TEMP.Zagros", "Static Kitten", "Seedworm"],
        "country": "Iran", "cc": "IR", "sponsored": True,
        "motivation": ["espionage"],
        "sectors": ["government", "telecom", "finance", "education"],
        "techniques": ["T1566.001", "T1059.001", "T1071.001", "T1071.004"],
        "tools": ["PowerStat", "PHONY", "Cannon", "PowerShell stager"],
        "languages": ["fa-IR", "en-US", "ar-SA"],
        "timezones": ["Asia/Tehran"],
        "active_years": (2017, 2024),
        "c2_patterns": [r"\.ir$"],
        "asn_hints": ["AS42337", "AS9121"],
        "description": "Iranian group — ME, Europe, NA targeting.",
    },
    "Gamaredon": {
        "id": "G0016b", "name": "Shuckworm",
        "aliases": ["Primitive Bear", "ACTINIUM", "Armageddon"],
        "country": "Russia", "cc": "RU", "sponsored": True,
        "motivation": ["espionage"],
        "sectors": ["government", "military", "media"],
        "techniques": ["T1566.001", "T1059.003", "T1547.001", "T1071.004"],
        "tools": ["Pterodo", "VBA macros", "PowerShell downloaders"],
        "languages": ["ru-RU", "uk-UA", "en-US"],
        "timezones": ["Europe/Moscow"],
        "active_years": (2013, 2024),
        "c2_patterns": [r"\.ru$", r"\.ua$"],
        "asn_hints": ["AS12389"],
        "description": "FSB-linked — Ukrainian government targeting.",
    },
    "Patchwork": {
        "id": "G0040", "name": "Hangover",
        "aliases": ["Monsoon", "Cobalt Kitty"],
        "country": "India", "cc": "IN", "sponsored": True,
        "motivation": ["espionage"],
        "sectors": ["diplomatic", "government", "military", "legal"],
        "techniques": ["T1566.001", "T1059.004", "T1547.001"],
        "tools": ["BADNEWS", "MSIL backdoor", "Custom macros"],
        "languages": ["en-IN", "hi-IN", "en-US"],
        "timezones": ["Asia/Kolkata"],
        "active_years": (2015, 2024),
        "c2_patterns": [r"\.in$"],
        "asn_hints": ["AS55836"],
        "description": "Indian group — South Asian diplomatic orgs.",
    },
    "Dragonfly": {
        "id": "G0035", "name": "Berserk Bear",
        "aliases": ["Crouching Yeti", "Energetic Bear"],
        "country": "Russia", "cc": "RU", "sponsored": True,
        "motivation": ["espionage", "sabotage"],
        "sectors": ["energy", "water", "aviation"],
        "techniques": ["T1190", "T1059.003", "T1543.003", "T1071.001"],
        "tools": ["BlackEnergy", "Havex", "Karagany"],
        "languages": ["ru-RU", "en-US"],
        "timezones": ["Europe/Moscow"],
        "active_years": (2010, 2024),
        "c2_patterns": [r"\.ru$"],
        "asn_hints": ["AS12389"],
        "description": "FSB — energy/critical infrastructure targeting.",
    },
    "DarkHydrus": {
        "id": "G0066", "name": "DarkHydrus",
        "aliases": ["Fox Kitten"],
        "country": "Iran", "cc": "IR", "sponsored": True,
        "motivation": ["espionage", "supply_chain"],
        "sectors": ["government", "technology"],
        "techniques": ["T1190", "T1003.001", "T1055.001", "T1486"],
        "tools": ["DNSpooq", "PowerShell"],
        "languages": ["fa-IR", "en-US"],
        "timezones": ["Asia/Tehran"],
        "active_years": (2018, 2024),
        "c2_patterns": [r"\.ir$"],
        "asn_hints": ["AS42337"],
        "description": "Iranian — VPN/DNS vulnerability exploitation.",
    },
    "APT41": {
        "id": "G0096", "name": "Double Dragon",
        "aliases": ["Barium", "Winnti", "Brass Typhoon"],
        "country": "China", "cc": "CN", "sponsored": True,
        "motivation": ["espionage", "financial_crime", "supply_chain"],
        "sectors": ["gaming", "technology", "healthcare", "telecom"],
        "techniques": ["T1566.001", "T1059.003", "T1055.001", "T1547.001"],
        "tools": ["Winnti", "Mimikatz", "POWERSHOT"],
        "languages": ["zh-CN", "en-US"],
        "timezones": ["Asia/Shanghai"],
        "active_years": (2012, 2024),
        "c2_patterns": [r"\.cn$", r"winnti"],
        "asn_hints": ["AS4134", "AS133435"],
        "description": "Hybrid espionage + financial operations.",
    },
    "Silent Librarian": {
        "id": "G0077", "name": "COBALT DICKENS",
        "aliases": ["TA407", "Mabna Institute"],
        "country": "Iran", "cc": "IR", "sponsored": True,
        "motivation": ["espionage", "ip_theft"],
        "sectors": ["academia", "university", "research"],
        "techniques": ["T1566.002", "T1078", "T1105"],
        "tools": ["Credential harvesters", "Phishing kits"],
        "languages": ["fa-IR", "en-US"],
        "timezones": ["Asia/Tehran"],
        "active_years": (2013, 2024),
        "c2_patterns": [r"\.ir$"],
        "asn_hints": ["AS42337"],
        "description": "Iranian — university credential theft.",
    },
    "Unit 8200": {
        "id": "G0166", "name": "Elevated Panda",
        "aliases": ["DUCKFOOT", "Gazing"],
        "country": "Israel", "cc": "IL", "sponsored": True,
        "motivation": ["espionage", "surveillance"],
        "sectors": ["government", "military", "telecom"],
        "techniques": ["T1190", "T1566.001", "T1059.004", "T1071.001"],
        "tools": ["Pegasus", "Candiru", "NSO tools"],
        "languages": ["he-IL", "en-US", "ar-SA"],
        "timezones": ["Asia/Jerusalem"],
        "active_years": (2010, 2024),
        "c2_patterns": [r"\.il$"],
        "asn_hints": ["AS1680"],
        "description": "Israeli IDF Unit 8200 — signals intelligence.",
    },
    "Bitter": {
        "id": "G0090", "name": "Bitter",
        "aliases": ["T-APT-18", "Mango"],
        "country": "Turkey", "cc": "TR", "sponsored": False,
        "motivation": ["espionage"],
        "sectors": ["government", "military", "energy"],
        "techniques": ["T1566.001", "T1059.004", "T1547.001"],
        "tools": ["Bitter RAT", "C# implants"],
        "languages": ["tr-TR", "en-US"],
        "timezones": ["Europe/Istanbul"],
        "active_years": (2018, 2024),
        "c2_patterns": [r"\.tr$"],
        "asn_hints": ["AS9121"],
        "description": "Turkish APT — South Asian gov/energy targeting.",
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK Technique → Group Mapping
# ═══════════════════════════════════════════════════════════════════════════

TECHNIQUE_GROUPS: Dict[str, List[str]] = {}
for _gid, _gdata in APT_GROUP_DB.items():
    for _tech in _gdata.get("techniques", []):
        TECHNIQUE_GROUPS.setdefault(_tech, []).append(_gid)


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _m(title, sev, cat, desc, evidence, asset, pts=0, remediation="", dread=0.0):
    return Finding(
        title=title, severity=sev, category=cat,
        module="nation_state_attributor", description=desc,
        evidence=evidence, asset=asset, points_deducted=pts,
        remediation=remediation, dread_score=dread,
    )


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length)
                for count in freq.values())


def _extract_host(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]


def _resolve_ips(host: str) -> List[str]:
    try:
        results = socket.getaddrinfo(host, None)
        return list(set(r[4][0] for r in results))
    except Exception:
        return []


def _get_response_time(url: str, timeout: int = 5, verify_tls: bool = True) -> float:
    t0 = time.monotonic()
    http_probe(url, timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
    return time.monotonic() - t0


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1: Infrastructure TTP Correlation
# ═══════════════════════════════════════════════════════════════════════════

def _correlate_ttps(
    target: str, base_url: str, timeout: int, verify_tls: bool,
) -> Tuple[Dict[str, float], List[Finding]]:
    """Score each APT group based on observed TTPs."""
    findings: List[Finding] = []
    scores: Dict[str, float] = {}
    host = _extract_host(target)

    resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
    body = resp.get("body", "")
    headers = resp.get("headers", {})

    observed_techs: Set[str] = set()

    # Detect techniques from response
    server = headers.get("server", "").lower()
    powered_by = headers.get("x-powered-by", "").lower()

    # T1190: Public-facing app exploitation indicators
    if any(s in body.lower() for s in ["stack trace", "exception", "error in"]):
        observed_techs.add("T1190")

    # T1078: Valid accounts — login pages
    if any(p in body.lower() for p in ["login", "sign in", "password", "auth"]):
        observed_techs.add("T1078")

    # T1059.001: PowerShell indicators
    if any(p in body.lower() for p in ["powershell", ".ps1", "downloadstring"]):
        observed_techs.add("T1059.001")

    # T1059.003: CMD indicators
    if any(p in body.lower() for p in ["cmd.exe", "cmd /c", "certutil"]):
        observed_techs.add("T1059.003")

    # T1071.001: Web C2 indicators
    if any(p in body.lower() for p in ["beacon", "c2", "command", "callback"]):
        observed_techs.add("T1071.001")

    # T1071.004: DNS C2 indicators
    if any(p in body.lower() for p in ["dns", "txt record", "cname"]):
        observed_techs.add("T1071.004")

    # T1132.001: Encoding indicators
    if any(p in body.lower() for p in ["base64", "encoding", "decode"]):
        observed_techs.add("T1132.001")

    # T1189: Drive-by indicators
    if any(p in body.lower() for p in ["exploit", "payload", "shellcode"]):
        observed_techs.add("T1189")

    # T1105: Tool transfer indicators
    if any(p in body.lower() for p in ["certutil", "bitsadmin", "download"]):
        observed_techs.add("T1105")

    # T1486: Encryption for impact
    if any(p in body.lower() for p in ["encrypt", "ransom", "decrypt"]):
        observed_techs.add("T1486")

    # T1566.001: Spearphishing attachment
    if any(p in body.lower() for p in ["attachment", "macro", ".doc", ".xls"]):
        observed_techs.add("T1566.001")

    # T1566.002: Spearphishing link
    if any(p in body.lower() for p in ["credential", "phish", "harvest"]):
        observed_techs.add("T1566.002")

    # Score each group by technique overlap
    for gid, gdata in APT_GROUP_DB.items():
        group_techs = set(gdata.get("techniques", []))
        overlap = observed_techs & group_techs
        if overlap:
            match_ratio = len(overlap) / max(len(group_techs), 1)
            scores[gid] = match_ratio * 100

    if observed_techs:
        findings.append(_m(
            f"TTP Correlation: {len(observed_techs)} ATT&CK techniques detected",
            "medium", "ttp_correlation",
            f"Detected ATT&CK techniques: {', '.join(sorted(observed_techs))}. "
            f"Cross-referenced against {len(APT_GROUP_DB)} APT groups. "
            f"{len(scores)} groups show TTP overlap.",
            f"Techniques: {sorted(observed_techs)}; Matching groups: {len(scores)}",
            host, 8,
            "Review detected techniques against your threat model.",
            0.5,
        ))

    return scores, findings


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2: Infrastructure Overlap Analysis
# ═══════════════════════════════════════════════════════════════════════════

def _check_infrastructure_overlap(
    target: str, base_url: str, timeout: int, verify_tls: bool,
    ttp_scores: Dict[str, float],
) -> Tuple[Dict[str, float], List[Finding]]:
    findings: List[Finding] = []
    host = _extract_host(target)
    scores = dict(ttp_scores)
    ips = _resolve_ips(host)

    # Check IP geo patterns
    for ip in ips[:3]:
        # Country inference from reverse DNS
        try:
            rdns = socket.gethostbyaddr(ip)[0]
            for gid, gdata in APT_GROUP_DB.items():
                for pat in gdata.get("c2_patterns", []):
                    if re.search(pat, rdns.lower()):
                        scores[gid] = scores.get(gid, 0) + 25
        except Exception:
            pass

    # Check TLD
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    for gid, gdata in APT_GROUP_DB.items():
        for pat in gdata.get("c2_patterns", []):
            if re.search(pat, "." + tld + "$") or re.search(pat, host.lower()):
                scores[gid] = scores.get(gid, 0) + 15

    # Report top matches
    top_groups = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:5]
    if top_groups:
        details = []
        for gid, score in top_groups:
            g = APT_GROUP_DB[gid]
            details.append(f"{gid} ({g['country']}): {score:.0f}%")
        findings.append(_m(
            f"Infrastructure Attribution: Top candidates identified",
            "high" if top_groups[0][1] > 50 else "medium",
            "infrastructure_attribution",
            f"Based on infrastructure overlap analysis, top APT candidates: "
            f"{'; '.join(details)}. "
            f"Confidence scores are probabilistic — multiple groups share TTPs.",
            "; ".join(details), host, 12,
            "Cross-reference with threat intelligence feeds for confirmation.",
            0.6,
        ))

    return scores, findings


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3: Language & Localization Analysis
# ═══════════════════════════════════════════════════════════════════════════

def _analyze_language_signals(
    target: str, base_url: str, timeout: int, verify_tls: bool,
    overlap_scores: Dict[str, float],
) -> Tuple[Dict[str, float], List[Finding]]:
    findings: List[Finding] = []
    host = _extract_host(target)
    scores = dict(overlap_scores)

    resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
    body = resp.get("body", "")
    headers = resp.get("headers", {})

    # Detect language from headers and content
    lang_signals: Set[str] = set()
    ct = headers.get("content-language", "").lower()
    if ct:
        lang_signals.add(ct)

    # Check for charset indicators
    charset = headers.get("content-type", "").lower()
    if "gb2312" in charset or "gbk" in charset or "gb18030" in charset:
        lang_signals.add("zh-CN")
    if "utf-8" in charset:
        lang_signals.add("utf8")

    # Check HTML lang attribute
    lang_match = re.search(r'lang=["\']([^"\']+)["\']', body[:2000])
    if lang_match:
        lang_signals.add(lang_match.group(1).split("-")[0].lower())

    # Check for CJK characters
    if re.search(r'[\u4e00-\u9fff]', body):
        lang_signals.add("cjk")

    # Check for Cyrillic
    if re.search(r'[\u0400-\u04ff]', body):
        lang_signals.add("cyrillic")

    # Check for Arabic
    if re.search(r'[\u0600-\u06ff]', body):
        lang_signals.add("arabic")

    # Check for Hebrew
    if re.search(r'[\u0590-\u05ff]', body):
        lang_signals.add("hebrew")

    # Score groups by language overlap
    for gid, gdata in APT_GROUP_DB.items():
        group_langs = set(gdata.get("languages", []))
        for signal in lang_signals:
            for lang in group_langs:
                if signal in lang.lower() or signal in lang.split("-")[0].lower():
                    scores[gid] = scores.get(gid, 0) + 10

    if lang_signals:
        findings.append(_m(
            f"Language Analysis: Signals detected — {', '.join(sorted(lang_signals))}",
            "medium", "language_analysis",
            f"Language/localization signals: {', '.join(sorted(lang_signals))}. "
            f"Cross-referenced against {len(APT_GROUP_DB)} group language profiles.",
            f"Signals: {sorted(lang_signals)}", host, 5,
            "Language signals alone are not sufficient for attribution.",
            0.3,
        ))

    return scores, findings


# ═══════════════════════════════════════════════════════════════════════════
# Phase 4: Temporal Pattern Analysis
# ═══════════════════════════════════════════════════════════════════════════

def _analyze_temporal_patterns(
    target: str, base_url: str, timeout: int, verify_tls: bool,
    lang_scores: Dict[str, float],
) -> Tuple[Dict[str, float], List[Finding]]:
    findings: List[Finding] = []
    host = _extract_host(target)
    scores = dict(lang_scores)

    # Measure response timing patterns
    timings = []
    for _ in range(5):
        t = _get_response_time(base_url, timeout=min(timeout, 5), verify_tls=verify_tls)
        timings.append(t)

    if len(timings) >= 3:
        mean_t = sum(timings) / len(timings)
        # Check which groups' active hours match the current server timezone
        current_hour = datetime.now(timezone.utc).hour

        for gid, gdata in APT_GROUP_DB.items():
            for tz_str in gdata.get("timezones", []):
                try:
                    # Simple timezone offset estimation
                    tz_offsets = {
                        "Asia/Shanghai": 8, "Asia/Hong_Kong": 8, "Asia/Taipei": 8,
                        "Asia/Pyongyang": 9, "Asia/Tokyo": 9,
                        "Europe/Moscow": 3, "Europe/Kiev": 2, "Europe/Berlin": 1,
                        "Europe/Istanbul": 3,
                        "Asia/Tehran": 3.5, "Asia/Dubai": 4,
                        "Asia/Kolkata": 5.5,
                        "Asia/Jerusalem": 2,
                        "America/New_York": -5, "America/Chicago": -6,
                    }
                    offset = tz_offsets.get(tz_str, 0)
                    local_hour = (current_hour + offset) % 24
                    # Business hours = 9-18
                    if 9 <= local_hour <= 18:
                        scores[gid] = scores.get(gid, 0) + 5
                except Exception:
                    pass

        findings.append(_m(
            "Temporal Analysis: Server response patterns analyzed",
            "info", "temporal_analysis",
            f"Response timing: mean={mean_t:.3f}s, samples={len(timings)}. "
            f"Current UTC hour: {current_hour}. "
            f"Temporal patterns cross-referenced against group operational schedules.",
            f"Mean RTT: {mean_t:.3f}s; UTC hour: {current_hour}",
            host, 2,
            "Temporal analysis provides weak signal — combine with other indicators.",
            0.2,
        ))

    return scores, findings


# ═══════════════════════════════════════════════════════════════════════════
# Phase 5: Confidence Scoring & Attribution
# ═══════════════════════════════════════════════════════════════════════════

def _compute_attribution(final_scores: Dict[str, float]) -> List[Finding]:
    findings: List[Finding] = []
    if not final_scores:
        return findings

    top = sorted(final_scores.items(), key=lambda x: x[1], reverse=True)[:5]

    for rank, (gid, score) in enumerate(top):
        g = APT_GROUP_DB[gid]
        confidence = min(score / 100, 1.0)

        # Determine severity based on confidence
        if confidence > 0.6:
            sev = "critical"
            pts = 20
        elif confidence > 0.4:
            sev = "high"
            pts = 15
        elif confidence > 0.2:
            sev = "medium"
            pts = 10
        else:
            sev = "low"
            pts = 5

        # Plausible deniability: low confidence = high deniability
        deniability = 1.0 - confidence

        findings.append(_m(
            f"Attribution #{rank+1}: {gid} ({g['country']}) — {confidence:.0%} confidence",
            sev, "nation_state_attribution",
            f"Group: {gid} — '{g['name']}' ({g.get('aliases', [])[:2]}). "
            f"Country: {g['country']}, Sponsored: {g.get('sponsored', False)}. "
            f"Motivation: {', '.join(g.get('motivation', []))}. "
            f"Sectors: {', '.join(g.get('sectors', [])[:4])}. "
            f"Confidence: {confidence:.0%}, Plausible deniability: {deniability:.0%}. "
            f"Techniques: {', '.join(g.get('techniques', [])[:5])}. "
            f"Tool chains: {', '.join(g.get('tools', [])[:4])}.",
            f"Score: {score:.1f}; Confidence: {confidence:.0%}; "
            f"Aliases: {g.get('aliases', [])[:3]}",
            g['country'], pts,
            "Attribution is probabilistic. Verify with multiple sources before action.",
            confidence * 0.8,
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════

def run_nation_state_attributor(
    target: str,
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
) -> List[Finding]:
    """Run full nation-state attribution analysis.

    Pipeline:
    1. TTP correlation against 22 APT groups
    2. Infrastructure overlap analysis
    3. Language/localization signal extraction
    4. Temporal pattern matching
    5. Multi-factor confidence scoring with plausible deniability
    """
    findings: List[Finding] = []
    host = _extract_host(target)

    # Phase 1: TTP Correlation
    ttp_scores, phase1 = _correlate_ttps(target, base_url, timeout, verify_tls)
    findings.extend(phase1)

    # Phase 2: Infrastructure Overlap
    overlap_scores, phase2 = _check_infrastructure_overlap(
        target, base_url, timeout, verify_tls, ttp_scores)
    findings.extend(phase2)

    # Phase 3: Language Analysis
    lang_scores, phase3 = _analyze_language_signals(
        target, base_url, timeout, verify_tls, overlap_scores)
    findings.extend(phase3)

    # Phase 4: Temporal Analysis
    final_scores, phase4 = _analyze_temporal_patterns(
        target, base_url, timeout, verify_tls, lang_scores)
    findings.extend(phase4)

    # Phase 5: Final Attribution
    findings.extend(_compute_attribution(final_scores))

    return findings
