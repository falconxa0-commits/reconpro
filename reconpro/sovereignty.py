"""
ReconPro v9.2.0 — Digital Sovereignty & Jurisdiction Mapping

Determines who controls the infrastructure behind a target. Maps ASN,
TLS certificates, DNS nameservers, cloud providers, and content signals
to jurisdictional risk profiles including surveillance programs and
data protection law compliance.

Exports:
    Jurisdiction             – jurisdictional assessment dataclass
    SovereigntyMapper        – main sovereignty analysis engine
    SURVEILLANCE_DATABASE    – country → surveillance program mapping
    DATA_PROTECTION_LAWS     – country → data protection law mapping
"""

from __future__ import annotations

import json
import os
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


# ══════════════════════════════════════════════════════════════════════
# SURVEILLANCE_DATABASE — known state surveillance programs by country
# ══════════════════════════════════════════════════════════════════════

SURVEILLANCE_DATABASE: Dict[str, Dict[str, Any]] = {
    "US": {
        "country_name": "United States",
        "programs": [
            "PRISM (NSA mass data collection)",
            "FISA Section 702 (foreign intelligence surveillance)",
            "CALEA (Communications Assistance for Law Enforcement Act)",
            "Upstream collection (fiber-tap program)",
            "XKeyscore (search and analysis tool)",
            "EO 12333 (intelligence collection overseas)",
            "CLOUD Act (cross-border data access)",
        ],
        "data_retention_laws": True,
        "retention_period": "Varies by provider; NSLs can compel indefinite retention",
        "encryption_backdoor_laws": False,
        "backdoor_notes": "No explicit mandate; ongoing legislative pressure (EARN IT Act, etc.)",
        "risk_level": "high",
        "intelligence_sharing": ["Five Eyes", "Nine Eyes", "Fourteen Eyes"],
    },
    "GB": {
        "country_name": "United Kingdom",
        "programs": [
            "Tempora (GCHQ mass interception)",
            "RIPA (Regulation of Investigatory Powers Act)",
            "Investigatory Powers Act 2016 (Snooper's Charter)",
            "Bulk Personal Datasets collection",
            "Equipment Interference ( hacking ) powers",
            "HMGCC (government cryptography centre)",
        ],
        "data_retention_laws": True,
        "retention_period": "12 months (Investigatory Powers Act)",
        "encryption_backdoor_laws": False,
        "backdoor_notes": "IP Act includes 'technical capability notices' that can demand weakening of encryption",
        "risk_level": "high",
        "intelligence_sharing": ["Five Eyes", "Nine Eyes", "Fourteen Eyes"],
    },
    "CN": {
        "country_name": "China",
        "programs": [
            "Great Firewall (Golden Shield Project)",
            "Social Credit System",
            "Sharp Eyes (mass video surveillance)",
            "Golden Tax (financial monitoring)",
            "Joint Operations Platform (Xinjiang)",
            "National Cybersecurity Center programs",
            "Deep Packet Inspection infrastructure",
        ],
        "data_retention_laws": True,
        "retention_period": "Indefinite (Cybersecurity Law Article 21)",
        "encryption_backdoor_laws": True,
        "backdoor_notes": "Encryption products must be certified; backdoor access mandated for state security",
        "risk_level": "critical",
        "intelligence_sharing": ["Shanghai Cooperation Organisation"],
    },
    "RU": {
        "country_name": "Russia",
        "programs": [
            "SORM (System for Operative Investigative Activities)",
            "Yarovaya Law (data retention & decryption)",
            "SORM-3 (next-generation interception)",
            "Federal Security Service (FSB) monitoring",
            "Sovereign Internet Law (Runet isolation capability)",
            "TII (Tactical Internet Intelligence)",
        ],
        "data_retention_laws": True,
        "retention_period": "6 months to 3 years (Yarovaya Law)",
        "encryption_backdoor_laws": True,
        "backdoor_notes": "Yarovaya Law mandates decryption capability for FSB; providers must provide keys",
        "risk_level": "critical",
        "intelligence_sharing": ["CIS (Commonwealth of Independent States)"],
    },
    "IR": {
        "country_name": "Iran",
        "programs": [
            "HAMED (deep packet inspection system)",
            "National Information Network (national intranet)",
            "FATA Police (cyber police)",
            "Halal Internet filtering",
            "Social media monitoring (Telegram, Instagram)",
            'Project "Spider Web" (surveillance network)',
        ],
        "data_retention_laws": True,
        "retention_period": "6 months minimum (varies by provider)",
        "encryption_backdoor_laws": True,
        "backdoor_notes": "ISPs must provide interception capabilities; mandatory key escrow discussed",
        "risk_level": "critical",
        "intelligence_sharing": [],
    },
    "DE": {
        "country_name": "Germany",
        "programs": [
            "G10 Act (intelligence surveillance)",
            "BND surveillance (foreign intelligence)",
            "Gesetz zur Bekämpfung von Terrorismus",
            "Bundeskriminalamt (BKA) monitoring",
            "Verfassungsschutz (domestic intelligence)",
        ],
        "data_retention_laws": True,
        "retention_period": "10 weeks (traffic data), 80 days (location); ISP-level, no content",
        "encryption_backdoor_laws": False,
        "backdoor_notes": "Strong constitutional protection; BND reform act limits domestic surveillance",
        "risk_level": "medium",
        "intelligence_sharing": ["Five Eyes (limited)", "Nine Eyes", "Fourteen Eyes"],
    },
    "FR": {
        "country_name": "France",
        "programs": [
            "French Intelligence Act 2015",
            "DGSE mass metadata collection",
            "CNIL enforcement (privacy regulator)",
            "Direction Nationale du Renseignement",
            "Black Boxes (algorithmic surveillance)",
        ],
        "data_retention_laws": True,
        "retention_period": "1 year (intelligence act)",
        "encryption_backdoor_laws": False,
        "backdoor_notes": "No backdoor mandate; strong CNIL oversight",
        "risk_level": "medium",
        "intelligence_sharing": ["Nine Eyes", "Fourteen Eyes"],
    },
    "AU": {
        "country_name": "Australia",
        "programs": [
            "Telecommunications and Other Legislation Amendment (Assistance and Access) Act 2018",
            "Telecommunications (Interception and Access) Act",
            "Australian Signals Directorate (ASD) collection",
            "Data Retention Act 2015",
            "Five Eyes intelligence sharing",
        ],
        "data_retention_laws": True,
        "retention_period": "2 years (metadata)",
        "encryption_backdoor_laws": True,
        "backdoor_notes": "Assistance and Access Act can compel technical assistance including building capabilities",
        "risk_level": "high",
        "intelligence_sharing": ["Five Eyes", "Nine Eyes", "Fourteen Eyes"],
    },
    "IN": {
        "country_name": "India",
        "programs": [
            "Central Monitoring System (CMS)",
            "NETRA (Network Traffic Analysis)",
            "Aadhaar biometric database",
            "IT Act Section 69 (surveillance powers)",
            "National Intelligence Grid (NATGRID)",
            "Social Media Communications Hub",
        ],
        "data_retention_laws": True,
        "retention_period": "1 year (CERT-In directive)",
        "encryption_backdoor_laws": False,
        "backdoor_notes": "IT Act Section 69 grants interception powers; draft encryption policy controversial",
        "risk_level": "high",
        "intelligence_sharing": ["Quad (limited intelligence)", "BRICS"],
    },
    "BR": {
        "country_name": "Brazil",
        "programs": [
            "ABIN (Brazilian Intelligence Agency) monitoring",
            "System of Monitoring of the Federal Police",
            "Marco Civil da Internet (framework law)",
        ],
        "data_retention_laws": True,
        "retention_period": "6 months (Marco Civil)",
        "encryption_backdoor_laws": False,
        "backdoor_notes": "No encryption backdoor law; Marco Civil protects net neutrality and privacy",
        "risk_level": "low",
        "intelligence_sharing": ["BRICS"],
    },
    "SA": {
        "country_name": "Saudi Arabia",
        "programs": [
            "National Cybersecurity Center (NCA) monitoring",
            "Communications and Information Technology Commission oversight",
            "Kingdom's mass surveillance infrastructure",
            "Pegasus spyware deployment (reportedly)",
        ],
        "data_retention_laws": True,
        "retention_period": "Not publicly disclosed",
        "encryption_backdoor_laws": False,
        "backdoor_notes": "No explicit backdoor law but encryption controls exist",
        "risk_level": "high",
        "intelligence_sharing": [],
    },
    "TR": {
        "country_name": "Turkey",
        "programs": [
            "TIB (Information and Communication Technologies Authority) monitoring",
            "Law on Combating Terrorism (broad surveillance powers)",
            "Internet filtering and DNS manipulation",
            "National Intelligence Agency (MIT) operations",
        ],
        "data_retention_laws": True,
        "retention_period": "1-2 years",
        "encryption_backdoor_laws": False,
        "backdoor_notes": "TIB can demand data; encryption products subject to regulation",
        "risk_level": "high",
        "intelligence_sharing": ["NATO"],
    },
    "JP": {
        "country_name": "Japan",
        "programs": [
            "Public Security Intelligence Agency",
            "National Police Agency cyber surveillance",
            "Act on the Protection of Specially Designated Secrets",
        ],
        "data_retention_laws": True,
        "retention_period": "6 months (telecommunications)",
        "encryption_backdoor_laws": False,
        "backdoor_notes": "No encryption backdoor mandate; relatively strong privacy protections",
        "risk_level": "low",
        "intelligence_sharing": ["Five Eyes (limited)", "Quad"],
    },
    "KR": {
        "country_name": "South Korea",
        "programs": [
            "National Intelligence Service (NIS)",
            "Korea Internet & Security Agency (KISA)",
            "Communication Secrets Protection Act (with exceptions)",
            "Real-name verification system (partially repealed)",
        ],
        "data_retention_laws": True,
        "retention_period": "3 months to 1 year",
        "encryption_backdoor_laws": False,
        "backdoor_notes": "Strong privacy framework but intelligence exemptions exist",
        "risk_level": "medium",
        "intelligence_sharing": ["Five Eyes (limited)", "Quad"],
    },
    "IL": {
        "country_name": "Israel",
        "programs": [
            "Unit 8200 (SIGINT)",
            "Shin Bet (domestic security) monitoring",
            "NSO Group (Pegasus) export",
            "Law on the Authority to Fight Terror (surveillance provisions)",
        ],
        "data_retention_laws": True,
        "retention_period": "Varies; security services have broad retention",
        "encryption_backdoor_laws": False,
        "backdoor_notes": "No formal backdoor law but security services have broad technical access",
        "risk_level": "high",
        "intelligence_sharing": ["Various bilateral agreements"],
    },
    "SG": {
        "country_name": "Singapore",
        "programs": [
            "Cybersecurity Act 2018",
            "Computer Misuse Act",
            "Singapore signals intelligence",
            "ISA (Internal Security Act) detention powers",
        ],
        "data_retention_laws": True,
        "retention_period": "Not specified in legislation",
        "encryption_backdoor_laws": False,
        "backdoor_notes": "Cybersecurity Act gives broad investigation powers",
        "risk_level": "medium",
        "intelligence_sharing": ["Five Eyes (limited partnership)"],
    },
    "AE": {
        "country_name": "United Arab Emirates",
        "programs": [
            "National Electronic Security Authority (NESA)",
            "Telecommunications and Digital Government Regulatory Authority",
            "DarkMatter (surveillance firm)",
            "Karma spyware (reported deployment)",
        ],
        "data_retention_laws": True,
        "retention_period": "Not publicly specified",
        "encryption_backdoor_laws": False,
        "backdoor_notes": "Strict content controls; VOIP and encryption services sometimes restricted",
        "risk_level": "high",
        "intelligence_sharing": [],
    },
    "KP": {
        "country_name": "North Korea",
        "programs": [
            "Bureau 121 (cyber warfare unit)",
            "Kwangmyong (national intranet)",
            "Complete state control of all communications",
            "Reconnaissance General Bureau",
        ],
        "data_retention_laws": True,
        "retention_period": "Indefinite (total state control)",
        "encryption_backdoor_laws": True,
        "backdoor_notes": "All encryption must be accessible to state; no independent encryption permitted",
        "risk_level": "critical",
        "intelligence_sharing": ["Limited to allied states"],
    },
}


# ══════════════════════════════════════════════════════════════════════
# DATA_PROTECTION_LAWS — data protection regulations by country
# ══════════════════════════════════════════════════════════════════════

DATA_PROTECTION_LAWS: Dict[str, Dict[str, Any]] = {
    "EU": {
        "name": "GDPR",
        "full_name": "General Data Protection Regulation",
        "jurisdiction": "European Union + EEA",
        "key_provisions": [
            "Data minimization and purpose limitation",
            "Right to erasure (right to be forgotten)",
            "Data portability",
            "Privacy by design and by default",
            "72-hour breach notification",
            "Mandatory DPO for large-scale processing",
            "Cross-border transfer restrictions (adequacy decisions)",
            "Maximum fines: 4% of global annual turnover or 20M EUR",
        ],
        "data_localization": False,
        "cross_border_transfer_mechanisms": [
            "Adequacy decisions",
            "Standard Contractual Clauses (SCCs)",
            "Binding Corporate Rules (BCRs)",
        ],
        "effective_date": "2018-05-25",
        "compliance_score": 10,
    },
    "US": {
        "name": "CCPA / CPRA",
        "full_name": "California Consumer Privacy Act / California Privacy Rights Act",
        "jurisdiction": "California, USA (sectoral at federal level)",
        "key_provisions": [
            "Right to know what data is collected",
            "Right to delete personal information",
            "Right to opt-out of sale of data",
            "Right to non-discrimination for exercising rights",
            "Private right of action for data breaches",
        ],
        "data_localization": False,
        "cross_border_transfer_mechanisms": [
            "No federal restrictions",
            "APEC Cross-Border Privacy Rules",
        ],
        "effective_date": "2020-01-01",
        "compliance_score": 6,
    },
    "CN": {
        "name": "PIPL",
        "full_name": "Personal Information Protection Law",
        "jurisdiction": "People's Republic of China",
        "key_provisions": [
            "Consent-based processing with specific purpose limitation",
            "Separate consent for sensitive personal information",
            "Mandatory data localization for critical infrastructure",
            "Cross-border transfer security assessment required",
            "Data subject access rights",
            "DPO requirement for processing above thresholds",
            "Maximum fines: 50M CNY or 5% of prior year revenue",
        ],
        "data_localization": True,
        "cross_border_transfer_mechanisms": [
            "Government security assessment",
            "Personal information protection certification",
            "Standard contract filing with CAC",
        ],
        "effective_date": "2021-11-01",
        "compliance_score": 7,
    },
    "BR": {
        "name": "LGPD",
        "full_name": "Lei Geral de Protecao de Dados",
        "jurisdiction": "Brazil",
        "key_provisions": [
            "Consent-based processing (10 legal bases)",
            "Right to access, correction, anonymization",
            "Data Protection Officer requirement",
            "Impact assessments for high-risk processing",
            "International transfer restrictions",
            "Administrative penalties up to 2% of revenue",
        ],
        "data_localization": False,
        "cross_border_transfer_mechanisms": [
            "Adequacy by ANPD",
            "Standard contractual clauses",
            "Binding corporate rules",
            "Specific consent",
        ],
        "effective_date": "2020-09-18",
        "compliance_score": 8,
    },
    "IN": {
        "name": "DPDP Act 2023",
        "full_name": "Digital Personal Data Protection Act",
        "jurisdiction": "India",
        "key_provisions": [
            "Consent-based processing with notice requirements",
            "Right to grievance redressal",
            "Data fiduciary obligations",
            "Cross-border transfer restrictions (government blacklist)",
            "Special protections for children's data",
            "Penalties up to 250 crore INR",
        ],
        "data_localization": False,
        "cross_border_transfer_mechanisms": [
            "Government-approved whitelist",
        ],
        "effective_date": "2023-08-11",
        "compliance_score": 5,
    },
    "RU": {
        "name": "Federal Law 152-FZ",
        "full_name": "On Personal Data",
        "jurisdiction": "Russia",
        "key_provisions": [
            "Consent-based processing",
            "Data localization (primary storage in Russia)",
            "Cross-border transfer notification required",
            "Data subject rights (access, correction, deletion)",
        ],
        "data_localization": True,
        "cross_border_transfer_mechanisms": [
            "Adequacy assessment by Roskomnadzor",
        ],
        "effective_date": "2006-07-27 (amended 2015, 2022)",
        "compliance_score": 4,
    },
    "KR": {
        "name": "PIPA",
        "full_name": "Personal Information Protection Act",
        "jurisdiction": "South Korea",
        "key_provisions": [
            "Consent-based processing",
            "Purpose limitation",
            "Data subject rights (access, correction, deletion, portability)",
            "Data localization for certain sectors (financial, health)",
            "Breach notification within 72 hours",
        ],
        "data_localization": False,
        "cross_border_transfer_mechanisms": [
            "Consent of data subject",
            "Adequacy by PIPC",
            "Standard contractual clauses",
        ],
        "effective_date": "2011-09-30 (amended 2023)",
        "compliance_score": 8,
    },
    "AU": {
        "name": "Privacy Act 1988",
        "full_name": "Australian Privacy Act",
        "jurisdiction": "Australia",
        "key_provisions": [
            "13 Australian Privacy Principles (APPs)",
            "Collection limitation",
            "Use and disclosure limitation",
            "Data quality and security",
            "Cross-border disclosure rules",
            "Notifiable Data Breaches scheme",
        ],
        "data_localization": False,
        "cross_border_transfer_mechanisms": [
            "Consent of data subject",
            "Adequate protections in recipient country",
        ],
        "effective_date": "1988-01-01 (amended 2022)",
        "compliance_score": 7,
    },
    "JP": {
        "name": "APPI",
        "full_name": "Act on the Protection of Personal Information",
        "jurisdiction": "Japan",
        "key_provisions": [
            "Purpose specification and use limitation",
            "Consent for sensitive information",
            "Data subject access rights",
            "Cross-border transfer with consent or adequacy",
            "Breach notification requirements",
            "Japan-EU Mutual Adequacy",
        ],
        "data_localization": False,
        "cross_border_transfer_mechanisms": [
            "Consent of data subject",
            "Countries with adequate protection",
            "Japan-EU adequacy (reciprocal)",
        ],
        "effective_date": "2003-05-30 (amended 2022)",
        "compliance_score": 8,
    },
}


# ══════════════════════════════════════════════════════════════════════
# Country code → name mapping
# ══════════════════════════════════════════════════════════════════════

COUNTRY_NAMES: Dict[str, str] = {
    code: data["country_name"]
    for code, data in SURVEILLANCE_DATABASE.items()
}


def _country_code_to_name(code: str) -> str:
    """Resolve a 2-letter country code to its full name."""
    return COUNTRY_NAMES.get(code.upper(), code.upper())


# ══════════════════════════════════════════════════════════════════════
# Jurisdiction dataclass
# ══════════════════════════════════════════════════════════════════════

@dataclass
class Jurisdiction:
    """Single jurisdiction assessment result."""

    country: str = "Unknown"
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    data_residency_risk: str = "unknown"
    surveillance_laws: List[str] = field(default_factory=list)
    encryption_regulations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "country": self.country,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "data_residency_risk": self.data_residency_risk,
            "surveillance_laws": self.surveillance_laws,
            "encryption_regulations": self.encryption_regulations,
        }


# ══════════════════════════════════════════════════════════════════════
# SovereigntyMapper
# ══════════════════════════════════════════════════════════════════════

class SovereigntyMapper:
    """Maps a target to its digital sovereignty profile.

    Combines ASN analysis, TLS certificate inspection, DNS nameserver
    geolocation, content language detection, and cloud provider region
    detection to build a comprehensive jurisdictional picture.
    """

    def __init__(self) -> None:
        self._ua = "ReconPro/9.2.0 (sovereignty-mapper)"

    # ── public API ─────────────────────────────────────────────────

    def map_sovereignty(
        self,
        target: str,
        base_url: str,
        geo_data: Optional[Dict[str, Any]] = None,
        tls_data: Optional[Dict[str, Any]] = None,
        timeout: int = 8,
    ) -> Dict[str, Any]:
        """Build a full sovereignty profile for *target*.

        Returns a dict with keys: ``jurisdictions``, ``primary_jurisdiction``,
        ``cloud_provider``, ``cloud_region``, ``surveillance_risk``,
        ``data_residency_compliance``, ``overall_risk_score``, ``details``.
        """
        host = self._extract_host(base_url)

        asn_jur = self.analyze_asn_jurisdiction(host, timeout=timeout)
        cert_jur = self.analyze_certificate_jurisdiction(host, timeout=timeout)
        dns_jur = self.analyze_dns_jurisdiction(host, timeout=timeout)
        content_jur = self.analyze_content_jurisdiction(base_url, timeout=timeout)
        cloud_jur = self.analyze_cloud_jurisdiction(base_url, timeout=timeout)

        all_jurisdictions: List[Jurisdiction] = [asn_jur, cert_jur, dns_jur, content_jur]

        # Merge into a primary assessment weighted by confidence
        primary = self._merge_jurisdictions(all_jurisdictions)

        # Surveillance risk assessment
        surveillance = self.assess_surveillance_risk(primary.country)

        # Data residency compliance
        involved_countries = list({
            j.country for j in all_jurisdictions if j.country != "Unknown"
        })
        compliance = self.assess_data_residency_compliance(involved_countries)

        risk_score = self._calculate_overall_risk(primary, surveillance, cloud_jur)

        return {
            "target": target,
            "base_url": base_url,
            "host": host,
            "jurisdictions": [j.to_dict() for j in all_jurisdictions],
            "primary_jurisdiction": primary.to_dict(),
            "cloud_provider": cloud_jur.get("provider", "Unknown"),
            "cloud_region": cloud_jur.get("region", "Unknown"),
            "surveillance_risk": surveillance,
            "data_residency_compliance": compliance,
            "overall_risk_score": risk_score,
            "details": {
                "geo_data_supplied": geo_data is not None,
                "tls_data_supplied": tls_data is not None,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        }

    # ── ASN jurisdiction ───────────────────────────────────────────

    def analyze_asn_jurisdiction(
        self, host: str, timeout: int = 8
    ) -> Jurisdiction:
        """Map a host's ASN to a country via WHOIS lookup."""
        jur = Jurisdiction(evidence=[])  # type: ignore[arg-type]

        try:
            result = self._whois_query(host, timeout=timeout)
            if result:
                country = self._extract_country_from_whois(result)
                if country:
                    jur.country = _country_code_to_name(country)
                    jur.confidence = 0.75
                    jur.evidence.append(f"WHOIS ASN country: {country}")

                org = self._extract_org_from_whois(result)
                if org:
                    jur.evidence.append(f"WHOIS Organization: {org}")

                # Check for known surveillance countries
                code = country.upper() if country else ""
                if code in SURVEILLANCE_DATABASE:
                    db = SURVEILLANCE_DATABASE[code]
                    jur.surveillance_laws = db["programs"]
                    if db["encryption_backdoor_laws"]:
                        jur.encryption_regulations.append(
                            "Mandatory backdoor / key escrow"
                        )
                    jur.data_residency_risk = db["risk_level"]
        except Exception as exc:
            jur.evidence.append(f"ASN lookup failed: {exc}")

        return jur

    # ── Certificate jurisdiction ────────────────────────────────────

    def analyze_certificate_jurisdiction(
        self, host: str, timeout: int = 8
    ) -> Jurisdiction:
        """Analyze TLS certificate issuer to determine jurisdiction."""
        jur = Jurisdiction(evidence=[])  # type: ignore[arg-type]

        try:
            from .http_layer import inspection_context
            # certificate inspection (audited helper — not data transport)
            ctx = inspection_context()

            with socket.create_connection((host, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert_der = tls.getpeercert(binary_form=True)
                    if cert_der is None:
                        jur.evidence.append("No TLS certificate returned")
                        return jur

                    import ssl as _ssl_mod
                    # decode_der_subj takes DER; we use getpeercert() dict instead
                    cert_dict = tls.getpeercert()
                    if not cert_dict:
                        jur.evidence.append("Could not parse certificate")
                        return jur

                    # Extract issuer
                    issuer_parts = cert_dict.get("issuer", [])
                    issuer_str = ", ".join(
                        f"{k}={v}" for item in issuer_parts for k, v in item
                    )

                    subject_parts = cert_dict.get("subject", [])
                    subject_str = ", ".join(
                        f"{k}={v}" for item in subject_parts for k, v in item
                    )

                    jur.evidence.append(f"Certificate Subject: {subject_str}")
                    jur.evidence.append(f"Certificate Issuer: {issuer_str}")

                    # Map known CAs to jurisdictions
                    issuer_country = self._map_ca_to_jurisdiction(issuer_str)
                    if issuer_country:
                        jur.country = issuer_country
                        jur.confidence = 0.55
                        jur.evidence.append(f"CA jurisdiction: {issuer_country}")

                    # Check for EV certs (higher identity assurance)
                    if "businessCategory" in subject_str or "jurisdiction" in subject_str.lower():
                        jur.evidence.append("Extended Validation (EV) certificate detected")
                        jur.confidence = min(jur.confidence + 0.1, 1.0)

        except socket.timeout:
            jur.evidence.append("TLS connection timed out")
        except socket.gaierror as exc:
            jur.evidence.append(f"DNS resolution failed: {exc}")
        except ssl.SSLError as exc:
            jur.evidence.append(f"TLS handshake error: {exc}")
        except OSError as exc:
            jur.evidence.append(f"Connection error: {exc}")

        return jur

    # ── DNS jurisdiction ────────────────────────────────────────────

    def analyze_dns_jurisdiction(
        self, host: str, timeout: int = 8
    ) -> Jurisdiction:
        """Check the countries where a host's nameservers are located."""
        jur = Jurisdiction(evidence=[])  # type: ignore[arg-type]

        try:
            answers = socket.getaddrinfo(host, None)
            ips = list({addr[4][0] for addr in answers if addr[4]})
            jur.evidence.append(f"Resolved IPs: {', '.join(ips[:5])}")

            # Try to get NS records via system resolver
            ns_result = self._dig_ns(host, timeout=timeout)
            if ns_result:
                for ns in ns_result:
                    jur.evidence.append(f"Nameserver: {ns}")
                    ns_country = self._infer_ns_country(ns)
                    if ns_country and jur.country == "Unknown":
                        jur.country = ns_country
                        jur.confidence = 0.45
        except socket.gaierror as exc:
            jur.evidence.append(f"DNS resolution failed: {exc}")
        except Exception as exc:
            jur.evidence.append(f"DNS analysis error: {exc}")

        return jur

    # ── Content jurisdiction ────────────────────────────────────────

    def analyze_content_jurisdiction(
        self, base_url: str, timeout: int = 8
    ) -> Jurisdiction:
        """Detect page language, cultural markers, and jurisdiction hints."""
        jur = Jurisdiction(evidence=[])  # type: ignore[arg-type]

        try:
            req = urllib.request.Request(
                base_url,
                headers={"User-Agent": self._ua},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(65_536).decode("utf-8", errors="replace")
                ct = resp.headers.get("Content-Language", "")
                if ct:
                    jur.evidence.append(f"Content-Language header: {ct}")

                # Detect lang attribute
                lang_match = re.search(r'<html[^>]+lang=["\']([a-zA-Z-]+)["\']', body, re.I)
                if lang_match:
                    lang = lang_match.group(1).split("-")[0].upper()
                    jur.evidence.append(f"HTML lang attribute: {lang_match.group(1)}")
                    country = self._lang_to_country(lang)
                    if country and jur.country == "Unknown":
                        jur.country = country
                        jur.confidence = 0.30

                # Detect cultural / jurisdictional markers
                markers = self._detect_cultural_markers(body)
                jur.evidence.extend(markers)

                # Detect privacy policy / legal jurisdiction references
                legal_refs = self._detect_legal_references(body)
                jur.evidence.extend(legal_refs)
                for ref in legal_refs:
                    detected_country = self._legal_ref_to_country(ref)
                    if detected_country and jur.country == "Unknown":
                        jur.country = detected_country
                        jur.confidence = 0.60

        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            jur.evidence.append(f"Content fetch failed: {exc}")

        return jur

    # ── Cloud jurisdiction ──────────────────────────────────────────

    def analyze_cloud_jurisdiction(
        self, base_url: str, timeout: int = 8
    ) -> Dict[str, str]:
        """Detect AWS, Azure, GCP region from headers, URLs, or page content."""
        result: Dict[str, str] = {"provider": "Unknown", "region": "Unknown"}

        try:
            req = urllib.request.Request(
                base_url,
                headers={"User-Agent": self._ua},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = dict(resp.headers)
                body = resp.read(65_536).decode("utf-8", errors="replace")

            # AWS detection
            if (headers.get("server", "").lower() in ("amazonS3", "awselb", "cloudfront")
                    or "amazonaws.com" in base_url.lower()
                    or "s3.amazonaws.com" in body.lower()
                    or "x-amz-request-id" in headers
                    or "x-amz-cf-id" in headers):
                result["provider"] = "AWS"
                region = self._detect_aws_region(base_url, headers, body)
                if region:
                    result["region"] = region

            # Azure detection
            elif ("azure" in headers.get("server", "").lower()
                  or ".azurewebsites.net" in base_url.lower()
                  or "x-azure-ref" in headers
                  or "x-ms-request-id" in headers):
                result["provider"] = "Azure"
                region = self._detect_azure_region(headers, body)
                if region:
                    result["region"] = region

            # GCP detection
            elif ("gke" in headers.get("server", "").lower()
                  or ".appspot.com" in base_url.lower()
                  or ".run.app" in base_url.lower()
                  or "x-goog-request-id" in headers):
                result["provider"] = "GCP"
                region = self._detect_gcp_region(base_url, headers, body)
                if region:
                    result["region"] = region

            # Cloudflare detection
            elif ("cloudflare" in headers.get("server", "").lower()
                  or "cf-ray" in headers):
                result["provider"] = "Cloudflare"
                cf_ray = headers.get("cf-ray", "")
                if "-" in cf_ray:
                    iata = cf_ray.rsplit("-", 1)[-1]
                    result["region"] = f"Cloudflare edge (IATA: {iata})"

            # Generic CDN / hosting detection
            elif headers.get("server", ""):
                result["provider"] = f"Hosting: {headers['server']}"

        except (urllib.error.URLError, socket.timeout, OSError):
            pass

        return result

    # ── Surveillance risk assessment ────────────────────────────────

    def assess_surveillance_risk(self, country: str) -> Dict[str, Any]:
        """Return surveillance profile for a country.

        Looks up the country in SURVEILLANCE_DATABASE. Falls back to
        a generic assessment when no entry exists.
        """
        code = self._country_name_to_code(country)

        if code and code in SURVEILLANCE_DATABASE:
            db = SURVEILLANCE_DATABASE[code]
            return {
                "country": db["country_name"],
                "country_code": code,
                "risk_level": db["risk_level"],
                "surveillance_programs": db["programs"],
                "data_retention_laws": db["data_retention_laws"],
                "retention_period": db["retention_period"],
                "encryption_backdoor_mandated": db["encryption_backdoor_laws"],
                "backdoor_notes": db["backdoor_notes"],
                "intelligence_sharing": db["intelligence_sharing"],
                "risk_score": self._surveillance_risk_score(db),
            }

        # Also check EU aggregate
        if country.lower() in ("european union", "eu", "eea"):
            return self._eu_surveillance_profile()

        return {
            "country": country,
            "country_code": code or "??",
            "risk_level": "unknown",
            "surveillance_programs": [],
            "data_retention_laws": False,
            "retention_period": "Unknown",
            "encryption_backdoor_mandated": False,
            "backdoor_notes": "No surveillance data available for this country",
            "intelligence_sharing": [],
            "risk_score": 0.0,
        }

    # ── Data residency compliance ───────────────────────────────────

    def assess_data_residency_compliance(
        self, countries: List[str]
    ) -> Dict[str, Any]:
        """Check GDPR, CCPA, PIPL, LGPD compliance across involved countries.

        Returns a compliance assessment showing which data protection
        frameworks apply and whether cross-border transfers are at risk.
        """
        applicable_laws: List[Dict[str, Any]] = []
        cross_border_risk = False
        data_localization_required = False
        compliance_gaps: List[str] = []

        for country in countries:
            code = self._country_name_to_code(country)
            if code and code in DATA_PROTECTION_LAWS:
                law = DATA_PROTECTION_LAWS[code]
                applicable_laws.append({
                    "country": country,
                    "law": law["name"],
                    "full_name": law["full_name"],
                    "compliance_score": law["compliance_score"],
                    "data_localization": law["data_localization"],
                })
                if law["data_localization"]:
                    data_localization_required = True

        # Check for cross-border transfer issues
        if len(countries) > 1:
            cross_border_risk = True
            compliance_gaps.append(
                "Data spans multiple jurisdictions — cross-border transfer mechanisms required"
            )

        # Check for conflicting data localization requirements
        localization_countries = [
            c for c, law in zip(countries, applicable_laws)
            if law.get("data_localization")
        ]
        if len(localization_countries) > 1:
            compliance_gaps.append(
                f"Conflicting data localization: {', '.join(localization_countries)}"
            )

        # Check for surveillance countries
        for country in countries:
            code = self._country_name_to_code(country)
            if code and code in SURVEILLANCE_DATABASE:
                risk = SURVEILLANCE_DATABASE[code]["risk_level"]
                if risk in ("high", "critical"):
                    compliance_gaps.append(
                        f"High surveillance risk in {country} may conflict with data protection obligations"
                    )

        return {
            "applicable_laws": applicable_laws,
            "cross_border_risk": cross_border_risk,
            "data_localization_required": data_localization_required,
            "compliance_gaps": compliance_gaps,
            "jurisdiction_count": len(countries),
            "assessment": "compliant" if not compliance_gaps else "review_required",
        }

    # ── private helpers ─────────────────────────────────────────────

    @staticmethod
    def _extract_host(url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname or parsed.path.split("/")[0]

    @staticmethod
    def _whois_query(host: str, timeout: int = 8) -> Optional[str]:
        """Attempt a WHOIS lookup via the system ``whois`` command."""
        try:
            proc = subprocess.run(
                ["whois", host],
                capture_output=True, text=True, timeout=timeout,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return None

    @staticmethod
    def _extract_country_from_whois(text: str) -> Optional[str]:
        for line in text.splitlines():
            low = line.lower().strip()
            if low.startswith("country:"):
                return line.split(":", 1)[1].strip().upper()
        return None

    @staticmethod
    def _extract_org_from_whois(text: str) -> Optional[str]:
        for key in ("OrgName", "org-name", "organisation", "Organization"):
            for line in text.splitlines():
                if line.lower().startswith(key.lower()):
                    return line.split(":", 1)[1].strip()
        return None

    @staticmethod
    def _map_ca_to_jurisdiction(issuer: str) -> Optional[str]:
        ca_map = {
            "DigiCert": "United States",
            "Sectigo": "United States",
            "Let's Encrypt": "United States",
            "ISRG": "United States",
            "GlobalSign": "Belgium",
            "IdenTrust": "United States",
            "Entrust": "United States",
            "CFCA": "China",
            "WoSign": "China",
            "StartCom": "China",
            "CNNIC": "China",
            "TeliaSonera": "Sweden",
            "Certum": "Poland",
            "AC Camerfirma": "Spain",
            "Izenpe": "Spain",
            "FNMT": "Spain",
            "eMudhra": "India",
            "Safescrypt": "India",
            "Nic ": "India",
            "NetLock": "Hungary",
            "T-Systems": "Germany",
            "TeleSec": "Germany",
            "D-Trust": "Germany",
            "Bundesnetzagentur": "Germany",
            "Gandi": "France",
            "Keynectis": "France",
        }
        low = issuer.lower()
        for ca, country in ca_map.items():
            if ca.lower() in low:
                return country
        return None

    @staticmethod
    def _dig_ns(host: str, timeout: int = 8) -> Optional[List[str]]:
        try:
            proc = subprocess.run(
                ["dig", "+short", "NS", host],
                capture_output=True, text=True, timeout=timeout,
            )
            if proc.returncode == 0:
                return [
                    line.strip()
                    for line in proc.stdout.strip().splitlines()
                    if line.strip()
                ]
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return None

    @staticmethod
    def _infer_ns_country(ns: str) -> Optional[str]:
        ns_tlds = {
            ".cn": "China",
            ".ru": "Russia",
            ".br": "Brazil",
            ".in": "India",
            ".jp": "Japan",
            ".kr": "South Korea",
            ".au": "Australia",
            ".de": "Germany",
            ".fr": "France",
            ".uk": "United Kingdom",
        }
        ns_lower = ns.lower().rstrip(".")
        for tld, country in ns_tlds.items():
            if ns_lower.endswith(tld):
                return country
        return None

    @staticmethod
    def _lang_to_country(lang_code: str) -> Optional[str]:
        mapping = {
            "ZH": "China", "EN": "Unknown", "DE": "Germany",
            "FR": "France", "ES": "Spain", "PT": "Brazil",
            "JA": "Japan", "KO": "South Korea", "AR": "Saudi Arabia",
            "FA": "Iran", "RU": "Russia", "HI": "India",
            "TR": "Turkey", "IT": "Italy", "NL": "Netherlands",
            "PL": "Poland", "SV": "Sweden", "DA": "Denmark",
        }
        return mapping.get(lang_code.upper())

    @staticmethod
    def _detect_cultural_markers(html: str) -> List[str]:
        markers: List[str] = []
        patterns = {
            "ICP license (China)": r"ICP[\s\d]*[\u8BB8\u53EF\u8BC1]|ICP\s*\d+",
            "Russian Federal registration": r"\u0424\u0435\u0434\u0435\u0440\u0430\u043B\u044C\u043D\u0430\u044F|Roskomnadzor",
            "Iranian registration": r"\u062B\u0628\u062A|\u0641\u0631\u0647\u0646\u06AF\u06CC|irancf.ir",
            "GDPR consent banner": r"cookie[- ]?consent|gdpr|privacy[- ]?policy|dsgvo|rgpd",
            "US-specific legal": r"california|ccpa|do[- ]?not[- ]?sell|state of california",
            "Brazil LGPD": r"lgpd|autoridade nacional de protecao|anpd",
            "China PIPL": r"\u4E2A\u4EBA\u4FE1\u606F\u4FDD\u62A4|PIPL|\u9690\u79C1\u653F\u7B56",
        }
        for label, pattern in patterns.items():
            if re.search(pattern, html, re.I):
                markers.append(f"Cultural marker: {label}")
        return markers

    @staticmethod
    def _detect_legal_references(html: str) -> List[str]:
        refs: List[str] = []
        patterns = {
            "Governing law: England/Wales": r"governing law[^.]*england|governing law[^.]*wales",
            "Governing law: California": r"governing law[^.]*california",
            "Governing law: New York": r"governing law[^.]*new\s+york",
            "Governing law: Germany": r"governing law[^.]*germany|gerichtsstand",
            "Governing law: France": r"governing law[^.]*france|droit\s+fran\u00E7ais",
            "Jurisdiction: EU": r"courts of the european union|eu\s+jurisdiction",
            "Arbitration: ICC Paris": r"icc\s+(arbitration|paris)|international\s+court\s+of\s+arbitration",
        }
        for label, pattern in patterns.items():
            if re.search(pattern, html, re.I):
                refs.append(f"Legal reference: {label}")
        return refs

    @staticmethod
    def _legal_ref_to_country(ref: str) -> Optional[str]:
        ref_map = {
            "england": "United Kingdom", "wales": "United Kingdom",
            "california": "United States", "new york": "United States",
            "germany": "Germany", "france": "France",
            "european union": "EU",
        }
        low = ref.lower()
        for key, country in ref_map.items():
            if key in low:
                return country
        return None

    @staticmethod
    def _detect_aws_region(url: str, headers: Dict[str, str], body: str) -> Optional[str]:
        region_patterns = [
            r"s3[.-]([a-z]{2}-[a-z]+-\d)\.amazonaws\.com",
            r"([a-z]{2}-[a-z]+-\d)\.compute\.amazonaws\.com",
            r"x-amz-cf-pop:\s*([a-z]{3}\d+-[a-z]+\d+)",
        ]
        for pattern in region_patterns:
            match = re.search(pattern, url + "\n" + "\n".join(headers.values()) + "\n" + body, re.I)
            if match:
                return match.group(1).upper()
        return None

    @staticmethod
    def _detect_azure_region(headers: Dict[str, str], body: str) -> Optional[str]:
        combined = "\n".join(headers.values()) + "\n" + body
        match = re.search(r"([a-z]{2}-[a-z]+\d?)\.azurewebsites\.net", combined, re.I)
        if match:
            return match.group(1).upper()
        return None

    @staticmethod
    def _detect_gcp_region(url: str, headers: Dict[str, str], body: str) -> Optional[str]:
        combined = url + "\n" + "\n".join(headers.values()) + "\n" + body
        match = re.search(r"([a-z]{2}-[a-z]+\d)\.run\.app", combined, re.I)
        if match:
            return match.group(1).upper()
        match = re.search(r"([a-z]{2}-[a-z]+\d)\.appspot\.com", combined, re.I)
        if match:
            return match.group(1).upper()
        return None

    @staticmethod
    def _country_name_to_code(name: str) -> Optional[str]:
        name_to_code = {
            "united states": "US", "usa": "US",
            "united kingdom": "GB", "uk": "GB", "great britain": "GB",
            "china": "CN", "russia": "RU", "iran": "IR",
            "germany": "DE", "france": "FR", "australia": "AU",
            "india": "IN", "brazil": "BR", "saudi arabia": "SA",
            "turkey": "TR", "japan": "JP", "south korea": "KR",
            "israel": "IL", "singapore": "SG",
            "united arab emirates": "AE", "uae": "AE",
            "north korea": "KP",
            "belgium": "BE", "spain": "ES", "sweden": "SE",
            "italy": "IT", "netherlands": "NL", "poland": "PL",
            "denmark": "DK", "portugal": "PT",
            "eu": "EU", "european union": "EU", "eea": "EU",
        }
        return name_to_code.get(name.lower().strip())

    @staticmethod
    def _merge_jurisdictions(jurisdictions: List[Jurisdiction]) -> Jurisdiction:
        """Weighted merge: highest-confidence non-Unknown country wins."""
        best = Jurisdiction()
        for j in jurisdictions:
            if j.country != "Unknown" and j.confidence > best.confidence:
                best = j
        if best.country == "Unknown":
            for j in jurisdictions:
                if j.evidence:
                    best.evidence.extend(j.evidence)
        return best

    @staticmethod
    def _surveillance_risk_score(db: Dict[str, Any]) -> float:
        score = 0.0
        risk_map = {"low": 20.0, "medium": 50.0, "high": 75.0, "critical": 95.0}
        score += risk_map.get(db["risk_level"], 0)
        if db["data_retention_laws"]:
            score += 10.0
        if db["encryption_backdoor_laws"]:
            score += 15.0
        score += min(len(db["programs"]) * 2.0, 20.0)
        return min(score, 100.0)

    @staticmethod
    def _eu_surveillance_profile() -> Dict[str, Any]:
        return {
            "country": "European Union",
            "country_code": "EU",
            "risk_level": "medium",
            "surveillance_programs": [
                "EU Data Retention Directive (invalidated, but national laws persist)",
                "Member state intelligence agencies (BND, DGSE, etc.)",
                "EU PNR Directive (Passenger Name Record)",
                "ePrivacy Directive tracking provisions",
            ],
            "data_retention_laws": True,
            "retention_period": "Varies by member state",
            "encryption_backdoor_mandated": False,
            "backdoor_notes": "No EU-wide backdoor mandate; GDPR protects encryption rights",
            "intelligence_sharing": ["Nine Eyes", "Fourteen Eyes"],
            "risk_score": 40.0,
        }

    @staticmethod
    def _calculate_overall_risk(
        primary: Jurisdiction,
        surveillance: Dict[str, Any],
        cloud: Dict[str, str],
    ) -> float:
        score = 0.0
        score += surveillance.get("risk_score", 0) * 0.5
        if cloud.get("provider") not in ("Unknown", ""):
            score += 15.0
        if primary.data_residency_risk == "critical":
            score += 20.0
        elif primary.data_residency_risk == "high":
            score += 10.0
        score += len(primary.evidence) * 0.5
        return round(min(score, 100.0), 1)
