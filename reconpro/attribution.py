"""
ReconPro v9.2.0 — Threat Actor Attribution Engine
===================================================
Pure Python threat intelligence module for attributing cyber attacks
to known Advanced Persistent Threat (APT) groups based on observed
TTPs, infrastructure patterns, campaign signatures, and nation-state
indicators.

Zero external dependencies — stdlib only.
"""

from __future__ import annotations

from .constants import __version__

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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Constants & APT Group Database
# ---------------------------------------------------------------------------

__module_name__ = "attribution"

MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
}

APT_GROUPS: Dict[str, Dict[str, Any]] = {
    "APT1": {
        "id": "APT1",
        "name": "Comment Panda",
        "aliases": ["PLA Unit 61398", "Byzantine Candor", "Shady RAT"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Defense", "Aerospace", "Energy", "Technology"],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1133",
            "T1059.001", "T1059.003", "T1547.001", "T1053.005", "T1543.003",
            "T1055", "T1070.004", "T1562.001", "T1003", "T1110.001",
            "T1082", "T1083", "T1046", "T1005", "T1119",
            "T1041", "T1048", "T1071.001", "T1573.001", "T1105",
        ],
        "description": (
            "PLA Unit 61398, one of the most prolific Chinese cyber espionage "
            "groups. Active since at least 2006, responsible for stealing "
            "terabytes of data from US government and corporate targets. "
            "Documented extensively in the Mandiant APT1 report (2013)."
        ),
        "first_seen": "2006",
        "last_seen": "2023",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT2": {
        "id": "APT2",
        "name": "Cocot",
        "aliases": ["Putter Panda", "MS Updater", "Codoso"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Defense", "Technology", "Telecommunications"],
        "techniques": [
            "T1566.001", "T1190", "T1078", "T1059.001", "T1059.003",
            "T1547.001", "T1053.005", "T1055", "T1070.004", "T1003",
            "T1082", "T1083", "T1046", "T1005", "T1041",
            "T1071.001", "T1573.001",
        ],
        "description": (
            "Chinese cyber espionage group also known as Putter Panda, "
            "focused on US and European government and defense targets. "
            "Associated with the PLA's electronic warfare capabilities."
        ),
        "first_seen": "2009",
        "last_seen": "2022",
        "motivation": "Espionage",
        "sophistication": "moderate",
    },
    "APT3": {
        "id": "APT3",
        "name": "Gothic Panda",
        "aliases": ["Operation Clandestine Wolf", "UPS Team", " Buckeye"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Healthcare", "Aerospace", "Defense", "Energy"],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1059.003", "T1547.001", "T1053.005", "T1543.003", "T1055",
            "T1070.004", "T1562.001", "T1003", "T1110.001", "T1110.003",
            "T1082", "T1083", "T1046", "T1005", "T1119",
            "T1041", "T1048.001", "T1071.001", "T1573.001", "T1105",
            "T1486",
        ],
        "description": (
            "Chinese cyber espionage group known for targeting healthcare, "
            "aerospace, and defense sectors. Used the Sakula and JPG "
            "backdoors. Linked to the 2015 Anthem breach."
        ),
        "first_seen": "2010",
        "last_seen": "2023",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT4": {
        "id": "APT4",
        "name": "Double Tap",
        "aliases": ["Moonstone Park", "Pirate Panda", "Caminolka"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Technology", "Telecommunications"],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1547.001", "T1055", "T1070.004", "T1003", "T1082",
            "T1083", "T1046", "T1041", "T1071.001", "T1573.001",
        ],
        "description": (
            "Chinese cyber espionage group focused on government and "
            "telecommunications targets in South and Southeast Asia."
        ),
        "first_seen": "2011",
        "last_seen": "2022",
        "motivation": "Espionage",
        "sophistication": "moderate",
    },
    "APT5": {
        "id": "APT5",
        "name": "Mutton Mandarin",
        "aliases": ["Hot Pirate", "MANGANESE", "Iron Tiger"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Defense", "Technology", "Aerospace"],
        "techniques": [
            "T1566.001", "T1190", "T1078", "T1059.001", "T1059.003",
            "T1547.001", "T1053.005", "T1055", "T1070.004", "T1003",
            "T1082", "T1083", "T1046", "T1005", "T1119",
            "T1041", "T1071.001", "T1573.001",
        ],
        "description": (
            "Chinese espionage group targeting US defense and government "
            "networks. Known for supply-chain compromise techniques and "
            "long-term persistent access."
        ),
        "first_seen": "2007",
        "last_seen": "2023",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT6": {
        "id": "APT6",
        "name": "Mudi",
        "aliases": ["Nightshade Panda", "Pillowmint", "Titmouse"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Technology", "Healthcare"],
        "techniques": [
            "T1566.001", "T1190", "T1078", "T1059.001", "T1547.001",
            "T1055", "T1070.004", "T1003", "T1082", "T1083",
            "T1041", "T1071.001",
        ],
        "description": (
            "Chinese cyber espionage group targeting government and "
            "technology sectors across North America and Europe."
        ),
        "first_seen": "2012",
        "last_seen": "2021",
        "motivation": "Espionage",
        "sophistication": "moderate",
    },
    "APT7": {
        "id": "APT7",
        "name": "SNAKE",
        "aliases": ["Purple Typhoon", "TSC-RAT", "Cuckoo Carver"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Military", "Telecommunications"],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1059.003", "T1547.001", "T1053.005", "T1055", "T1070.004",
            "T1003", "T1082", "T1083", "T1046", "T1005",
            "T1041", "T1048", "T1071.001", "T1573.001",
        ],
        "description": (
            "Chinese cyber espionage group active since 2012. Known for "
            "the SNAKE malware family and targeting military and "
            "telecommunications infrastructure."
        ),
        "first_seen": "2012",
        "last_seen": "2022",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT10": {
        "id": "APT10",
        "name": "Stone Panda",
        "aliases": ["Cloud Hopper", "MenuPass", "POTATO", "CVNX"],
        "country": "China",
        "country_code": "CN",
        "sectors": [
            "Government", "Defense", "Technology", "Healthcare",
            "Aerospace", "Energy", "Managed Service Providers",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1133",
            "T1059.001", "T1059.003", "T1547.001", "T1053.005",
            "T1543.003", "T1055", "T1070.004", "T1562.001",
            "T1003.001", "T1003.002", "T1110.001", "T1110.003",
            "T1082", "T1083", "T1046", "T1049", "T1005",
            "T1119", "T1041", "T1048", "T1071.001", "T1573.001",
            "T1105", "T1071.004",
        ],
        "description": (
            "Chinese cyber espionage group operated by the MSS. Known for "
            "supply-chain attacks via managed service providers (Cloud "
            "Hopper operation). Indicted by the US DOJ in 2018. "
            "Targets span government, defense, and commercial sectors globally."
        ),
        "first_seen": "2009",
        "last_seen": "2024",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT12": {
        "id": "APT12",
        "name": "DynCalc",
        "aliases": ["IXESHE", "Numbered Panda", "DEEP PANDA"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Technology", "Media", "Financial"],
        "techniques": [
            "T1566.001", "T1190", "T1078", "T1059.001", "T1547.001",
            "T1055", "T1070.004", "T1003", "T1082", "T1083",
            "T1041", "T1071.001",
        ],
        "description": (
            "Chinese espionage group targeting media, government, and "
            "technology sectors. Known for the IXESHE malware family "
            "and sophisticated social engineering campaigns."
        ),
        "first_seen": "2010",
        "last_seen": "2022",
        "motivation": "Espionage",
        "sophistication": "moderate",
    },
    "APT14": {
        "id": "APT14",
        "name": "Dynamite Panda",
        "aliases": ["Aurora Panda", "Pcsnoopy", "Buer Unc"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Technology", "Defense"],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1547.001", "T1055", "T1070.004", "T1003", "T1082",
            "T1083", "T1041", "T1071.001", "T1573.001",
        ],
        "description": (
            "Chinese cyber espionage group targeting US government and "
            "technology companies. Linked to the Aurora attacks and "
            "Operation Aurora."
        ),
        "first_seen": "2009",
        "last_seen": "2021",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT15": {
        "id": "APT15",
        "name": "Winnti",
        "aliases": ["G0045", "Viceroy Tiger", "Talented Spider", "Threat Group-3390"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Technology", "Gaming", "Healthcare", "Aerospace", "Energy"],
        "techniques": [
            "T1566.001", "T1190", "T1078", "T1059.001", "T1547.001",
            "T1053.005", "T1055", "T1070.004", "T1003", "T1082",
            "T1083", "T1046", "T1005", "T1119", "T1041",
            "T1071.001", "T1573.001", "T1105",
        ],
        "description": (
            "Chinese cyber espionage group known for the Winnti malware "
            "family. Targets gaming, technology, and pharmaceutical sectors. "
            "Known for digital certificate theft and supply-chain compromise."
        ),
        "first_seen": "2011",
        "last_seen": "2024",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT16": {
        "id": "APT16",
        "name": "Pirpi",
        "aliases": ["Grey Typhoon", "Pleiades", "Naval Rains"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Defense", "Technology"],
        "techniques": [
            "T1566.001", "T1190", "T1078", "T1059.001", "T1547.001",
            "T1055", "T1070.004", "T1003", "T1082", "T1083",
            "T1041", "T1071.001",
        ],
        "description": (
            "Chinese cyber espionage group targeting defense and "
            "government entities. Known for using custom RATs and "
            "spear-phishing campaigns."
        ),
        "first_seen": "2010",
        "last_seen": "2021",
        "motivation": "Espionage",
        "sophistication": "moderate",
    },
    "APT17": {
        "id": "APT17",
        "name": "Deputy Dog",
        "aliases": ["Hidden Lynx", "TG-1996", "V8 Panda"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Defense", "Government", "Technology", "Media"],
        "techniques": [
            "T1566.001", "T1190", "T1078", "T1059.001", "T1547.001",
            "T1053.005", "T1055", "T1070.004", "T1562.001", "T1003",
            "T1082", "T1083", "T1046", "T1041", "T1071.001",
            "T1573.001",
        ],
        "description": (
            "Chinese cyber espionage group known for targeting defense "
            "contractors and media organizations. Documented in the "
            "FireEye Hidden Lynx report."
        ),
        "first_seen": "2011",
        "last_seen": "2022",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT18": {
        "id": "APT18",
        "name": "Turla",
        "aliases": ["KRYPTON", "Venomous Bear", "Secret Blizzard", "Waterbug"],
        "country": "Russia",
        "country_code": "RU",
        "sectors": [
            "Government", "Defense", "Embassies", "Education",
            "Journalism", "Military",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1133",
            "T1059.001", "T1059.003", "T1547.001", "T1053.005",
            "T1543.003", "T1055.001", "T1070.004", "T1562.001",
            "T1562.003", "T1003.001", "T1003.002", "T1110.001",
            "T1110.003", "T1082", "T1083", "T1046", "T1049",
            "T1005", "T1119", "T1041", "T1048", "T1071.001",
            "T1573.001", "T1105", "T1071.004",
        ],
        "description": (
            "Russian FSB-linked cyber espionage group active since at least "
            "2004. Known for hijacking satellite communications and the "
            "Carbon/ComRAT toolset. Targets governments, embassies, and "
            "military organizations worldwide. One of the most sophisticated "
            "APT groups in operation."
        ),
        "first_seen": "2004",
        "last_seen": "2024",
        "motivation": "Espionage",
        "sophistication": "very_high",
    },
    "APT19": {
        "id": "APT19",
        "name": "Codoso",
        "aliases": ["Deep Panda", "Stonewall Panda", "Operation Public Enemy"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Technology", "Legal", "Financial", "Healthcare"],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1059.003", "T1547.001", "T1055", "T1070.004", "T1003",
            "T1082", "T1083", "T1046", "T1005", "T1119",
            "T1041", "T1071.001", "T1573.001",
        ],
        "description": (
            "Chinese cyber espionage group known for targeting legal, "
            "financial, and government sectors. Involved in high-profile "
            "breaches including Anthem and OPM."
        ),
        "first_seen": "2011",
        "last_seen": "2023",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT20": {
        "id": "APT20",
        "name": "Chimera",
        "aliases": ["PassCV", "Dark Hotel", "Fierce Panda"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Technology", "Government", "Hospitality", "Financial"],
        "techniques": [
            "T1566.001", "T1190", "T1078", "T1059.001", "T1547.001",
            "T1055", "T1070.004", "T1003", "T1082", "T1083",
            "T1041", "T1071.001",
        ],
        "description": (
            "Chinese cyber espionage group targeting technology companies "
            "and government agencies. Known for hotel Wi-Fi attacks "
            "(Dark Hotel) and credential harvesting."
        ),
        "first_seen": "2007",
        "last_seen": "2022",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT21": {
        "id": "APT21",
        "name": "BadAutumn",
        "aliases": ["Scarlet Mimic", "ALUMINUM", "Emerald Sleet"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Defense", "Technology", "Mining"],
        "techniques": [
            "T1566.001", "T1190", "T1078", "T1059.001", "T1547.001",
            "T1055", "T1070.004", "T1003", "T1082", "T1083",
            "T1041", "T1071.001",
        ],
        "description": (
            "Chinese cyber espionage group targeting defense and "
            "technology sectors. Known for targeting mining and "
            "extraction industry companies."
        ),
        "first_seen": "2013",
        "last_seen": "2021",
        "motivation": "Espionage",
        "sophistication": "moderate",
    },
    "APT22": {
        "id": "APT22",
        "name": "Poodle Panda",
        "aliases": ["Tiger Lync", "Hugging Panda", "Double Dragon"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Defense", "Technology", "Energy"],
        "techniques": [
            "T1566.001", "T1190", "T1078", "T1059.001", "T1547.001",
            "T1055", "T1070.004", "T1003", "T1082", "T1083",
            "T1041", "T1071.001",
        ],
        "description": (
            "Chinese cyber espionage group active in Southeast Asia. "
            "Known for targeting government and defense organizations."
        ),
        "first_seen": "2011",
        "last_seen": "2021",
        "motivation": "Espionage",
        "sophistication": "moderate",
    },
    "APT23": {
        "id": "APT23",
        "name": "Keyboy",
        "aliases": ["Admin@338", "Panda Monster", "Ursnif", "APT_GROUP_SM"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Technology", "Energy", "Transportation"],
        "techniques": [
            "T1566.001", "T1190", "T1078", "T1059.001", "T1547.001",
            "T1055", "T1070.004", "T1003", "T1082", "T1083",
            "T1041", "T1071.001",
        ],
        "description": (
            "Chinese cyber espionage group targeting government and "
            "energy sectors. Known for custom backdoors and credential "
            "harvesting campaigns."
        ),
        "first_seen": "2013",
        "last_seen": "2022",
        "motivation": "Espionage",
        "sophistication": "moderate",
    },
    "APT24": {
        "id": "APT24",
        "name": "Karakurt",
        "aliases": ["Flying Cat", "BADFLUX", "Group 27"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Technology", "Healthcare", "Government"],
        "techniques": [
            "T1566.001", "T1190", "T1078", "T1059.001", "T1547.001",
            "T1055", "T1070.004", "T1003", "T1082", "T1083",
            "T1041", "T1071.001",
        ],
        "description": (
            "Chinese cyber espionage group targeting technology and "
            "healthcare organizations in North America and Europe."
        ),
        "first_seen": "2014",
        "last_seen": "2022",
        "motivation": "Espionage",
        "sophistication": "moderate",
    },
    "APT25": {
        "id": "APT25",
        "name": "Gallium",
        "aliases": ["Empire Panda", "Light Bogey", "Brave Typhoon"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Technology", "Telecommunications"],
        "techniques": [
            "T1566.001", "T1190", "T1078", "T1059.001", "T1547.001",
            "T1055", "T1070.004", "T1003", "T1082", "T1083",
            "T1041", "T1071.001", "T1573.001",
        ],
        "description": (
            "Chinese cyber espionage group targeting government and "
            "telecommunications organizations in Southeast Asia."
        ),
        "first_seen": "2012",
        "last_seen": "2023",
        "motivation": "Espionage",
        "sophistication": "moderate",
    },
    "APT26": {
        "id": "APT26",
        "name": "Naikon",
        "aliases": ["Hellsing", "Aria-body", "LordNm", "Solar",
                     "ProjectM", "Whirlpool"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Defense", "Military", "Telecommunications"],
        "techniques": [
            "T1566.001", "T1190", "T1078", "T1059.001", "T1059.003",
            "T1547.001", "T1053.005", "T1055", "T1070.004", "T1003",
            "T1082", "T1083", "T1046", "T1049", "T1005",
            "T1119", "T1041", "T1071.001", "T1573.001",
        ],
        "description": (
            "Chinese PLA cyber espionage group targeting government "
            "and military organizations in Southeast Asia. Known for "
            "the Naikon RAT and detailed reconnaissance."
        ),
        "first_seen": "2010",
        "last_seen": "2023",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT27": {
        "id": "APT27",
        "name": "Emissary Panda",
        "aliases": ["Hippo", "Lucky Mouse", "Threat Group-3390"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Defense", "Religious Organizations", "Healthcare"],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1133",
            "T1059.001", "T1059.003", "T1547.001", "T1053.005",
            "T1543.003", "T1055", "T1070.004", "T1562.001",
            "T1003", "T1110.001", "T1110.003", "T1082", "T1083",
            "T1046", "T1049", "T1005", "T1119", "T1041",
            "T1048", "T1071.001", "T1573.001", "T1105",
        ],
        "description": (
            "Chinese cyber espionage group targeting government, defense, "
            "and religious organizations. Known for Operation Legion "
            "and targeting Tibetan and Uyghur groups."
        ),
        "first_seen": "2011",
        "last_seen": "2024",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT28": {
        "id": "APT28",
        "name": "Fancy Bear",
        "aliases": [
            "Sofacy", "Strontium", "Sednit", "Pawn Storm",
            "Forest Blizzard", "Sandworm",
        ],
        "country": "Russia",
        "country_code": "RU",
        "sectors": [
            "Government", "Defense", "Military", "Media",
            "Energy", "Political Organizations", "Healthcare",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078.003",
            "T1059.001", "T1059.003", "T1547.001", "T1053.005",
            "T1543.003", "T1055.001", "T1070.004", "T1562.001",
            "T1562.003", "T1003.001", "T1003.002", "T1110.001",
            "T1110.002", "T1110.003", "T1082", "T1083", "T1046",
            "T1049", "T1005", "T1119", "T1041", "T1048.003",
            "T1071.001", "T1573.001", "T1105", "T1486",
            "T1489.001",
        ],
        "description": (
            "Russian GRU Unit 26165 cyber espionage group. Known for "
            "interfering in the 2016 US presidential election, targeting "
            "the DNC, NATO, and World Anti-Doping Agency. Uses "
            "X-Agent, X-Tunnel, and Sofacy/Office macros. Highly active "
            "in geopolitical operations including Ukraine conflict."
        ),
        "first_seen": "2007",
        "last_seen": "2024",
        "motivation": "Espionage / Sabotage",
        "sophistication": "very_high",
    },
    "APT29": {
        "id": "APT29",
        "name": "Cozy Bear",
        "aliases": [
            "The Dukes", "Yttrium", "CozyDuke", "Noble Baron",
            "Midnight Blizzard", "UNC2452",
        ],
        "country": "Russia",
        "country_code": "RU",
        "sectors": [
            "Government", "Defense", "Think Tanks", "Technology",
            "Healthcare", "Financial", "Diplomatic Organizations",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078.003",
            "T1059.001", "T1059.003", "T1547.001", "T1053.005",
            "T1543.003", "T1055.001", "T1070.004", "T1562.001",
            "T1003.001", "T1003.002", "T1110.001", "T1110.003",
            "T1082", "T1083", "T1046", "T1049", "T1005",
            "T1119", "T1041", "T1071.001", "T1573.001",
            "T1105", "T1071.004", "T1195.002",
        ],
        "description": (
            "Russian SVR foreign intelligence cyber espionage group. "
            "Known for the SolarWinds supply-chain compromise (SUNBURST), "
            "DNC breach, and targeting diplomatic organizations. Uses "
            "sophisticated supply-chain attacks and living-off-the-land "
            "techniques. One of the most capable APT groups globally."
        ),
        "first_seen": "2008",
        "last_seen": "2024",
        "motivation": "Espionage",
        "sophistication": "very_high",
    },
    "APT30": {
        "id": "APT30",
        "name": "Nautilus",
        "aliases": ["Operation NetTraveler", "Traveler", "Rainy PANDA"],
        "country": "China",
        "country_code": "CN",
        "sectors": ["Government", "Diplomatic", "Military", "Media", "NGOs"],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1133",
            "T1059.001", "T1547.001", "T1055", "T1070.004",
            "T1003", "T1082", "T1083", "T1046", "T1005",
            "T1119", "T1041", "T1071.001", "T1573.001",
        ],
        "description": (
            "Chinese cyber espionage group targeting diplomatic and "
            "government organizations across Southeast Asia. Known for "
            "air-gapped network targeting and cross-platform malware."
        ),
        "first_seen": "2004",
        "last_seen": "2023",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT31": {
        "id": "APT31",
        "name": "Zirconium",
        "aliases": [
            "Hurricane Panda", "Silver Fox", "Vicious Panda",
            "G0064", "Judgment Panda",
        ],
        "country": "China",
        "country_code": "CN",
        "sectors": [
            "Government", "Defense", "Diplomatic", "Think Tanks",
            "Political Organizations", "Technology",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1133",
            "T1059.001", "T1059.003", "T1547.001", "T1053.005",
            "T1055", "T1070.004", "T1562.001", "T1003",
            "T1110.001", "T1110.003", "T1082", "T1083",
            "T1046", "T1049", "T1005", "T1119", "T1041",
            "T1071.001", "T1573.001", "T1105",
        ],
        "description": (
            "Chinese MSS cyber espionage group targeting government, "
            "diplomatic, and political entities worldwide. Indicted by "
            "the US DOJ in 2020 for targeting election infrastructure. "
            "Known for sophisticated spear-phishing and zero-day exploits."
        ),
        "first_seen": "2008",
        "last_seen": "2024",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT32": {
        "id": "APT32",
        "name": "OceanLotus",
        "aliases": [
            "SeaLotus", "Sea Wasp", "BISMUTH", "Embargo",
            "Phosphorus",
        ],
        "country": "Vietnam",
        "country_code": "VN",
        "sectors": [
            "Government", "Corporate", "Media", "Technology",
            "Research Institutions", "Human Rights Organizations",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1059.003", "T1547.001", "T1053.005", "T1055",
            "T1070.004", "T1003", "T1110.001", "T1082",
            "T1083", "T1046", "T1005", "T1119", "T1041",
            "T1071.001", "T1573.001", "T1105",
        ],
        "description": (
            "Vietnamese state-sponsored cyber espionage group active since "
            "2012. Targets Vietnamese corporations, foreign governments, "
            "and human rights organizations. Known for the OceanLotus "
            "backdoor and macOS-targeting malware."
        ),
        "first_seen": "2012",
        "last_seen": "2024",
        "motivation": "Espionage",
        "sophistication": "moderate",
    },
    "APT33": {
        "id": "APT33",
        "name": "Elfin",
        "aliases": [
            "Refined Kitten", "Pioneer Kitten", "G0034",
            "TA456", "Holmium",
        ],
        "country": "Iran",
        "country_code": "IR",
        "sectors": [
            "Energy", "Aerospace", "Defense", "Chemical",
            "Financial", "Healthcare", "Government",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1059.003", "T1547.001", "T1053.005", "T1055",
            "T1070.004", "T1562.001", "T1003", "T1110.001",
            "T1110.003", "T1082", "T1083", "T1046", "T1005",
            "T1119", "T1041", "T1071.001", "T1573.001",
            "T1486", "T1489.001",
        ],
        "description": (
            "Iranian IRGC cyber espionage group targeting energy, "
            "aerospace, and defense sectors. Known for the Shamoon "
            "disk-wiping malware and targeting Saudi Aramco. Also "
            "involved in credential harvesting campaigns."
        ),
        "first_seen": "2013",
        "last_seen": "2024",
        "motivation": "Espionage / Sabotage",
        "sophistication": "high",
    },
    "APT34": {
        "id": "APT34",
        "name": "OilRig",
        "aliases": [
            "Helix Kitten", "Cobalt Ulster", "Rising Sun",
            "Green Spider", "Lyceum", "Siamesekitten",
        ],
        "country": "Iran",
        "country_code": "IR",
        "sectors": [
            "Government", "Financial", "Energy", "Telecommunications",
            "Defense", "Chemical",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1059.003", "T1547.001", "T1053.005", "T1055",
            "T1070.004", "T1562.001", "T1003", "T1110.001",
            "T1082", "T1083", "T1046", "T1005", "T1119",
            "T1041", "T1071.001", "T1573.001",
        ],
        "description": (
            "Iranian MOIS cyber espionage group targeting government, "
            "financial, and energy sectors in the Middle East. Known for "
            "phishing campaigns using compromised legitimate accounts "
            "and the PowerSnake and BONDUPDATER tools."
        ),
        "first_seen": "2014",
        "last_seen": "2024",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT35": {
        "id": "APT35",
        "name": "Charming Kitten",
        "aliases": [
            "Phosphorus", "Magic Hound", "TA453", "Ajax Security Team",
            "NewsBeef", "iKittens",
        ],
        "country": "Iran",
        "country_code": "IR",
        "sectors": [
            "Government", "Academia", "Media", "Think Tanks",
            "Activists", "Diplomatic", "Defense", "Healthcare",
            "Financial", "Technology",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1566.003", "T1190",
            "T1078.003", "T1059.001", "T1059.003", "T1547.001",
            "T1053.005", "T1055", "T1070.004", "T1562.001",
            "T1003", "T1110.001", "T1110.002", "T1110.003",
            "T1082", "T1083", "T1046", "T1005", "T1119",
            "T1041", "T1071.001", "T1573.001", "T1105",
            "T1566.002", "T1589.002",
        ],
        "description": (
            "Iranian IRGC cyber espionage group with broad targeting "
            "including academia, media, and government. Known for "
            "sophisticated social engineering, credential phishing via "
            "spoofed websites, and multi-factor authentication bypass "
            "campaigns. Indicted by the US DOJ in 2019."
        ),
        "first_seen": "2013",
        "last_seen": "2024",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT36": {
        "id": "APT36",
        "name": "Transparent Tribe",
        "aliases": ["ProjectM", "MYTH", "C-Major", "APT-C-35"],
        "country": "Pakistan",
        "country_code": "PK",
        "sectors": [
            "Government", "Military", "Diplomatic", "Defense",
            "Legal", "Academia",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1547.001", "T1053.005", "T1055", "T1070.004",
            "T1003", "T1110.001", "T1082", "T1083", "T1046",
            "T1005", "T1041", "T1071.001", "T1573.001",
        ],
        "description": (
            "Pakistani state-sponsored cyber espionage group targeting "
            "Indian government, military, and diplomatic entities. Known "
            "for Android malware and malicious document-based campaigns."
        ),
        "first_seen": "2013",
        "last_seen": "2024",
        "motivation": "Espionage",
        "sophistication": "moderate",
    },
    "APT37": {
        "id": "APT37",
        "name": "Reaper",
        "aliases": [
            "Group123", "ScarCruft", "InkySquid",
            "STARCRUIT", "Redcall", "Ricochet Chollima",
        ],
        "country": "North Korea",
        "country_code": "KP",
        "sectors": [
            "Government", "Defense", "Media", "Academia",
            "Think Tanks", "Financial", "Technology",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1059.003", "T1547.001", "T1053.005", "T1055",
            "T1070.004", "T1562.001", "T1003", "T1110.001",
            "T1110.003", "T1082", "T1083", "T1046", "T1005",
            "T1119", "T1041", "T1071.001", "T1573.001",
            "T1189", "T1203",
        ],
        "description": (
            "North Korean (RGB) cyber espionage group targeting South "
            "Korean government, media, and academic organizations. Known "
            "for zero-day exploits (CVE-2018-0802), targeted "
            "spear-phishing, and the ROKRAT toolset."
        ),
        "first_seen": "2012",
        "last_seen": "2024",
        "motivation": "Espionage / Financial",
        "sophistication": "high",
    },
    "APT38": {
        "id": "APT38",
        "name": "Lazarus",
        "aliases": [
            "Hidden Cobra", "Zinc", "Labyrinth Chollima",
            "NICKEL HYDRA", "FASTCash", "DUST",
        ],
        "country": "North Korea",
        "country_code": "KP",
        "sectors": [
            "Financial", "Cryptocurrency", "Banking", "Government",
            "Defense", "Energy", "Technology",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1059.003", "T1547.001", "T1053.005", "T1543.003",
            "T1055.001", "T1070.004", "T1562.001", "T1003.001",
            "T1003.002", "T1110.001", "T1110.003", "T1082",
            "T1083", "T1046", "T1049", "T1005", "T1119",
            "T1041", "T1048", "T1071.001", "T1573.001",
            "T1105", "T1486", "T1489.001", "T1498",
        ],
        "description": (
            "North Korean (RGB 121 Bureau) cyber group responsible for "
            "WannaCry ransomware, the 2016 Bangladesh Bank heist ($81M), "
            "and attacks on SWIFT. Known for FASTCash ATM malware, "
            "cryptocurrency theft, and destructive campaigns. "
            "One of the most financially-motivated APT groups."
        ),
        "first_seen": "2009",
        "last_seen": "2024",
        "motivation": "Financial / Espionage",
        "sophistication": "very_high",
    },
    "APT39": {
        "id": "APT39",
        "name": "Kimsuky",
        "aliases": [
            "Temp.Hermit", "Clover", "Elfin", "Reaper",
            "G0053", "NICKEL KIMBALL",
        ],
        "country": "North Korea",
        "country_code": "KP",
        "sectors": [
            "Government", "Think Tanks", "Academia", "Media",
            "Defense", "Technology",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1059.003", "T1547.001", "T1053.005", "T1055",
            "T1070.004", "T1003", "T1110.001", "T1110.003",
            "T1082", "T1083", "T1046", "T1005", "T1119",
            "T1041", "T1071.001", "T1573.001",
        ],
        "description": (
            "North Korean (RGB 225 Bureau) cyber espionage group "
            "specializing in intelligence collection supporting North "
            "Korean nuclear and geopolitical strategy. Targets think "
            "tanks, academic institutions, and South Korean government "
            "entities."
        ),
        "first_seen": "2013",
        "last_seen": "2024",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT40": {
        "id": "APT40",
        "name": "Ratna",
        "aliases": [
            "Double Tap", "Leviathan", "TEMP.Hippo",
            "PANDA DRAGON", "Stinking Cabbage",
        ],
        "country": "China",
        "country_code": "CN",
        "sectors": [
            "Government", "Military", "Technology", "Healthcare",
            "Maritime", "Engineering",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1059.003", "T1547.001", "T1053.005", "T1055",
            "T1070.004", "T1003", "T1110.001", "T1082",
            "T1083", "T1046", "T1005", "T1119", "T1041",
            "T1071.001", "T1573.001",
        ],
        "description": (
            "Chinese MSS Hainan State Security Department cyber espionage "
            "group targeting governments and militaries in Southeast Asia "
            "and the South China Sea region. Indicted by the US DOJ in 2020."
        ),
        "first_seen": "2010",
        "last_seen": "2024",
        "motivation": "Espionage",
        "sophistication": "moderate",
    },
    "APT41": {
        "id": "APT41",
        "name": "Double Dragon",
        "aliases": [
            "BARIUM", "Winnti 2.0", "Wicked Panda",
            "Brass Typhoon", "Dual Dragon",
        ],
        "country": "China",
        "country_code": "CN",
        "sectors": [
            "Technology", "Gaming", "Healthcare", "Government",
            "Telecommunications", "Software Supply Chain",
            "Financial",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1059.003", "T1547.001", "T1053.005", "T1543.003",
            "T1055", "T1070.004", "T1562.001", "T1003.001",
            "T1003.002", "T1110.001", "T1110.003", "T1082",
            "T1083", "T1046", "T1049", "T1005", "T1119",
            "T1041", "T1048", "T1071.001", "T1573.001",
            "T1105", "T1195.002",
        ],
        "description": (
            "Unique Chinese group that conducts both espionage AND "
            "financially-motivated operations. Known for supply-chain "
            "attacks (CCleaner, ASUS), game companies targeting, and "
            "ransomware. Operates globally with sophisticated "
            "malware including SIGNBT, DRIDEX variants, and InterProc."
        ),
        "first_seen": "2012",
        "last_seen": "2024",
        "motivation": "Espionage / Financial",
        "sophistication": "very_high",
    },
    "APT42": {
        "id": "APT42",
        "name": "Mint Sandstorm",
        "aliases": ["TA453", "Yellow Garuda", "Cuba", "FROZENLAKE"],
        "country": "Iran",
        "country_code": "IR",
        "sectors": [
            "Government", "Academia", "Media", "Think Tanks",
            "Activists", "NGOs", "Legal", "Diplomatic",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1566.003", "T1190",
            "T1078.003", "T1059.001", "T1547.001", "T1055",
            "T1070.004", "T1562.001", "T1003", "T1110.001",
            "T1082", "T1083", "T1046", "T1005", "T1041",
            "T1071.001", "T1589.002",
        ],
        "description": (
            "Iranian IRGC intelligence-gathering group focused on "
            "long-term surveillance and information operations. Known "
            "for persona-based social engineering, decoy documents, "
            "and multi-platform targeting including macOS and Windows."
        ),
        "first_seen": "2015",
        "last_seen": "2024",
        "motivation": "Espionage",
        "sophistication": "moderate",
    },
    "APT43": {
        "id": "APT43",
        "name": "Smart Mantis",
        "aliases": [
            "Siamesekitten", "Venomous Spider", "Sandstorm",
            "Kimsuky Variant",
        ],
        "country": "Iran",
        "country_code": "IR",
        "sectors": [
            "Government", "Financial", "Energy", "Telecommunications",
            "Defense", "Legal",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1059.003", "T1547.001", "T1053.005", "T1055",
            "T1070.004", "T1003", "T1110.001", "T1110.003",
            "T1082", "T1083", "T1046", "T1005", "T1119",
            "T1041", "T1071.001", "T1573.001",
        ],
        "description": (
            "Iranian MOIS cyber espionage group targeting government, "
            "financial, and energy sectors in the Middle East and "
            "beyond. Known for credential phishing and supply-chain "
            "attack methodologies."
        ),
        "first_seen": "2015",
        "last_seen": "2024",
        "motivation": "Espionage",
        "sophistication": "high",
    },
    "APT44": {
        "id": "APT44",
        "name": "Sandworm",
        "aliases": [
            "Seashell Blizzard", "Voodoo Bear", "ELECTRUM",
            "TEMP.Noble", "Iron Viking", "Group 415",
        ],
        "country": "Russia",
        "country_code": "RU",
        "sectors": [
            "Energy", "Government", "Defense", "Telecommunications",
            "Transportation", "Financial", "Critical Infrastructure",
        ],
        "techniques": [
            "T1566.001", "T1566.002", "T1190", "T1078", "T1059.001",
            "T1059.003", "T1547.001", "T1053.005", "T1543.003",
            "T1055.001", "T1070.004", "T1562.001", "T1003.001",
            "T1003.002", "T1110.001", "T1110.003", "T1082",
            "T1083", "T1046", "T1049", "T1005", "T1119",
            "T1041", "T1048.003", "T1071.001", "T1573.001",
            "T1105", "T1486", "T1489.001", "T1498",
            "T0831", "T0842",
        ],
        "description": (
            "Russian GRU Unit 74455 destructive operations group. "
            "Responsible for NotPetya (2017), Ukraine power grid attacks "
            "(2015, 2016), Olympic Destroyer (2018), and the French "
            "presidential election disruption. Known for Industroyer/"
            "CRASHOVERRIDE ICS malware targeting critical infrastructure. "
            "Also conducts intelligence operations via the TELEBOT and "
            "BADFLICK toolsets. Indicted by the US DOJ in 2018 and 2020."
        ),
        "first_seen": "2007",
        "last_seen": "2024",
        "motivation": "Espionage / Sabotage",
        "sophistication": "very_high",
    },
}

# ---------------------------------------------------------------------------
# Known Campaigns Database
# ---------------------------------------------------------------------------

KNOWN_CAMPAIGNS: List[Dict[str, Any]] = [
    {
        "id": "CAMP-001",
        "name": "Operation Aurora",
        "attributed_to": ["APT14"],
        "year": "2009",
        "description": "Targeted Google and other US companies",
        "sectors": ["Technology"],
        "techniques": ["T1566.001", "T1190"],
        "countries": ["US", "CN"],
    },
    {
        "id": "CAMP-002",
        "name": "Operation Shady RAT",
        "attributed_to": ["APT1"],
        "year": "2006",
        "description": "Long-term espionage against 70+ organizations",
        "sectors": ["Government", "Defense", "Technology"],
        "techniques": ["T1566.001", "T1059.001", "T1071.001"],
        "countries": ["US", "CN", "EU"],
    },
    {
        "id": "CAMP-003",
        "name": "Cloud Hopper",
        "attributed_to": ["APT10"],
        "year": "2017",
        "description": "Supply-chain via MSPs to target government and corporate targets",
        "sectors": ["Government", "Technology", "Managed Service Providers"],
        "techniques": ["T1190", "T1078", "T1071.004"],
        "countries": ["US", "EU", "JP"],
    },
    {
        "id": "CAMP-004",
        "name": "SolarWinds SUNBURST",
        "attributed_to": ["APT29"],
        "year": "2020",
        "description": "Supply-chain compromise via SolarWinds Orion platform",
        "sectors": ["Government", "Technology", "Defense", "Financial"],
        "techniques": ["T1195.002", "T1055", "T1071.004"],
        "countries": ["US", "EU"],
    },
    {
        "id": "CAMP-005",
        "name": "DNC Hack",
        "attributed_to": ["APT28"],
        "year": "2016",
        "description": "Targeted the Democratic National Committee to influence elections",
        "sectors": ["Political Organizations", "Government"],
        "techniques": ["T1566.001", "T1078.003", "T1110.001"],
        "countries": ["US"],
    },
    {
        "id": "CAMP-006",
        "name": "NotPetya",
        "attributed_to": ["APT28"],
        "year": "2017",
        "description": "Destructive malware disguised as ransomware, targeted Ukraine",
        "sectors": ["Energy", "Transportation", "Financial", "Government"],
        "techniques": ["T1486", "T1489.001", "T1048.003"],
        "countries": ["UA", "US", "EU"],
    },
    {
        "id": "CAMP-007",
        "name": "Bangladesh Bank Heist",
        "attributed_to": ["APT38"],
        "year": "2016",
        "description": "Attempted $1B theft from Bangladesh Bank via SWIFT",
        "sectors": ["Financial", "Banking"],
        "techniques": ["T1190", "T1110.001", "T1003"],
        "countries": ["BD"],
    },
    {
        "id": "CAMP-008",
        "name": "WannaCry",
        "attributed_to": ["APT38"],
        "year": "2017",
        "description": "Global ransomware campaign exploiting EternalBlue",
        "sectors": ["Healthcare", "Government", "Technology", "Transportation"],
        "techniques": ["T1203", "T1486", "T1048"],
        "countries": ["Global"],
    },
    {
        "id": "CAMP-009",
        "name": "Shamoon",
        "attributed_to": ["APT33"],
        "year": "2012",
        "description": "Destructive disk-wiping attacks targeting Saudi energy sector",
        "sectors": ["Energy", "Chemical"],
        "techniques": ["T1486", "T1489.001", "T1071.001"],
        "countries": ["SA"],
    },
    {
        "id": "CAMP-010",
        "name": "Olympic Destroyer",
        "attributed_to": ["APT28"],
        "year": "2018",
        "description": "Disruptive malware targeting PyeongChang Winter Olympics",
        "sectors": ["Government", "Technology", "Sports"],
        "techniques": ["T1486", "T1059.001", "T1070.004"],
        "countries": ["KR"],
    },
    {
        "id": "CAMP-011",
        "name": "Operation Night Dragon",
        "attributed_to": ["APT1"],
        "year": "2011",
        "description": "Targeted energy and oil companies",
        "sectors": ["Energy", "Oil & Gas"],
        "techniques": ["T1566.001", "T1110.001", "T1041"],
        "countries": ["US", "EU"],
    },
    {
        "id": "CAMP-012",
        "name": "Operation Titanium",
        "attributed_to": ["APT28"],
        "year": "2016",
        "description": "Targeted French presidential campaign",
        "sectors": ["Political Organizations", "Government"],
        "techniques": ["T1566.001", "T1078.003", "T1041"],
        "countries": ["FR"],
    },
    {
        "id": "CAMP-013",
        "name": "Operation AppleJeus",
        "attributed_to": ["APT38"],
        "year": "2018",
        "description": "Cryptocurrency exchange targeting",
        "sectors": ["Financial", "Cryptocurrency"],
        "techniques": ["T1566.001", "T1059.001", "T1041"],
        "countries": ["Global"],
    },
    {
        "id": "CAMP-014",
        "name": "Operation Red Signature",
        "attributed_to": ["APT41"],
        "year": "2019",
        "description": "Supply-chain compromise via game developers",
        "sectors": ["Technology", "Gaming"],
        "techniques": ["T1195.002", "T1055", "T1105"],
        "countries": ["US", "EU", "KR", "JP"],
    },
]

# ---------------------------------------------------------------------------
# Country / Infrastructure Signatures for Nation-State Profiling
# ---------------------------------------------------------------------------

COUNTRY_ASN_PATTERNS: Dict[str, List[str]] = {
    "CN": ["AS4134", "AS4837", "AS9808", "AS9929", "AS10099", "AS58453"],
    "RU": ["AS12389", "AS8359", "AS20485", "AS31500", "AS3216", "AS12714"],
    "IR": ["AS58224", "AS31549", "AS44244", "AS49581", "AS207177"],
    "KP": ["AS131279", "AS55329"],
    "VN": ["AS45896", "AS7610", "AS7568", "AS18403"],
    "PK": ["AS17557", "AS53844", "AS45595"],
}

# Patterns used in TLS certificates to identify nation-state proxies
COUNTRY_TLS_SIGNATURES: Dict[str, List[str]] = {
    "CN": [
        r"shanghai", r"beijing", r"shenzhen", r"hangzhou",
        r"china\b", r"huawei", r"alibaba\b", r"tencent",
        r"baidu", r"cloud\.cn",
    ],
    "RU": [
        r"moscow", r"saint.petersburg", r"\.ru\b", r"rostelecom",
        r"yandex", r"mail\.ru", r"vk\.com", r"kaspersky",
        r"russian\b", r"federal.*service",
    ],
    "IR": [
        r"tehran", r"isfahan", r"\.ir\b", r"iran\b",
        r"mci\.ir", r"irancell", r"shatel",
    ],
    "KP": [
        r"pyongyang", r"star.*joint", r"korea.*dp",
    ],
    "VN": [
        r"ho.chi.minh", r"hanoi", r"\.vn\b", r"viettel",
        r"vnpt", r"fpt\b",
    ],
    "PK": [
        r"islamabad", r"karachi", r"\.pk\b", r"ptcl",
        r"mobilink", r"jazz",
    ],
}

# Language tokens for content-based country detection
LANGUAGE_PROFILES: Dict[str, List[str]] = {
    "CN": [
        "zh-cn", "zh-tw", "chinese", "simplified chinese",
        "gb2312", "gbk", "gb18030", "big5",
        "content-language.*zh", "lang.*zh",
    ],
    "RU": [
        "ru-ru", "russian", "utf-8.*ru", "windows-1251",
        "content-language.*ru", "lang.*ru",
    ],
    "IR": [
        "fa-ir", "persian", "farsi", "arabic",
        "content-language.*fa", "lang.*fa",
    ],
    "KP": [
        "ko-kp", "korean", "joseon",
        "content-language.*ko", "lang.*ko",
    ],
    "VN": [
        "vi-vn", "vietnamese",
        "content-language.*vi", "lang.*vi",
    ],
    "PK": [
        "ur-pk", "urdu", "arabic",
        "content-language.*ur", "lang.*ur",
    ],
}


# ---------------------------------------------------------------------------
# Data Classes for Structured Output
# ---------------------------------------------------------------------------

class ConfidenceLevel(Enum):
    """Confidence level for attribution."""
    CRITICAL = "critical"      # 0.90+
    HIGH = "high"               # 0.70–0.89
    MODERATE = "moderate"       # 0.40–0.69
    LOW = "low"                 # 0.20–0.39
    MINIMAL = "minimal"         # <0.20
    NONE = "none"               # 0.00


@dataclass
class TTPMatch:
    """Represents a single TTP match between observed and known APT techniques."""
    technique_id: str
    technique_name: str
    matched_groups: List[str]
    confidence: float = 0.0
    tactics: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "matched_groups": self.matched_groups,
            "confidence": round(self.confidence, 4),
            "tactics": self.tactics,
        }


@dataclass
class APTAttribution:
    """Attribution result for a single APT group."""
    group_id: str
    group_name: str
    confidence: float
    confidence_level: ConfidenceLevel
    matching_techniques: List[str]
    matching_campaigns: List[str]
    country: str
    motivation: str
    sophistication: str
    reasoning: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group_id": self.group_id,
            "group_name": self.group_name,
            "confidence": round(self.confidence, 4),
            "confidence_level": self.confidence_level.value,
            "matching_techniques": self.matching_techniques,
            "matching_campaigns": self.matching_campaigns,
            "country": self.country,
            "motivation": self.motivation,
            "sophistication": self.sophistication,
            "reasoning": self.reasoning,
        }


@dataclass
class CampaignMatch:
    """Match result for a known campaign."""
    campaign_id: str
    campaign_name: str
    attributed_groups: List[str]
    confidence: float
    technique_overlap: List[str]
    sector_overlap: List[str]
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "campaign_name": self.campaign_name,
            "attributed_groups": self.attributed_groups,
            "confidence": round(self.confidence, 4),
            "technique_overlap": self.technique_overlap,
            "sector_overlap": self.sector_overlap,
            "description": self.description,
        }


@dataclass
class SovereigntyProfile:
    """Nation-state sovereignty profile based on infrastructure analysis."""
    primary_country: str
    country_code: str
    confidence: float
    indicators: Dict[str, Any] = field(default_factory=dict)
    supporting_countries: List[Dict[str, float]] = field(default_factory=list)
    reasoning: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_country": self.primary_country,
            "country_code": self.country_code,
            "confidence": round(self.confidence, 4),
            "indicators": self.indicators,
            "supporting_countries": self.supporting_countries,
            "reasoning": self.reasoning,
        }


@dataclass
class IOCProfile:
    """Profile of indicators of compromise to monitor."""
    target: str
    ioc_type: str
    patterns: List[str] = field(default_factory=list)
    watch_domains: List[str] = field(default_factory=list)
    watch_ips: List[str] = field(default_factory=list)
    watch_hashes: List[str] = field(default_factory=list)
    watch_asns: List[str] = field(default_factory=list)
    recommended_detections: List[str] = field(default_factory=list)
    generated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "ioc_type": self.ioc_type,
            "patterns": self.patterns,
            "watch_domains": self.watch_domains,
            "watch_ips": self.watch_ips,
            "watch_hashes": self.watch_hashes,
            "watch_asns": self.watch_asns,
            "recommended_detections": self.recommended_detections,
            "generated_at": self.generated_at,
        }


@dataclass
class AttributionReport:
    """Full attribution report for a target."""
    target: str
    base_url: str
    timestamp: str
    primary_attribution: Optional[Dict[str, Any]] = None
    secondary_attributions: List[Dict[str, Any]] = field(default_factory=list)
    campaign_matches: List[Dict[str, Any]] = field(default_factory=list)
    sovereignty_profile: Optional[Dict[str, Any]] = None
    ioc_profile: Optional[Dict[str, Any]] = None
    ttp_matches: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    summary: str = ""
    engine_version: str = __version__

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "base_url": self.base_url,
            "timestamp": self.timestamp,
            "primary_attribution": self.primary_attribution,
            "secondary_attributions": self.secondary_attributions,
            "campaign_matches": self.campaign_matches,
            "sovereignty_profile": self.sovereignty_profile,
            "ioc_profile": self.ioc_profile,
            "ttp_matches": self.ttp_matches,
            "risk_score": round(self.risk_score, 4),
            "summary": self.summary,
            "engine_version": self.engine_version,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


# ---------------------------------------------------------------------------
# TTPMatcher — matches observed TTPs against APT group databases
# ---------------------------------------------------------------------------

class TTPMatcher:
    """Matches observed tactics, techniques, and procedures against the
    APT group database to identify potential threat actors.

    The matcher uses a weighted scoring algorithm that considers:
      - Jaccard similarity of technique sets
      - Rarity weighting (less common techniques score higher)
      - Campaign overlap bonuses
      - Temporal activity signals
    """

    def __init__(self, group_db: Optional[Dict[str, Any]] = None) -> None:
        self._groups = group_db if group_db is not None else APT_GROUPS
        self._technique_frequency: Dict[str, int] = {}
        self._compute_technique_frequency()

    def _compute_technique_frequency(self) -> None:
        """Pre-compute how many groups use each technique for rarity weighting."""
        for group_data in self._groups.values():
            for tech in group_data.get("techniques", []):
                self._technique_frequency[tech] = (
                    self._technique_frequency.get(tech, 0) + 1
                )

    def _technique_rarity(self, technique: str, total_groups: int) -> float:
        """Compute rarity score for a technique. Rarer = more discriminating.

        Uses inverse frequency weighting: techniques used by fewer groups
        contribute more to attribution confidence.
        """
        freq = self._technique_frequency.get(technique, 0)
        if freq == 0:
            return 1.0
        # Inverse frequency: 1 for unique, approaching 0 for universal
        return math.log2(total_groups / (freq + 1)) / math.log2(total_groups)

    def match_observed_ttps(
        self, observed_techniques: List[str],
    ) -> List[APTAttribution]:
        """Match observed TTPs against all APT groups and return a ranked list.

        Args:
            observed_techniques: List of MITRE ATT&CK technique IDs observed
                                 in findings (e.g., ["T1566.001", "T1059.001"]).

        Returns:
            Ranked list of :class:`APTAttribution` sorted by confidence
            (highest first).
        """
        total_groups = len(self._groups)
        results: List[APTAttribution] = []

        if not observed_techniques:
            return results

        observed_set = set(observed_techniques)

        for group_id, group_data in self._groups.items():
            group_techs = set(group_data.get("techniques", []))
            overlap = observed_set & group_techs

            if not overlap:
                continue

            # --- Jaccard similarity ---
            jaccard = len(overlap) / len(observed_set | group_techs)

            # --- Coverage: what fraction of observed techniques are explained ---
            coverage = len(overlap) / len(observed_set)

            # --- Weighted rarity score ---
            rarity_sum = sum(
                self._technique_rarity(t, total_groups) for t in overlap
            )
            rarity_avg = rarity_sum / len(overlap)

            # --- Composite confidence ---
            confidence = 0.35 * jaccard + 0.40 * coverage + 0.25 * rarity_avg
            confidence = min(confidence, 1.0)

            reasoning: List[str] = []
            reasoning.append(
                f"Jaccard similarity: {jaccard:.4f} "
                f"({len(overlap)} shared techniques)"
            )
            reasoning.append(f"Coverage: {coverage:.2%} of observed TTPs")
            reasoning.append(f"Technique rarity factor: {rarity_avg:.4f}")

            # Campaign overlap bonus
            matching_campaigns = self._find_matching_campaigns(
                group_id, overlap
            )
            if matching_campaigns:
                bonus = min(len(matching_campaigns) * 0.05, 0.15)
                confidence = min(confidence + bonus, 1.0)
                reasoning.append(
                    f"Campaign overlap bonus (+{bonus:.2f}): "
                    f"{', '.join(matching_campaigns)}"
                )

            results.append(
                APTAttribution(
                    group_id=group_id,
                    group_name=group_data.get("name", group_id),
                    confidence=confidence,
                    confidence_level=self._confidence_level(confidence),
                    matching_techniques=sorted(overlap),
                    matching_campaigns=matching_campaigns,
                    country=group_data.get("country", "Unknown"),
                    motivation=group_data.get("motivation", "Unknown"),
                    sophistication=group_data.get("sophistication", "Unknown"),
                    reasoning=reasoning,
                )
            )

        results.sort(key=lambda a: a.confidence, reverse=True)
        return results

    def calculate_confidence(
        self,
        group_profile: Dict[str, Any],
        observed_findings: List[Dict[str, Any]],
    ) -> float:
        """Calculate a confidence score (0.0–1.0) that the observed findings
        align with the given APT group profile.

        Args:
            group_profile: APT group dict from the database.
            observed_findings: List of finding dicts with at least ``"type"``
                               and ``"evidence"`` keys.

        Returns:
            Float confidence between 0 and 1.
        """
        if not observed_findings or not group_profile:
            return 0.0

        # Extract technique IDs from findings if present
        observed_techs: Set[str] = set()
        observed_sectors: Set[str] = set()
        for finding in observed_findings:
            tech = finding.get("technique_id") or finding.get("ttp") or ""
            if tech:
                observed_techs.add(tech)
            if "sector" in finding:
                observed_sectors.add(finding["sector"])

        group_techs = set(group_profile.get("techniques", []))
        group_sectors = set(
            s.lower() for s in group_profile.get("sectors", [])
        )

        tech_overlap = len(observed_techs & group_techs)
        total_relevant = len(observed_techs | group_techs)

        if total_relevant == 0:
            return 0.0

        jaccard = tech_overlap / total_relevant

        # Sector alignment bonus
        sector_bonus = 0.0
        if observed_sectors:
            matching_sectors = len(
                observed_sectors & group_sectors
            )
            sector_bonus = 0.1 * (
                matching_sectors / max(len(observed_sectors), 1)
            )

        # Sophistication factor
        soph = group_profile.get("sophistication", "moderate")
        soph_weight = {"minimal": 0.6, "moderate": 0.75,
                       "high": 0.9, "very_high": 1.0}
        soph_factor = soph_weight.get(soph, 0.75)

        confidence = (0.8 * jaccard + sector_bonus) * soph_factor
        return round(min(max(confidence, 0.0), 1.0), 4)

    def generate_ioc_profile(self, target: str) -> IOCProfile:
        """Generate an IOC watch profile for a target based on top
        matching APT groups.

        Args:
            target: The target hostname or IP being analyzed.

        Returns:
            An :class:`IOCProfile` with recommended IOCs to monitor.
        """
        now = datetime.now(timezone.utc).isoformat()
        return IOCProfile(
            target=target,
            ioc_type="proactive_watch",
            patterns=self._generate_patterns(target),
            watch_domains=self._generate_watch_domains(target),
            watch_ips=[],
            watch_hashes=[],
            watch_asns=[],
            recommended_detections=self._generate_detection_rules(),
            generated_at=now,
        )

    def _generate_patterns(self, target: str) -> List[str]:
        """Generate regex patterns for phishing and malware IOC detection."""
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        patterns: List[str] = []
        patterns.append(
            rf"(?i)login.*{re.escape(domain)}"  # Phishing login page
        )
        patterns.append(
            rf"(?i)account.*verify.*{re.escape(domain)}"
        )
        patterns.append(
            rf"(?i)update.*{re.escape(domain)}.*\.exe"
        )
        patterns.append(
            rf"(?i){re.escape(domain)}.*\.php\?.*=.{8,}"
        )
        patterns.append(
            rf"(?i)base64.*[A-Za-z0-9+/]{{200,}}"  # Encoded payload
        )
        return patterns

    def _generate_watch_domains(self, target: str) -> List[str]:
        """Generate domain watchlist entries."""
        base = target.replace("https://", "").replace("http://", "").split("/")[0]
        parts = base.split(".")
        domains: List[str] = []
        if len(parts) >= 2:
            # Typosquatting variants
            domains.append(
                parts[0] + "-" + ".".join(parts[1:])
            )
            domains.append(
                parts[0] + parts[0] + "." + ".".join(parts[1:])
            )
            for swap in ("rn", "m", "vv", "l1", "0o"):
                domains.append(
                    parts[0].replace("n", swap[0]).replace("m", swap)
                    + "." + ".".join(parts[1:])
                )
        return list(set(domains))

    def _generate_detection_rules(self) -> List[str]:
        """Generate recommended detection rule descriptions."""
        return [
            "Monitor for spear-phishing emails referencing target organization",
            "Alert on DNS queries to suspicious newly-registered domains",
            "Detect anomalous authentication attempts from unusual ASN blocks",
            "Watch for TLS certificate changes on target infrastructure",
            "Monitor for data exfiltration patterns (DNS tunneling, HTTPS beacons)",
            "Alert on PowerShell or WMI lateral movement from target subnet",
            "Monitor for credential dump tool execution (Mimikatz, LSASS access)",
            "Detect unusual process injection into legitimate system binaries",
        ]

    def _find_matching_campaigns(
        self, group_id: str, overlap: Set[str],
    ) -> List[str]:
        """Find known campaigns that match both the group and technique set."""
        matched: List[str] = []
        for campaign in KNOWN_CAMPAIGNS:
            if group_id in campaign.get("attributed_to", []):
                camp_techs = set(campaign.get("techniques", []))
                if overlap & camp_techs:
                    matched.append(campaign["name"])
        return matched

    @staticmethod
    def _confidence_level(confidence: float) -> ConfidenceLevel:
        """Map a numeric confidence value to a :class:`ConfidenceLevel`."""
        if confidence >= 0.90:
            return ConfidenceLevel.CRITICAL
        elif confidence >= 0.70:
            return ConfidenceLevel.HIGH
        elif confidence >= 0.40:
            return ConfidenceLevel.MODERATE
        elif confidence >= 0.20:
            return ConfidenceLevel.LOW
        elif confidence > 0.0:
            return ConfidenceLevel.MINIMAL
        return ConfidenceLevel.NONE


# ---------------------------------------------------------------------------
# CampaignTracker — cross-reference findings with known campaigns
# ---------------------------------------------------------------------------

class CampaignTracker:
    """Tracks and identifies campaign signatures by cross-referencing
    observed findings against the known campaigns database.

    Campaign identification uses multi-factor analysis:
      - Technique overlap (MITRE ATT&CK)
      - Sector alignment
      - Temporal correlation
      - Known infrastructure reuse
    """

    def __init__(
        self,
        campaigns: Optional[List[Dict[str, Any]]] = None,
        groups: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._campaigns = campaigns if campaigns is not None else KNOWN_CAMPAIGNS
        self._groups = groups if groups is not None else APT_GROUPS

    def identify_campaign(
        self,
        target: str,
        findings: List[Dict[str, Any]],
    ) -> List[CampaignMatch]:
        """Identify which known campaigns the target's findings align with.

        Args:
            target: The target being analyzed.
            findings: List of finding dicts. Each should ideally contain
                      ``"technique_id"``, ``"sector"``, and ``"evidence"``.

        Returns:
            Ranked list of :class:`CampaignMatch` objects.
        """
        observed_techs: Set[str] = set()
        observed_sectors: Set[str] = set()
        current_year = datetime.now().year

        for finding in findings:
            tech = finding.get("technique_id") or finding.get("ttp") or ""
            if tech:
                observed_techs.add(tech)
            sector = finding.get("sector") or finding.get("industry") or ""
            if sector:
                observed_sectors.add(sector.lower())

        if not observed_techs:
            return []

        results: List[CampaignMatch] = []

        for campaign in self._campaigns:
            camp_techs = set(campaign.get("techniques", []))
            tech_overlap = list(observed_techs & camp_techs)

            if not tech_overlap:
                continue

            # Technique overlap score
            tech_score = len(tech_overlap) / len(observed_techs | camp_techs)

            # Sector overlap
            camp_sectors = set(
                s.lower() for s in campaign.get("sectors", [])
            )
            sector_overlap = list(observed_sectors & camp_sectors)

            # Temporal factor: campaigns active in the last 5 years score higher
            year = int(campaign.get("year", 2010))
            age = current_year - year
            temporal = max(0.0, 1.0 - (age / 20.0))

            # Group attribution overlap
            attributed = campaign.get("attributed_to", [])

            # Composite score
            sector_bonus = 0.1 if sector_overlap else 0.0
            confidence = (0.5 * tech_score + 0.3 * temporal + sector_bonus)
            confidence = min(confidence, 1.0)

            results.append(
                CampaignMatch(
                    campaign_id=campaign.get("id", ""),
                    campaign_name=campaign.get("name", ""),
                    attributed_groups=attributed,
                    confidence=confidence,
                    technique_overlap=tech_overlap,
                    sector_overlap=sector_overlap,
                    description=campaign.get("description", ""),
                )
            )

        results.sort(key=lambda m: m.confidence, reverse=True)
        return results

    def track_campaign_signature(
        self, findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate a unique campaign signature hash from findings.

        This fingerprint can be used to cluster similar attack campaigns
        and detect repetitions across different targets.

        Args:
            findings: List of finding dicts.

        Returns:
            Dict with ``signature_hash``, ``technique_fingerprint``,
            ``sector_fingerprint``, and ``composite_hash``.
        """
        techs: List[str] = sorted(
            {f.get("technique_id", "") or f.get("ttp", "")
             for f in findings if f.get("technique_id") or f.get("ttp")}
        )
        sectors: List[str] = sorted(
            {f.get("sector", "") for f in findings if f.get("sector")}
        )

        tech_str = "|".join(techs)
        sector_str = "|".join(sectors)

        tech_hash = hashlib.sha256(tech_str.encode()).hexdigest()[:16]
        sector_hash = hashlib.sha256(sector_str.encode()).hexdigest()[:16]
        composite = hashlib.sha256(
            (tech_str + "||" + sector_str).encode()
        ).hexdigest()[:20]

        return {
            "signature_hash": composite,
            "technique_fingerprint": tech_hash,
            "sector_fingerprint": sector_hash,
            "technique_count": len(techs),
            "sector_count": len(sectors),
            "techniques": techs,
            "sectors": sectors,
        }

    def cross_reference_active_campaigns(
        self, target: str, findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Cross-reference findings against all active campaigns and
        return a combined analysis.

        Returns:
            Dict with ``campaign_matches``, ``signature``, and ``summary``.
        """
        matches = self.identify_campaign(target, findings)
        signature = self.track_campaign_signature(findings)

        active_campaigns = [m for m in matches if m.confidence >= 0.3]

        return {
            "campaign_matches": [m.to_dict() for m in matches],
            "active_campaigns": [m.to_dict() for m in active_campaigns],
            "signature": signature,
            "summary": (
                f"{len(matches)} campaign(s) identified, "
                f"{len(active_campaigns)} with moderate or higher confidence. "
                f"Signature: {signature['signature_hash']}"
            ),
        }


# ---------------------------------------------------------------------------
# NationStateProfiler — attribute infrastructure to nation-states
# ---------------------------------------------------------------------------

class NationStateProfiler:
    """Profiles and attributes infrastructure to nation-state actors based
    on multiple signals: ASN ownership, timezone patterns, page language,
    TLS certificate metadata, and WAF signatures.

    Each signal is independently scored and then fused using a weighted
    voting scheme to produce a sovereignty profile.
    """

    # Weight assignments for each signal source
    WEIGHT_ASN = 0.25
    WEIGHT_TIMEZONE = 0.10
    WEIGHT_LANGUAGE = 0.20
    WEIGHT_TLS = 0.25
    WEIGHT_WAF = 0.20

    def __init__(self) -> None:
        self._country_asns = COUNTRY_ASN_PATTERNS
        self._tls_signatures = COUNTRY_TLS_SIGNATURES
        self._language_profiles = LANGUAGE_PROFILES

    def profile_sovereignty(
        self,
        target: str,
        geo_data: Optional[Dict[str, Any]] = None,
        tls_data: Optional[Dict[str, Any]] = None,
        page_content: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        waf_data: Optional[Dict[str, Any]] = None,
    ) -> SovereigntyProfile:
        """Generate a nation-state sovereignty profile for the target.

        Args:
            target: Hostname or IP being analyzed.
            geo_data: Optional geo-intel dict (``"asn"``, ``"country"``,
                      ``"timezone"``).
            tls_data: Optional TLS cert dict (``"issuer"``, ``"subject"``,
                       ``"organization"``, ``"serial"``).
            page_content: Optional page body for language detection.
            headers: Optional HTTP response headers dict.
            waf_data: Optional WAF info dict (``"waf_name"``, ``"waf_vendor"``).

        Returns:
            A :class:`SovereigntyProfile` with confidence scores.
        """
        geo_data = geo_data or {}
        tls_data = tls_data or {}
        waf_data = waf_data or {}

        scores: Dict[str, float] = {}

        # --- ASN signal ---
        asn_signal = self._analyze_asn(geo_data.get("asn", ""))
        for cc, score in asn_signal.items():
            scores[cc] = scores.get(cc, 0.0) + score * self.WEIGHT_ASN

        # --- Timezone signal ---
        tz_signal = self._analyze_timezone(geo_data.get("timezone", ""))
        for cc, score in tz_signal.items():
            scores[cc] = scores.get(cc, 0.0) + score * self.WEIGHT_TIMEZONE

        # --- Language / content signal ---
        content_blob = page_content or ""
        if headers:
            header_str = json.dumps(headers, separators=("", " "))
            content_blob = header_str + " " + content_blob
        lang_signal = self._analyze_language(content_blob)
        for cc, score in lang_signal.items():
            scores[cc] = scores.get(cc, 0.0) + score * self.WEIGHT_LANGUAGE

        # --- TLS certificate signal ---
        cert_text = (
            tls_data.get("issuer", "")
            + " " + tls_data.get("subject", "")
            + " " + tls_data.get("organization", "")
            + " " + tls_data.get("serial", "")
        )
        tls_signal = self._analyze_tls(cert_text)
        for cc, score in tls_signal.items():
            scores[cc] = scores.get(cc, 0.0) + score * self.WEIGHT_TLS

        # --- WAF signal ---
        waf_text = (
            waf_data.get("waf_name", "") + " " + waf_data.get("waf_vendor", "")
        )
        waf_signal = self._analyze_waf(waf_text)
        for cc, score in waf_signal.items():
            scores[cc] = scores.get(cc, 0.0) + score * self.WEIGHT_WAF

        # --- Fused result ---
        reasoning: List[str] = []
        if asn_signal:
            reasoning.append(
                f"ASN analysis: {dict(asn_signal)}"
            )
        if tz_signal:
            reasoning.append(
                f"Timezone analysis: {dict(tz_signal)}"
            )
        if lang_signal:
            reasoning.append(
                f"Language analysis: {dict(lang_signal)}"
            )
        if tls_signal:
            reasoning.append(
                f"TLS certificate analysis: {dict(tls_signal)}"
            )
        if waf_signal:
            reasoning.append(
                f"WAF signature analysis: {dict(waf_signal)}"
            )

        if not scores:
            return SovereigntyProfile(
                primary_country="Unknown",
                country_code="??",
                confidence=0.0,
                indicators={},
                supporting_countries=[],
                reasoning=["No signals detected for nation-state attribution"],
            )

        # Sort by score
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        primary_country_code, primary_conf = sorted_scores[0]

        # Map country code to name
        country_name = self._code_to_name(primary_country_code)

        # Normalize confidence to [0, 1]
        max_possible = sum([self.WEIGHT_ASN, self.WEIGHT_TIMEZONE,
                            self.WEIGHT_LANGUAGE, self.WEIGHT_TLS,
                            self.WEIGHT_WAF])
        normalized_conf = min(primary_conf / max_possible, 1.0)

        supporting: List[Dict[str, float]] = []
        for cc, sc in sorted_scores[1:6]:
            supporting.append(
                {
                    "country": self._code_to_name(cc),
                    "country_code": cc,
                    "score": round(sc, 4),
                }
            )

        return SovereigntyProfile(
            primary_country=country_name,
            country_code=primary_country_code,
            confidence=normalized_conf,
            indicators={
                "asn_signal": dict(asn_signal),
                "timezone_signal": dict(tz_signal),
                "language_signal": dict(lang_signal),
                "tls_signal": dict(tls_signal),
                "waf_signal": dict(waf_signal),
            },
            supporting_countries=supporting,
            reasoning=reasoning,
        )

    def _analyze_asn(self, asn: str) -> Dict[str, float]:
        """Score country confidence based on ASN ownership."""
        if not asn:
            return {}
        results: Dict[str, float] = {}
        for country_code, asns in self._country_asns.items():
            if asn.upper().startswith("AS") and asn[2:] in [a[2:] for a in asns]:
                results[country_code] = 1.0
            elif asn.upper() in [a.upper() for a in asns]:
                results[country_code] = 1.0
        return results

    def _analyze_timezone(self, tz: str) -> Dict[str, float]:
        """Score country confidence based on timezone hints."""
        if not tz:
            return {}

        tz_country_map: Dict[str, Dict[str, float]] = {
            "asia/shanghai": {"CN": 0.9, "KP": 0.3},
            "asia/chongqing": {"CN": 0.8},
            "asia/hong_kong": {"CN": 0.7},
            "asia/taipei": {"CN": 0.6},
            "europe/moscow": {"RU": 0.9},
            "europe/kaliningrad": {"RU": 0.8},
            "asia/tehran": {"IR": 0.9},
            "asia/pyongyang": {"KP": 0.9, "CN": 0.2},
            "asia/hanoi": {"VN": 0.9},
            "asia/ho_chi_minh": {"VN": 0.9},
            "asia/karachi": {"PK": 0.9},
            "asia/islamabad": {"PK": 0.9},
            "asia/kolkata": {"PK": 0.4, "IN": 0.6},
            "asia/tokyo": {"JP": 0.9},
            "asia/seoul": {"KR": 0.9},
        }

        tz_lower = tz.lower().strip()
        for pattern, country_scores in tz_country_map.items():
            if pattern in tz_lower:
                return dict(country_scores)
        return {}

    def _analyze_language(self, content: str) -> Dict[str, float]:
        """Score country confidence based on language markers in content."""
        if not content:
            return {}

        content_lower = content.lower()
        results: Dict[str, float] = {}

        for country_code, patterns in self._language_profiles.items():
            match_count = 0
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    match_count += 1
            if match_count > 0:
                results[country_code] = min(match_count / max(len(patterns), 1), 1.0)

        return results

    def _analyze_tls(self, cert_text: str) -> Dict[str, float]:
        """Score country confidence based on TLS certificate patterns."""
        if not cert_text:
            return {}

        cert_lower = cert_text.lower()
        results: Dict[str, float] = {}

        for country_code, patterns in self._tls_signatures.items():
            match_count = 0
            for pattern in patterns:
                if re.search(pattern, cert_lower, re.IGNORECASE):
                    match_count += 1
            if match_count > 0:
                results[country_code] = min(match_count / max(len(patterns), 1), 1.0)

        return results

    def _analyze_waf(self, waf_text: str) -> Dict[str, float]:
        """Score country confidence based on WAF signatures."""
        if not waf_text:
            return {}

        waf_lower = waf_text.lower()
        waf_country_map: Dict[str, Dict[str, float]] = {
            "cloud.tencent": {"CN": 0.8},
            "cloudflare": {"US": 0.3},
            "akamai": {"US": 0.3},
            "aliyun": {"CN": 0.8},
            "huaweicloud": {"CN": 0.9},
            "yundun": {"CN": 0.8},
            "incapsula": {"US": 0.3},
            "sucuri": {"US": 0.3},
            "mod_security": {"US": 0.2},
            "shield": {"CN": 0.5, "RU": 0.5},
            "jiasule": {"CN": 0.8},
            "beijing": {"CN": 0.7},
            "yunjiasu": {"CN": 0.8},
        }

        results: Dict[str, float] = {}
        for waf_name, country_scores in waf_country_map.items():
            if waf_name in waf_lower:
                for cc, score in country_scores.items():
                    results[cc] = max(results.get(cc, 0.0), score)
        return results

    @staticmethod
    def _code_to_name(code: str) -> str:
        """Convert a 2-letter country code to a country name."""
        mapping: Dict[str, str] = {
            "CN": "China",
            "RU": "Russia",
            "IR": "Iran",
            "KP": "North Korea",
            "VN": "Vietnam",
            "PK": "Pakistan",
            "US": "United States",
            "KR": "South Korea",
            "JP": "Japan",
            "IN": "India",
            "UA": "Ukraine",
            "SA": "Saudi Arabia",
            "FR": "France",
            "BD": "Bangladesh",
            "EU": "European Union",
        }
        return mapping.get(code.upper(), code)


# ---------------------------------------------------------------------------
# AttributionEngine — main public API
# ---------------------------------------------------------------------------

class AttributionEngine:
    """Top-level threat actor attribution engine for ReconPro v9.2.0.

    Provides a unified API for:
      - Analyzing targets against the APT group database
      - Matching observed TTPs to known threat actors
      - Generating full attribution reports
      - Identifying campaign patterns
      - Profiling nation-state sovereignty

    Usage::

        from reconpro.attribution import AttributionEngine

        engine = AttributionEngine()
        report = engine.analyze("example.com", "https://example.com",
                                findings=[...])
        print(report.to_json())
    """

    def __init__(self) -> None:
        self._groups = APT_GROUPS
        self._ttp_matcher = TTPMatcher(group_db=self._groups)
        self._campaign_tracker = CampaignTracker(
            campaigns=KNOWN_CAMPAIGNS, groups=self._groups
        )
        self._nation_profiler = NationStateProfiler()
        self._analysis_count = 0

    @property
    def groups(self) -> Dict[str, Dict[str, Any]]:
        """Read-only access to the APT groups database."""
        return dict(self._groups)

    @property
    def analysis_count(self) -> int:
        """Number of analyses performed."""
        return self._analysis_count

    def analyze(
        self,
        target: str,
        base_url: str,
        findings: Optional[List[Dict[str, Any]]] = None,
        timeout: int = 8,
    ) -> Dict[str, Any]:
        """Run a full attribution analysis on the given target.

        This is the primary entry point. It orchestrates TTP matching,
        campaign identification, sovereignty profiling, and IOC
        generation into a single comprehensive report.

        Args:
            target: Hostname or IP of the target (e.g., ``"example.com"``).
            base_url: The base URL scanned (e.g., ``"https://example.com"``).
            findings: Optional list of finding dicts from prior scans.
                      Each dict may contain ``"technique_id"``, ``"ttp"``,
                      ``"sector"``, ``"evidence"``, ``"severity"``.
            timeout: Network timeout in seconds for any live data fetches
                     (default 8). Set to ``0`` to skip live probes entirely.

        Returns:
            Attribution report dict with keys: ``target``, ``base_url``,
            ``timestamp``, ``primary_attribution``, ``secondary_attributions``,
            ``campaign_matches``, ``sovereignty_profile``, ``ioc_profile``,
            ``ttp_matches``, ``risk_score``, ``summary``, ``engine_version``.
        """
        self._analysis_count += 1
        findings = findings or []
        now = datetime.now(timezone.utc)

        # --- 1. Extract observed techniques from findings ---
        observed_techniques = self._extract_techniques(findings)

        # --- 2. TTP matching ---
        ttp_results = self._ttp_matcher.match_observed_ttps(observed_techniques)
        ttp_dicts = [r.to_dict() for r in ttp_results]

        # --- 3. Campaign identification ---
        campaign_results = self._campaign_tracker.identify_campaign(
            target, findings
        )
        campaign_dicts = [r.to_dict() for r in campaign_results]

        # --- 4. Sovereignty profiling (passive — no live fetches in default mode) ---
        geo_data: Dict[str, Any] = {}
        tls_data: Dict[str, Any] = {}
        page_content = ""
        headers: Dict[str, str] = {}
        waf_data: Dict[str, Any] = {}

        # Attempt to gather passive signals from findings
        for f in findings:
            if "geo" in f and isinstance(f["geo"], dict):
                geo_data.update(f["geo"])
            if "tls" in f and isinstance(f["tls"], dict):
                tls_data.update(f["tls"])
            if "page_content" in f:
                page_content += f["page_content"] + " "
            if "headers" in f and isinstance(f["headers"], dict):
                headers.update(f["headers"])
            if "waf" in f and isinstance(f["waf"], dict):
                waf_data.update(f["waf"])

        if timeout > 0:
            # Try to fetch passive data from the target
            live_data = self._passive_recon(base_url, timeout)
            geo_data.update(live_data.get("geo", {}))
            tls_data.update(live_data.get("tls", {}))
            headers.update(live_data.get("headers", {}))
            if live_data.get("body"):
                page_content += live_data["body"]
            waf_data.update(live_data.get("waf", {}))

        sovereignty = self._nation_profiler.profile_sovereignty(
            target, geo_data, tls_data, page_content, headers, waf_data
        )

        # --- 5. IOC profile generation ---
        ioc_profile = self._ttp_matcher.generate_ioc_profile(target)

        # --- 6. Risk score ---
        risk_score = self._calculate_risk_score(
            ttp_results, campaign_results, sovereignty
        )

        # --- 7. Assemble report ---
        primary_attr = None
        secondary_attrs: List[Dict[str, Any]] = []

        if ttp_results:
            primary_attr = ttp_results[0].to_dict()
            for attr in ttp_results[1:6]:
                if attr.confidence >= 0.20:
                    secondary_attrs.append(attr.to_dict())

        # Enrich attributions with sovereignty correlation
        if primary_attr and sovereignty.confidence >= 0.3:
            primary_attr["sovereignty_correlation"] = (
                "consistent"
                if primary_attr.get("country", "") == sovereignty.primary_country
                else "divergent"
            )

        summary = self._build_summary(
            target, ttp_results, campaign_results, sovereignty, risk_score
        )

        report = AttributionReport(
            target=target,
            base_url=base_url,
            timestamp=now.isoformat(),
            primary_attribution=primary_attr,
            secondary_attributions=secondary_attrs,
            campaign_matches=campaign_dicts,
            sovereignty_profile=sovereignty.to_dict(),
            ioc_profile=ioc_profile.to_dict(),
            ttp_matches=ttp_dicts,
            risk_score=risk_score,
            summary=summary,
        )

        return report.to_dict()

    def match_ttps(self, technique_ids: List[str]) -> List[Dict[str, Any]]:
        """Match a list of MITRE ATT&CK technique IDs against APT groups.

        Args:
            technique_ids: List of technique IDs (e.g., ``["T1566.001", "T1059.001"]``).

        Returns:
            Ranked list of attribution dicts with confidence scores.
        """
        results = self._ttp_matcher.match_observed_ttps(technique_ids)
        return [r.to_dict() for r in results]

    def get_apt_profile(self, group_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve the full profile for a specific APT group.

        Args:
            group_id: The APT group identifier (e.g., ``"APT28"``).

        Returns:
            The APT group profile dict, or ``None`` if not found.
        """
        group = self._groups.get(group_id.upper()) or self._groups.get(group_id)
        if not group:
            # Fuzzy search by name or alias
            gid_lower = group_id.lower()
            for gid, data in self._groups.items():
                if (gid.lower() == gid_lower
                        or data.get("name", "").lower() == gid_lower
                        or gid_lower in [a.lower()
                                         for a in data.get("aliases", [])]):
                    return dict(data)
            return None
        return dict(group)

    def generate_threat_report(
        self, target: str, findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate a comprehensive threat intelligence report.

        This is a convenience method that wraps :meth:`analyze` and
        enriches the output with additional narrative and
        context-aware threat intelligence.

        Args:
            target: The target being reported on.
            findings: List of finding dicts.

        Returns:
            Full threat report dict.
        """
        base_url = f"https://{target}" if not target.startswith("http") else target
        attribution_report = self.analyze(target, base_url, findings)

        # Enrich the report with additional threat intel sections
        observed_techniques = self._extract_techniques(findings)
        technique_details = self._enrich_technique_details(observed_techniques)

        # Identify related groups through shared techniques
        related_groups = self._find_related_groups(observed_techniques)

        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            target, attribution_report, findings
        )

        # Recommendations
        recommendations = self._generate_recommendations(
            attribution_report, findings
        )

        threat_report = {
            "report_type": "threat_attribution_report",
            "engine_version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "executive_summary": executive_summary,
            "attribution": attribution_report,
            "technique_analysis": technique_details,
            "related_groups": related_groups,
            "recommendations": recommendations,
            "mitre_attack_version": "v14.1",
        }

        return threat_report

    # ----- Internal helpers -----

    def _extract_techniques(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Extract unique technique IDs from findings."""
        techniques: Set[str] = set()
        for finding in findings:
            for key in ("technique_id", "ttp", "technique", "mitre_id"):
                val = finding.get(key)
                if val and isinstance(val, str):
                    techniques.add(val)
        return sorted(techniques)

    def _calculate_risk_score(
        self,
        ttp_results: List[APTAttribution],
        campaign_results: List[CampaignMatch],
        sovereignty: SovereigntyProfile,
    ) -> float:
        """Calculate an overall risk score (0–100) for the target."""
        risk = 0.0

        # TTP risk component (0–40)
        if ttp_results:
            top_conf = ttp_results[0].confidence
            risk += top_conf * 40
            if len(ttp_results) > 1:
                risk += min(len(ttp_results) - 1, 5) * 2  # up to 10

        # Campaign risk component (0–25)
        if campaign_results:
            top_campaign = campaign_results[0].confidence
            risk += top_campaign * 25

        # Sovereignty risk component (0–25)
        risk += sovereignty.confidence * 25

        # Sophistication bonus (0–10)
        if ttp_results:
            soph = ttp_results[0].sophistication
            soph_bonus = {
                "minimal": 1, "moderate": 3,
                "high": 6, "very_high": 10,
            }
            risk += soph_bonus.get(soph, 3)

        return round(min(risk, 100.0), 2)

    def _build_summary(
        self,
        target: str,
        ttp_results: List[APTAttribution],
        campaign_results: List[CampaignMatch],
        sovereignty: SovereigntyProfile,
        risk_score: float,
    ) -> str:
        """Build a human-readable summary string."""
        parts: List[str] = [f"Attribution analysis for {target}."]

        if ttp_results:
            top = ttp_results[0]
            parts.append(
                f"Primary attribution: {top.group_name} ({top.group_id}) "
                f"with {top.confidence_level.value} confidence "
                f"({top.confidence:.1%}). "
                f"Origin: {top.country}. "
                f"Motivation: {top.motivation}."
            )
            if len(ttp_results) > 1:
                parts.append(
                    f"Secondary candidates: "
                    + ", ".join(
                        f"{r.group_name} ({r.confidence:.0%})"
                        for r in ttp_results[1:4]
                    )
                )
        else:
            parts.append("No APT groups matched the observed TTPs.")

        if campaign_results:
            top_camp = campaign_results[0]
            parts.append(
                f"Top campaign match: {top_camp.campaign_name} "
                f"(confidence {top_camp.confidence:.0%})."
            )

        if sovereignty.confidence > 0.2:
            parts.append(
                f"Infrastructure sovereignty: {sovereignty.primary_country} "
                f"(confidence {sovereignty.confidence:.0%})."
            )

        parts.append(f"Overall risk score: {risk_score}/100.")
        return " ".join(parts)

    def _passive_recon(
        self, url: str, timeout: int,
    ) -> Dict[str, Any]:
        """Attempt a lightweight HTTP fetch to gather passive signals
        (headers, WAF banners, etc.) without being intrusive.

        Returns a dict with ``"headers"``, ``"body"``, ``"tls"``, ``"geo"``,
        ``"waf"`` fields. Never raises — returns partial data on failure.
        """
        result: Dict[str, Any] = {
            "headers": {},
            "body": "",
            "tls": {},
            "geo": {},
            "waf": {},
        }

        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            # TLS certificate probe
            if parsed.scheme == "https":
                try:
                    from .http_layer import inspection_context
                    # certificate inspection (audited helper — not data transport)
                    context = inspection_context()
                    with socket.create_connection(
                        (hostname, port), timeout=timeout
                    ) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert(binary_form=True)
                            if cert:
                                cert_text = ssl.DER_cert_to_PEM_cert(cert)
                                result["tls"]["raw"] = cert_text[:2000]
                                # Extract org, issuer etc. via regex
                                for field in ("O=", "CN=", "OU=", "ST=", "L="):
                                    matches = re.findall(
                                        rf"{field}([^,\n]+)", cert_text
                                    )
                                    if matches:
                                        result["tls"][field.rstrip("=").lower()] = (
                                            matches[0].strip()
                                        )
                            # Resolve IP for geo hints
                            ip = sock.getpeername()[0]
                            result["geo"]["resolved_ip"] = ip
                            try:
                                # Extract ASN-style info from reverse DNS
                                rev = socket.gethostbyaddr(ip)[0]
                                result["geo"]["reverse_dns"] = rev
                                asn_hint = rev.split(".")
                                if len(asn_hint) > 1:
                                    for part in asn_hint:
                                        if part.upper().startswith("AS"):
                                            result["geo"]["asn"] = part.upper()
                                            break
                            except (socket.herror, socket.gaierror):
                                pass
                except (socket.timeout, socket.error, ssl.SSLError):
                    pass

            # HTTP header fetch
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "ReconPro/9.2.0 AttributionEngine"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    headers_dict = dict(resp.headers)
                    result["headers"] = headers_dict
                    # Read body (first 8KB for language analysis)
                    body = resp.read(8192)
                    try:
                        result["body"] = body.decode("utf-8", errors="replace")
                    except Exception:
                        result["body"] = body.decode("latin-1", errors="replace")

                    # Detect WAF from headers
                    server = headers_dict.get("server", "")
                    waf_headers = (
                        headers_dict.get("x-waf", "")
                        + " " + headers_dict.get("cf-ray", "")
                        + " " + headers_dict.get("x-cdn", "")
                    )
                    if server or waf_headers.strip():
                        result["waf"] = {
                            "waf_name": server,
                            "waf_vendor": waf_headers.strip(),
                        }

            except (urllib.error.URLError, socket.timeout, ValueError):
                pass

        except Exception:
            pass

        return result

    def _enrich_technique_details(
        self, technique_ids: List[str],
    ) -> List[Dict[str, Any]]:
        """Add contextual information for observed techniques."""
        details: List[Dict[str, Any]] = []

        for tech_id in technique_ids:
            tech_info: Dict[str, Any] = {
                "technique_id": tech_id,
                "tactic": "Unknown",
                "description": self._technique_description(tech_id),
                "groups_using": [],
                "detection_difficulty": self._detection_difficulty(tech_id),
            }

            # Map to tactic
            for tactic_id, tactic_name in MITRE_TACTICS.items():
                if tech_id.startswith(tactic_id[:3]):
                    tech_info["tactic"] = tactic_name
                    tech_info["tactic_id"] = tactic_id
                    break

            # Find groups using this technique
            for gid, gdata in self._groups.items():
                if tech_id in gdata.get("techniques", []):
                    tech_info["groups_using"].append(
                        {
                            "group_id": gid,
                            "group_name": gdata.get("name", gid),
                        }
                    )

            details.append(tech_info)

        return details

    def _technique_description(self, technique_id: str) -> str:
        """Return a human-readable description for a technique ID."""
        descriptions: Dict[str, str] = {
            "T1566.001": "Spearphishing Attachment — Malicious file delivered via email",
            "T1566.002": "Spearphishing Link — Malicious URL delivered via email",
            "T1566.003": "Spearphishing via Service — Third-party service exploitation",
            "T1190": "Exploit Public-Facing Application — Remote code execution via vulnerable services",
            "T1078": "Valid Accounts — Using compromised or stolen credentials",
            "T1078.003": "Valid Accounts: Local Accounts — Compromised local credentials",
            "T1133": "External Remote Services — Exploiting VPN/RDP for initial access",
            "T1059.001": "PowerShell — Command execution via PowerShell",
            "T1059.003": "Windows Command Shell — cmd.exe execution",
            "T1547.001": "Registry Run Keys — Persistence via Windows registry",
            "T1053.005": "Scheduled Task — Persistence via Windows Task Scheduler",
            "T1543.003": "Windows Service — Persistence via malicious services",
            "T1055": "Process Injection — Code injection into legitimate processes",
            "T1055.001": "Dynamic-link Library Injection — DLL injection",
            "T1070.004": "File Deletion — Anti-forensics via file removal",
            "T1562.001": "Disable or Modify Tools — Disabling security software",
            "T1562.003": "Impair Command History Logging — Bash history manipulation",
            "T1003": "OS Credential Dumping — Extracting credentials from memory/registry",
            "T1003.001": "LSASS Memory — Credential extraction from LSASS",
            "T1003.002": "Security Account Manager — SAM database extraction",
            "T1110.001": "Brute Force — Password guessing attacks",
            "T1110.002": "Password Spraying — Low-and-slow password attacks",
            "T1110.003": "Password Policy Manipulation — Weakening password requirements",
            "T1082": "System Information Discovery — Gathering system metadata",
            "T1083": "File and Directory Discovery — Enumerating filesystem",
            "T1046": "Network Service Discovery — Scanning for network services",
            "T1049": "System Network Connections Discovery — Enumerating active connections",
            "T1005": "Data from Local System — Collecting data from local storage",
            "T1119": "Automated Collection — Automated data harvesting",
            "T1041": "Exfiltration Over C2 Channel — Data theft via command and control",
            "T1048": "Exfiltration Over Alternative Protocol — DNS/HTTP exfiltration",
            "T1048.003": "Exfiltration Over Unencrypted Protocol — Cleartext exfiltration",
            "T1071.001": "Web Protocols — C2 via HTTP/HTTPS",
            "T1071.004": "DNS — C2 via DNS tunneling",
            "T1573.001": "Symmetric Cryptography — Encrypted C2 communications",
            "T1105": "Ingress Tool Transfer — Downloading tools to target",
            "T1486": "Data Encrypted for Impact — Ransomware/disk encryption",
            "T1489.001": "Inhibit System Recovery — Destroying backups and recovery tools",
            "T1498": "Network Denial of Service — Flooding attacks",
            "T1189": "Drive-by Compromise — Watering hole attacks",
            "T1203": "Exploitation for Client Execution — Malicious file exploitation",
            "T1195.002": "Compromise Software Supply Chain — Supply chain attack",
            "T1589.002": "Phishing Information — Victim reconnaissance for phishing",
        }
        return descriptions.get(technique_id, "MITRE ATT&CK technique")

    def _detection_difficulty(self, technique_id: str) -> str:
        """Estimate detection difficulty for a given technique."""
        hard_techniques = {
            "T1055", "T1055.001", "T1003", "T1003.001",
            "T1071.004", "T1573.001", "T1048", "T1562.001",
        }
        moderate_techniques = {
            "T1566.001", "T1566.002", "T1190", "T1547.001",
            "T1053.005", "T1082", "T1083", "T1046",
            "T1041", "T1105", "T1110.001", "T1110.003",
        }
        if technique_id in hard_techniques:
            return "difficult"
        elif technique_id in moderate_techniques:
            return "moderate"
        return "easy"

    def _find_related_groups(
        self, observed_techniques: List[str],
    ) -> List[Dict[str, Any]]:
        """Find APT groups that share the most techniques with the observed set
        beyond the top match — useful for identifying potential
        false flags or allied threat actors.
        """
        observed_set = set(observed_techniques)
        related: List[Dict[str, Any]] = []

        for gid, gdata in self._groups.items():
            group_techs = set(gdata.get("techniques", []))
            overlap = observed_set & group_techs
            if len(overlap) >= 2:
                related.append({
                    "group_id": gid,
                    "group_name": gdata.get("name", gid),
                    "country": gdata.get("country", ""),
                    "shared_techniques": len(overlap),
                    "overlap_pct": round(
                        len(overlap) / len(observed_set) * 100, 1
                    ) if observed_set else 0,
                })

        related.sort(key=lambda x: x["shared_techniques"], reverse=True)
        return related[:15]

    def _generate_executive_summary(
        self,
        target: str,
        attribution_report: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> str:
        """Generate an executive-level summary paragraph."""
        primary = attribution_report.get("primary_attribution")
        risk = attribution_report.get("risk_score", 0)
        sovereignty = attribution_report.get("sovereignty_profile", {})

        if primary and primary.get("confidence", 0) >= 0.3:
            name = primary.get("group_name", "Unknown")
            conf = primary.get("confidence", 0)
            level = primary.get("confidence_level", "low")
            country = primary.get("country", "Unknown")
            motivation = primary.get("motivation", "Unknown")

            summary = (
                f"Analysis of {target} reveals indicators consistent with "
                f"activity by {name} ({country}), a threat actor primarily "
                f"motivated by {motivation.lower()}. Attribution confidence "
                f"is {level} ({conf:.0%}). "
            )

            if sovereignty and sovereignty.get("confidence", 0) >= 0.3:
                s_country = sovereignty.get("primary_country", "")
                s_conf = sovereignty.get("confidence", 0)
                summary += (
                    f"Infrastructure analysis supports attribution to "
                    f"{s_country} ({s_conf:.0%} confidence). "
                )

            if risk >= 70:
                summary += (
                    f"Overall risk score is {risk}/100 — CRITICAL. "
                    f"Immediate defensive action recommended."
                )
            elif risk >= 40:
                summary += (
                    f"Overall risk score is {risk}/100 — HIGH. "
                    f"Enhanced monitoring and investigation recommended."
                )
            else:
                summary += f"Overall risk score is {risk}/100."
        elif primary:
            summary = (
                f"Analysis of {target} shows weak indicators of APT activity. "
                f"The best match is {primary.get('group_name', 'Unknown')} "
                f"at {primary.get('confidence_level', 'low')} confidence. "
                f"Additional intelligence is needed for conclusive attribution."
            )
        else:
            summary = (
                f"Analysis of {target} did not identify indicators consistent "
                f"with known APT group activity. The observed techniques and "
                f"patterns do not match any tracked threat actors in the database."
            )

        return summary

    def _generate_recommendations(
        self,
        attribution_report: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Generate actionable security recommendations based on findings."""
        recommendations: List[Dict[str, Any]] = []
        primary = attribution_report.get("primary_attribution")

        # General hardening
        recommendations.append({
            "priority": "high",
            "category": "monitoring",
            "recommendation": (
                "Deploy network traffic analysis (NTA) to detect "
                "C2 communication patterns and data exfiltration attempts."
            ),
        })

        recommendations.append({
            "priority": "high",
            "category": "endpoint",
            "recommendation": (
                "Enable advanced endpoint detection and response (EDR) "
                "with behavioral analysis for process injection and "
                "credential dumping detection."
            ),
        })

        if primary and primary.get("confidence", 0) >= 0.4:
            country = primary.get("country", "")
            techniques = primary.get("matching_techniques", [])

            # Country-specific recommendations
            if country in ("China", "Russia", "Iran", "North Korea"):
                recommendations.append({
                    "priority": "high",
                    "category": "network_defense",
                    "recommendation": (
                        f"Block or heavily inspect traffic to/from "
                        f"{country} ASNs associated with state-sponsored "
                        f"activity. Implement geo-IP filtering for "
                        f"non-business-essential traffic."
                    ),
                })

            # Technique-specific recommendations
            tech_rec_map = {
                "T1566.001": {
                    "category": "email_security",
                    "rec": (
                        "Enhance email security with sandboxed attachment "
                        "analysis and URL rewriting for phishing prevention."
                    ),
                },
                "T1078": {
                    "category": "identity",
                    "rec": (
                        "Implement phishing-resistant MFA (FIDO2/WebAuthn) "
                        "across all accounts. Audit for credential reuse."
                    ),
                },
                "T1003": {
                    "category": "endpoint",
                    "rec": (
                        "Deploy credential guard and LSASS protection. "
                        "Monitor for Mimikatz-style credential dumping."
                    ),
                },
                "T1055": {
                    "category": "endpoint",
                    "rec": (
                        "Enable anti-process-injection policies. Monitor "
                        "for suspicious cross-process memory access."
                    ),
                },
                "T1071.004": {
                    "category": "network_defense",
                    "rec": (
                        "Monitor DNS query patterns for tunneling indicators. "
                        "Deploy DNS security solutions with anomaly detection."
                    ),
                },
                "T1486": {
                    "category": "backup",
                    "rec": (
                        "Verify offline, immutable backups are in place. "
                        "Test backup restoration procedures quarterly."
                    ),
                },
                "T1190": {
                    "category": "patch_management",
                    "rec": (
                        "Accelerate patching for public-facing applications. "
                        "Deploy virtual patching/WAF rules for known CVEs."
                    ),
                },
            }

            for tech in techniques:
                if tech in tech_rec_map:
                    rec = tech_rec_map[tech]
                    recommendations.append({
                        "priority": "medium",
                        "category": rec["category"],
                        "recommendation": rec["rec"],
                    })

        if attribution_report.get("risk_score", 0) >= 60:
            recommendations.append({
                "priority": "critical",
                "category": "incident_response",
                "recommendation": (
                    "Initiate incident response procedures. "
                    "Isolate affected systems and preserve forensic evidence. "
                    "Engage threat intelligence and legal teams."
                ),
            })

        # De-duplicate
        seen = set()
        unique: List[Dict[str, Any]] = []
        for rec in recommendations:
            key = rec["recommendation"][:80]
            if key not in seen:
                seen.add(key)
                unique.append(rec)

        return unique

    # ----- Utility / class methods -----

    @classmethod
    def list_groups(cls) -> List[Dict[str, str]]:
        """Return a summary list of all APT groups in the database.

        Returns:
            List of dicts with ``id``, ``name``, ``country``, ``motivation``.
        """
        return [
            {
                "id": gid,
                "name": data.get("name", gid),
                "country": data.get("country", "?"),
                "motivation": data.get("motivation", "?"),
                "sophistication": data.get("sophistication", "?"),
            }
            for gid, data in APT_GROUPS.items()
        ]

    @classmethod
    def list_campaigns(cls) -> List[Dict[str, str]]:
        """Return a summary list of all known campaigns.

        Returns:
            List of dicts with ``id``, ``name``, ``year``, ``attributed_to``.
        """
        return [
            {
                "id": c.get("id", ""),
                "name": c.get("name", ""),
                "year": str(c.get("year", "?")),
                "attributed_to": ", ".join(c.get("attributed_to", [])),
            }
            for c in KNOWN_CAMPAIGNS
        ]

    @classmethod
    def search_groups_by_technique(
        cls, technique_id: str,
    ) -> List[Dict[str, str]]:
        """Find all APT groups that use a specific technique.

        Args:
            technique_id: MITRE ATT&CK technique ID.

        Returns:
            List of group summary dicts.
        """
        results: List[Dict[str, str]] = []
        for gid, data in APT_GROUPS.items():
            if technique_id in data.get("techniques", []):
                results.append({
                    "id": gid,
                    "name": data.get("name", gid),
                    "country": data.get("country", "?"),
                })
        return results

    @classmethod
    def search_groups_by_country(cls, country: str) -> List[Dict[str, str]]:
        """Find all APT groups associated with a country.

        Args:
            country: Country name or code.

        Returns:
            List of group summary dicts.
        """
        results: List[Dict[str, str]] = []
        country_upper = country.upper()
        for gid, data in APT_GROUPS.items():
            if (data.get("country", "").upper() == country_upper
                    or data.get("country_code", "").upper() == country_upper):
                results.append({
                    "id": gid,
                    "name": data.get("name", gid),
                    "aliases": ", ".join(data.get("aliases", [])),
                    "sophistication": data.get("sophistication", "?"),
                })
        return results

    @classmethod
    def technique_overlap_matrix(
        cls, group_ids: Optional[List[str]] = None,
    ) -> Dict[str, Dict[str, int]]:
        """Compute a pairwise technique overlap matrix for APT groups.

        Args:
            group_ids: Optional list of group IDs. If ``None``, uses all groups.

        Returns:
            Nested dict mapping ``group_id -> group_id -> overlap_count``.
        """
        ids = group_ids or list(APT_GROUPS.keys())
        matrix: Dict[str, Dict[str, int]] = {}

        for gid_a in ids:
            matrix[gid_a] = {}
            techs_a = set(APT_GROUPS.get(gid_a, {}).get("techniques", []))
            for gid_b in ids:
                techs_b = set(APT_GROUPS.get(gid_b, {}).get("techniques", []))
                matrix[gid_a][gid_b] = len(techs_a & techs_b)

        return matrix

    def __repr__(self) -> str:
        return (
            f"AttributionEngine(groups={len(self._groups)}, "
            f"version={__version__}, "
            f"analyses={self._analysis_count})"
        )
