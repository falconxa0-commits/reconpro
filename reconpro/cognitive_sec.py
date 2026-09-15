"""ReconPro v9.2.0 — Cognitive Security & Influence Operations Detection

Detects information warfare, bot armies, and manipulation techniques.
Analyzes web content for sentiment manipulation, astroturfing patterns,
information laundering, and deepfake/AI-generation infrastructure.

Exports:
    InfluenceIndicator       – single detected influence indicator
    BotProfile              – bot activity assessment
    CognitiveSecurityEngine – main cognitive security engine
    SENTIMENT_PATTERNS      – known manipulation pattern database
    BOT_SIGNATURES          – automated content generation patterns
    INFLUENCE_OPERATION_DATABASE – known influence operation catalog
"""

from __future__ import annotations

import json
import math
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


# ══════════════════════════════════════════════════════════════════════
# SENTIMENT_PATTERNS — known manipulation technique patterns
# ══════════════════════════════════════════════════════════════════════

SENTIMENT_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "fear_appeal",
        "category": "emotional_manipulation",
        "description": "Exploiting fear to drive action or compliance",
        "severity": "high",
        "indicators": [
            r"(?i)\b(?:imminent|immediate|urgent|critical|emergency)\b.{0,30}(?:threat|danger|risk|crisis|attack|disaster)",
            r"(?i)\bwarns?\b.{0,20}(?:of|about)\b.{0,30}(?:catastroph|devastat|destroy|kill|death)",
            r"(?i)\b(?:don't|do not|never)\b.{0,15}(?:ignore|wait|delay|hesitate)",
            r"(?i)\b(?:act now|before it.{0,5}(?:too late|is over))",
            r"(?i)\b(?:your (?:life|family|children|loved ones))\b.{0,20}(?:at (?:risk|stake)|in (?:danger|jeopardy))",
        ],
        "cognitive_bias": "negativity bias, loss aversion",
    },
    {
        "name": "authority_exploitation",
        "category": "credibility_manipulation",
        "description": "False or misleading use of authority signals",
        "severity": "medium",
        "indicators": [
            r"(?i)\b(?:experts?|scientists?|doctors?|professors?)\b.{0,20}(?:all agree|confirm|prove|say)",
            r"(?i)\bstudy (?:shows?|proves?|confirms?|finds?)\b.{0,5}(?:that|the)",
            r"(?i)\baccording (?:to|from)\b.{0,15}(?:official|authority|expert|government)",
            r"(?i)\b(?:peer.?(?:reviewed|approved))\b",
            r"(?i)\b(?:award.?(?:?:winning|winning))\b.{0,15}(?:expert|scientist|doctor)",
        ],
        "cognitive_bias": "authority bias, appeal to authority",
    },
    {
        "name": "social_proof_manipulation",
        "category": "credibility_manipulation",
        "description": "Fabricating or amplifying social consensus",
        "severity": "medium",
        "indicators": [
            r"(?i)\b(?:millions?|thousands?|everyone)\b.{0,20}(?:already|are|have)\b.{0,15}(?:joined|switched|signed|agreed|know)",
            r"(?i)\b(?:going viral|trending|breaking|just in)\b",
            r"(?i)\b(?:join|sign up with)\b.{0,20}(?:\d[\d,.]*\s*(?:million|thousand|people|users|members))",
            r"(?i)\b(?:\d{1,3}(?:,\d{3})*\s*(?:people|users|shares|likes|retweets))\b.{0,15}(?:agree|think|believe|say)",
        ],
        "cognitive_bias": "bandwagon effect, social proof",
    },
    {
        "name": "us_vs_them_framing",
        "category": "divisive_content",
        "description": "Creating in-group vs out-group narratives",
        "severity": "high",
        "indicators": [
            r"(?i)\b(?:they|them|those people|the (?:elite|establishment|deep state|mainstream|media))\b.{0,20}(?:don.{0,2}t want you to|are hiding|are lying|won.{0,2}t tell)",
            r"(?i)\b(?:we|us|real|true|patriot|awake)\b.{0,10}(?:vs\.?|versus|against|know better|can see)",
            r"(?i)\b(?:wake up|open your eyes|think for yourself|do your own research)\b",
            r"(?i)\b(?:the (?:truth|reality|fact))\b.{0,20}(?:they|mainstream|government)\b.{0,15}(?:hide|suppress|censor|cover)",
        ],
        "cognitive_bias": "in-group bias, tribalism, othering",
    },
    {
        "name": "false_dichotomy",
        "category": "logical_fallacy",
        "description": "Presenting only two options when more exist",
        "severity": "medium",
        "indicators": [
            r"(?i)(?:either|you.{0,5}either)\b.{0,30}(?:or|otherwise)\b",
            r"(?i)\byou.{0,5}(?:are either|must either|can either)\b",
            r"(?i)\b(?:only two|one of two|choose (?:one|between))\b",
            r"(?i)\b(?:it.{0,3}s (?:us or|them or|this or|that or|now or))\b",
        ],
        "cognitive_bias": "false dilemma, black-and-white thinking",
    },
    {
        "name": "bandwagon_effect",
        "category": "emotional_manipulation",
        "description": "Pressuring conformity through implied majority opinion",
        "severity": "low",
        "indicators": [
            r"(?i)\b(?:most people|the majority|everyone knows|everybody)\b.{0,25}(?:that|this)",
            r"(?i)\b(?:don.{0,2}t be (?:left out|the only one|behind))\b",
            r"(?i)\b(?:people are (?:switching|leaving|waking up|realizing))\b",
        ],
        "cognitive_bias": "bandwagon effect, herd mentality",
    },
    {
        "name": "emotional_trigger_words",
        "category": "emotional_manipulation",
        "description": "Using highly charged language to bypass critical thinking",
        "severity": "medium",
        "indicators": [
            r"(?i)\b(?:outrageous|shocking|horrifying|disgusting|appalling|unbelievable)\b",
            r"(?i)\b(?:bombshell|explosive|jaw-dropping|game-chang|world-shatter)\b",
            r"(?i)\b(?:must.see|you won.{0,2}t believe|will blow your mind)\b",
            r"(?i)\b(?:exposed|caught|leaked|revealed|busted)\b.{0,15}(?!(?:by|through|to))",
        ],
        "cognitive_bias": "affect heuristic, emotion-driven judgment",
    },
    {
        "name": "conspiracy_narrative",
        "category": "disinformation",
        "description": "Promoting conspiracy theories without evidence",
        "severity": "high",
        "indicators": [
            r"(?i)\b(?:what they|the (?:media|government|establishment))\b.{0,15}(?:don.{0,2}t want you to|are hiding|won.{0,2}t tell|are covering up)",
            r"(?i)\b(?:follow (?:the|this) money|deep state|globalist|new world order| Agenda\s*\d+)\b",
            r"(?i)\b(?:connect (?:the )?dots|read between (?:the )?lines|look (?:it |at who) up)\b",
            r"(?i)\b(?:(?:mainstream|corporate|lame)stream media|msm|fake news)\b",
        ],
        "cognitive_bias": "patternicity, apophenia, confirmation bias",
    },
    {
        "name": "loaded_language",
        "category": "emotional_manipulation",
        "description": "Using emotionally charged or pejorative terminology",
        "severity": "low",
        "indicators": [
            r"(?i)\b(?:regime|dictator|tyrant|fascist|nazi|communist|traitor|enemy)\b",
            r"(?i)\b(?:propaganda|brainwash|indoctrinat|manipulat)\b.{0,20}(?:you|us|people|masses)",
            r"(?i)\b(?:crisis actor|false flag|hoax|scam|shill|bot|troll)\b",
        ],
        "cognitive_bias": "labeling, name-calling",
    },
    {
        "name": "urgency_pressure",
        "category": "pressure_tactics",
        "description": "Creating artificial time pressure to prevent deliberation",
        "severity": "medium",
        "indicators": [
            r"(?i)\b(?:limited time|time is (?:running out|almost up)|hurry|rush|act fast)\b",
            r"(?i)\b(?:only \d+ (?:left|remaining|days|hours))\b",
            r"(?i)\b(?:before (?:they|it|the government))\b.{0,15}(?:ban|block|remove|delete|shut down)",
            r"(?i)\b(?:share (?:this|it) (?:now|before|while you can))\b",
        ],
        "cognitive_bias": "scarcity bias, urgency heuristic",
    },
]


# ══════════════════════════════════════════════════════════════════════
# BOT_SIGNATURES — patterns indicating automated content generation
# ══════════════════════════════════════════════════════════════════════

BOT_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "template_fill",
        "description": "Content with visible template placeholder patterns",
        "patterns": [
            r"\{\{[^}]+\}\}",
            r"\[\[(?:FIRST|LAST|CITY|STATE|DATE|YEAR|NAME)\]\]",
            r"\$(?:first|last|city|name|date)\$",
            r"%(?:name|first|last|city|date|company)%",
            r"<NAME>|<EMAIL>|<CITY>|<DATE>",
        ],
        "confidence": 0.95,
    },
    {
        "name": "repetitive_structure",
        "description": "Highly repetitive sentence or paragraph structures",
        "patterns": [
            # Check for sentences starting with the same phrase more than 3 times
            r"(?:^|\.\s+)([A-Z][a-z]+\s+[a-z]+)\s+is\s+",
        ],
        "confidence": 0.70,
        "requires_count": 3,
    },
    {
        "name": "generated_disclaimer",
        "description": "AI generation disclaimers or watermarks",
        "patterns": [
            r"(?i)(?:generated|written|created)\s+(?:by|using|with)\s+(?:AI|GPT|an?\s+AI|artificial intelligence|language model)",
            r"(?i)(?:as an?\s+)?AI\s+(?:language model|assistant|system)",
            r"(?i)I\s+(?:am|'m)\s+(?:not|an?)\s+(?:a\s+)?(?:human|person|real)",
            r"(?i)(?:disclaimer|notice).{0,30}(?:AI.?(?:generated|created|written|produced))",
        ],
        "confidence": 0.99,
    },
    {
        "name": "bot_comment_patterns",
        "description": "Patterns common in bot-generated comments/posts",
        "patterns": [
            r"(?i)^(?:great|amazing|awesome|love this|nice|good|excellent|perfect)!?\s*[.!]?$",
            r"(?i)^(?:thanks?|thank you|thx)\s+(?:for|so much|a lot)!?\s*[.!]?$",
            r"(?i)^(?:check out|visit|go to|see)\s+(?:my|our|this)\s+(?:page|site|channel|profile)",
            r"(?i)^\W*(?:\+1|100%|agreed|this|\U0001f44d|\U0001f44f)\W*$",
            r"(?i)^(?:first|early|here before)\b",
        ],
        "confidence": 0.80,
    },
    {
        "name": "coordinate_posting",
        "description": "Identical or near-identical content (copy-paste campaigns)",
        "patterns": [],  # Handled by deduplication logic
        "confidence": 0.85,
    },
    {
        "name": "unnatural_language",
        "description": "Statistical markers of machine-generated text",
        "patterns": [
            r"(?i)\b(?:furthermore|moreover|additionally|consequently|nevertheless|henceforth)\b.{0,5}(?:,\s*)?(?:furthermore|moreover|additionally|consequently)",
            r"(?i)(?:in conclusion|to summarize|in summary)\b.{0,50}(?:in conclusion|to summarize|in summary)\b",
            r"(?i)\b(?:it is (?:important|crucial|essential|imperative|vital) to note)\b",
        ],
        "confidence": 0.65,
    },
]


# ══════════════════════════════════════════════════════════════════════
# INFLUENCE_OPERATION_DATABASE — known influence operation patterns
# ══════════════════════════════════════════════════════════════════════

INFLUENCE_OPERATION_DATABASE: List[Dict[str, Any]] = [
    {
        "name": "Internet Research Agency (IRA)",
        "attribution": "Russia",
        "active": "2014-present",
        "platforms": ["Facebook", "Twitter/X", "Instagram", "YouTube", "TikTok"],
        "techniques": [
            "Create fake personas with American-sounding names",
            "Operate competing groups (pro and anti) to amplify division",
            "Use stolen US identities for profile creation",
            "Post on both sides of divisive issues",
            "Coordinate posting timing for maximum engagement",
            "Purchase targeted political advertisements",
        ],
        "content_signatures": [
            r"(?i)(?:heart of texas|being patriotic|united muslims of america)",
        ],
        "indicators": [
            "accounts created in bulk around same date",
            "profile photos from stock photo sites",
            "posting patterns aligned to Russian business hours (UTC+3)",
            "content recycles from Russian state media (RT, Sputnik)",
        ],
    },
    {
        "name": "Dragonbridge / Spamouflage",
        "attribution": "China (PRC)",
        "active": "2019-present",
        "platforms": ["Facebook", "Twitter/X", "YouTube", "Reddit", "TikTok"],
        "techniques": [
            "Defame Chinese dissidents and critics",
            "Promote pro-PRC narratives",
            "Amplify divisive US political content",
            "Use AI-generated profile pictures",
            "Cross-platform content recycling",
            "Astroturf campaigns on geopolitical topics",
        ],
        "content_signatures": [
            r"(?i)(?:dragonbridge|spamouflage|50 cent army|wumao)",
        ],
        "indicators": [
            "posting bursts aligned to Chinese business hours (UTC+8)",
            "coordinated use of specific hashtags across platforms",
            "accounts with AI-generated faces",
            "content attacking specific dissidents by name",
        ],
    },
    {
        "name": "Islamic State (ISIS) Online Operations",
        "attribution": "ISIS/ISIL",
        "active": "2014-present",
        "platforms": ["Telegram", "Twitter/X", "Facebook", "TikTok"],
        "techniques": [
            "High-production-value propaganda videos",
            "Multi-language recruitment materials",
            "Encrypted channel distribution (Telegram)",
            "Exploitation of grievances and identity crises",
            "Rapid content migration when platforms remove accounts",
        ],
        "content_signatures": [],
        "indicators": [
            "encrypted messaging group coordination",
            "rapid platform migration patterns",
            "professional media production with specific aesthetic",
        ],
    },
    {
        "name": "Iranian Cyber Influence (CyAvengers, Endless Mayfly)",
        "attribution": "Iran",
        "active": "2018-present",
        "platforms": ["Twitter/X", "Facebook", "YouTube", "LinkedIn"],
        "techniques": [
            "Impersonate journalists and media outlets",
            "Create fake news websites mimicking real ones",
            "Amplify anti-Saudi and anti-US narratives",
            "Steal and republish legitimate content with altered context",
            "LinkedIn-based influence targeting professionals",
        ],
        "content_signatures": [],
        "indicators": [
            "lookalike domains with typosquatting",
            "content alignment with Iranian state media (Press TV, IRNA)",
            "posting aligned to Iranian business hours (UTC+3:30)",
        ],
    },
    {
        "name": "Political Troll Farms (Generic)",
        "attribution": "Various",
        "active": "Ongoing",
        "platforms": ["Facebook", "Twitter/X", "Reddit", "YouTube"],
        "techniques": [
            "Bulk account creation from single IP ranges",
            "Coordinated hashtag campaigns",
            "Reply-chain manipulation",
            "Fake engagement (likes, shares, retweets)",
            "Astroturfing as grassroots movements",
        ],
        "content_signatures": [],
        "indicators": [
            "unnatural posting frequency (>50 posts/day)",
            "accounts with near-identical bios or profile photos",
            "identical content posted from multiple accounts",
            "synchronized posting patterns",
        ],
    },
]


# ══════════════════════════════════════════════════════════════════════
# Data classes
# ══════════════════════════════════════════════════════════════════════

@dataclass
class InfluenceIndicator:
    """Single detected influence or manipulation indicator."""
    indicator_type: str = ""
    confidence: float = 0.0
    evidence: str = ""
    severity: str = "low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator_type": self.indicator_type,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "severity": self.severity,
        }


@dataclass
class BotProfile:
    """Assessment of bot-like activity on a target."""
    bot_score: float = 0.0
    indicators: List[InfluenceIndicator] = field(default_factory=list)
    platform: str = "web"
    behavior_pattern: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bot_score": round(self.bot_score, 3),
            "indicators": [i.to_dict() for i in self.indicators],
            "platform": self.platform,
            "behavior_pattern": self.behavior_pattern,
        }


# ══════════════════════════════════════════════════════════════════════
# CognitiveSecurityEngine
# ══════════════════════════════════════════════════════════════════════

class CognitiveSecurityEngine:
    """Detect cognitive security threats and influence operations.

    Analyzes web content for manipulation techniques, bot activity,
    astroturfing, information laundering, and AI-generation infrastructure.
    """

    def __init__(self) -> None:
        self._ua = "ReconPro/9.2.0 (cognitive-sec)"

    # ── public API ─────────────────────────────────────────────────

    def analyze(
        self, target: str, base_url: str, timeout: int = 8
    ) -> Dict[str, Any]:
        """Full cognitive security assessment of *target*.

        Returns a comprehensive report with bot analysis, sentiment
        manipulation scores, astroturfing detection, information
        laundering assessment, and cognitive impact rating.
        """
        body = self._fetch_content(base_url, timeout=timeout)
        headers = self._fetch_headers(base_url, timeout=timeout)

        bot_profile = self.detect_bot_activity(base_url, timeout=timeout)
        sentiment = self.analyze_sentiment_manipulation(body)
        astroturf = self.detect_astroturfing(body)
        laundering = self.analyze_information_laundering(base_url, headers, timeout=timeout)
        deepfake_infra = self.detect_deepfake_infrastructure(base_url, headers, timeout=timeout)
        cognitive_impact = self.assess_cognitive_impact(
            target, sentiment, bot_profile, astroturf
        )

        # Aggregate risk score
        scores = []
        if bot_profile.bot_score > 0:
            scores.append(bot_profile.bot_score * 100)
        if sentiment.get("manipulation_score", 0) > 0:
            scores.append(sentiment["manipulation_score"])
        if astroturf.get("astroturf_score", 0) > 0:
            scores.append(astroturf["astroturf_score"])
        if laundering.get("laundering_score", 0) > 0:
            scores.append(laundering["laundering_score"])
        if deepfake_infra.get("ai_infra_score", 0) > 0:
            scores.append(deepfake_infra["ai_infra_score"])

        overall_score = max(scores) if scores else 0.0

        return {
            "target": target,
            "base_url": base_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_cognitive_risk": round(overall_score, 1),
            "risk_level": self._risk_level(overall_score),
            "bot_analysis": bot_profile.to_dict(),
            "sentiment_manipulation": sentiment,
            "astroturfing": astroturf,
            "information_laundering": laundering,
            "deepfake_infrastructure": deepfake_infra,
            "cognitive_impact": cognitive_impact,
        }

    def detect_bot_activity(
        self, base_url: str, timeout: int = 8
    ) -> BotProfile:
        """Detect signs of bot armies and automated content generation.

        Analyzes page content for bot signatures and behavioral patterns.
        """
        body = self._fetch_content(base_url, timeout=timeout)
        indicators: List[InfluenceIndicator] = []
        total_score = 0.0
        max_possible = 0.0

        for sig in BOT_SIGNATURES:
            if not sig["patterns"]:
                continue
            matches: List[str] = []
            for pattern in sig["patterns"]:
                found = re.findall(pattern, body)
                matches.extend(found)

            if matches:
                required = sig.get("requires_count", 1)
                if len(matches) >= required:
                    evidence = f"Pattern '{sig['name']}' matched {len(matches)} times"
                    confidence = sig["confidence"]
                    severity = "high" if confidence > 0.8 else "medium"
                    indicators.append(InfluenceIndicator(
                        indicator_type=f"bot_signature:{sig['name']}",
                        confidence=confidence,
                        evidence=evidence,
                        severity=severity,
                    ))
                    total_score += confidence
            max_possible += sig["confidence"]

        # Check for URL patterns common in bot operations
        bot_url_patterns = [
            r"(?:bit\.ly|tinyurl\.com|t\.co)/[a-zA-Z0-9]+",
            r"(?:telegram\.me|t\.me)/joinchat/[a-zA-Z0-9_-]+",
        ]
        for pattern in bot_url_patterns:
            matches = re.findall(pattern, body)
            if matches:
                indicators.append(InfluenceIndicator(
                    indicator_type="bot_url_pattern",
                    confidence=0.5,
                    evidence=f"Bot-typical URL shortener/link pattern: {matches[0]}",
                    severity="low",
                ))
                total_score += 0.5
                max_possible += 1.0

        # Normalize to 0-1
        bot_score = total_score / max_possible if max_possible > 0 else 0.0
        bot_score = min(bot_score, 1.0)

        # Determine behavior pattern
        if bot_score > 0.7:
            pattern = "coordinated_bot_army"
        elif bot_score > 0.4:
            pattern = "mixed_automated_content"
        elif bot_score > 0.1:
            pattern = "some_automated_elements"
        else:
            pattern = "primarily_human"

        return BotProfile(
            bot_score=bot_score,
            indicators=indicators,
            platform="web",
            behavior_pattern=pattern,
        )

    def analyze_sentiment_manipulation(self, body: str) -> Dict[str, Any]:
        """Detect sentiment manipulation techniques in page content.

        Scans for emotional trigger words, fear/anger language,
        and known manipulation patterns from SENTIMENT_PATTERNS.
        """
        results: List[Dict[str, Any]] = []
        total_weight = 0.0
        max_weight = 0.0

        for pattern_def in SENTIMENT_PATTERNS:
            matches: List[str] = []
            for regex in pattern_def["indicators"]:
                found = re.findall(regex, body)
                matches.extend(found)

            if matches:
                severity_weight = {"high": 3.0, "medium": 2.0, "low": 1.0}
                weight = severity_weight.get(pattern_def["severity"], 1.0)
                total_weight += weight * len(matches)
                max_weight += weight * 3  # normalize against expected max

                results.append({
                    "technique": pattern_def["name"],
                    "category": pattern_def["category"],
                    "severity": pattern_def["severity"],
                    "match_count": len(matches),
                    "cognitive_bias": pattern_def.get("cognitive_bias", ""),
                    "sample_evidence": matches[:3],
                })

        # Calculate manipulation score 0-100
        manipulation_score = (total_weight / max_weight * 100) if max_weight > 0 else 0.0
        manipulation_score = min(manipulation_score, 100.0)

        # Categorize dominant manipulation type
        categories: Dict[str, int] = {}
        for r in results:
            cat = r["category"]
            categories[cat] = categories.get(cat, 0) + r["match_count"]

        dominant = max(categories, key=categories.get) if categories else "none"  # type: ignore[arg-type]

        return {
            "manipulation_score": round(manipulation_score, 1),
            "manipulation_risk": self._risk_level(manipulation_score),
            "techniques_detected": results,
            "technique_count": len(results),
            "category_breakdown": categories,
            "dominant_category": dominant,
            "recommendation": self._sentiment_recommendation(manipulation_score, dominant),
        }

    def detect_astroturfing(self, body: str) -> Dict[str, Any]:
        """Detect fake grassroots (astroturfing) patterns.

        Looks for coordinated messaging, artificial consensus signals,
        and manufactured support indicators.
        """
        indicators: List[Dict[str, Any]] = []
        score = 0.0

        # Coordinated messaging: repeated phrases
        sentences = re.split(r'[.!?]+', body)
        phrase_freq: Dict[str, int] = {}
        for sent in sentences:
            sent = sent.strip()
            if len(sent) < 20 or len(sent) > 200:
                continue
            phrase_freq[sent.lower()] = phrase_freq.get(sent.lower(), 0) + 1

        repeated = {p: c for p, c in phrase_freq.items() if c >= 2}
        if repeated:
            top_phrase = max(repeated, key=repeated.get)  # type: ignore[arg-type]
            indicators.append({
                "type": "repeated_phrases",
                "evidence": f"{len(repeated)} phrase(s) repeated, top: '{top_phrase[:80]}...' ({repeated[top_phrase]}x)",
                "severity": "medium",
            })
            score += min(len(repeated) * 10, 30)

        # Artificial consensus indicators
        consensus_patterns = [
            (r"(?i)\b(?:\d{1,3}(?:,\d{3})*\s*(?:people|citizens|voters|experts))\b.{0,30}(?:agree|support|sign|demand)", "statistical_claim"),
            (r"(?i)\b(?:petition|movement|campaign)\b.{0,30}(?:has (?:already )?(?:\d|gained|reached|collected))", "petition_claim"),
            (r"(?i)\b(?:overwhelming|vast|strong|massive)\b.{0,15}(?:majority|support|consensus|agreement)", "consensus_claim"),
            (r"(?i)\b(?:polls?|survey|research)\b.{0,30}(?:shows?|reveals?|finds?|confirms?)\b.{0,20}(?:\d+\s*%)", "poll_claim"),
        ]
        for pattern, label in consensus_patterns:
            matches = re.findall(pattern, body)
            if matches:
                indicators.append({
                    "type": f"artificial_consensus:{label}",
                    "evidence": f"Matched {len(matches)} time(s)",
                    "severity": "medium",
                })
                score += min(len(matches) * 15, 30)

        # Check for "grassroots" self-identification
        grassroots = re.findall(
            r"(?i)(?:grassroots|ground.up|people.{0,5}powered|community.{0,5}led|citizen.{0,5}driven)",
            body,
        )
        if grassroots:
            indicators.append({
                "type": "grassroots_self_identification",
                "evidence": f"'{grassroots[0]}' self-identification found",
                "severity": "low",
            })
            score += 5

        # Check for call-to-action coordination patterns
        cta_patterns = [
            r"(?i)(?:share|repost|retweet|forward|send)\s+(?:this|it)\s+(?:now|widely|everywhere|with everyone)",
            r"(?i)(?:copy and paste|copy.{0,5}paste|forward this message)",
            r"(?i)(?:tag (?:your|\d+|everyone)|share with (?:your|\d+) friends)",
        ]
        for pattern in cta_patterns:
            if re.search(pattern, body):
                indicators.append({
                    "type": "coordinated_cta",
                    "evidence": "Coordinated call-to-action detected",
                    "severity": "high",
                })
                score += 25

        score = min(score, 100.0)

        return {
            "astroturf_score": round(score, 1),
            "astroturf_risk": self._risk_level(score),
            "indicators": indicators,
            "indicator_count": len(indicators),
            "assessment": "likely_astroturf" if score > 60 else "possible_astroturf" if score > 30 else "unlikely_astroturf",
        }

    def analyze_information_laundering(
        self,
        base_url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 8,
    ) -> Dict[str, Any]:
        """Detect information laundering: obscured sources, circular reporting,
        and multi-hop redirection chains.
        """
        indicators: List[Dict[str, Any]] = []
        score = 0.0
        parsed = urllib.parse.urlparse(base_url)
        host = parsed.hostname or ""

        # Check redirect chain
        redirect_chain = self._trace_redirects(base_url, timeout=timeout)
        if len(redirect_chain) > 3:
            indicators.append({
                "type": "long_redirect_chain",
                "evidence": f"{len(redirect_chain)}-hop redirect chain",
                "severity": "high",
            })
            score += 40
        elif len(redirect_chain) > 1:
            indicators.append({
                "type": "redirect_chain",
                "evidence": f"{len(redirect_chain)}-hop redirect: {' -> '.join(redirect_chain[:4])}",
                "severity": "medium",
            })
            score += 15

        # Check for referrer masking
        if headers:
            if "x-frame-options" not in {k.lower() for k in headers}:
                indicators.append({
                    "type": "framing_allowed",
                    "evidence": "No X-Frame-Options header — page can be embedded to obscure source",
                    "severity": "low",
                })
                score += 5

        # Check for anonymous hosting / WhoisGuard
        whois_privacy_patterns = [
            r"(?i)(?:whoisguard|domains by proxy|privacy protect|anonymous|redacted|redacted for privacy)",
        ]
        body = self._fetch_content(base_url, timeout=timeout)
        for pattern in whois_privacy_patterns:
            if re.search(pattern, body):
                indicators.append({
                    "type": "anonymous_hosting_signal",
                    "evidence": "Domain privacy/WHOIS protection indicators found",
                    "severity": "medium",
                })
                score += 15

        # Check for circular reporting: site references itself or sister sites
        # as authoritative source
        circular = re.findall(
            r"(?i)(?:according to|reported by|sources? (?:say|confirm|report))\b.{0,50}" + re.escape(host or "__none__"),
            body,
        )
        if circular:
            indicators.append({
                "type": "self_referential",
                "evidence": f"Site references itself as authority source ({len(circular)} time(s))",
                "severity": "high",
            })
            score += 30

        # Check for content scraping indicators
        scrape_patterns = [
            r"(?i)(?:source|originally published|reposted|syndicated from|via)",
            r"(?i)\b(?:read more|continue reading|full article)\b.{0,30}(?:at|on|here)",
        ]
        for pattern in scrape_patterns:
            if re.search(pattern, body):
                indicators.append({
                    "type": "content_aggregation_signal",
                    "evidence": "Content appears to be aggregated/syndicated",
                    "severity": "low",
                })
                score += 5

        score = min(score, 100.0)

        return {
            "laundering_score": round(score, 1),
            "laundering_risk": self._risk_level(score),
            "redirect_chain": redirect_chain,
            "indicators": indicators,
            "indicator_count": len(indicators),
            "assessment": "likely_laundering" if score > 60 else "possible_laundering" if score > 30 else "unlikely_laundering",
        }

    def detect_deepfake_infrastructure(
        self,
        base_url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 8,
    ) -> Dict[str, Any]:
        """Detect AI generation infrastructure: LLM endpoints, image generation
        APIs, TTS services, and related tooling.
        """
        indicators: List[Dict[str, Any]] = []
        score = 0.0
        parsed = urllib.parse.urlparse(base_url)
        host = parsed.hostname or ""
        body = self._fetch_content(base_url, timeout=timeout)

        # Known AI service URL patterns
        ai_url_patterns = [
            (r"(?i)(?:openai|api\.openai\.com|chatgpt|gpt-\d|gpt4|gpt-4|dall-e|dalle)", "OpenAI", "high"),
            (r"(?i)(?:anthropic|claude|api\.anthropic\.com)", "Anthropic", "high"),
            (r"(?i)(?:stability\.ai|stabilityai|stable.?(?:diffusion|image))", "Stability AI", "high"),
            (r"(?i)(?:midjourney|discord\.com/channels/)", "Midjourney", "medium"),
            (r"(?i)(?:huggingface|hf\.co|hf\.space)", "Hugging Face", "medium"),
            (r"(?i)(?:replicate|replicate\.com)", "Replicate", "medium"),
            (r"(?i)(?:elevenlabs|eleven\.io|eleven_labs)", "ElevenLabs (TTS)", "high"),
            (r"(?i)(?:deepfake|deep.?fake|face.?swap|deep.?nude|nudify)", "Deepfake tooling", "high"),
            (r"(?i)(?:runway|runwayml|runway\.ml)", "Runway ML", "medium"),
            (r"(?i)(?:langchain|llamaindex|auto.?gpt|baby.?agi)", "AI Agent framework", "medium"),
            (r"(?i)(?:/v1/(?:chat/)?completions|/v1/images/generations|/v1/audio)", "LLM API endpoint", "high"),
            (r"(?i)(?:text.to.speech|tts.api|speech.synthesis|voice.clone|voice.synthesis)", "TTS API", "high"),
        ]

        # Check URL and body
        combined = base_url + "\n" + body
        if headers:
            combined += "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())

        for pattern, service, severity in ai_url_patterns:
            if re.search(pattern, combined):
                indicators.append({
                    "type": "ai_service_detected",
                    "service": service,
                    "severity": severity,
                    "evidence": f"Reference to {service} detected",
                })
                weight = {"high": 20, "medium": 10, "low": 5}
                score += weight.get(severity, 10)

        # Check for API key patterns in exposed endpoints
        api_key_patterns = [
            (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key"),
            (r"key-[a-zA-Z0-9]{20,}", "Anthropic API key"),
            (r"hf_[a-zA-Z0-9]{30,}", "Hugging Face token"),
            (r"r8_[a-zA-Z0-9]{20,}", "Replicate API token"),
        ]
        for pattern, label in api_key_patterns:
            matches = re.findall(pattern, body)
            if matches:
                indicators.append({
                    "type": "exposed_ai_api_key",
                    "service": label,
                    "severity": "critical",
                    "evidence": f"Exposed {label} detected (masked)",
                })
                score += 30

        # Check for AI-generated content markers in meta tags
        ai_meta = re.findall(
            r"(?i)(?:generator|author|created.by|powered.by)[^\"]*?(?:ai|gpt|openai|claude|gemini)",
            body,
        )
        if ai_meta:
            indicators.append({
                "type": "ai_generator_meta_tag",
                "severity": "medium",
                "evidence": f"AI generator found in meta tags",
            })
            score += 15

        score = min(score, 100.0)

        return {
            "ai_infra_score": round(score, 1),
            "ai_infra_risk": self._risk_level(score),
            "indicators": indicators,
            "indicator_count": len(indicators),
            "assessment": "active_ai_infrastructure" if score > 50 else "possible_ai_usage" if score > 20 else "no_ai_infrastructure_detected",
        }

    def assess_cognitive_impact(
        self,
        target: str,
        sentiment: Dict[str, Any],
        bot_profile: BotProfile,
        astroturf: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Assess potential cognitive impact on visitors.

        Combines manipulation, bot, and astroturf scores to estimate
        the likely cognitive effect on a typical visitor.
        """
        manipulation_score = sentiment.get("manipulation_score", 0)
        bot_score = bot_profile.bot_score * 100
        astroturf_score = astroturf.get("astroturf_score", 0)

        # Weighted cognitive impact assessment
        impact_score = (
            manipulation_score * 0.4
            + bot_score * 0.3
            + astroturf_score * 0.3
        )
        impact_score = min(impact_score, 100.0)

        # Determine vulnerability level
        if impact_score > 75:
            vuln_level = "extremely_high"
            description = (
                "This content employs multiple sophisticated manipulation techniques. "
                "Visitors are at extreme risk of being misinformed or radicalized."
            )
        elif impact_score > 50:
            vuln_level = "high"
            description = (
                "This content uses multiple influence techniques. "
                "Visitors with lower media literacy are likely to be affected."
            )
        elif impact_score > 25:
            vuln_level = "moderate"
            description = (
                "Some manipulation indicators present. "
                "Cautious evaluation is recommended."
            )
        elif impact_score > 10:
            vuln_level = "low"
            description = (
                "Minimal manipulation indicators detected. "
                "Standard critical thinking applies."
            )
        else:
            vuln_level = "negligible"
            description = (
                "No significant cognitive security threats detected."
            )

        # Identify primary threats
        threats: List[str] = []
        if manipulation_score > 40:
            dominant_cat = sentiment.get("dominant_category", "")
            threats.append(f"Sentiment manipulation ({dominant_cat})")
        if bot_score > 40:
            threats.append(f"Bot activity ({bot_profile.behavior_pattern})")
        if astroturf_score > 40:
            threats.append("Potential astroturfing")

        # Check against known influence operations
        matched_ops: List[Dict[str, Any]] = []
        # This would require fetching more content; use what we have
        for op in INFLUENCE_OPERATION_DATABASE:
            if op.get("content_signatures"):
                for sig in op["content_signatures"]:
                    body_snippet = self._fetch_content(f"https://{target}", timeout=4) if "." in target else ""
                    if body_snippet and re.search(sig, body_snippet):
                        matched_ops.append({
                            "operation": op["name"],
                            "attribution": op["attribution"],
                            "techniques": op["techniques"][:3],
                        })
                        break

        return {
            "impact_score": round(impact_score, 1),
            "vulnerability_level": vuln_level,
            "description": description,
            "primary_threats": threats,
            "visitor_recommendation": self._visitor_recommendation(vuln_level),
            "matched_influence_operations": matched_ops,
        }

    # ── private helpers ─────────────────────────────────────────────

    def _fetch_content(self, base_url: str, timeout: int = 8) -> str:
        """Fetch page body text."""
        try:
            req = urllib.request.Request(
                base_url, headers={"User-Agent": self._ua}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(262_144).decode("utf-8", errors="replace")
        except (urllib.error.URLError, socket.timeout, OSError):
            return ""

    def _fetch_headers(self, base_url: str, timeout: int = 8) -> Dict[str, str]:
        """Fetch HTTP response headers."""
        try:
            req = urllib.request.Request(
                base_url, headers={"User-Agent": self._ua}, method="HEAD"
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return {k: v for k, v in resp.headers.items()}
        except (urllib.error.URLError, socket.timeout, OSError):
            # Fall back to GET
            try:
                req = urllib.request.Request(
                    base_url, headers={"User-Agent": self._ua}
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return {k: v for k, v in resp.headers.items()}
            except (urllib.error.URLError, socket.timeout, OSError):
                return {}

    def _trace_redirects(
        self, base_url: str, timeout: int = 8
    ) -> List[str]:
        """Follow redirects and return the full chain of URLs."""
        chain: List[str] = []
        url = base_url
        for _ in range(10):  # max 10 hops
            chain.append(url)
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": self._ua}
                )
                opener = urllib.request.build_opener(
                    urllib.request.HTTPRedirectHandler
                )
                # Manually handle redirect to capture chain
                resp = urllib.request.urlopen(req, timeout=timeout)
                final_url = resp.url
                if final_url != url and final_url not in chain:
                    chain.append(final_url)
                break
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    location = e.headers.get("Location", "")
                    if location:
                        url = urllib.parse.urljoin(url, location)
                        continue
                break
            except (urllib.error.URLError, socket.timeout, OSError):
                break
        return chain

    @staticmethod
    def _risk_level(score: float) -> str:
        """Map a 0-100 score to a risk level string."""
        if score > 75:
            return "critical"
        elif score > 50:
            return "high"
        elif score > 25:
            return "medium"
        elif score > 10:
            return "low"
        return "negligible"

    @staticmethod
    def _sentiment_recommendation(score: float, dominant: str) -> str:
        """Generate a recommendation based on sentiment analysis."""
        if score > 60:
            return (
                f"HIGH RISK: Content employs {dominant} manipulation at scale. "
                "Recommend independent fact-checking before engagement."
            )
        elif score > 30:
            return (
                f"MODERATE: Some {dominant} techniques detected. "
                "Cross-reference claims with authoritative sources."
            )
        return "LOW: Minimal manipulation indicators. Standard media literacy applies."

    @staticmethod
    def _visitor_recommendation(vuln_level: str) -> str:
        """Recommendation for visitors based on cognitive impact level."""
        recs = {
            "extremely_high": (
                "AVOID: This content presents extreme cognitive security risks. "
                "Do not engage or share without thorough independent verification."
            ),
            "high": (
                "CAUTION: This content uses significant influence techniques. "
                "Verify all claims through independent, authoritative sources."
            ),
            "moderate": (
                "EVALUATE: Apply critical thinking and seek corroboration "
                "from diverse, credible sources."
            ),
            "low": (
                "NORMAL: Standard critical thinking and media literacy apply."
            ),
            "negligible": (
                "CLEAR: No significant cognitive threats detected."
            ),
        }
        return recs.get(vuln_level, "")
