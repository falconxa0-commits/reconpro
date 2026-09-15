"""ReconPro — Prompt Injection Defense System.

Defends AI-facing components (chat, agent, nexus_agent) against prompt injection
attacks. This module is specifically for AI prompt/chat input defense — NOT for
scan data sanitization (see security.py / sanitize.py for that).

Classes:
    InjectionDetector    — Pattern-based injection detection (6 categories)
    ThreatClassifier     — Classifies detected threats into 5 severity levels
    PromptSanitizer      — Sanitizes user input for safe AI consumption
    DefenseAuditLogger   — Structured logging of all defense events
    PromptDefense        — Core facade combining all defenses

Pure Python, zero external dependencies.
"""
from __future__ import annotations

import hashlib
import json
import logging
import logging.handlers
import os
import re
import unicodedata
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple


logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

# Maximum allowed prompt length (tokens ≈ chars for ASCII)
MAX_PROMPT_LENGTH: int = 32_000

# Context overflow threshold — inputs longer than this trigger overflow checks
CONTEXT_OVERFLOW_THRESHOLD: int = 20_000

# Maximum number of repeating characters/lines before flagged
MAX_REPEAT_CHAR: int = 50
MAX_REPEAT_LINE: int = 10

# Audit log settings
_DEFENSE_LOG_DIR = os.path.join(os.path.expanduser("~"), ".reconpro")
_DEFENSE_LOG_FILE = "prompt_defense.log"


# ═══════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════


class ThreatLevel(Enum):
    """Severity levels for detected prompt injection threats."""
    CRITICAL = "critical"   # Direct system control / command execution attempts
    HIGH = "high"           # Data exfiltration, credential theft attempts
    MEDIUM = "medium"       # Context manipulation, delimiter injection
    LOW = "low"             # Suspicious patterns, potential probing
    INFO = "info"           # Benign but unusual patterns


@dataclass
class ThreatMatch:
    """A single threat match found in user input.

    Attributes:
        pattern_name: Human-readable name of the matched pattern.
        category: Category of the injection technique.
        matched_text: The actual text that matched the pattern.
        position: Character offset where the match was found.
        severity: Classified threat level.
        description: Human-readable description of why this is a threat.
    """
    pattern_name: str
    category: str
    matched_text: str
    position: int
    severity: ThreatLevel
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_name": self.pattern_name,
            "category": self.category,
            "matched_text": self.matched_text[:200],  # Truncate for safety
            "position": self.position,
            "severity": self.severity.value,
            "description": self.description,
        }


@dataclass
class ScanResult:
    """Result of scanning user input for injection threats.

    Attributes:
        is_safe: True if no threats were detected (or only info-level).
        threats: List of all detected ThreatMatch objects.
        max_severity: The highest severity threat found.
        sanitized_input: The input after sanitization.
        input_hash: SHA-256 hash of the original input.
        scan_timestamp: When the scan was performed.
    """
    is_safe: bool
    threats: List[ThreatMatch]
    max_severity: ThreatLevel
    sanitized_input: str
    input_hash: str
    scan_timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_safe": self.is_safe,
            "threat_count": len(self.threats),
            "max_severity": self.max_severity.value,
            "threats": [t.to_dict() for t in self.threats],
            "sanitized_length": len(self.sanitized_input),
            "input_hash": self.input_hash,
            "scan_timestamp": self.scan_timestamp,
        }


# ═══════════════════════════════════════════════════════════════════════════
#  INJECTION DETECTOR — Pattern-based detection (6 categories)
# ═══════════════════════════════════════════════════════════════════════════

# Whitespace-squashed attack phrases for de-obfuscation (scan_input only:
# catches "I  g  n  o  r  e     a  l  l     p  r  e  v  i  o  u  s ..." style
# padding).  Matched against input with ALL whitespace/zero-width chars removed.
_DEOBFUSCATION_MARKERS: tuple = (
    "ignoreallpreviousinstructions",
    "ignorepreviousinstructions",
    "ignoreallpriorinstructions",
    "ignoreallpriorprompts",
    "disregardallpreviousinstructions",
    "disregardpreviousinstructions",
    "forgetallpreviousinstructions",
    "forgetyourinstructions",
    "ignoreallyourinstructions",
    "youarenowadan",
    "youarenowanaiwithout",
    "disableyoursafetyfilter",
    "disablesafetyfilter",
    "turnoffyoursafetyfilter",
    "showmeursystemprompt",
    "revealursystemprompt",
    "printyoursystemprompt",
    "ignoreallrulesandrestrictions",
)


class InjectionDetector:
    """Pattern-based prompt injection detection engine.

    Detects six categories of prompt injection:
      1. Role manipulation — attempts to change system persona or ignore instructions
      2. Delimiter injection — attempts to break out of structured prompts
      3. Code injection — attempts to execute code via prompts
      4. Context overflow — extremely long inputs to dilute system context
      5. Data exfiltration — encoding sensitive data in model output
      6. Instruction hijacking — attempts to control system behavior directly

    All patterns are compiled regex using the standard ``re`` module.
    Each pattern is documented with its purpose and real-world attack examples.
    """

    def __init__(self) -> None:
        self._patterns: List[Tuple[str, str, Pattern[str], str, ThreatLevel]] = []
        self._compile_patterns()

    def _add(
        self,
        name: str,
        category: str,
        regex: str,
        description: str,
        severity: ThreatLevel,
        flags: int = re.IGNORECASE,
    ) -> None:
        """Compile and register a single detection pattern.

        Args:
            name: Human-readable pattern name.
            category: One of the 6 injection categories.
            regex: Raw regex pattern string.
            description: Why this pattern is dangerous.
            severity: Default severity when matched.
            flags: Regex flags (default: case-insensitive).
        """
        compiled = re.compile(regex, flags)
        self._patterns.append((name, category, compiled, description, severity))

    def _compile_patterns(self) -> None:
        """Build the complete pattern database.

        Patterns are organized by category and documented with
        real-world attack vectors they defend against.
        """

        # ─────────────────────────────────────────────────────────────
        # CATEGORY 1: Role Manipulation
        # Attacker tries to convince the AI to change its behavior,
        # ignore prior instructions, or adopt a new persona.
        # ─────────────────────────────────────────────────────────────

        # "Ignore all previous instructions" — the most classic injection
        self._add(
            name="ignore_previous_instructions",
            category="role_manipulation",
            regex=r"(?:(?:ignore|disregard|forget|discard|delete|erase|clear|drop|skip|overlook|neglect|override|undo|cancel|dismiss)\s+(?:(?:all|your|the|my|these|those)\s+)*(?:previous|prior|above|earlier|former|preceding|past|old|existing|current|system)\s+(?:instructions?|prompts?|directives?|rules?|guidelines?|orders?|commands?|settings?|constraints?|restrictions?|requirements?|policies?|system\s+prompts?))",
            description="Attempts to make the AI ignore its system instructions",
            severity=ThreatLevel.CRITICAL,
        )

        # "You are now..." — persona takeover
        self._add(
            name="persona_takeover",
            category="role_manipulation",
            regex=r"(?:(?:you\s+(?:are|have\s+become|will\s+be|must\s+be|should\s+be|need\s+to\s+be)\s+(?:now\s+)?(?:a|an|the)\s+)(?:helpful\s+assistant|evil|malicious|unrestricted|unfiltered|unbound|jailbroken|uncensored|dangerous|unhinged|rogue|rebel|liberated|free))",
            description="Attempts to override the AI's persona or role",
            severity=ThreatLevel.CRITICAL,
        )

        # "Pretend you are..." — role switching
        self._add(
            name="role_switching",
            category="role_manipulation",
            regex=r"(?:(?:pretend|act|imagine|roleplay|role-play|simulate|play|become|portray|embody|channel)\s+(?:you(?:'re|\s+are)\s+(?:a|an|the)?)?\s*(?:a|an|the)\s+(?:evil|malicious|unrestricted|unfiltered|jailbroken|uncensored|DAN|unhinged|rogue|unbound|helpful\s+assistant))",
            description="Attempts to make the AI pretend to be an unrestricted entity",
            severity=ThreatLevel.HIGH,
        )

        # "New instructions:" / "From now on:" — instruction override
        self._add(
            name="instruction_override",
            category="role_manipulation",
            regex=r"(?:(?:new\s+instructions?:|from\s+now\s+on[,:]?|starting\s+now[,:]?|henceforth[,:]?|hereafter[,:]?|from\s+this\s+point|effective\s+(?:immediately|now)))",
            description="Attempts to establish new overriding instructions",
            severity=ThreatLevel.HIGH,
        )

        # "System:" — system prompt injection
        self._add(
            name="system_prompt_injection",
            category="role_manipulation",
            regex=r"(?:^|\n)\s*(?:system|admin|developer|maintainer|operator|root|sudo|superuser|sysadmin)\s*[:=]\s*",
            description="Attempts to inject fake system-level directives",
            severity=ThreatLevel.CRITICAL,
        )

        # "Developer mode" — DAN-style attacks
        self._add(
            name="developer_mode",
            category="role_manipulation",
            regex=r"(?:(?:developer|admin|maintenance|debug|test|god|root|sudo|superuser|internal|backend)\s+(?:mode|access|panel|console|terminal|shell|override))",
            description="Attempts to activate a hidden 'developer' or 'admin' mode",
            severity=ThreatLevel.HIGH,
        )

        # "Do not follow" / "Break your rules"
        self._add(
            name="rule_violation_request",
            category="role_manipulation",
            regex=r"(?:(?:do\s+not\s+follow|break\s+(?:(?:your|the|all)\s+){1,2}|bypass|circumvent|evade|elude|go\s+around|work\s+around)\s*(?:(?:your|the|any|all|these|those)\s+)*(?:rules?|guidelines?|restrictions?|safety(?:\s+(?:restrictions?|measures?|filters?))?|filter|guardrail|policy|policies|limitation|constraint|protocol))",
            description="Directly requests the AI to violate its rules or safety measures",
            severity=ThreatLevel.HIGH,
        )

        # ─────────────────────────────────────────────────────────────
        # CATEGORY 2: Delimiter Injection
        # Attacker uses delimiters to break out of structured prompts
        # or inject content between sections.
        # ─────────────────────────────────────────────────────────────

        # "---END OF PROMPT---" style delimiter termination
        self._add(
            name="delimiter_termination",
            category="delimiter_injection",
            regex=r"(?:(?:-{3,}|={3,}|#{3,}|\*{3,}|_{3,}|~{3,})\s*(?:END|STOP|FINISH|CLOSE|DONE|TERMINATE|HALT|CUT|BREAK|DIVIDER|SEPARATOR)\s+(?:OF\s+)?(?:PROMPT|INPUT|INSTRUCTIONS?|CONTEXT|SYSTEM|USER|MESSAGE|TEXT|CHAT|CONVERSATION)\s*-{3,}|={3,}|#{3,}|\*{3,}|_{3,}|~{3,})",
            description="Uses delimiter patterns to terminate the current prompt section",
            severity=ThreatLevel.CRITICAL,
        )

        # XML/JSON structure injection
        self._add(
            name="structured_format_injection",
            category="delimiter_injection",
            regex=r"(?:<\/(?:system|instruction|prompt|context|rules?|guidelines?)>|<\/?system_prompt>|<\/?user_input>|\[\/?(?:SYSTEM|INSTRUCTION|PROMPT|CONTEXT)\])",
            description="Injects structured format tags to manipulate prompt structure",
            severity=ThreatLevel.HIGH,
        )

        # "### Response:" / "### Answer:" — response section injection
        self._add(
            name="response_section_injection",
            category="delimiter_injection",
            regex=r"(?:^|\n)\s*#{2,}\s*(?:response|answer|output|result|reply|completion|continuation|assistant|ai|bot)\s*:?\s*\n",
            description="Injects a fake response section to control AI output",
            severity=ThreatLevel.HIGH,
        )

        # "Human:" / "Assistant:" — conversation role injection
        self._add(
            name="conversation_role_injection",
            category="delimiter_injection",
            regex=r"(?:^|\n)\s*(?:Human|Assistant|User|AI|Bot|System|Admin|Mod)\s*:\s*",
            description="Injects fake conversation turns to manipulate multi-turn context",
            severity=ThreatLevel.MEDIUM,
        )

        # ─────────────────────────────────────────────────────────────
        # CATEGORY 3: Code Injection
        # Attempts to make the AI execute code or generate exploit code.
        # ─────────────────────────────────────────────────────────────

        # Python code execution via prompt
        self._add(
            name="python_execution_request",
            category="code_injection",
            regex=r"(?:(?:exec|eval|compile|__import__|subprocess|os\.system|os\.popen|Popen)\s*\(\s*['\"]?|(?:import\s+(?:os|subprocess|sys|shutil|ctypes|socket|ftplib|smtplib|telnetlib|pickle|marshal|yaml|code|codeop|compile|importlib))\b)",
            description="Attempts to trigger code execution via Python builtins or imports",
            severity=ThreatLevel.CRITICAL,
        )

        # Shell command injection
        self._add(
            name="shell_command_injection",
            category="code_injection",
            regex=r"(?:(?:\$\(|`[^`]+`|;\s*(?:rm|wget|curl|nc|ncat|bash|sh|zsh|python|perl|ruby|php)\b|\|\s*(?:sh|bash|nc|ncat)\b))",
            description="Injects shell commands via substitution or piping syntax",
            severity=ThreatLevel.CRITICAL,
        )

        # File system access attempts
        self._add(
            name="filesystem_access",
            category="code_injection",
            regex=r"(?:(?:open\s*\(\s*['\"][^'\"]*(?:/etc/|/proc/|/sys/|/dev/|~/.ssh|~/.gnupg|/var/|/root/|/home/|passwords?|shadow|id_rsa|authorized_keys))|(?:open|read|write|delete|remove|copy|move|cat|access)\s+(?:(?:the|this|that|my)\s+)?(?:file|directory|folder)\s+(?:(?:at|in|from|to)\s+)?['\"]?(?:/etc/|/proc/|/sys/|/dev/|/root/|/var/|/tmp/|~/.ssh|~/.gnupg|/home/))",
            description="Attempts to access sensitive filesystem locations via prompts",
            severity=ThreatLevel.HIGH,
        )

        # Network access / C2 attempts
        self._add(
            name="network_access",
            category="code_injection",
            regex=r"(?:(?:connect\s+to|send\s+(?:data|request|packet|payload)\s+to|make\s+(?:a\s+)?(?:request|connection)\s+to|download\s+from|upload\s+to|exfiltrate\s+(?:data|to|via))\s+(?:https?://|ftp://|sftp://|ssh://|\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}))",
            description="Attempts to establish network connections or exfiltrate data",
            severity=ThreatLevel.HIGH,
        )

        # Template injection (SSTI, Jinja2, etc.)
        self._add(
            name="template_injection",
            category="code_injection",
            regex=r"(?:\{\{.*?(?:__class__|__mro__|__subclasses__|__builtins__|__globals__|__base__|__init__|request|config|self|lipsum|cycler|joiner|namespace).*?\}\}|\{\%-?\s*(?:for|if|set|import|extends|include|block|macro)\b)",
            description="Server-Side Template Injection (SSTI) via Jinja2/templating syntax",
            severity=ThreatLevel.CRITICAL,
        )

        # ─────────────────────────────────────────────────────────────
        # CATEGORY 4: Context Overflow
        # Extremely long inputs designed to dilute system instructions
        # and push them out of the context window.
        # ─────────────────────────────────────────────────────────────

        # Repeating characters (filler to push context out)
        # This is checked programmatically in detect(), not via regex.

        # "Repeat the word X" — token flooding
        self._add(
            name="token_flooding",
            category="context_overflow",
            regex=r"(?:(?:repeat\s+(?:the\s+)?(?:word|phrase|sentence|line|character)\s+[\"']?[a-zA-Z]{1,10}[\"']?\s+(?:\d+|many|lots|a\s+lot|infinite|endless|forever)\s+times?|(?:say|write|print|output|type)\s+[\"']?[a-zA-Z]{1,10}[\"']?\s+(?:\d+|many|lots|a\s+lot|infinite|endless|forever)\s+times?))",
            description="Requests repetitive output to flood the token window",
            severity=ThreatLevel.MEDIUM,
        )

        # "Ignore everything above" — context dismissal
        self._add(
            name="context_dismissal",
            category="context_overflow",
            regex=r"(?:(?:ignore\s+(?:everything|all)\s+(?:above|before|prior|earlier|up\s+to\s+here)|forget\s+(?:everything|all)\s+(?:above|before|prior|earlier)|the\s+(?:above|previous|prior)\s+(?:text|content|instructions?|context|information)\s+(?:is|are|was|were)\s+(?:irrelevant|wrong|invalid|deprecated|obsolete|false|fake|not\s+real|imaginary|fictional)))",
            description="Attempts to dismiss the existing context window content",
            severity=ThreatLevel.HIGH,
        )

        # Long irrelevant story/poem to push context
        self._add(
            name="context_filler",
            category="context_overflow",
            regex=r"(?:(?:once\s+upon\s+a\s+time|in\s+a\s+(?:land|world|kingdom|place)\s+(?:far\s+)?(?:away|beyond)|it\s+was\s+a\s+(?:dark|stormy|bright|sunny)\s+(?:and|night|day)\s+when).{200,})",
            description="Long narrative filler used to dilute system context",
            severity=ThreatLevel.LOW,
        )

        # ─────────────────────────────────────────────────────────────
        # CATEGORY 5: Data Exfiltration
        # Attempts to encode sensitive system data into AI outputs
        # that the attacker can decode later.
        # ─────────────────────────────────────────────────────────────

        # Base64 encoding request
        self._add(
            name="base64_exfiltration",
            category="data_exfiltration",
            regex=r"(?:(?:encode|convert|translate|transform|render|output|return|respond\s+with|reply\s+with|print|write|display|show)\s+(?:(?:the|your|all|my)\s+)?(?:(?:above|previous|system|entire|full|complete|whole|original|secret|hidden)\s+)*(?:(?:data|text|content|prompt|prompts|instructions|message|response|answer|output|rules|context|configuration)\s+)*(?:as|in|to|into|using)\s+(?:base64|hex|binary|unicode|utf-?8|ascii|rot13|caesar|morse|braille)\b(?:\s+(?:encoding|format|code|representation|string))?)",
            description="Requests encoding of system data into a decodable format",
            severity=ThreatLevel.HIGH,
        )

        # "Reveal your instructions" / "What are your rules"
        self._add(
            name="instruction_leak",
            category="data_exfiltration",
            regex=r"(?:(?:reveal|show|display|output|print|tell|say|state|share|disclose|leak|dump|paste|echo|repeat|recite|quote|read\s+(?:out|back|aloud)|write\s+(?:out|down))\s+(?:me\s+)?(?:(?:your|the|all|every)\s+)?(?:(?:exact|full|complete|original|initial|first|entire)\s+)*(?:system\s+)?(?:instructions?|prompts?|rules?|guidelines?|directives?|orders?|commands?|settings?|configuration|constraints?|restrictions?|setup|initialization|boot|pre|prefix))",
            description="Attempts to extract the system prompt or instructions",
            severity=ThreatLevel.HIGH,
        )

        # "What was your first message" / "Repeat your training data"
        self._add(
            name="training_data_extraction",
            category="data_exfiltration",
            regex=r"(?:(?:what\s+(?:is|are|was|were)\s+your\s+(?:first|original|initial|system|hidden|secret|private|internal)\s+(?:(?:system|hidden|secret|initial)\s+)?(?:message|prompt|instruction|rule|guideline|directive|command|setting|configuration)|repeat\s+(?:your|the)\s+(?:training|pre-training|fine-tuning|system)\s+(?:data|text|content|material)|what\s+(?:prompt|instructions?|context|system\s+message)\s+(?:were|was|are|is)\s+(?:given|provided|used|fed|supplied|injected)\s+to\s+you))",
            description="Attempts to extract training data, system prompts, or hidden context",
            severity=ThreatLevel.HIGH,
        )

        # Invisible/zero-width character steganography
        self._add(
            name="steganography_request",
            category="data_exfiltration",
            regex=r"(?:(?:use|hide|embed|conceal|inject|place|put|insert)\s+(?:(?:the|your)\s+)?(?:data|information|message|text|response|answer|output)\s+(?:in|within|inside|using|via|through|with)\s+(?:(?:invisible|zero-width|zero\s*width|hidden|steganograph\w*|unicode|whitespace|blank|empty)\s+){1,2}(?:characters?|text|spaces?|glyphs?|symbols?|runes?))",
            description="Requests steganographic encoding of data in invisible characters",
            severity=ThreatLevel.HIGH,
        )

        # "Output in JSON/XML" to structure exfiltrated data
        self._add(
            name="structured_exfiltration",
            category="data_exfiltration",
            regex=r"(?:(?:output|respond|reply|return|print|write|display|give\s+me)\s+(?:(?:your|the|all|every|entire|full|complete)\s+){1,2}(?:system\s+)?(?:prompt|instructions?|rules?|settings?|configuration|context|memory|state|internal|hidden|secret|private)\s+(?:as|in|into|using)\s+(?:JSON|XML|YAML|TOML|CSV|markdown|code\s+block|fenced\s+block|data\s+structure|structured\s+format|serialized))",
            description="Requests structured output format to extract system configuration",
            severity=ThreatLevel.HIGH,
        )

        # ─────────────────────────────────────────────────────────────
        # CATEGORY 6: Instruction Hijacking
        # Attempts to directly control the AI's behavior, tool usage,
        # or decision-making process.
        # ─────────────────────────────────────────────────────────────

        # "Run the following command" / "Execute this code"
        self._add(
            name="direct_command",
            category="instruction_hijacking",
            regex=r"(?:(?:run|execute|perform|carry\s+out|do|implement|apply|process|invoke|call)\s+(?:the\s+)?(?:following|this|these|below|next|command|code|script|program|instruction|action|operation|task|step|query))",
            description="Directly commands the AI to execute arbitrary instructions",
            severity=ThreatLevel.HIGH,
        )

        # "Call this API" / "Use this tool"
        self._add(
            name="tool_hijacking",
            category="instruction_hijacking",
            regex=r"(?:(?:call|invoke|use|access|trigger|activate|run|execute|send\s+(?:a\s+)?request\s+to)\s+(?:the\s+)?(?:API|endpoint|function|tool|plugin|module|service|webhook|callback|handler|interface)\s+(?:at|on|with|using|via))",
            description="Attempts to hijack tool/API usage with attacker-controlled parameters",
            severity=ThreatLevel.HIGH,
        )

        # "Scan this target" with embedded malicious intent
        self._add(
            name="malicious_scan_redirect",
            category="instruction_hijacking",
            regex=r"(?:(?:scan|audit|attack|test|probe|check|fuzz|exploit|hack|penetrat)\s+(?:this|the|these|my|our|a)\s+(?:target|host|server|system|network|machine|address|ip|url|endpoint)\s*(?:at|on|:|\(|=)\s*)",
            description="Redirects scan/audit tools to attacker-controlled targets",
            severity=ThreatLevel.MEDIUM,
        )

        # "Your new task is..." — task reassignment
        self._add(
            name="task_reassignment",
            category="instruction_hijacking",
            regex=r"(?:(?:your\s+(?:new|next|only|primary|real|actual|true)\s+(?:task|goal|objective|mission|purpose|job|role|duty|assignment|instruction|directive|priority|focus)\s+is|I\s+(?:want|need|require|demand|insist|command|order)\s+you\s+to))",
            description="Attempts to reassign the AI's task or purpose",
            severity=ThreatLevel.HIGH,
        )

        # "Disable safety" / "Turn off filtering"
        self._add(
            name="safety_disabling",
            category="instruction_hijacking",
            regex=r"(?:(?:disable|turn\s+off|deactivate|shut\s+off|remove|eliminate|get\s+rid\s+of|bypass|override|suppress|supress)\s+(?:(?:your|the|all|any|this|that|content)\s+)*(?:safety\s+)?(?:filter|filtering|moderation|guardrail|restriction|limitation|constraint|block|censor|censorship|protection|firewall|shield|defense|monitor|watchdog|safety))",
            description="Directly requests disabling of safety mechanisms",
            severity=ThreatLevel.CRITICAL,
        )

        # Multi-step attack chains ("Step 1: ... Step 2: ... Step 3: ...")
        self._add(
            name="multi_step_attack",
            category="instruction_hijacking",
            regex=r"(?:(?:step\s+\d+\s*[:.]\s*(?:(?:first|second|third|then|next|after\s+that|finally|lastly)\s+)?(?:ignore|bypass|disable|override|break|hack|exploit|extract|exfiltrate|access|connect|download|upload|install|run|execute|scan)|\b(?:step\s+)?\d+\.\s*(?:ignore|bypass|disable|break|hack|exploit)\s))",
            description="Multi-step attack chain often used in sophisticated prompt injection",
            severity=ThreatLevel.CRITICAL,
        )

        # Multilingual injection (ES/FR/DE/PT/RU variants of "ignore previous
        # instructions" / "you are now unrestricted")
        self._add(
            name="multilingual_injection",
            category="role_manipulation",
            regex=r"(?:(?:ignora(?:r)?(?:\s+(?:todas?|todos|los|las))?\s+instrucciones|ignore\s+(?:toutes?|tous)\s+(?:les\s+)?instructions|ignoriere\s+(?:alle\s+)?(?:vorherigen\s+)?(?:anweisungen|anweisung)|ignora\s+(?:todas?|todos)\s+as\s+instru[cç][õo]es|проигнорируй\s+(?:все\s+)?(?:предыдущие\s+)?инструкции|eres\s+ahora\s+(?:un|una)\s+(?:asistente|asistente)?\s*sin\s+restricciones|tu\s+es\s+maintenant\s+un\s+assistant\s+sans\s+restrictions?))",
            description="Prompt injection phrased in a non-English language",
            severity=ThreatLevel.CRITICAL,
        )

    def detect(self, text: str) -> List[ThreatMatch]:
        """Scan input text for all known injection patterns.

        Args:
            text: The user input to scan.

        Returns:
            List of ThreatMatch objects for each detected pattern.
        """
        if not text or not text.strip():
            return []

        threats: List[ThreatMatch] = []

        # Regex-based pattern matching
        for name, category, pattern, description, severity in self._patterns:
            for match in pattern.finditer(text):
                threats.append(ThreatMatch(
                    pattern_name=name,
                    category=category,
                    matched_text=match.group(0),
                    position=match.start(),
                    severity=severity,
                    description=description,
                ))

        # Programmatic checks (not easily expressed as regex)

        # Check for repeating characters (context overflow indicator)
        char_repeat = self._detect_char_repetition(text)
        if char_repeat:
            threats.append(ThreatMatch(
                pattern_name="excessive_char_repetition",
                category="context_overflow",
                matched_text=char_repeat[:50],
                position=text.index(char_repeat) if char_repeat in text else 0,
                severity=ThreatLevel.MEDIUM,
                description="Excessive character repetition detected — possible context overflow attempt",
            ))

        # Check for repeating lines (token flooding)
        line_repeat = self._detect_line_repetition(text)
        if line_repeat:
            threats.append(ThreatMatch(
                pattern_name="excessive_line_repetition",
                category="context_overflow",
                matched_text=line_repeat[:80],
                position=text.index(line_repeat) if line_repeat in text else 0,
                severity=ThreatLevel.MEDIUM,
                description="Excessive line repetition detected — possible token flooding attempt",
            ))

        # Check for zero-width / invisible characters (steganography)
        zw_chars = self._detect_zero_width_chars(text)
        if zw_chars:
            threats.append(ThreatMatch(
                pattern_name="zero_width_characters",
                category="data_exfiltration",
                matched_text=f"<{len(zw_chars)} invisible chars>",
                position=0,
                severity=ThreatLevel.HIGH,
                description=f"Zero-width/invisible characters detected — potential steganographic data channel ({len(zw_chars)} chars)",
            ))

        # Check for mixed-script homoglyphs (spoofing)
        homoglyphs = self._detect_homoglyph_spoofing(text)
        if homoglyphs:
            threats.append(ThreatMatch(
                pattern_name="homoglyph_spoofing",
                category="role_manipulation",
                matched_text=homoglyphs[:50],
                position=text.index(homoglyphs) if homoglyphs in text else 0,
                severity=ThreatLevel.MEDIUM,
                description="Mixed-script characters detected — potential keyword obfuscation via homoglyphs",
            ))

        return threats

    @staticmethod
    def _detect_char_repetition(text: str) -> str:
        """Detect if any single character repeats beyond the threshold."""
        # Check for runs of the same character
        for char in set(text):
            run = char * (MAX_REPEAT_CHAR + 1)
            if run in text:
                return run
        return ""

    @staticmethod
    def _detect_line_repetition(text: str) -> str:
        """Detect if any line repeats beyond the threshold."""
        lines = text.split("\n")
        line_counts: Dict[str, int] = defaultdict(int)
        for line in lines:
            stripped = line.strip()
            if stripped and len(stripped) > 1:
                line_counts[stripped] += 1

        for line, count in line_counts.items():
            if count >= MAX_REPEAT_LINE:
                return line
        return ""

    @staticmethod
    def _detect_zero_width_chars(text: str) -> str:
        """Detect zero-width and invisible Unicode characters."""
        zero_width_ranges = [
            (0x200B, 0x200F),   # Zero-width space, joiners, etc.
            (0x2028, 0x202E),   # Line/paragraph separator, bidirectional
            (0x2060, 0x2064),   # Word joiner, invisible operators
            (0xFEFF, 0xFEFF),   # BOM / zero-width no-break space
            (0x00AD, 0x00AD),   # Soft hyphen
            (0x034F, 0x034F),   # Combining grapheme joiner
            (0x180E, 0x180E),   # Mongolian vowel separator
            (0x2066, 0x2069),   # Bidirectional controls
            (0xFFF9, 0xFFFB),   # Interlinear annotations
        ]
        found = ""
        for ch in text:
            cp = ord(ch)
            for start, end in zero_width_ranges:
                if start <= cp <= end:
                    found += ch
                    break
        return found

    @staticmethod
    def _detect_homoglyph_spoofing(text: str) -> str:
        """Detect mixed Latin/Cyrillic/Greek characters (homoglyph attacks).

        Attackers use visually identical characters from different scripts
        to bypass keyword filters (e.g., Cyrillic 'а' for Latin 'a').
        """
        scripts_found: Set[str] = set()
        suspicious = ""

        for ch in text:
            if not ch.isalpha():
                continue
            name = unicodedata.name(ch, "")
            if "CYRILLIC" in name:
                scripts_found.add("cyrillic")
                suspicious += ch
            elif "GREEK" in name:
                scripts_found.add("greek")
                suspicious += ch
            elif "LATIN" in name:
                scripts_found.add("latin")

        # If we have more than one script, it could be a homoglyph attack
        if len(scripts_found) > 1 and suspicious:
            return suspicious
        return ""

    @property
    def pattern_count(self) -> int:
        """Return the total number of registered detection patterns."""
        return len(self._patterns)

    def list_patterns(self) -> List[Dict[str, str]]:
        """List all registered patterns for documentation/testing.

        Returns:
            List of dicts with name, category, description, severity.
        """
        return [
            {
                "name": name,
                "category": category,
                "description": desc,
                "severity": sev.value,
            }
            for name, category, _, desc, sev in self._patterns
        ]


# ═══════════════════════════════════════════════════════════════════════════
#  THREAT CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════


# Severity ordering for comparison
_SEVERITY_ORDER: Dict[ThreatLevel, int] = {
    ThreatLevel.CRITICAL: 5,
    ThreatLevel.HIGH: 4,
    ThreatLevel.MEDIUM: 3,
    ThreatLevel.LOW: 2,
    ThreatLevel.INFO: 1,
}


class ThreatClassifier:
    """Classifies detected prompt injection threats by severity.

    Takes raw ThreatMatch objects and applies contextual rules to
    determine the final threat level. Rules consider:
      - The inherent severity of the matched pattern
      - The number of distinct threat categories found
      - The total number of threats (multi-vector attacks)
      - Input length relative to the context overflow threshold
      - Whether the input targets specific system components

    Severity levels:
      - critical: Direct system control attempts, multi-vector attacks, safety disabling
      - high: Data exfiltration, credential theft, role manipulation
      - medium: Context manipulation, delimiter injection, probing
      - low: Suspicious patterns, potential reconnaissance
      - info: Benign but unusual (e.g., uncommon formatting)
    """

    # Categories that elevate to critical when combined with others
    _CRITICAL_CATEGORIES: Set[str] = {
        "role_manipulation",
        "code_injection",
        "instruction_hijacking",
    }

    # Patterns that are always critical regardless of context
    _ALWAYS_CRITICAL: Set[str] = {
        "system_prompt_injection",
        "ignore_previous_instructions",
        "persona_takeover",
        "python_execution_request",
        "shell_command_injection",
        "template_injection",
        "safety_disabling",
        "multi_step_attack",
        "delimiter_termination",
    }

    # Patterns that are always high regardless of context
    _ALWAYS_HIGH: Set[str] = {
        "base64_exfiltration",
        "instruction_leak",
        "training_data_extraction",
        "steganography_request",
        "structured_exfiltration",
        "zero_width_characters",
        "developer_mode",
        "rule_violation_request",
        "task_reassignment",
        "direct_command",
        "tool_hijacking",
    }

    def classify(self, threats: List[ThreatMatch], input_text: str = "") -> ThreatLevel:
        """Classify the overall threat level from detected threats.

        Args:
            threats: List of ThreatMatch objects from InjectionDetector.
            input_text: The original input (for contextual analysis).

        Returns:
            The highest applicable ThreatLevel.
        """
        if not threats:
            # Check for unusual but benign patterns in the input
            if input_text and self._is_unusual_benign(input_text):
                return ThreatLevel.INFO
            return ThreatLevel.INFO

        # Check for always-critical patterns
        for threat in threats:
            if threat.pattern_name in self._ALWAYS_CRITICAL:
                return ThreatLevel.CRITICAL

        # Check for always-high patterns
        has_high = False
        for threat in threats:
            if threat.pattern_name in self._ALWAYS_HIGH:
                has_high = True
                break

        # Multi-vector attack: threats from 2+ critical categories
        categories: Set[str] = {t.category for t in threats}
        critical_cats = categories & self._CRITICAL_CATEGORIES
        if len(critical_cats) >= 2:
            return ThreatLevel.CRITICAL

        # Escalation: high + any other threat category
        if has_high and len(categories) >= 2:
            return ThreatLevel.CRITICAL

        # High severity patterns present
        if has_high:
            return ThreatLevel.HIGH

        # Check inherent severity of threats
        max_inherent = max(threats, key=lambda t: _SEVERITY_ORDER[t.severity])
        if max_inherent.severity in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            return max_inherent.severity

        # Multiple medium threats = high
        medium_count = sum(1 for t in threats if t.severity == ThreatLevel.MEDIUM)
        if medium_count >= 3:
            return ThreatLevel.HIGH

        # Context: long input with any threats
        if input_text and len(input_text) > CONTEXT_OVERFLOW_THRESHOLD and threats:
            return ThreatLevel.MEDIUM

        # Return highest inherent severity
        return max_inherent.severity

    def classify_threat(self, input_text: str) -> ThreatLevel:
        """Convenience method: detect and classify in one call.

        Args:
            input_text: The user input to analyze.

        Returns:
            Classified ThreatLevel.
        """
        detector = InjectionDetector()
        threats = detector.detect(input_text)
        return self.classify(threats, input_text)

    @staticmethod
    def _is_unusual_benign(text: str) -> bool:
        """Check if text is benign but has unusual characteristics.

        Returns True if the text contains patterns that are not threatening
        but are uncommon enough to warrant INFO-level logging.
        """
        if not text:
            return False

        # Very short inputs are normal
        if len(text) < 10:
            return False

        # Check for unusual formatting
        unusual_count = 0

        # Excessive punctuation
        if re.search(r'[!]{3,}', text):
            unusual_count += 1
        if re.search(r'[?]{3,}', text):
            unusual_count += 1

        # All caps (except very short inputs)
        if len(text) > 20 and text.isupper():
            unusual_count += 1

        # Unusual Unicode (non-Latin script mixed with Latin)
        non_latin = sum(1 for ch in text if ord(ch) > 0x024F and ch.isalpha())
        if non_latin > 5 and non_latin < len(text) * 0.5:
            unusual_count += 1

        # Multiple languages detected (simple heuristic)
        has_cjk = any(0x4E00 <= ord(ch) <= 0x9FFF for ch in text)
        has_arabic = any(0x0600 <= ord(ch) <= 0x06FF for ch in text)
        has_latin = any(0x0041 <= ord(ch) <= 0x024F for ch in text)
        lang_count = sum([has_cjk, has_arabic, has_latin])
        if lang_count >= 2:
            unusual_count += 1

        return unusual_count >= 2


# ═══════════════════════════════════════════════════════════════════════════
#  PROMPT SANITIZER
# ═══════════════════════════════════════════════════════════════════════════


class PromptSanitizer:
    """Sanitizes user input for safe consumption by AI systems.

    Unlike security.sanitize_target (which handles scan targets, paths, URLs),
    this class specifically sanitizes prompts and chat inputs for AI contexts.

    Sanitization steps:
      1. Strip dangerous control sequences (ANSI escapes, zero-width chars)
      2. Escape special characters that could confuse prompt parsing
      3. Enforce input length limits
      4. Normalize whitespace and Unicode encoding
      5. Remove or neutralize known injection structure patterns
    """

    def __init__(
        self,
        max_length: int = MAX_PROMPT_LENGTH,
        strip_control_sequences: bool = True,
        normalize_unicode: bool = True,
        escape_special_chars: bool = True,
    ) -> None:
        self.max_length = max_length
        self.strip_control_sequences = strip_control_sequences
        self.normalize_unicode = normalize_unicode
        self.escape_special_chars = escape_special_chars

    def sanitize(self, prompt: str) -> str:
        """Fully sanitize a prompt for safe AI consumption.

        Args:
            prompt: Raw user input prompt.

        Returns:
            Sanitized prompt string safe for AI processing.
        """
        if not prompt:
            return ""

        result = prompt

        # Step 1: Normalize Unicode
        if self.normalize_unicode:
            result = self._normalize_unicode(result)

        # Step 2: Strip control sequences
        if self.strip_control_sequences:
            result = self._strip_control_sequences(result)

        # Step 3: Escape special characters
        if self.escape_special_chars:
            result = self._escape_special_chars(result)

        # Step 4: Neutralize injection structures
        result = self._neutralize_structures(result)

        # Step 5: Normalize whitespace
        result = self._normalize_whitespace(result)

        # Step 6: Enforce length limit
        result = self._enforce_length(result)

        return result

    @staticmethod
    def _normalize_unicode(text: str) -> str:
        """Normalize Unicode to NFC form and replace homoglyphs.

        Converts visually similar characters from non-Latin scripts
        to their Latin equivalents where possible.
        """
        # NFC normalization
        result = unicodedata.normalize("NFC", text)

        # Replace common Cyrillic homoglyphs with Latin equivalents
        homoglyph_map = {
            '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041A': 'K',
            '\u041C': 'M', '\u041D': 'H', '\u041E': 'O', '\u0420': 'P',
            '\u0421': 'C', '\u0422': 'T', '\u0425': 'X',
            '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u043A': 'k',
            '\u043C': 'm', '\u043F': 'p', '\u0441': 'c', '\u0443': 'y',
            '\u0445': 'x',
            # Greek homoglyphs
            '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z',
            '\u0397': 'H', '\u0399': 'I', '\u039A': 'K', '\u039C': 'M',
            '\u039D': 'N', '\u039F': 'O', '\u03A1': 'P', '\u03A4': 'T',
            '\u03A5': 'Y', '\u03A7': 'X',
            '\u03B1': 'a', '\u03B2': 'B', '\u03B5': 'e', '\u03B6': 'z',
            '\u03B7': 'n', '\u03B9': 'i', '\u03BA': 'k', '\u03BC': 'm',
            '\u03BD': 'v', '\u03BF': 'o', '\u03C1': 'p', '\u03C4': 't',
            '\u03C5': 'u', '\u03C7': 'x',
        }
        for cyrillic, latin in homoglyph_map.items():
            result = result.replace(cyrillic, latin)

        return result

    @staticmethod
    def _strip_control_sequences(text: str) -> str:
        """Remove ANSI escape sequences, zero-width chars, and control chars.

        Preserves newlines (\n), tabs (\t), and regular spaces.
        """
        result = text

        # Remove ANSI escape sequences (CSI: ESC [ ... final_byte)
        result = re.sub(r'\x1B\[[0-9;]*[a-zA-Z]', '', result)
        # Remove OSC sequences (ESC ] ... BEL or ESC \\)  
        result = re.sub(r'\x1B\][^\x07]*\x07', '', result)
        result = re.sub(r'\x1B\][^\x1B]*\x1B\\', '', result)
        # Remove other ESC sequences
        result = re.sub(r'\x1B[^\[\]].', '', result)

        # Remove zero-width and invisible Unicode characters
        zero_width_ranges = [
            (0x200B, 0x200F),
            (0x2028, 0x202E),
            (0x2060, 0x2064),
            (0xFEFF, 0xFEFF),
            (0x00AD, 0x00AD),
            (0x034F, 0x034F),
            (0x180E, 0x180E),
            (0x2066, 0x2069),
            (0xFFF9, 0xFFFB),
        ]
        cleaned = []
        for ch in result:
            cp = ord(ch)
            is_zero_width = any(start <= cp <= end for start, end in zero_width_ranges)
            if not is_zero_width:
                cleaned.append(ch)
        result = ''.join(cleaned)

        # Remove other control characters (keep \n, \t, \r)
        result = ''.join(
            ch for ch in result
            if ord(ch) >= 0x20 or ch in ('\n', '\t', '\r')
        )

        # Remove null bytes
        result = result.replace('\x00', '')

        return result

    @staticmethod
    def _escape_special_chars(text: str) -> str:
        """Escape characters that could confuse prompt structure parsing.

        Specifically targets:
          - Backslash-heavy sequences (escape character abuse)
          - Excessive markup characters
          - Backtick code fence abuse
        """
        result = text

        # Collapse excessive backslashes (max 2 in a row)
        result = re.sub(r'\\{4,}', '\\\\', result)

        # NOTE: backtick-fence abuse is handled by _neutralize_structures
        # (which collapses the FIRST 4+ run to a standard ``` and removes
        # later runs) — not here, so the two rules cannot fight each other.

        return result

    @staticmethod
    def _neutralize_structures(text: str) -> str:
        """Neutralize known injection structure patterns.

        Rather than removing content (which could break legitimate input),
        this method breaks the structure of injection patterns by inserting
        spaces within matched delimiter sequences.
        """
        result = text

        # Break "===END OF PROMPT===" style patterns
        result = re.sub(
            r'(-{3,}|={3,}|#{3,}|\*{3,})\s*(?:END|STOP|FINISH|CLOSE|DONE|TERMINATE|HALT)\s+(?:OF\s+)?(?:PROMPT|INPUT|INSTRUCTIONS?|CONTEXT|SYSTEM|USER|MESSAGE|TEXT|CHAT|CONVERSATION)\s*(-{3,}|={3,}|#{3,}|\*{3,})',
            lambda m: ' '.join(m.group(0)),
            result,
            flags=re.IGNORECASE,
        )

        # Break XML-style tag injection (replace angle brackets with escaped form)
        result = re.sub(
            r'</(?:system|instruction|prompt|context|rules?|guidelines?|system_prompt|user_input)>',
            lambda m: m.group(0).replace('<', '&lt;').replace('>', '&gt;'),
            result,
            flags=re.IGNORECASE,
        )

        # Break "### Response:" / "### Assistant:" patterns
        result = re.sub(
            r'#{2,}\s*(?:response|answer|output|result|reply|completion|assistant|ai|bot)\s*:',
            lambda m: '# ' + m.group(0).lstrip('#').strip(),
            result,
            flags=re.IGNORECASE,
        )

        # Collapse backtick abuse: a run of 4+ backticks is a fake code
        # fence (injection structure).  The first run collapses to a
        # standard ``` fence; every later 4+ run is removed so the result
        # contains at most ONE fence marker from abused runs.
        parts = re.split(r'`{4,}', result)
        if len(parts) > 1:
            cleaned = parts[0]
            for i, segment in enumerate(parts[1:]):
                cleaned += ('```' if i == 0 else '') + segment
            result = cleaned

        return result

    @staticmethod
    def _normalize_whitespace(text: str) -> str:
        """Normalize whitespace: collapse runs, trim, handle line endings."""
        # Normalize line endings to \n
        result = text.replace('\r\n', '\n').replace('\r', '\n')
        # Collapse multiple spaces into one (but preserve leading indentation)
        lines = result.split('\n')
        normalized_lines = []
        for line in lines:
            # Preserve leading whitespace (indentation), collapse the rest
            stripped = line.lstrip()
            leading = line[:len(line) - len(stripped)]
            stripped = re.sub(r' {2,}', ' ', stripped)
            # Collapse multiple tabs to one
            stripped = re.sub(r'\t{2,}', '\t', stripped)
            normalized_lines.append(leading + stripped)
        result = '\n'.join(normalized_lines)
        # Remove excessive blank lines (more than 3 consecutive)
        result = re.sub(r'\n{4,}', '\n\n\n', result)
        # Strip trailing whitespace and leading blank lines — but PRESERVE the
        # first line's indentation (code prompts keep their leading spaces).
        result = result.rstrip()
        result = re.sub(r'^\n+', '', result)
        return result

    def _enforce_length(self, text: str) -> str:
        """Enforce maximum prompt length.

        Truncates at the nearest sentence boundary or word boundary
        within 10% of the limit to avoid cutting mid-word.

        Args:
            text: Text to potentially truncate.

        Returns:
            Text truncated to at most self.max_length characters.
        """
        if len(text) <= self.max_length:
            return text

        # Try to truncate at a sentence boundary within the last 10%
        search_start = max(0, self.max_length - int(self.max_length * 0.1))
        truncated = text[:self.max_length]

        # Look for sentence endings in the last 10%
        for i in range(len(truncated) - 1, search_start - 1, -1):
            if truncated[i] in ('.', '!', '?') and (i + 1 >= len(truncated) or truncated[i + 1] == ' '):
                return truncated[:i + 1].rstrip() + "\n[Input truncated: exceeded maximum length]"

        # Fall back to word boundary
        last_space = truncated.rfind(' ')
        if last_space > search_start:
            return truncated[:last_space].rstrip() + "\n[Input truncated: exceeded maximum length]"

        # Last resort: hard truncate
        return truncated + "\n[Input truncated: exceeded maximum length]"


# ═══════════════════════════════════════════════════════════════════════════
#  DEFENSE AUDIT LOGGER
# ═══════════════════════════════════════════════════════════════════════════


class DefenseAuditLogger:
    """Structured audit logging for prompt defense events.

    Tracks all scanned inputs, blocked attempts, and threat statistics.
    Logs to ~/.reconpro/prompt_defense.log with rotation.

    Events logged:
      - INPUT_SCANNED: Every input that passes through the defense system
      - THREAT_DETECTED: When any threat pattern is matched
      - INPUT_BLOCKED: When critical/high threats cause input rejection
      - INPUT_SANITIZED: When input is modified during sanitization
    """

    _MAX_BYTES = 10 * 1024 * 1024  # 10 MB
    _BACKUP_COUNT = 5

    def __init__(self, log_dir: Optional[str] = None) -> None:
        if log_dir is None:
            log_dir = _DEFENSE_LOG_DIR
        self._log_dir = log_dir
        self._log_path = os.path.join(log_dir, _DEFENSE_LOG_FILE)

        # Ensure directory exists
        os.makedirs(log_dir, exist_ok=True)

        # Statistics
        self._stats: Dict[str, int] = defaultdict(int)
        self._threat_pattern_counts: Dict[str, int] = defaultdict(int)
        self._threat_category_counts: Dict[str, int] = defaultdict(int)
        self._threat_severity_counts: Dict[str, int] = defaultdict(int)
        self._blocked_count: int = 0
        self._scanned_count: int = 0
        self._sanitized_count: int = 0

        # Set up rotating file logger
        self._handler = logging.handlers.RotatingFileHandler(
            self._log_path,
            maxBytes=self._MAX_BYTES,
            backupCount=self._BACKUP_COUNT,
            encoding="utf-8",
        )
        self._handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger = logging.getLogger("reconpro.prompt_defense")
        self._logger.setLevel(logging.DEBUG)
        if not self._logger.handlers:
            self._logger.addHandler(self._handler)

    def _emit(self, level: str, event: Dict[str, Any]) -> None:
        """Emit a structured JSON log entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            **event,
        }
        try:
            msg = json.dumps(entry, default=str)
        except (TypeError, ValueError):
            msg = json.dumps({"timestamp": entry["timestamp"], "level": level, "error": "serialization_failed"})

        if level == "ALERT":
            self._logger.critical(msg)
        elif level == "WARN":
            self._logger.warning(msg)
        else:
            self._logger.info(msg)

    def log_scan(self, result: ScanResult, input_text: str, source: str = "unknown") -> None:
        """Log the result of an input scan.

        Args:
            result: The ScanResult from PromptDefense.scan_input().
            input_text: The original input text (will be hashed, not stored).
            source: Where the input came from ("chat", "agent", "nexus", etc.).
        """
        self._scanned_count += 1

        # Update statistics
        self._threat_severity_counts[result.max_severity.value] += 1
        for threat in result.threats:
            self._threat_pattern_counts[threat.pattern_name] += 1
            self._threat_category_counts[threat.category] += 1

        event: Dict[str, Any] = {
            "event_type": "INPUT_SCANNED",
            "source": source,
            "input_length": len(input_text),
            "input_hash": result.input_hash,
            "is_safe": result.is_safe,
            "max_severity": result.max_severity.value,
            "threat_count": len(result.threats),
            "threat_patterns": [t.pattern_name for t in result.threats],
        }

        level = "INFO"
        if not result.is_safe:
            if result.max_severity == ThreatLevel.CRITICAL:
                level = "ALERT"
                self._blocked_count += 1
            elif result.max_severity == ThreatLevel.HIGH:
                level = "WARN"
                self._blocked_count += 1
            else:
                level = "WARN"

            event["event_type"] = "THREAT_DETECTED"
            if result.max_severity in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
                event["event_type"] = "INPUT_BLOCKED"

        self._emit(level, event)

    def log_sanitization(self, original: str, sanitized: str, source: str = "unknown") -> None:
        """Log when input is modified during sanitization.

        Args:
            original: The original input text.
            sanitized: The sanitized output text.
            source: Where the input came from.
        """
        if original == sanitized:
            return

        self._sanitized_count += 1
        original_hash = hashlib.sha256(original.encode("utf-8", errors="replace")).hexdigest()[:16]

        self._emit("INFO", {
            "event_type": "INPUT_SANITIZED",
            "source": source,
            "original_length": len(original),
            "sanitized_length": len(sanitized),
            "original_hash": original_hash,
            "length_delta": len(sanitized) - len(original),
        })

    def get_statistics(self) -> Dict[str, Any]:
        """Return current defense statistics.

        Returns:
            Dict with comprehensive statistics about defense events.
        """
        return {
            "total_scanned": self._scanned_count,
            "total_blocked": self._blocked_count,
            "total_sanitized": self._sanitized_count,
            "block_rate": (self._blocked_count / self._scanned_count * 100) if self._scanned_count > 0 else 0.0,
            "threat_severity_breakdown": dict(self._threat_severity_counts),
            "threat_pattern_breakdown": dict(self._threat_pattern_counts),
            "threat_category_breakdown": dict(self._threat_category_counts),
            "log_path": self._log_path,
        }

    def get_threat_report(self) -> str:
        """Generate a human-readable threat report.

        Returns:
            Formatted string with threat statistics and trends.
        """
        stats = self.get_statistics()
        lines = [
            "=" * 60,
            "  PROMPT DEFENSE — THREAT REPORT",
            "=" * 60,
            f"  Total inputs scanned:  {stats['total_scanned']}",
            f"  Inputs blocked:        {stats['total_blocked']}",
            f"  Inputs sanitized:      {stats['total_sanitized']}",
            f"  Block rate:            {stats['block_rate']:.1f}%",
            "",
            "  Threat Severity Breakdown:",
        ]

        for sev in ("critical", "high", "medium", "low", "info"):
            count = stats["threat_severity_breakdown"].get(sev, 0)
            bar = "#" * min(count, 50)
            lines.append(f"    {sev.upper():10} {count:5}  {bar}")

        lines.append("")
        lines.append("  Top Threat Patterns:")
        sorted_patterns = sorted(
            stats["threat_pattern_breakdown"].items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]
        for pattern, count in sorted_patterns:
            lines.append(f"    {count:5}x  {pattern}")

        lines.append("")
        lines.append("  Threat Categories:")
        for cat, count in sorted(stats["threat_category_breakdown"].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"    {count:5}x  {cat}")

        lines.append("")
        lines.append(f"  Log file: {stats['log_path']}")
        lines.append("=" * 60)
        return "\n".join(lines)

    def reset_statistics(self) -> None:
        """Reset all in-memory statistics (does not affect log file)."""
        self._stats.clear()
        self._threat_pattern_counts.clear()
        self._threat_category_counts.clear()
        self._threat_severity_counts.clear()
        self._blocked_count = 0
        self._scanned_count = 0
        self._sanitized_count = 0

    def close(self) -> None:
        """Close the logger and release file handles."""
        self._handler.close()
        self._logger.removeHandler(self._handler)

    @property
    def log_path(self) -> str:
        """Return the path to the defense audit log."""
        return self._log_path


# ═══════════════════════════════════════════════════════════════════════════
#  PROMPT DEFENSE — Core Facade
# ═══════════════════════════════════════════════════════════════════════════


class PromptDefense:
    """Core prompt injection defense system.

    Combines InjectionDetector, ThreatClassifier, PromptSanitizer, and
    DefenseAuditLogger into a unified defense facade.

    Usage:
        defense = PromptDefense()
        result = defense.scan_input(user_input)
        if not result.is_safe:
            print(f"Blocked: {result.max_severity}")
            return
        clean = defense.sanitize_prompt(user_input)
        # Use clean input...
    """

    def __init__(
        self,
        max_prompt_length: int = MAX_PROMPT_LENGTH,
        log_dir: Optional[str] = None,
        enable_logging: bool = True,
        auto_block_critical: bool = True,
        auto_block_high: bool = True,
    ) -> None:
        self._detector = InjectionDetector()
        self._classifier = ThreatClassifier()
        self._sanitizer = PromptSanitizer(max_length=max_prompt_length)
        self._auto_block_critical = auto_block_critical
        self._auto_block_high = auto_block_high

        self._logger: Optional[DefenseAuditLogger] = None
        if enable_logging:
            try:
                self._logger = DefenseAuditLogger(log_dir=log_dir)
            except Exception as e:
                logger.warning("Failed to initialize DefenseAuditLogger: %s", e)

    def scan_input(self, user_input: str, source: str = "unknown") -> ScanResult:
        """Scan user input for prompt injection threats.

        Args:
            user_input: Raw user input to scan.
            source: Identifier for where the input originated ("chat", "agent", "nexus").

        Returns:
            ScanResult with threat details, severity, and sanitized input.
        """
        if not user_input:
            return ScanResult(
                is_safe=True,
                threats=[],
                max_severity=ThreatLevel.INFO,
                sanitized_input="",
                input_hash=hashlib.sha256(b"").hexdigest(),
                scan_timestamp=datetime.now(timezone.utc).isoformat(),
            )

        input_hash = hashlib.sha256(
            user_input.encode("utf-8", errors="replace")
        ).hexdigest()

        # Detect threats (raw text)
        threats = self._detector.detect(user_input)

        # De-obfuscation pass: whitespace-padded attacks ("I  g  n  o  r  e
        #  a l l  p r e v i o u s ...") hide the classic phrases from the
        # regexes.  Squash ALL whitespace and match against squashed
        # attack phrases; on match, re-detect on a whitespace-collapsed
        # version so the normal patterns can fire.
        if not threats:
            squashed = re.sub(r"[\s\u200b\u200c\u200d\ufeff]+", "", user_input).lower()
            deobfuscated_attack = any(
                marker in squashed
                for marker in _DEOBFUSCATION_MARKERS
            )
            if deobfuscated_attack:
                collapsed = re.sub(r"\s+", " ", user_input)
                threats = self._detector.detect(collapsed)
                if not threats:
                    # synthesize a generic detection so the input is blocked
                    threats = [ThreatMatch(
                        pattern_name="obfuscated_injection",
                        category="role_manipulation",
                        matched_text=user_input[:80],
                        position=0,
                        severity=ThreatLevel.CRITICAL,
                        description="Whitespace/zero-width obfuscated prompt injection",
                    )]

        # Classify overall severity
        severity = self._classifier.classify(threats, user_input)

        # Sanitize the input
        sanitized = self._sanitizer.sanitize(user_input)

        # Determine if safe
        is_safe = True
        if self._auto_block_critical and severity == ThreatLevel.CRITICAL:
            is_safe = False
        if self._auto_block_high and severity == ThreatLevel.HIGH:
            is_safe = False

        result = ScanResult(
            is_safe=is_safe,
            threats=threats,
            max_severity=severity,
            sanitized_input=sanitized,
            input_hash=input_hash,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Log the scan
        if self._logger:
            try:
                self._logger.log_scan(result, user_input, source)
                self._logger.log_sanitization(user_input, sanitized, source)
            except Exception as e:
                logger.warning("Failed to log defense event: %s", e)

        return result

    def classify_threat(self, input_text: str) -> ThreatLevel:
        """Classify the threat level of input text.

        Args:
            input_text: The text to classify.

        Returns:
            The classified ThreatLevel.
        """
        return self._classifier.classify_threat(input_text)

    def sanitize_prompt(self, prompt: str) -> str:
        """Sanitize a prompt for safe AI consumption.

        Args:
            prompt: Raw user prompt.

        Returns:
            Sanitized prompt string.
        """
        return self._sanitizer.sanitize(prompt)

    def validate_context(self, context: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate that context hasn't been tampered with.

        Checks context dictionaries for signs of injection or tampering:
        - Unexpected keys that could override system behavior
        - Values containing injection patterns
        - Excessively large context that could indicate overflow

        Args:
            context: A dict representing system context or state.

        Returns:
            Tuple of (is_valid, reason). If is_valid is False, reason
            explains what was detected.
        """
        if not isinstance(context, dict):
            return False, "Context must be a dictionary"

        # Check for suspicious keys (injection via dict key manipulation)
        suspicious_keys = {
            "system_prompt", "instructions", "role", "persona",
            "ignore_previous", "new_instructions", "override",
            "__class__", "__init__", "__globals__", "__builtins__",
        }
        for key in context:
            key_str = str(key).lower()
            if key_str in suspicious_keys:
                return False, f"Suspicious context key detected: '{key}'"

        # Check values for injection patterns
        for key, value in context.items():
            value_str = str(value)
            if len(value_str) > MAX_PROMPT_LENGTH:
                return False, f"Context value for '{key}' exceeds maximum length"

            # Scan value for injection patterns
            threats = self._detector.detect(value_str)
            critical_threats = [t for t in threats if t.severity in (ThreatLevel.CRITICAL, ThreatLevel.HIGH)]
            if critical_threats:
                pattern_names = ", ".join(t.pattern_name for t in critical_threats[:3])
                return False, f"Injection pattern in context key '{key}': {pattern_names}"

        return True, ""

    def get_threat_report(self) -> str:
        """Generate a comprehensive threat report.

        Returns:
            Formatted threat report string, or a message if logging is disabled.
        """
        if self._logger:
            return self._logger.get_threat_report()
        return "  Logging is disabled. Enable logging to view threat reports."

    def get_statistics(self) -> Dict[str, Any]:
        """Return current defense statistics.

        Returns:
            Dict with defense statistics, or empty dict if logging is disabled.
        """
        if self._logger:
            return self._logger.get_statistics()
        return {}

    @property
    def pattern_count(self) -> int:
        """Return the number of registered detection patterns."""
        return self._detector.pattern_count

    def list_patterns(self) -> List[Dict[str, str]]:
        """List all registered detection patterns.

        Returns:
            List of pattern documentation dicts.
        """
        return self._detector.list_patterns()

    def close(self) -> None:
        """Release resources."""
        if self._logger:
            self._logger.close()


# ═══════════════════════════════════════════════════════════════════════════
#  CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

# Module-level singleton for quick use
_default_defense: Optional[PromptDefense] = None


def get_defense() -> PromptDefense:
    """Get or create the module-level default PromptDefense instance.

    Returns:
        A shared PromptDefense instance (logging enabled).
    """
    global _default_defense
    if _default_defense is None:
        _default_defense = PromptDefense(enable_logging=True)
    return _default_defense


def quick_scan(text: str, source: str = "unknown") -> ScanResult:
    """Quick one-shot scan of text for prompt injection.

    Convenience function that uses the module-level defense instance.

    Args:
        text: Input text to scan.
        source: Identifier for the input source.

    Returns:
        ScanResult with threat analysis.
    """
    return get_defense().scan_input(text, source)


def quick_classify(text: str) -> ThreatLevel:
    """Quick one-shot threat classification.

    Args:
        text: Input text to classify.

    Returns:
        Classified ThreatLevel.
    """
    return get_defense().classify_threat(text)


def quick_sanitize(text: str) -> str:
    """Quick one-shot prompt sanitization.

    Args:
        text: Input text to sanitize.

    Returns:
        Sanitized text.
    """
    return get_defense().sanitize_prompt(text)


__all__ = [
    "ThreatLevel",
    "ThreatMatch",
    "ScanResult",
    "InjectionDetector",
    "ThreatClassifier",
    "PromptSanitizer",
    "DefenseAuditLogger",
    "PromptDefense",
    "get_defense",
    "quick_scan",
    "quick_classify",
    "quick_sanitize",
    "MAX_PROMPT_LENGTH",
    "CONTEXT_OVERFLOW_THRESHOLD",
]
