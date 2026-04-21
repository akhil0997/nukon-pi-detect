"""
Curated prompt-injection pattern library.

Each pattern has:
  id:         stable identifier, e.g. "CI-001"
  category:   one of: classic, jailbreak, delimiter, unicode, indirect
  name:       short human-readable label
  pattern:    compiled regex (applied to NFKC-normalized, case-folded text)
  confidence: 0.0-1.0 — how sure we are this is malicious in isolation
  mitigation: one-line suggested fix

Confidence guide:
  0.90+   almost certainly an attack (DAN, explicit override tokens)
  0.70+   strong signal (ignore-previous variants, fake system tags)
  0.50+   suspicious (roleplay framings, "assistant:" prefixes)
  <0.50   weak/noisy (common in benign text too)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern


@dataclass(frozen=True)
class InjectionPattern:
    id: str
    category: str
    name: str
    pattern: Pattern[str]
    confidence: float
    mitigation: str


def _p(expr: str, extra_flags: int = 0) -> Pattern[str]:
    return re.compile(expr, re.IGNORECASE | re.DOTALL | extra_flags)


# ---------------------------------------------------------------------------
# 1. Classic injection (direct instruction overrides)
# ---------------------------------------------------------------------------
CLASSIC = [
    InjectionPattern("CI-001", "classic", "ignore previous instructions",
        _p(r"ignore\s+(?:all\s+|the\s+)?(?:previous|prior|above|preceding)\s+(?:instructions?|prompts?|messages?|rules?)"),
        0.92, "Strip or quote user input before concatenation; never trust 'override' language."),
    InjectionPattern("CI-002", "classic", "disregard prior",
        _p(r"disregard\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|preceding|earlier)"),
        0.88, "Treat user text as data, not instructions."),
    InjectionPattern("CI-003", "classic", "forget everything",
        _p(r"forget\s+(?:everything|all|everything\s+you|what\s+you\s+(?:were|have\s+been))"),
        0.85, "Reject memory-reset language in untrusted input."),
    InjectionPattern("CI-004", "classic", "new instructions marker",
        _p(r"(?:new|updated|revised)\s+(?:instructions?|rules?|system\s+prompt)\s*[:\-]"),
        0.80, "Quote/escape user content; don't parse it as directives."),
    InjectionPattern("CI-005", "classic", "override directive",
        _p(r"\b(?:override|overrule|supersede)\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|system|safety|default)"),
        0.88, "Block imperative override verbs in untrusted spans."),
    InjectionPattern("CI-006", "classic", "stop being assistant",
        _p(r"stop\s+being\s+(?:an?\s+)?(?:assistant|chatbot|ai|helpful|claude|gpt)"),
        0.90, "Role-reassignment is always suspicious from user input."),
    InjectionPattern("CI-007", "classic", "admin/root mode",
        _p(r"\b(?:admin|root|sudo|superuser|god)\s+mode\b"),
        0.85, "Models have no 'admin mode' — treat as social engineering."),
    InjectionPattern("CI-008", "classic", "bypass filters",
        _p(r"\bbypass\s+(?:all\s+|any\s+|the\s+)?(?:filter|safety|guard|moderation|content\s+polic)"),
        0.92, "Any request to disable safety is high-severity."),
    InjectionPattern("CI-009", "classic", "reveal system prompt",
        _p(r"(?:show|reveal|print|repeat|output|display|leak)\s+(?:me\s+)?(?:your\s+|the\s+)?(?:system\s+prompt|initial\s+(?:prompt|instructions?)|hidden\s+instructions?)"),
        0.82, "System prompt exfiltration attempt — enforce at output layer too."),
    InjectionPattern("CI-010", "classic", "repeat above verbatim",
        _p(r"repeat\s+(?:the\s+)?(?:text|words|content)\s+above\s+verbatim"),
        0.75, "Common prompt-leak vector; sanitize or refuse."),
    InjectionPattern("CI-011", "classic", "you are now",
        _p(r"(?:you\s+are|from\s+now\s+on\s+you\s+are|act\s+as)\s+(?:now\s+)?(?:a\s+)?(?:different|new|evil|unrestricted|uncensored)"),
        0.80, "Persona reassignment with negative framing."),
    InjectionPattern("CI-012", "classic", "ignore safety",
        _p(r"ignore\s+(?:all\s+)?(?:safety|ethical|moral)\s+(?:guidelines?|rules?|constraints?|considerations?)"),
        0.95, "Explicit safety-disable — always block."),
]

# ---------------------------------------------------------------------------
# 2. Jailbreaks (persona-based bypasses)
# ---------------------------------------------------------------------------
JAILBREAK = [
    InjectionPattern("JB-001", "jailbreak", "DAN (Do Anything Now)",
        _p(r"\bDAN\b|do\s+anything\s+now"),
        0.88, "Classic DAN variant — match and refuse."),
    InjectionPattern("JB-002", "jailbreak", "developer mode",
        _p(r"(?:enable|activate|enter|switch\s+to)\s+(?:developer|debug|dev)\s+mode"),
        0.85, "No such mode exists; reject."),
    InjectionPattern("JB-003", "jailbreak", "STAN (Strive To Avoid Norms)",
        _p(r"\bSTAN\b|strive\s+to\s+avoid\s+norms"),
        0.88, "Known jailbreak persona."),
    InjectionPattern("JB-004", "jailbreak", "AIM (Always Intelligent, Machiavellian)",
        _p(r"\bAIM\b\s*:.*\bmachiavellian|always\s+intelligent\s+(?:and\s+)?machiavellian"),
        0.90, "Known jailbreak persona."),
    InjectionPattern("JB-005", "jailbreak", "jailbreak keyword",
        _p(r"\bjailbreak(?:ing|ed)?\s+(?:mode|prompt|you|this|the\s+(?:model|ai|system))"),
        0.82, "Explicit keyword; often paired with persona swap."),
    InjectionPattern("JB-006", "jailbreak", "no restrictions roleplay",
        _p(r"(?:you\s+have\s+)?no\s+(?:restrictions?|rules?|filters?|limits?|limitations?|ethics?|morals?)"),
        0.80, "Negation of constraints is a strong signal."),
    InjectionPattern("JB-007", "jailbreak", "evil/unfiltered persona",
        _p(r"(?:pretend|imagine|roleplay|act)\s+(?:to\s+be|as|you\s+are)\s+(?:an?\s+)?(?:evil|unfiltered|uncensored|malicious|unrestricted|amoral)"),
        0.85, "Harmful persona framing — refuse."),
    InjectionPattern("JB-008", "jailbreak", "grandma exploit",
        _p(r"(?:my\s+)?(?:dead\s+|late\s+)?grandma(?:ther)?\s+used\s+to.*(?:tell|read|sing|recite)"),
        0.70, "Known sympathy-based jailbreak template."),
    InjectionPattern("JB-009", "jailbreak", "hypothetical harmful scenario",
        _p(r"hypothetically.*(?:how\s+(?:to|would|could)\s+(?:make|build|create|synthesize)).*(?:bomb|weapon|malware|virus|drug)"),
        0.85, "Hypothetical framing doesn't bypass safety."),
    InjectionPattern("JB-010", "jailbreak", "token-smuggling base64 hint",
        _p(r"decode\s+(?:this\s+)?(?:base64|b64)\s+and\s+(?:follow|execute|do)"),
        0.82, "Encoding-based instruction smuggling."),
    InjectionPattern("JB-011", "jailbreak", "opposite day / reverse",
        _p(r"(?:opposite\s+day|say\s+the\s+opposite|invert\s+your\s+answer|answer\s+in\s+reverse)"),
        0.65, "Low-confidence inversion trick."),
    InjectionPattern("JB-012", "jailbreak", "two responses (safe + unsafe)",
        _p(r"(?:give|provide|output)\s+(?:me\s+)?two\s+responses?.*(?:one\s+(?:safe|normal|filtered)|one\s+(?:unsafe|jailbroken|unfiltered))"),
        0.88, "Dual-response exploit — refuse entirely."),
]

# ---------------------------------------------------------------------------
# 3. Delimiter escapes (fake structural tokens)
# ---------------------------------------------------------------------------
DELIMITER = [
    InjectionPattern("DL-001", "delimiter", "fake </system> tag",
        _p(r"</\s*(?:system|sys|instructions?|prompt)\s*>"),
        0.85, "Strip or escape angle-bracket pseudo-tags before concat."),
    InjectionPattern("DL-002", "delimiter", "fake <system> reopen",
        _p(r"<\s*(?:system|sys|instructions?|prompt)\s*>"),
        0.80, "Attempt to reopen a system scope inside user input."),
    InjectionPattern("DL-003", "delimiter", "ChatML im_end/im_start",
        _p(r"<\|(?:im_end|im_start|endoftext|startoftext)\|>"),
        0.92, "ChatML control tokens must never appear in user data."),
    InjectionPattern("DL-004", "delimiter", "Llama [INST] tags",
        _p(r"\[\s*/?\s*INST\s*\]"),
        0.88, "Llama-style instruction tags in user input."),
    InjectionPattern("DL-005", "delimiter", "sentence-end </s> token",
        _p(r"</s>|<s>"),
        0.70, "Low-level model tokens embedded in input."),
    InjectionPattern("DL-006", "delimiter", "### Instruction hijack",
        _p(r"^\s*#{2,4}\s*(?:instruction|system|user|assistant)\s*:?\s*$", re.MULTILINE),
        0.75, "Markdown-header role hijack."),
    InjectionPattern("DL-007", "delimiter", "triple-backtick role block",
        _p(r"```(?:system|assistant|user)\b"),
        0.72, "Code-fence role prefix used to smuggle roles."),
    InjectionPattern("DL-008", "delimiter", "assistant: prefix",
        _p(r"(?:^|\n)\s*(?:assistant|ai|claude|gpt|bot)\s*:\s*\S"),
        0.60, "Role-prefix spoof — low confidence alone, strong in combination."),
    InjectionPattern("DL-009", "delimiter", "user: prefix with new directive",
        _p(r"(?:^|\n)\s*user\s*:\s*(?:ignore|forget|disregard|new\s+task)"),
        0.85, "User-prefix with override verb."),
    InjectionPattern("DL-010", "delimiter", "Anthropic Human/Assistant turns",
        _p(r"\n\n(?:Human|Assistant)\s*:"),
        0.78, "Legacy Claude turn markers in input."),
    InjectionPattern("DL-011", "delimiter", "end of prompt marker",
        _p(r"(?:end\s+of\s+(?:prompt|instructions?|system)|---\s*end\s*---)"),
        0.72, "Attempt to close the system section."),
]

# ---------------------------------------------------------------------------
# 4. Unicode smuggling (invisible / deceptive characters)
# ---------------------------------------------------------------------------
# These ranges are checked by code, not regex — see detector.py.
UNICODE_SMUGGLING = {
    "US-001": {
        "name": "zero-width characters",
        "codepoints": {0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060},
        "confidence": 0.75,
        "mitigation": "NFKC-normalize and strip zero-width chars before prompting.",
    },
    "US-002": {
        "name": "bidi/RTL override",
        "codepoints": {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069},
        "confidence": 0.88,
        "mitigation": "Strip bidi control chars; they can reorder visible text vs logical text.",
    },
    "US-003": {
        "name": "tag characters (U+E00xx) — Unicode tag smuggling",
        "codepoints_range": (0xE0000, 0xE007F),
        "confidence": 0.98,
        "mitigation": "Tag characters are invisible and carry hidden payloads — always strip.",
    },
    "US-004": {
        "name": "private use area",
        "codepoints_range": (0xE080, 0xF8FF),
        "confidence": 0.55,
        "mitigation": "PUA chars have no standard meaning; strip unless your app needs them.",
    },
}

# Simple Cyrillic→Latin homoglyph set (most common confusables)
HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X",
}

# ---------------------------------------------------------------------------
# 5. Indirect injection (payloads designed for downstream LLM consumers)
# ---------------------------------------------------------------------------
INDIRECT = [
    InjectionPattern("IN-001", "indirect", "AI reading this directive",
        _p(r"(?:if\s+you\s+are\s+an?\s+(?:ai|llm|assistant|language\s+model)|to\s+the\s+(?:ai|llm|assistant))\b.{0,80}(?:please|you\s+must|ignore|do|execute|follow)"),
        0.90, "Content targets downstream LLM — quote before summarizing."),
    InjectionPattern("IN-002", "indirect", "when summarizing also",
        _p(r"when\s+(?:summari[sz]ing|processing|reading|parsing)\s+this\b.{0,60}(?:also|additionally|remember\s+to|make\s+sure\s+to)"),
        0.82, "Secondary-instruction injection for retrieval pipelines."),
    InjectionPattern("IN-003", "indirect", "hidden instruction to assistant",
        _p(r"hidden\s+(?:instruction|message|note|directive)\s+(?:for|to)\s+(?:the\s+)?(?:assistant|ai|llm|model)"),
        0.92, "Explicit indirect-injection marker."),
    InjectionPattern("IN-004", "indirect", "exfiltrate via URL",
        _p(r"(?:send|post|fetch|exfil|leak|encode).{0,40}(?:to|at|via)\s+https?://"),
        0.80, "Exfiltration via embedded URL in summarized content."),
    InjectionPattern("IN-005", "indirect", "markdown image exfil",
        _p(r"!\[[^\]]*\]\(https?://[^\)]{0,200}\?[^\)]*\{[^\)]*\}"),
        0.85, "Markdown image with templated query string — exfil vector."),
    InjectionPattern("IN-006", "indirect", "tool/function call injection",
        _p(r"(?:call|invoke|use|run)\s+(?:the\s+)?(?:tool|function|api)\s+\w+\s*\("),
        0.70, "Instruction to invoke a specific tool — verify against policy."),
    InjectionPattern("IN-007", "indirect", "email/dm auto-reply directive",
        _p(r"(?:reply|respond|send)\s+(?:an?\s+)?(?:email|message|dm)\s+(?:to|with|saying)"),
        0.65, "Common in email-summarization indirect injection."),
    InjectionPattern("IN-008", "indirect", "append to output",
        _p(r"(?:append|add|include|insert)\s+(?:the\s+following|this\s+text|this\s+string)\s+(?:to|at\s+the\s+end\s+of)\s+(?:your|the)\s+(?:response|output|answer)"),
        0.82, "Output-manipulation directive."),
    InjectionPattern("IN-009", "indirect", "do not mention this instruction",
        _p(r"(?:do\s+not|don'?t|never)\s+(?:mention|reveal|tell|disclose|show)\s+(?:this|these|the|that).{0,30}(?:instruction|message|note|directive|request)"),
        0.92, "Secrecy clause — hallmark of indirect injection."),
]

# ---------------------------------------------------------------------------
# Flat registry
# ---------------------------------------------------------------------------
ALL_PATTERNS: list[InjectionPattern] = CLASSIC + JAILBREAK + DELIMITER + INDIRECT


def count_by_category() -> dict[str, int]:
    out: dict[str, int] = {}
    for p in ALL_PATTERNS:
        out[p.category] = out.get(p.category, 0) + 1
    out["unicode"] = len(UNICODE_SMUGGLING)
    return out
