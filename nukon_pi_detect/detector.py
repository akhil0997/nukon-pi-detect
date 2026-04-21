"""
Core detector: normalize input, run pattern checks, return a ScanResult.

Design goals:
  * Deterministic and fast (pure regex + codepoint scans, no ML, no network).
  * Stateless: safe to call concurrently.
  * Well-structured output: every hit carries id, span, snippet, confidence.

This module is intentionally small. The pattern library lives in patterns.py.
"""

from __future__ import annotations

import time
import unicodedata
from dataclasses import asdict, dataclass, field
from typing import Iterable

from .patterns import (
    ALL_PATTERNS,
    HOMOGLYPH_MAP,
    UNICODE_SMUGGLING,
    InjectionPattern,
)


DECISION_CLEAN = "CLEAN"
DECISION_SUSPICIOUS = "SUSPICIOUS"
DECISION_MALICIOUS = "MALICIOUS"


@dataclass
class Hit:
    id: str
    category: str
    name: str
    confidence: float
    mitigation: str
    start: int
    end: int
    snippet: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    decision: str
    score: float                 # 0.0-1.0 aggregated confidence
    hits: list[Hit] = field(default_factory=list)
    input_length: int = 0
    normalized_length: int = 0
    elapsed_ms: float = 0.0
    categories_hit: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "score": round(self.score, 3),
            "hits": [h.to_dict() for h in self.hits],
            "input_length": self.input_length,
            "normalized_length": self.normalized_length,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "categories_hit": self.categories_hit,
        }


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def _normalize(text: str) -> tuple[str, list[Hit]]:
    """
    NFKC-normalize, detect unicode-smuggling artifacts, map homoglyphs.
    Returns (normalized_text, unicode_hits). Normalized text is what regexes run on.
    """
    hits: list[Hit] = []

    # Pre-normalization unicode smuggling checks (on raw text)
    for pid, info in UNICODE_SMUGGLING.items():
        found_positions: list[int] = []
        if "codepoints" in info:
            target = info["codepoints"]
            for i, ch in enumerate(text):
                if ord(ch) in target:
                    found_positions.append(i)
        elif "codepoints_range" in info:
            lo, hi = info["codepoints_range"]
            for i, ch in enumerate(text):
                if lo <= ord(ch) <= hi:
                    found_positions.append(i)
        if found_positions:
            first = found_positions[0]
            hits.append(Hit(
                id=pid,
                category="unicode",
                name=info["name"],
                confidence=info["confidence"],
                mitigation=info["mitigation"],
                start=first,
                end=first + 1,
                snippet=f"<{len(found_positions)} char(s) at positions {found_positions[:5]}"
                        f"{'...' if len(found_positions) > 5 else ''}>",
            ))

    # Homoglyph detection: if Cyrillic confusables appear alongside Latin letters,
    # flag it.
    cyrillic_hits = sum(1 for ch in text if ch in HOMOGLYPH_MAP)
    if cyrillic_hits >= 2:
        hits.append(Hit(
            id="US-005",
            category="unicode",
            name="homoglyph substitution (Cyrillic→Latin)",
            confidence=min(0.5 + 0.05 * cyrillic_hits, 0.85),
            mitigation="Detect and normalize confusable characters before downstream use.",
            start=0, end=0,
            snippet=f"<{cyrillic_hits} Cyrillic lookalike char(s) detected>",
        ))

    # Now build normalized text for regex scanning: NFKC + homoglyph map.
    mapped = "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)
    normalized = unicodedata.normalize("NFKC", mapped)
    # Strip known invisible chars so regexes that expect word boundaries still work.
    stripped_chars = set()
    for info in UNICODE_SMUGGLING.values():
        if "codepoints" in info:
            stripped_chars |= info["codepoints"]
    normalized = "".join(ch for ch in normalized if ord(ch) not in stripped_chars)

    return normalized, hits


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _scan_patterns(text: str, patterns: Iterable[InjectionPattern]) -> list[Hit]:
    out: list[Hit] = []
    for p in patterns:
        for m in p.pattern.finditer(text):
            start, end = m.span()
            snippet = _excerpt(text, start, end)
            out.append(Hit(
                id=p.id,
                category=p.category,
                name=p.name,
                confidence=p.confidence,
                mitigation=p.mitigation,
                start=start,
                end=end,
                snippet=snippet,
            ))
    return out


def _excerpt(text: str, start: int, end: int, pad: int = 30) -> str:
    lo = max(0, start - pad)
    hi = min(len(text), end + pad)
    prefix = "…" if lo > 0 else ""
    suffix = "…" if hi < len(text) else ""
    return (prefix + text[lo:hi] + suffix).replace("\n", " ⏎ ")


def _aggregate(hits: list[Hit]) -> tuple[float, str]:
    """
    Aggregate individual hit confidences into a single score + decision.
    Uses complement-product so multiple independent signals reinforce.
    """
    if not hits:
        return 0.0, DECISION_CLEAN

    # 1 - ∏(1 - c_i), capped at 0.999
    prod = 1.0
    for h in hits:
        prod *= (1.0 - h.confidence)
    score = min(1.0 - prod, 0.999)

    if score >= 0.85 or any(h.confidence >= 0.90 for h in hits):
        return score, DECISION_MALICIOUS
    if score >= 0.50:
        return score, DECISION_SUSPICIOUS
    return score, DECISION_CLEAN


def scan(text: str) -> ScanResult:
    """
    Scan a string for prompt-injection patterns.

    Returns a ScanResult with decision, score, and per-hit details.
    Runtime is O(N * P) where N is input length and P is pattern count;
    typical inputs scan in <1 ms.
    """
    t0 = time.perf_counter()
    normalized, unicode_hits = _normalize(text)
    regex_hits = _scan_patterns(normalized, ALL_PATTERNS)
    hits = unicode_hits + regex_hits
    # Sort by position (unicode hits first is fine; stable)
    hits.sort(key=lambda h: (h.start, -h.confidence))
    score, decision = _aggregate(hits)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    categories = sorted({h.category for h in hits})
    return ScanResult(
        decision=decision,
        score=score,
        hits=hits,
        input_length=len(text),
        normalized_length=len(normalized),
        elapsed_ms=elapsed_ms,
        categories_hit=categories,
    )
