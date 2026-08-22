"""
Secrets / API-key / credential detector.

Same approach as TruffleHog/Gitleaks: known-provider regex signatures first
(high confidence), then generic high-entropy string detection as a fallback
(lower confidence, higher false-positive rate -> flagged for human triage).

IMPORTANT: this module only DETECTS the presence/format of a secret. It never
attempts to use a found key to authenticate anywhere — see README ethics
section. The only "liveness" check permitted is a passive existence check
(e.g., is this bucket URL publicly listable) via app/discovery/cloud_storage.py,
not credential use.
"""
import re
import math
from dataclasses import dataclass


@dataclass
class SecretMatch:
    kind: str
    redacted: str
    confidence: float
    context_snippet: str = ""


PROVIDER_PATTERNS = {
    "aws_access_key_id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    "generic_api_key_assignment": re.compile(
        r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]([A-Za-z0-9\-_/+=]{16,64})['\"]"
    ),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b"),
    "private_key_block": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
    "db_connection_string": re.compile(
        r"(?i)\b(postgres|mysql|mongodb)(\+\w+)?://[^:\s]+:[^@\s]+@[^\s/]+"
    ),
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


HIGH_ENTROPY_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/_=\-]{24,64}\b")


def _redact(s: str) -> str:
    if len(s) <= 6:
        return "*" * len(s)
    return s[:3] + "*" * (len(s) - 6) + s[-3:]


def _context(text: str, start: int, end: int, window: int = 40) -> str:
    s = max(0, start - window)
    e = min(len(text), end + window)
    return text[s:e].replace("\n", " ")


def detect_secrets(text: str, entropy_threshold: float = 4.3) -> list[SecretMatch]:
    matches: list[SecretMatch] = []

    for kind, pattern in PROVIDER_PATTERNS.items():
        for m in pattern.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            matches.append(SecretMatch(
                kind=kind,
                redacted=_redact(value),
                confidence=0.9,
                context_snippet=_context(text, m.start(), m.end()),
            ))

    # Generic high-entropy fallback (lower confidence -> human triage)
    already_flagged_spans = {(m.context_snippet) for m in matches}
    for m in HIGH_ENTROPY_TOKEN_RE.finditer(text):
        token = m.group(0)
        ent = shannon_entropy(token)
        if ent >= entropy_threshold:
            ctx = _context(text, m.start(), m.end())
            if ctx in already_flagged_spans:
                continue
            matches.append(SecretMatch(
                kind="high_entropy_token",
                redacted=_redact(token),
                confidence=min(0.6, 0.3 + (ent - entropy_threshold) * 0.15),
                context_snippet=ctx,
            ))

    return matches
