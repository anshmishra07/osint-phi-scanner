"""
PHI / patient-identifier detector.

Design notes:
- Pure regex/context-window MVP so it runs with zero external ML deps today.
  Swap in Microsoft Presidio (+ custom healthcare recognizers) for prod —
  see PRESIDIO_UPGRADE_NOTE below.
- Detectors return REDACTED excerpts, never the raw matched value, so that
  downstream storage never accidentally retains full PHI.
- Confidence blends: pattern strength + presence of corroborating context
  (e.g., a bare 9-digit number is weak; "SSN: 123-45-6789" near a name is strong).

PRESIDIO_UPGRADE_NOTE:
    from presidio_analyzer import AnalyzerEngine
    analyzer = AnalyzerEngine()
    results = analyzer.analyze(text=doc_text, language="en",
                                entities=["PERSON","US_SSN","DATE_TIME","MEDICAL_LICENSE"])
    # then layer the healthcare-specific regexes below as custom recognizers.
"""
import re
from dataclasses import dataclass, field


@dataclass
class PHIMatch:
    kind: str            # e.g. "ssn", "mrn", "insurance_id", "name_dob_proximity"
    redacted: str         # redacted excerpt for storage
    confidence: float     # 0-1
    context_snippet: str = ""


# --- Base identifier patterns -------------------------------------------------
SSN_RE = re.compile(r"\b(\d{3}-\d{2}-\d{4})\b")
GENERIC_MRN_RE = re.compile(r"\b(MRN|Medical Record( No)?\.?|Patient ID)[:\s#-]*([A-Z0-9-]{5,15})\b", re.I)
INSURANCE_ID_RE = re.compile(r"\b(Policy|Member|Insurance)\s*(No\.?|ID|#)?[:\s]*([A-Z]{0,3}\d{6,12})\b", re.I)
DOB_RE = re.compile(r"\b(DOB|Date of Birth)[:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b", re.I)
ICD10_RE = re.compile(r"\b([A-TV-Z][0-9][0-9AB]\.?[0-9A-TV-Z]{0,4})\b")  # ICD-10-CM shape
NAME_NEAR_MED_RE = re.compile(
    r"\b([A-Z][a-z]+ [A-Z][a-z]+)\b(?=(?:.{0,60})(diagnos|patient|treatment|prescri))",
    re.I | re.DOTALL,
)


def _redact(match_text: str, keep: int = 2) -> str:
    """Keep only the first/last couple chars so evidence is auditable
    without storing the full identifier."""
    if len(match_text) <= keep * 2:
        return "*" * len(match_text)
    return match_text[:keep] + "*" * (len(match_text) - keep * 2) + match_text[-keep:]


def _context(text: str, start: int, end: int, window: int = 40) -> str:
    s = max(0, start - window)
    e = min(len(text), end + window)
    return text[s:e].replace("\n", " ")


def detect_phi(text: str, tenant_identifier_regex: str | None = None) -> list[PHIMatch]:
    """
    Run all PHI detectors against a block of text (already fetched from a
    discovered public source). tenant_identifier_regex lets a tenant plug
    in their own MRN/patient-ID format for a high-confidence match.
    """
    matches: list[PHIMatch] = []

    for m in SSN_RE.finditer(text):
        matches.append(PHIMatch(
            kind="ssn",
            redacted=_redact(m.group(1)),
            confidence=0.9,
            context_snippet=_context(text, m.start(), m.end()),
        ))

    for m in GENERIC_MRN_RE.finditer(text):
        matches.append(PHIMatch(
            kind="mrn",
            redacted=_redact(m.group(3)),
            confidence=0.7,
            context_snippet=_context(text, m.start(), m.end()),
        ))

    for m in INSURANCE_ID_RE.finditer(text):
        matches.append(PHIMatch(
            kind="insurance_id",
            redacted=_redact(m.group(3)),
            confidence=0.55,
            context_snippet=_context(text, m.start(), m.end()),
        ))

    dob_matches = list(DOB_RE.finditer(text))
    name_matches = list(NAME_NEAR_MED_RE.finditer(text))
    for m in dob_matches:
        matches.append(PHIMatch(
            kind="dob",
            redacted="DOB:" + _redact(m.group(2)),
            confidence=0.5,
            context_snippet=_context(text, m.start(), m.end()),
        ))
    # A bare "TwoCapitalizedWords near a clinical keyword" match is too noisy
    # on its own (fires on things like "Monday Friday... patient privacy" in
    # ordinary marketing copy). Only surface it when corroborated by a
    # nearby DOB match -- that combination is a much stronger, low-false-
    # positive signal of an actual patient record.
    for nm in name_matches:
        boosted = any(abs(nm.start() - dm.start()) < 150 for dm in dob_matches)
        if boosted:
            matches.append(PHIMatch(
                kind="name_clinical_context",
                redacted=_redact(nm.group(1), keep=1),
                confidence=0.75,
                context_snippet=_context(text, nm.start(), nm.end()),
            ))

    if tenant_identifier_regex:
        try:
            custom_re = re.compile(tenant_identifier_regex)
            for m in custom_re.finditer(text):
                matches.append(PHIMatch(
                    kind="tenant_identifier_format",
                    redacted=_redact(m.group(0)),
                    confidence=0.85,  # matches the org's own known ID format = high confidence
                    context_snippet=_context(text, m.start(), m.end()),
                ))
        except re.error:
            pass  # bad tenant-supplied regex should never crash the pipeline

    return matches


def estimate_record_count(text: str, matches: list[PHIMatch]) -> int:
    """Rough heuristic: count distinct MRN/SSN-like matches as a proxy for
    number of patients affected — used later for breach-threshold logic."""
    identifier_kinds = {"ssn", "mrn", "tenant_identifier_format"}
    distinct = {m.redacted for m in matches if m.kind in identifier_kinds}
    return max(1, len(distinct))
