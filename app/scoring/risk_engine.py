"""
Risk scoring engine.

Combines: data sensitivity, accessibility, volume, asset criticality
into a 0-100 score + severity tier, and flags likely HIPAA breach-
notification thresholds so compliance teams can act fast.

This encodes the "risk assessment factors" HHS/OCR guidance points to
for determining breach probability (nature/extent of PHI, who accessed
it, whether it was actually acquired/viewed, and mitigation) — this
tool approximates that with what's programmatically observable
(what's exposed + how discoverable it is), and should feed a human
compliance review, not replace one.
"""
from dataclasses import dataclass
from app.models.finding import Severity, ExposureType

# Base sensitivity weight per exposure type (0-40 pts)
SENSITIVITY_WEIGHTS = {
    ExposureType.PATIENT_IDENTIFIER: 40,
    ExposureType.MEDICAL_RECORD_TEMPLATE: 20,
    ExposureType.CONFIDENTIAL_REPORT: 25,
    ExposureType.API_KEY_SECRET: 30,          # can lead to further PHI exposure -> weighted high
    ExposureType.MISCONFIGURED_STORAGE: 22,
    ExposureType.OTHER: 10,
}

# Accessibility weight (0-25 pts) - how easily can someone stumble onto it
ACCESSIBILITY_WEIGHTS = {
    "indexed_by_search_engine": 25,   # Google-indexed = worst case, zero effort to find
    "public_no_auth": 20,             # directly public, not indexed yet
    "guessable_url": 12,              # needs a guessed/enumerated URL
    "auth_gated_misconfigured": 8,    # technically gated but broken/weak
}

# Volume weight (0-20 pts), scaled by estimated record count
def volume_weight(estimated_record_count: int) -> float:
    if estimated_record_count >= 500:
        return 20.0  # crosses HIPAA's 500-individual "major breach" reporting threshold
    if estimated_record_count >= 50:
        return 15.0
    if estimated_record_count >= 10:
        return 10.0
    if estimated_record_count >= 2:
        return 5.0
    return 2.0

# Asset criticality weight (0-15 pts)
ASSET_CRITICALITY_WEIGHTS = {
    "production": 15,
    "staging": 8,
    "archive_or_marketing": 4,
    "unknown": 6,
}


@dataclass
class RiskAssessment:
    score: float
    severity: Severity
    breach_notification_flag: bool
    rationale: list[str]


def score_finding(
    exposure_type: ExposureType,
    accessibility: str,
    estimated_record_count: int,
    asset_criticality: str,
    detection_confidence: float,
) -> RiskAssessment:
    rationale = []

    sens = SENSITIVITY_WEIGHTS.get(exposure_type, 10)
    rationale.append(f"sensitivity({exposure_type.value})={sens}")

    access = ACCESSIBILITY_WEIGHTS.get(accessibility, 10)
    rationale.append(f"accessibility({accessibility})={access}")

    vol = volume_weight(estimated_record_count)
    rationale.append(f"volume({estimated_record_count} records)={vol}")

    crit = ASSET_CRITICALITY_WEIGHTS.get(asset_criticality, 6)
    rationale.append(f"asset_criticality({asset_criticality})={crit}")

    raw_score = (sens + access + vol + crit) * detection_confidence
    raw_score = min(100.0, raw_score)
    rationale.append(f"confidence_multiplier={detection_confidence}")

    if raw_score >= 75:
        severity = Severity.CRITICAL
    elif raw_score >= 55:
        severity = Severity.HIGH
    elif raw_score >= 35:
        severity = Severity.MEDIUM
    elif raw_score >= 15:
        severity = Severity.LOW
    else:
        severity = Severity.INFO

    # Simplified breach-threshold heuristic: PHI-type exposure + >=500 records
    # + reasonably confident detection -> flag for compliance review against
    # the HIPAA Breach Notification Rule's "major breach" (500+) threshold.
    breach_flag = (
        exposure_type in (ExposureType.PATIENT_IDENTIFIER, ExposureType.CONFIDENTIAL_REPORT)
        and estimated_record_count >= 500
        and detection_confidence >= 0.5
    )
    if breach_flag:
        rationale.append("BREACH_NOTIFICATION_THRESHOLD_LIKELY_MET (>=500 records, PHI, confident match)")

    return RiskAssessment(
        score=round(raw_score, 1),
        severity=severity,
        breach_notification_flag=breach_flag,
        rationale=rationale,
    )
