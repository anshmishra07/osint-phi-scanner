"""
The core pipeline: given a candidate artifact (already fetched text + source
metadata), run detection, classify exposure type, score risk, persist a
Finding, and dispatch an alert if warranted. This is what wires the modules
built separately into one flow — call this from a scheduled job or from the
discovery connectors once they're live.
"""
from app.models.tenant import Tenant
from app.models.finding import Finding, Alert, ExposureType, Severity
from app.db import next_id
from app.detectors.phi_detector import detect_phi, estimate_record_count
from app.detectors.secrets_detector import detect_secrets
from app.scoring.risk_engine import score_finding
from app.remediation.playbooks import get_playbook
from app.alerting.alert_engine import dispatch_alert


def _classify_exposure_type(phi_matches, secret_matches) -> ExposureType:
    if secret_matches:
        return ExposureType.API_KEY_SECRET
    if any(m.kind in ("ssn", "mrn", "tenant_identifier_format", "name_clinical_context") for m in phi_matches):
        return ExposureType.PATIENT_IDENTIFIER
    if phi_matches:
        return ExposureType.CONFIDENTIAL_REPORT
    return ExposureType.OTHER


def _overall_confidence(phi_matches, secret_matches) -> float:
    all_conf = [m.confidence for m in phi_matches] + [m.confidence for m in secret_matches]
    if not all_conf:
        return 0.0
    # weight toward the strongest signal, not just the average, since one
    # very confident match (e.g. exact tenant MRN format) should dominate
    return round(max(all_conf) * 0.7 + (sum(all_conf) / len(all_conf)) * 0.3, 2)


def process_candidate(
    db,
    tenant: Tenant,
    url: str,
    source_type: str,
    text: str,
    accessibility: str = "public_no_auth",
    asset_criticality: str = "unknown",
    tenant_identifier_regex: str | None = None,
) -> Finding | None:
    phi_matches = detect_phi(text, tenant_identifier_regex=tenant_identifier_regex)
    secret_matches = detect_secrets(text)

    if not phi_matches and not secret_matches:
        return None  # nothing to report

    exposure_type = _classify_exposure_type(phi_matches, secret_matches)
    confidence = _overall_confidence(phi_matches, secret_matches)
    record_count = estimate_record_count(text, phi_matches) if phi_matches else 1

    assessment = score_finding(
        exposure_type=exposure_type,
        accessibility=accessibility,
        estimated_record_count=record_count,
        asset_criticality=asset_criticality,
        detection_confidence=confidence,
    )

    excerpt_parts = [m.context_snippet for m in (phi_matches + secret_matches)][:3]
    redacted_excerpt = " | ".join(excerpt_parts)[:500]

    finding = Finding(
        id=next_id(db, "findings"),
        tenant_id=tenant.id,
        source_url=url,
        source_type=source_type,
        exposure_type=exposure_type,
        redacted_excerpt=redacted_excerpt,
        detector_signals={
            "phi_matches": [{"kind": m.kind, "confidence": m.confidence} for m in phi_matches],
            "secret_matches": [{"kind": m.kind, "confidence": m.confidence} for m in secret_matches],
            "risk_rationale": assessment.rationale,
        },
        confidence=confidence,
        risk_score=assessment.score,
        severity=assessment.severity,
        estimated_record_count=record_count,
        breach_notification_flag=assessment.breach_notification_flag,
    )
    db.findings.insert_one(finding.to_document())

    if assessment.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
        playbook = get_playbook(exposure_type, source_type)
        payload = dispatch_alert(finding, playbook)
        alert = Alert(
            id=next_id(db, "alerts"),
            finding_id=finding.id,
            channel=payload["channel"],
            payload=payload,
        )
        db.alerts.insert_one(alert.to_document())

    return finding
