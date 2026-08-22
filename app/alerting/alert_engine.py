"""
Alert dispatch. MVP ships a console logger + a webhook stub (Slack/Teams/
generic HTTP). Wire in email/PagerDuty/ticketing per deployment.
"""
import json
import logging
from app.models.finding import Finding, Severity

logger = logging.getLogger("phi_scanner.alerts")
logging.basicConfig(level=logging.INFO)

# Severity -> how urgently to notify. In prod, map these to PagerDuty routing
# keys / Slack channels / email distribution lists.
SEVERITY_CHANNEL_MAP = {
    Severity.CRITICAL: "page_oncall",
    Severity.HIGH: "slack_urgent",
    Severity.MEDIUM: "slack_digest",
    Severity.LOW: "weekly_digest_email",
    Severity.INFO: "log_only",
}


def build_alert_payload(finding: Finding, playbook: list[str]) -> dict:
    return {
        "tenant_id": finding.tenant_id,
        "finding_id": finding.id,
        "severity": finding.severity.value,
        "exposure_type": finding.exposure_type.value,
        "risk_score": finding.risk_score,
        "source_url": finding.source_url,
        "redacted_excerpt": finding.redacted_excerpt,
        "breach_notification_flag": finding.breach_notification_flag,
        "remediation_playbook": playbook,
    }


def dispatch_alert(finding: Finding, playbook: list[str]) -> dict:
    """Returns the payload actually sent, for storage in the Alert record."""
    channel = SEVERITY_CHANNEL_MAP.get(finding.severity, "log_only")
    payload = build_alert_payload(finding, playbook)

    # TODO(prod): replace console log with real webhook/email/ticket call, e.g.:
    # httpx.post(SLACK_WEBHOOK_URL, json={"text": format_slack_message(payload)})
    logger.info("[ALERT via %s] %s", channel, json.dumps(payload, indent=2))

    return {"channel": channel, **payload}
