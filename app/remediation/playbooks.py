"""
Remediation playbook lookup. Returns actionable, ordered steps for a given
(exposure_type, source_type) combination. Kept as data (not hardcoded prose
scattered in views) so it's easy to extend per-tenant later.
"""
from app.models.finding import ExposureType

PLAYBOOKS: dict[tuple[str, str], list[str]] = {
    ("misconfigured_storage", "cloud_bucket"): [
        "Set the bucket/container ACL to private immediately (block public read/list).",
        "Enable 'Block Public Access' account-wide setting for the cloud provider if not already on.",
        "Rotate any credentials that were readable from the bucket listing.",
        "Review CloudTrail/Activity logs for the exposure window to check for unauthorized access.",
        "Re-scan the bucket URL to verify it now returns Access Denied.",
    ],
    ("api_key_secret", "code_repo"): [
        "Revoke/rotate the exposed key or credential immediately at the provider.",
        "Purge the secret from git history (git filter-repo / BFG), not just the latest commit.",
        "Add the pattern to a pre-commit secret scanner (e.g. gitleaks) to prevent recurrence.",
        "Check provider audit logs for any usage of the key during the exposure window.",
        "Re-scan the repo to confirm the secret no longer appears in any branch or history.",
    ],
    ("patient_identifier", "web_page"): [
        "Remove or de-identify the page content immediately.",
        "Submit a Google Search Console / Bing Webmaster removal request for the URL.",
        "Add a robots.txt disallow + noindex meta tag if the page must remain for internal reasons.",
        "Request cache eviction (Google's 'Outdated Content' removal tool) so cached copies drop too.",
        "Assess against HIPAA Breach Notification Rule thresholds; loop in compliance/legal.",
        "Re-scan in 48-72h to confirm de-indexing.",
    ],
    ("medical_record_template", "web_page"): [
        "Remove the publicly accessible template/document.",
        "Check whether real patient data was filled into the template copy that leaked.",
        "Move internal templates to an authenticated document management system.",
        "Re-scan to verify removal.",
    ],
    ("confidential_report", "cloud_bucket"): [
        "Restrict bucket access to authenticated, authorized roles only.",
        "Determine how the report became publicly accessible (misconfigured IaC, manual change?).",
        "Add a policy check (e.g. AWS Config rule / OPA policy) to prevent recurrence.",
        "Re-scan to verify.",
    ],
}

DEFAULT_PLAYBOOK = [
    "Take the exposed resource offline or restrict access immediately.",
    "Preserve evidence (URL, timestamp, redacted excerpt) for the incident record.",
    "Determine root cause (misconfiguration, accidental commit, third-party leak).",
    "Loop in security/compliance to assess notification obligations.",
    "Re-scan to verify the exposure is resolved.",
]


def get_playbook(exposure_type: ExposureType, source_type: str) -> list[str]:
    key = (exposure_type.value, source_type)
    return PLAYBOOKS.get(key, DEFAULT_PLAYBOOK)
