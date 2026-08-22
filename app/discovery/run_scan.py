"""Run credential-gated discovery and detection for one authorized tenant.

Usage: python -m app.discovery.run_scan --tenant-id 1
"""
import argparse
import base64
import logging
from urllib.parse import urlparse

import httpx

from app.db import database, initialize_database
from app.discovery.connectors import is_authorized_domain_url, run_all_connectors
from app.models.tenant import AssetPattern, AssetType, Tenant
from app.pipeline import process_candidate

logger = logging.getLogger("phi_scanner.discovery")
MAX_FETCH_BYTES = 1_000_000


def _fetch_text(candidate: dict, domains: list[str]) -> str | None:
    """Fetch only a URL whose host is an approved tenant domain or GitHub API URL."""
    fetch_url = candidate.get("fetch_url") or candidate["url"]
    source_type = candidate["source_type"]
    if source_type == "web_page" and not is_authorized_domain_url(fetch_url, domains):
        logger.warning("Skipped off-scope URL returned by discovery: %s", fetch_url)
        return None
    if source_type == "code_repo" and urlparse(fetch_url).hostname != "api.github.com":
        logger.warning("Skipped non-GitHub-API code result: %s", fetch_url)
        return None

    response = httpx.get(fetch_url, headers=candidate.get("github_headers"), timeout=20.0, follow_redirects=False)
    response.raise_for_status()
    if len(response.content) > MAX_FETCH_BYTES:
        logger.warning("Skipped oversized candidate: %s", candidate["url"])
        return None
    if source_type == "code_repo":
        payload = response.json()
        encoded = payload.get("content", "").replace("\n", "")
        return base64.b64decode(encoded).decode("utf-8", errors="replace")
    return response.text


def run(tenant_id: int) -> int:
    initialize_database()
    document = database.tenants.find_one({"id": tenant_id})
    if not document:
        raise RuntimeError(f"Tenant {tenant_id} was not found.")
    tenant = Tenant.from_document(document)
    if not tenant.authorization_confirmed or not tenant.authorization_reference:
        raise RuntimeError("Discovery refused: tenant lacks a signed authorization reference.")

    patterns = [AssetPattern.from_document(item) for item in database.asset_patterns.find({"tenant_id": tenant_id})]
    if not patterns:
        raise RuntimeError("Discovery refused: tenant has no registered asset patterns.")
    domains = [pattern.value for pattern in patterns if pattern.asset_type == AssetType.DOMAIN]
    identifier_patterns = [pattern.value for pattern in patterns if pattern.asset_type == AssetType.IDENTIFIER_PATTERN]
    identifier_regex = identifier_patterns[0] if identifier_patterns else None

    persisted = 0
    for candidate in run_all_connectors(patterns):
        try:
            text = _fetch_text(candidate, domains)
            if text is None:
                continue
            finding = process_candidate(
                db=database, tenant=tenant, url=candidate["url"], source_type=candidate["source_type"], text=text,
                accessibility=candidate["accessibility"], asset_criticality=candidate["asset_criticality"],
                tenant_identifier_regex=identifier_regex,
            )
            persisted += bool(finding)
        except httpx.HTTPError as exc:
            logger.warning("Could not fetch candidate %s: %s", candidate["url"], exc)
    return persisted


def main() -> None:
    parser = argparse.ArgumentParser(description="Run authorized tenant discovery.")
    parser.add_argument("--tenant-id", type=int, required=True)
    args = parser.parse_args()
    print(f"Persisted {run(args.tenant_id)} finding(s).")


if __name__ == "__main__":
    main()
