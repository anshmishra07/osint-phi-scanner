"""Credential-gated, tenant-scoped discovery connectors.

These connectors never run a broad query: every query is derived from an
authorized tenant's AssetPattern records. They return metadata only; callers
must validate scope again before fetching any result.
"""
import logging
import os
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv

from app.models.tenant import AssetPattern, AssetType

load_dotenv()
logger = logging.getLogger("phi_scanner.discovery")

GITHUB_SEARCH_ENDPOINT = "https://api.github.com/search/code"
CODE_SEARCH_TERMS = ('"API_KEY"', '"SECRET"', '"DATABASE_URL"', 'filename:.env')
MAX_SITEMAPS_PER_DOMAIN = 5
MAX_URLS_PER_DOMAIN = 100


def _domains(patterns: list[AssetPattern]) -> list[str]:
    domains = [item.value.lower().removeprefix("https://").removeprefix("http://").rstrip("/")
               for item in patterns if item.asset_type == AssetType.DOMAIN]
    return list(dict.fromkeys(domains))


def _github_orgs(patterns: list[AssetPattern]) -> list[str]:
    orgs = []
    for item in patterns:
        if item.asset_type != AssetType.GITHUB_ORG:
            continue
        value = item.value.rstrip("/")
        orgs.append(value.rsplit("/", 1)[-1])
    return orgs


def is_authorized_domain_url(url: str, domains: list[str]) -> bool:
    """Allow a configured domain and its subdomains, over HTTP(S) only."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return parsed.scheme in {"http", "https"} and any(host == domain or host.endswith(f".{domain}") for domain in domains)


def _sitemap_urls(client: httpx.Client, domain: str) -> list[str]:
    """Read only same-domain sitemap URLs advertised by robots.txt or sitemap.xml."""
    root = f"https://{domain}"
    sitemap_locations = [f"{root}/sitemap.xml"]
    try:
        robots = client.get(f"{root}/robots.txt")
        if robots.is_success:
            sitemap_locations.extend(
                line.split(":", 1)[1].strip()
                for line in robots.text.splitlines()
                if line.lower().startswith("sitemap:") and ":" in line
            )
    except httpx.HTTPError as exc:
        logger.info("Could not read robots.txt for %s: %s", domain, exc)

    pages: list[str] = []
    visited: set[str] = set()
    while sitemap_locations and len(visited) < MAX_SITEMAPS_PER_DOMAIN and len(pages) < MAX_URLS_PER_DOMAIN:
        sitemap_url = sitemap_locations.pop(0)
        if sitemap_url in visited or not is_authorized_domain_url(sitemap_url, [domain]):
            continue
        visited.add(sitemap_url)
        try:
            response = client.get(sitemap_url)
            response.raise_for_status()
            root_element = ET.fromstring(response.content)
        except (httpx.HTTPError, ET.ParseError) as exc:
            logger.info("Could not read sitemap %s: %s", sitemap_url, exc)
            continue
        for loc in root_element.findall(".//{*}loc"):
            url = (loc.text or "").strip()
            if not is_authorized_domain_url(url, [domain]):
                continue
            if root_element.tag.endswith("sitemapindex"):
                sitemap_locations.append(url)
            elif url not in pages:
                pages.append(url)
                if len(pages) >= MAX_URLS_PER_DOMAIN:
                    break
    return pages


def authorized_site_crawl(patterns: list[AssetPattern]) -> list[dict]:
    """Discover an authorized tenant's own public pages without an API key.

    This is intentionally a same-domain sitemap crawl, not a web-wide search
    engine scraper. It makes no queries outside registered tenant domains.
    """
    domains = _domains(patterns)
    if not domains:
        return []

    candidates: list[dict] = []
    with httpx.Client(timeout=15.0, follow_redirects=False, headers={"User-Agent": "Authorized-PHI-Scanner/0.1"}) as client:
        for domain in domains:
            if domain in {"yourorg.com", "example.com"} or domain.endswith(".example"):
                logger.warning("Skipped placeholder domain %s. Register an authorized real domain instead.", domain)
                continue
            for url in _sitemap_urls(client, domain):
                candidates.append({
                    "url": url,
                    "source_type": "web_page",
                    "accessibility": "public_no_auth",
                    "asset_criticality": "unknown",
                    "discovery_source": "tenant_sitemap",
                })
    return candidates


def code_repo_scan(patterns: list[AssetPattern]) -> list[dict]:
    """Search only GitHub organizations explicitly registered as tenant assets."""
    token = os.getenv("GITHUB_TOKEN")
    orgs = _github_orgs(patterns)
    if not token:
        logger.info("GitHub discovery skipped: GITHUB_TOKEN is required.")
        return []

    candidates: list[dict] = []
    headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}"}
    with httpx.Client(timeout=15.0, headers=headers) as client:
        for org in orgs:
            for term in CODE_SEARCH_TERMS:
                query = f"org:{org} {term}"
                try:
                    response = client.get(GITHUB_SEARCH_ENDPOINT, params={"q": query, "per_page": 10})
                    response.raise_for_status()
                except httpx.HTTPError as exc:
                    logger.warning("GitHub discovery query failed for %s: %s", org, exc)
                    continue
                for item in response.json().get("items", []):
                    repository = item.get("repository", {})
                    # Defense in depth: trust neither the query nor API result blindly.
                    if repository.get("owner", {}).get("login", "").lower() != org.lower():
                        continue
                    candidates.append({
                        "url": item.get("html_url", repository.get("html_url", "")),
                        "fetch_url": item.get("url", ""),  # GitHub Contents API URL
                        "source_type": "code_repo",
                        "accessibility": "public_no_auth",
                        "asset_criticality": "unknown",
                        "github_headers": headers,
                        "discovery_query": query,
                    })
    return candidates


def cloud_bucket_check(patterns: list[AssetPattern]) -> list[dict]:
    """Reserved for an explicitly approved cloud-account verifier.

    A name prefix alone cannot prove a public bucket belongs to the tenant, so
    this connector intentionally does no network probing until an ownership
    verification mechanism is configured.
    """
    if any(item.asset_type == AssetType.CLOUD_BUCKET_PREFIX for item in patterns):
        logger.info("Cloud bucket discovery is disabled pending tenant ownership verification.")
    return []


def leak_feed_check(patterns: list[AssetPattern]) -> list[dict]:
    """Reserved for a licensed provider with tenant-specific authorization."""
    return []


ALL_CONNECTORS = [authorized_site_crawl, code_repo_scan, cloud_bucket_check, leak_feed_check]


def run_all_connectors(patterns: list[AssetPattern]) -> list[dict]:
    candidates: list[dict] = []
    for connector in ALL_CONNECTORS:
        candidates.extend(connector(patterns))
    return candidates
