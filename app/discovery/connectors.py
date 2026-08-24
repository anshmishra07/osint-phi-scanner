"""Credential-gated, tenant-scoped discovery connectors.

These connectors never run a broad query: every query is derived from an
authorized tenant's AssetPattern records. They return metadata only; callers
must validate scope again before fetching any result.
"""
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

import httpx
from dotenv import dotenv_values

from app.models.tenant import AssetPattern, AssetType

logger = logging.getLogger("phi_scanner.discovery")
DOTENV_PATH = Path(__file__).resolve().parents[2] / ".env"

GITHUB_SEARCH_ENDPOINT = "https://api.github.com/search/code"
CODE_SEARCH_TERMS = ('"API_KEY"', '"SECRET"', '"DATABASE_URL"', 'filename:.env')
MAX_SITEMAPS_PER_DOMAIN = 5
MAX_URLS_PER_DOMAIN = 100
GITHUB_ORG_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")


def _domains(patterns: list[AssetPattern]) -> list[str]:
    domains = [item.value.lower().removeprefix("https://").removeprefix("http://").rstrip("/")
               for item in patterns if item.asset_type == AssetType.DOMAIN]
    return list(dict.fromkeys(domains))


def _github_orgs(patterns: list[AssetPattern]) -> list[str]:
    return _github_accounts(patterns, AssetType.GITHUB_ORG)


def _github_users(patterns: list[AssetPattern]) -> list[str]:
    return _github_accounts(patterns, AssetType.GITHUB_USER)


def _github_accounts(patterns: list[AssetPattern], asset_type: AssetType) -> list[str]:
    orgs = []
    for item in patterns:
        if item.asset_type != asset_type:
            continue
        value = item.value.strip().rstrip("/")
        # Asset registration accepts either "org-name" or a GitHub org URL.
        if value.startswith(("https://", "http://")):
            parsed = urlparse(value)
            if parsed.hostname not in {"github.com", "www.github.com"}:
                continue
            value = parsed.path.strip("/").split("/", 1)[0]
        if GITHUB_ORG_RE.fullmatch(value):
            orgs.append(value)
        else:
            logger.warning("Ignored invalid GitHub account asset: %s", item.value)
    return list(dict.fromkeys(orgs))


def _github_token() -> str | None:
    """Read the optional credential from this project's ignored .env file only."""
    token = dotenv_values(DOTENV_PATH).get("GITHUB_TOKEN")
    return token.strip() if isinstance(token, str) and token.strip() else None


def is_authorized_domain_url(url: str, domains: list[str]) -> bool:
    """Allow a configured domain and its subdomains, over HTTP(S) only."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return parsed.scheme in {"http", "https"} and any(host == domain or host.endswith(f".{domain}") for domain in domains)


def is_authorized_github_url(url: str, orgs: list[str]) -> bool:
    """Allow only a github.com file URL owned by a registered organization."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in {"github.com", "www.github.com"}:
        return False
    path_parts = [part for part in parsed.path.split("/") if part]
    return len(path_parts) >= 2 and any(path_parts[0].lower() == org.lower() for org in orgs)


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
            # A large number of legitimate small sites do not publish a sitemap.
            # The authorized home page is therefore always a bounded first candidate;
            # sitemap pages add coverage when available.
            urls = [f"https://{domain}/", *_sitemap_urls(client, domain)]
            for url in dict.fromkeys(urls):
                candidates.append({
                    "url": url,
                    "source_type": "web_page",
                    "accessibility": "public_no_auth",
                    "asset_criticality": "unknown",
                    "discovery_source": "tenant_sitemap",
                })
    return candidates


def code_repo_scan(patterns: list[AssetPattern]) -> list[dict]:
    """Search only registered GitHub organizations or user accounts."""
    scopes = [("org", org) for org in _github_orgs(patterns)]
    scopes.extend(("user", user) for user in _github_users(patterns))
    if not scopes:
        return []
    token = _github_token()
    if not token:
        logger.info("GitHub discovery skipped: GITHUB_TOKEN is required.")
        return []

    candidates: list[dict] = []
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Authorized-PHI-Scanner/0.1",
    }
    seen_content_urls: set[str] = set()
    with httpx.Client(timeout=15.0, headers=headers) as client:
        for qualifier, account in scopes:
            for term in CODE_SEARCH_TERMS:
                query = f"{qualifier}:{account} {term}"
                try:
                    response = client.get(GITHUB_SEARCH_ENDPOINT, params={"q": query, "per_page": 10})
                    if response.status_code in {403, 429}:
                        logger.warning("GitHub discovery stopped for %s: API rate limit or access restriction.", account)
                        break
                    response.raise_for_status()
                except httpx.HTTPError:
                    logger.warning("GitHub discovery query failed for authorized GitHub account %s.", account)
                    continue
                try:
                    items = response.json().get("items", [])
                except ValueError:
                    logger.warning("GitHub discovery returned an invalid response for authorized GitHub account %s.", account)
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    repository = item.get("repository", {})
                    if not isinstance(repository, dict):
                        continue
                    owner = repository.get("owner", {})
                    if not isinstance(owner, dict):
                        continue
                    # Defense in depth: trust neither the query nor API result blindly.
                    if owner.get("login", "").lower() != account.lower():
                        continue
                    content_url = item.get("url", "")
                    html_url = item.get("html_url", "")
                    repository_url = repository.get("url", "")
                    if not all(isinstance(value, str) for value in (content_url, html_url, repository_url)):
                        continue
                    if not content_url or content_url in seen_content_urls or not is_authorized_github_url(html_url, [account]):
                        continue
                    seen_content_urls.add(content_url)
                    candidates.append({
                        "url": html_url,
                        "fetch_url": content_url,  # GitHub Contents API URL
                        "source_type": "code_repo",
                        "accessibility": "public_no_auth",
                        "asset_criticality": "unknown",
                        "github_headers": headers,
                        "repository_url": repository_url,
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
