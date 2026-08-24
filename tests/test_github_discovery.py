from unittest.mock import Mock, patch

from app.detectors.phi_detector import detect_phi
from app.detectors.secrets_detector import detect_secrets
from app.discovery.connectors import (
    _github_orgs,
    code_repo_scan,
    is_authorized_domain_url,
    is_authorized_github_url,
)
from app.discovery.run_scan import _fetch_text
from app.models.tenant import AssetPattern, AssetType


def github_asset(value="acme-health"):
    return AssetPattern(1, 1, AssetType.GITHUB_ORG, value)


def github_item(owner="acme-health", path="synthetic-demo.txt"):
    return {
        "url": f"https://api.github.com/repositories/1/contents/{path}",
        "html_url": f"https://github.com/{owner}/demo/blob/main/{path}",
        "repository": {
            "url": "https://api.github.com/repos/acme-health/demo",
            "owner": {"login": owner},
        },
    }


def configured_client(mock_client, response):
    client = mock_client.return_value.__enter__.return_value
    client.get.return_value = response
    return client


def test_domain_scope_allows_registered_domain_and_subdomains_only():
    domains = ["clinic.example"]
    assert is_authorized_domain_url("https://clinic.example/patients", domains)
    assert is_authorized_domain_url("https://portal.clinic.example/export", domains)
    assert not is_authorized_domain_url("https://clinic.example.attacker.test", domains)
    assert not is_authorized_domain_url("ftp://clinic.example/export", domains)


def test_github_scope_requires_registered_org_owner():
    assert is_authorized_github_url("https://github.com/Acme-Health/repo/blob/main/file.txt", ["acme-health"])
    assert not is_authorized_github_url("https://github.com/other-org/repo/blob/main/file.txt", ["acme-health"])
    assert not is_authorized_github_url("https://evil.test/acme-health/repo", ["acme-health"])


def test_github_org_accepts_name_and_rejects_non_github_url():
    patterns = [github_asset("Acme-Health"), github_asset("https://evil.test/not-ours")]
    assert _github_orgs(patterns) == ["Acme-Health"]


@patch("app.discovery.connectors.dotenv_values", return_value={"GITHUB_TOKEN": "nonempty-local-value"})
@patch("app.discovery.connectors.httpx.Client")
def test_personal_account_uses_only_the_registered_user_qualifier(mock_client, _mock_env):
    response = Mock(status_code=200)
    response.raise_for_status.return_value = None
    response.json.return_value = {"items": [github_item(owner="my-account")]}
    client = configured_client(mock_client, response)
    asset = AssetPattern(1, 1, AssetType.GITHUB_USER, "my-account")

    results = code_repo_scan([asset])

    assert len(results) == 1
    assert all(call.kwargs["params"]["q"].startswith("user:my-account ") for call in client.get.call_args_list)


@patch("app.discovery.connectors.dotenv_values", return_value={})
@patch("app.discovery.connectors.httpx.Client")
def test_github_discovery_skips_when_local_token_is_missing(mock_client, _mock_env):
    assert code_repo_scan([github_asset()]) == []
    mock_client.assert_not_called()


@patch("app.discovery.connectors.dotenv_values", return_value={"GITHUB_TOKEN": "nonempty-local-value"})
@patch("app.discovery.connectors.httpx.Client")
def test_github_discovery_rejects_other_organizations_and_deduplicates_urls(mock_client, _mock_env):
    response = Mock(status_code=200)
    response.raise_for_status.return_value = None
    owned = github_item()
    response.json.return_value = {"items": [owned, owned, github_item(owner="outside-org")]}
    client = configured_client(mock_client, response)

    results = code_repo_scan([github_asset()])

    assert len(results) == 1
    assert results[0]["url"] == owned["html_url"]
    assert results[0]["repository_url"] == owned["repository"]["url"]
    assert client.get.call_count == 4


@patch("app.discovery.connectors.dotenv_values", return_value={"GITHUB_TOKEN": "nonempty-local-value"})
@patch("app.discovery.connectors.httpx.Client")
def test_github_rate_limit_is_handled_without_a_failure(mock_client, _mock_env):
    response = Mock(status_code=403)
    client = configured_client(mock_client, response)

    assert code_repo_scan([github_asset()]) == []
    assert client.get.call_count == 1


@patch("app.discovery.connectors.dotenv_values", return_value={"GITHUB_TOKEN": "nonempty-local-value"})
@patch("app.discovery.connectors.httpx.Client")
def test_github_invalid_api_response_is_handled_without_a_failure(mock_client, _mock_env):
    response = Mock(status_code=200)
    response.raise_for_status.return_value = None
    response.json.side_effect = ValueError("not json")
    client = configured_client(mock_client, response)

    assert code_repo_scan([github_asset()]) == []
    assert client.get.call_count == 4


def test_off_scope_github_content_is_never_fetched():
    candidate = {"url": "https://github.com/outside-org/repo/blob/main/file.txt", "fetch_url": "https://api.github.com/repositories/1/contents/file.txt", "source_type": "code_repo"}
    with patch("app.discovery.run_scan.httpx.get") as get:
        assert _fetch_text(candidate, [], ["acme-health"]) is None
    get.assert_not_called()


def test_synthetic_phi_reaches_the_phi_detector():
    text = "\n".join(("Patient: Test Patient", "DOB: 01/01/1990", "MRN: DEMO-1234567", "Diagnosis: DEMO"))
    kinds = {match.kind for match in detect_phi(text)}
    assert {"mrn", "dob", "name_clinical_context"}.issubset(kinds)


def test_synthetic_secret_reaches_the_secret_detector():
    fake_value = "_".join(("DEMO", "NOT", "A", "REAL", "SECRET", "12345"))
    matches = detect_secrets(f'API_KEY="{fake_value}"')
    assert any(match.kind == "generic_api_key_assignment" for match in matches)
