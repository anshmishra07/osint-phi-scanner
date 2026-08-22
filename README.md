# PHI Exposure Scanner (MVP)

Detects accidental public exposure of a healthcare organization's own data:
exposed patient identifiers, medical record templates, confidential reports,
API keys/secrets, and misconfigured public cloud resources — then scores risk
and suggests remediation.

## Scope guardrail (read before extending)
This tool is designed to search **only within an authorized tenant's own namespace** (their domains, cloud account patterns, repo orgs, document
fingerprints) — never as a general internet-wide PHI scraper. Every discovery
connector must be constrained by `AssetPattern` records tied to a `Tenant`
that has signed an authorization record. See `app/models/tenant.py`.

## Quickstart

```bash
pip install -r requirements.txt --break-system-packages
# Start a local MongoDB daemon (offline only; default: 127.0.0.1:27017)
mongod --dbpath .\\mongo-data
python -m app.seed_demo        # creates a demo tenant + runs detection on sample_data/
uvicorn app.main:app           # start the API
```

The app defaults to `mongodb://127.0.0.1:27017` and database `phi_scanner`.
Set `MONGODB_URI` or `MONGODB_DATABASE` only for another **local** MongoDB
instance; hosted and non-local URIs are rejected in this offline MVP.

Then visit http://localhost:8000/docs for the interactive API.

On this Windows setup, run without `--reload`: the watcher uses a named pipe
that may be blocked by local permissions (`WinError 5`). Stop and re-run the
command after code changes instead.

## Optional authorized discovery

Copy `.env.example` to `.env` only if GitHub code search is required. The
tenant-site crawler needs no API key. To run discovery, the selected tenant
must have a signed authorization reference and at least one registered asset
pattern:

```bash
python -m app.discovery.run_scan --tenant-id 1
```

The crawler reads `robots.txt` and XML sitemaps only from authorized domains,
then revalidates every discovered URL before fetching. It is not a web-wide
search engine or search-result scraper. GitHub searches are restricted to
registered `github_org` patterns. Cloud-bucket probing remains disabled until
ownership verification is implemented; a naming prefix alone is not sufficient
proof of ownership.

Use `GET /tenants/{tenant_id}/asset-patterns` to check registered assets and
`DELETE /asset-patterns/{asset_pattern_id}` to remove an incorrect one. Domain
asset patterns are normalized and duplicate registrations return the existing
asset instead of creating another crawl target.

## What's implemented in this MVP
- Tenant + asset-pattern scoping model
- PHI/PII detector (regex + context scoring; MRN, SSN, DOB+name proximity, insurance ID)
- Secrets/credential detector (regex + Shannon entropy, like TruffleHog-style rules)
- Cloud bucket misconfig checker (stub connector — wire up real HEAD requests when deployed)
- Risk scoring engine (sensitivity x accessibility x volume x asset criticality)
- Alerting (console/webhook stub, severity-tiered)
- Remediation playbook lookup + verification re-scan hook
- FastAPI CRUD for tenants, findings, alerts
- Local-only MongoDB persistence (default: `mongodb://127.0.0.1:27017`)

## What's stubbed (needs real credentials/network to finish)
- Google/Bing Custom Search API calls (`app/discovery/search_engine.py`)
- GitHub/GitLab code search API (`app/discovery/code_repo.py`)
- Cloud bucket enumeration (`app/discovery/cloud_storage.py`)
- Paste-site / breach-feed connectors (`app/discovery/leak_feeds.py`)

Each stub has a `# TODO(prod)` marking exactly what to plug in.
