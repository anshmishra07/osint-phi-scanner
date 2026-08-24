from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import RedirectResponse
from pymongo import ReturnDocument

from app.db import get_db, initialize_database, next_id
from app.models.tenant import Tenant, AssetPattern, AssetType
from app.models.finding import Finding
from app.schemas import (
    TenantCreate, TenantOut, AssetPatternCreate, ScanRequest, FindingOut, StatusUpdate, DiscoveryRunOut
)
from app.pipeline import process_candidate
from app.remediation.playbooks import get_playbook
from app.discovery.connectors import _github_orgs, _github_users, is_authorized_domain_url, is_authorized_github_url
from app.discovery.run_scan import run as run_discovery

app = FastAPI(
    title="PHI Exposure Scanner",
    description="Detects and helps remediate public exposure of healthcare org data.",
    version="0.1.0",
)


@app.on_event("startup")
def startup() -> None:
    initialize_database()


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    """Send browser visits to the interactive API documentation."""
    return RedirectResponse(url="/docs")


@app.post("/tenants", response_model=TenantOut)
def create_tenant(payload: TenantCreate, db=Depends(get_db)):
    tenant = Tenant(
        id=next_id(db, "tenants"),
        name=payload.name,
        contact_email=payload.contact_email,
        authorization_reference=payload.authorization_reference,
        authorization_confirmed=bool(payload.authorization_reference),
    )
    db.tenants.insert_one(tenant.to_document())
    return tenant


@app.post("/tenants/{tenant_id}/asset-patterns")
def add_asset_pattern(tenant_id: int, payload: AssetPatternCreate, db=Depends(get_db)):
    tenant = db.tenants.find_one({"id": tenant_id})
    if not tenant:
        raise HTTPException(404, "Tenant not found")
    value = payload.value.strip()
    if payload.asset_type == "domain":
        value = value.lower().removeprefix("https://").removeprefix("http://").rstrip("/")
        if not value or "/" in value or "?" in value or "#" in value:
            raise HTTPException(422, "A domain asset must be a bare domain, without a path or query string.")
    if payload.asset_type in {AssetType.GITHUB_ORG, AssetType.GITHUB_USER}:
        candidate = AssetPattern(id=0, tenant_id=tenant_id, asset_type=payload.asset_type, value=value)
        accounts = _github_orgs([candidate]) if payload.asset_type == AssetType.GITHUB_ORG else _github_users([candidate])
        if len(accounts) != 1:
            raise HTTPException(422, "GitHub asset must be an account name or https://github.com/<account>.")
        value = accounts[0]
    existing = db.asset_patterns.find_one({
        "tenant_id": tenant_id, "asset_type": payload.asset_type.value, "value": value,
    })
    if existing:
        return {"id": existing["id"], "asset_type": existing["asset_type"], "value": existing["value"]}
    ap = AssetPattern(id=next_id(db, "asset_patterns"), tenant_id=tenant_id, asset_type=payload.asset_type, value=value, notes=payload.notes)
    db.asset_patterns.insert_one(ap.to_document())
    return {"id": ap.id, "asset_type": ap.asset_type, "value": ap.value}


@app.get("/tenants/{tenant_id}/asset-patterns")
def list_asset_patterns(tenant_id: int, db=Depends(get_db)):
    if not db.tenants.find_one({"id": tenant_id}):
        raise HTTPException(404, "Tenant not found")
    return [
        {"id": item["id"], "asset_type": item["asset_type"], "value": item["value"], "notes": item.get("notes")}
        for item in db.asset_patterns.find({"tenant_id": tenant_id}).sort("id", 1)
    ]


@app.delete("/asset-patterns/{asset_pattern_id}")
def delete_asset_pattern(asset_pattern_id: int, db=Depends(get_db)):
    result = db.asset_patterns.delete_one({"id": asset_pattern_id})
    if not result.deleted_count:
        raise HTTPException(404, "Asset pattern not found")
    return {"deleted": True, "id": asset_pattern_id}


@app.post("/scan", response_model=FindingOut | None)
def scan_candidate(payload: ScanRequest, db=Depends(get_db)):
    document = db.tenants.find_one({"id": payload.tenant_id})
    if not document:
        raise HTTPException(404, "Tenant not found")
    tenant = Tenant.from_document(document)
    if not tenant.authorization_confirmed:
        raise HTTPException(
            403,
            "Tenant authorization not confirmed. Cannot scan without a signed "
            "authorization reference (see app/models/tenant.py).",
        )
    patterns = [AssetPattern.from_document(item) for item in db.asset_patterns.find({"tenant_id": tenant.id})]
    domains = [pattern.value for pattern in patterns if pattern.asset_type == AssetType.DOMAIN]
    if payload.source_type == "web_page" and not is_authorized_domain_url(payload.url, domains):
        raise HTTPException(403, "The URL is outside this tenant's registered domain assets.")
    github_accounts = [*_github_orgs(patterns), *_github_users(patterns)]
    if payload.source_type == "code_repo" and not is_authorized_github_url(payload.url, github_accounts):
        raise HTTPException(403, "The GitHub URL is outside this tenant's registered GitHub organizations.")

    identifier_patterns = [pattern.value for pattern in patterns if pattern.asset_type == AssetType.IDENTIFIER_PATTERN]
    finding = process_candidate(
        db=db,
        tenant=tenant,
        url=payload.url,
        source_type=payload.source_type,
        text=payload.text,
        accessibility=payload.accessibility,
        asset_criticality=payload.asset_criticality,
        tenant_identifier_regex=identifier_patterns[0] if identifier_patterns else None,
    )
    return finding


@app.post("/tenants/{tenant_id}/discovery", response_model=DiscoveryRunOut)
def discover_tenant_assets(tenant_id: int, db=Depends(get_db)):
    """Run the authorized live-site and GitHub discovery connectors."""
    if not db.tenants.find_one({"id": tenant_id}):
        raise HTTPException(404, "Tenant not found")
    try:
        result = run_discovery(tenant_id)
    except RuntimeError as exc:
        raise HTTPException(403, str(exc)) from exc
    return DiscoveryRunOut(
        tenant_id=tenant_id,
        discovered=result.discovered,
        processed=result.processed,
        findings=result.findings,
    )


@app.get("/tenants/{tenant_id}/findings", response_model=list[FindingOut])
def list_findings(tenant_id: int, db=Depends(get_db)):
    return [Finding.from_document(item) for item in db.findings.find({"tenant_id": tenant_id}).sort("risk_score", -1)]


@app.get("/findings/{finding_id}/remediation")
def get_remediation(finding_id: int, db=Depends(get_db)):
    document = db.findings.find_one({"id": finding_id})
    if not document:
        raise HTTPException(404, "Finding not found")
    finding = Finding.from_document(document)
    return {
        "finding_id": finding.id,
        "exposure_type": finding.exposure_type,
        "playbook": get_playbook(finding.exposure_type, finding.source_type),
    }


@app.patch("/findings/{finding_id}/status", response_model=FindingOut)
def update_status(finding_id: int, payload: StatusUpdate, db=Depends(get_db)):
    result = db.findings.find_one_and_update(
        {"id": finding_id}, {"$set": {"status": payload.status.value}}, return_document=ReturnDocument.AFTER
    )
    if not result:
        raise HTTPException(404, "Finding not found")
    return Finding.from_document(result)


@app.get("/health")
def health():
    return {"status": "ok"}
