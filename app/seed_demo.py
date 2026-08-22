"""
Runnable demo: creates a demo tenant (with authorization confirmed),
registers their asset patterns, then runs the sample_data/ files through
the full pipeline (detect -> score -> alert -> persist) exactly as a
scheduled job would after real discovery connectors are wired in.

Run: python -m app.seed_demo
"""
from pathlib import Path

from app.db import database, initialize_database, next_id
from app.models.tenant import Tenant, AssetPattern, AssetType
from app.pipeline import process_candidate

SAMPLE_DIR = Path(__file__).parent.parent / "sample_data"


def main():
    initialize_database()
    db = database

    document = db.tenants.find_one({"name": "Acme Health Clinic (Demo)"})
    if not document:
        tenant = Tenant(
            id=next_id(db, "tenants"),
            name="Acme Health Clinic (Demo)",
            contact_email="security@acmehealth.com",
            authorization_reference="DEMO-AUTH-2026-001",
            authorization_confirmed=True,
        )
        db.tenants.insert_one(tenant.to_document())
        db.asset_patterns.insert_many([
            AssetPattern(id=next_id(db, "asset_patterns"), tenant_id=tenant.id, asset_type=AssetType.DOMAIN, value="acmehealth.com").to_document(),
            AssetPattern(id=next_id(db, "asset_patterns"), tenant_id=tenant.id, asset_type=AssetType.EMAIL_DOMAIN, value="@acmehealth.com").to_document(),
            AssetPattern(id=next_id(db, "asset_patterns"), tenant_id=tenant.id, asset_type=AssetType.CLOUD_BUCKET_PREFIX, value="acmehealth-").to_document(),
            AssetPattern(id=next_id(db, "asset_patterns"), tenant_id=tenant.id, asset_type=AssetType.IDENTIFIER_PATTERN, value=r"ACME-\d{7}").to_document(),
        ])
        print(f"Created demo tenant id={tenant.id}")
    else:
        tenant = Tenant.from_document(document)
        print(f"Using existing demo tenant id={tenant.id}")

    scenarios = [
        ("exposed_web_page_1.txt", "https://acmehealth.com/reports/discharge_export.txt",
         "web_page", "indexed_by_search_engine", "production"),
        ("exposed_code_repo_1.txt", "https://github.com/some-fork/acmehealth-ehr-connector/config.py",
         "code_repo", "public_no_auth", "production"),
        ("benign_marketing_page.txt", "https://acmehealth.com/about",
         "web_page", "indexed_by_search_engine", "production"),
    ]

    print("\nRunning pipeline on sample_data/ artifacts...\n" + "-" * 60)
    for filename, url, source_type, accessibility, criticality in scenarios:
        text = (SAMPLE_DIR / filename).read_text()
        finding = process_candidate(
            db=db,
            tenant=tenant,
            url=url,
            source_type=source_type,
            text=text,
            accessibility=accessibility,
            asset_criticality=criticality,
            tenant_identifier_regex=r"ACME-\d{7}",
        )
        if finding:
            print(f"[{filename}] -> Finding #{finding.id}: {finding.exposure_type.value} | "
                  f"severity={finding.severity.value} | risk_score={finding.risk_score} | "
                  f"records~{finding.estimated_record_count} | "
                  f"breach_flag={finding.breach_notification_flag}")
        else:
            print(f"[{filename}] -> no sensitive signal detected (correct: benign page)")

    print("-" * 60)
    print("\nDemo complete. Start the API with: uvicorn app.main:app --reload")
    print("Then GET /tenants/{}/findings to see results via the API.".format(tenant.id))


if __name__ == "__main__":
    main()
