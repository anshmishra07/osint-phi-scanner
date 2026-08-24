from pydantic import BaseModel
from app.models.finding import Severity, FindingStatus, ExposureType
from app.models.tenant import AssetType


class TenantCreate(BaseModel):
    name: str
    contact_email: str
    authorization_reference: str | None = None


class TenantOut(BaseModel):
    id: int
    name: str
    contact_email: str
    authorization_confirmed: bool

    class Config:
        from_attributes = True


class AssetPatternCreate(BaseModel):
    asset_type: AssetType
    value: str
    notes: str | None = None


class ScanRequest(BaseModel):
    """Manually submit a candidate artifact for scanning (used for demo /
    ad-hoc checks; the scheduled pipeline calls process_candidate directly)."""
    tenant_id: int
    url: str
    source_type: str  # web_page, cloud_bucket, code_repo, paste_site
    text: str
    accessibility: str = "public_no_auth"
    asset_criticality: str = "unknown"


class DiscoveryRunOut(BaseModel):
    tenant_id: int
    discovered: int
    processed: int
    findings: int


class FindingOut(BaseModel):
    id: int
    tenant_id: int
    source_url: str
    source_type: str
    exposure_type: ExposureType
    redacted_excerpt: str | None
    confidence: float
    risk_score: float
    severity: Severity
    status: FindingStatus
    estimated_record_count: int
    breach_notification_flag: bool

    class Config:
        from_attributes = True


class StatusUpdate(BaseModel):
    status: FindingStatus
