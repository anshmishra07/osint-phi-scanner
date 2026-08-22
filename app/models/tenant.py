"""Tenant and asset-pattern documents used by the local MongoDB store."""
import datetime as dt
import enum
from dataclasses import dataclass, field


class AssetType(str, enum.Enum):
    DOMAIN = "domain"
    EMAIL_DOMAIN = "email_domain"
    CLOUD_BUCKET_PREFIX = "cloud_bucket_prefix"
    GITHUB_ORG = "github_org"
    DOC_FINGERPRINT = "doc_fingerprint"
    IDENTIFIER_PATTERN = "identifier_pattern"


@dataclass
class Tenant:
    id: int
    name: str
    contact_email: str
    authorization_confirmed: bool = False
    authorization_reference: str | None = None
    created_at: dt.datetime = field(default_factory=dt.datetime.utcnow)

    @classmethod
    def from_document(cls, document: dict) -> "Tenant":
        return cls(**{key: value for key, value in document.items() if key != "_id"})

    def to_document(self) -> dict:
        return self.__dict__.copy()


@dataclass
class AssetPattern:
    id: int
    tenant_id: int
    asset_type: AssetType
    value: str
    notes: str | None = None

    @classmethod
    def from_document(cls, document: dict) -> "AssetPattern":
        values = {key: value for key, value in document.items() if key != "_id"}
        values["asset_type"] = AssetType(values["asset_type"])
        return cls(**values)

    def to_document(self) -> dict:
        document = self.__dict__.copy()
        document["asset_type"] = self.asset_type.value
        return document
