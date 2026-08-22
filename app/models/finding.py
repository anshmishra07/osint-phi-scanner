import datetime as dt
import enum
from dataclasses import dataclass, field


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    NEW = "new"
    TRIAGED = "triaged"
    REMEDIATION_IN_PROGRESS = "remediation_in_progress"
    REMEDIATED_PENDING_VERIFICATION = "remediated_pending_verification"
    VERIFIED_RESOLVED = "verified_resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class ExposureType(str, enum.Enum):
    PATIENT_IDENTIFIER = "patient_identifier"
    MEDICAL_RECORD_TEMPLATE = "medical_record_template"
    CONFIDENTIAL_REPORT = "confidential_report"
    API_KEY_SECRET = "api_key_secret"
    MISCONFIGURED_STORAGE = "misconfigured_storage"
    OTHER = "other"


@dataclass
class Finding:
    id: int
    tenant_id: int
    source_url: str
    source_type: str
    exposure_type: ExposureType
    redacted_excerpt: str | None = None
    detector_signals: dict = field(default_factory=dict)
    confidence: float = 0.0
    risk_score: float = 0.0
    severity: Severity = Severity.INFO
    status: FindingStatus = FindingStatus.NEW
    estimated_record_count: int = 1
    breach_notification_flag: bool = False
    first_seen: dt.datetime = field(default_factory=dt.datetime.utcnow)
    last_verified: dt.datetime = field(default_factory=dt.datetime.utcnow)

    @classmethod
    def from_document(cls, document: dict) -> "Finding":
        values = {key: value for key, value in document.items() if key != "_id"}
        for name, enum_type in (("exposure_type", ExposureType), ("severity", Severity), ("status", FindingStatus)):
            values[name] = enum_type(values[name])
        return cls(**values)

    def to_document(self) -> dict:
        document = self.__dict__.copy()
        for name in ("exposure_type", "severity", "status"):
            document[name] = document[name].value
        return document


@dataclass
class Alert:
    id: int
    finding_id: int
    channel: str = "console"
    sent_at: dt.datetime = field(default_factory=dt.datetime.utcnow)
    payload: dict = field(default_factory=dict)

    def to_document(self) -> dict:
        return self.__dict__.copy()
