"""Local-only MongoDB connection and collection helpers."""
import os

from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument
from pymongo.errors import ServerSelectionTimeoutError
from pymongo.uri_parser import parse_uri

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://127.0.0.1:27017")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "phi_scanner")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _require_local_uri(uri: str) -> None:
    """Prevent this offline MVP from being pointed at a hosted MongoDB."""
    if not uri.startswith("mongodb://"):
        raise RuntimeError("Offline mode only supports a local mongodb:// URI.")
    hosts = {host for host, _port in parse_uri(uri)["nodelist"]}
    if not hosts or not hosts.issubset(_LOCAL_HOSTS):
        raise RuntimeError("Offline mode requires MongoDB on localhost or 127.0.0.1.")


_require_local_uri(MONGODB_URI)
client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=2_000)
database = client[MONGODB_DATABASE]


def get_db():
    """FastAPI dependency. The process-wide MongoClient manages pooling."""
    yield database


def next_id(db, collection: str) -> int:
    counter = db.counters.find_one_and_update(
        {"_id": collection}, {"$inc": {"value": 1}}, upsert=True, return_document=ReturnDocument.AFTER
    )
    return counter["value"]


def initialize_database() -> None:
    """Verify the local daemon and set the indexes required by the API."""
    try:
        client.admin.command("ping")
    except ServerSelectionTimeoutError as exc:
        raise RuntimeError(
            "Local MongoDB is unavailable. Start mongod, then retry. "
            f"Expected server: {MONGODB_URI}"
        ) from exc
    database.tenants.create_index("id", unique=True)
    database.asset_patterns.create_index([("tenant_id", ASCENDING)])
    database.findings.create_index([("id", ASCENDING)], unique=True)
    database.findings.create_index([("tenant_id", ASCENDING), ("risk_score", DESCENDING)])
    database.alerts.create_index([("finding_id", ASCENDING)])
