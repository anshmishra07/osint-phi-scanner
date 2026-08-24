"""MongoDB connection and collection helpers for local and hosted deployments."""
import os

from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument
from pymongo.errors import ServerSelectionTimeoutError

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://127.0.0.1:27017")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "phi_scanner")
def _require_supported_uri(uri: str) -> None:
    """Accept only standard MongoDB URI schemes without logging credentials."""
    if not uri.startswith(("mongodb://", "mongodb+srv://")):
        raise RuntimeError("MONGODB_URI must use mongodb:// or mongodb+srv://.")


_require_supported_uri(MONGODB_URI)
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
