"""Small, evidence-based collection history retained in the public snapshot."""
from datetime import datetime, timezone

MAX_CHECKS = 48


def _timestamp(value):
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError):
        return None


def append_collection_history(source, previous=None):
    """Record actual checks, never infer uptime from missing runs or fetch age.

    A legacy registry can contribute its one explicitly recorded last attempt.
    Re-assembling the same attempt replaces that observation, not the sample
    count. Counts describe retained/displayed records after the snapshot budget.
    """
    if source.get("kind") == "curated":
        return []
    previous = previous or {}
    rows = list(previous.get("collectionHistory", [])) if isinstance(previous.get("collectionHistory"), list) else []
    if not rows and previous.get("status") in {"ok", "error"}:
        rows.append({"at": previous.get("lastAttemptAt"), "status": previous["status"],
                     "recordCount": previous.get("itemCount", 0)})
    if source.get("status") in {"ok", "error"}:
        rows.append({"at": source.get("lastAttemptAt"), "status": source["status"],
                     "recordCount": source.get("itemCount", 0)})
    current = _timestamp(source.get("lastAttemptAt"))
    current_time = datetime.fromisoformat(current.replace("Z", "+00:00")) if current else None
    checks = {}
    for row in rows[-(MAX_CHECKS + 2):]:
        if not isinstance(row, dict):
            continue
        at, count = _timestamp(row.get("at")), row.get("recordCount")
        if not at or row.get("status") not in {"ok", "error"}:
            continue
        instant = datetime.fromisoformat(at.replace("Z", "+00:00"))
        if current_time and instant > current_time:
            continue
        if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 2000:
            continue
        checks[instant] = {"at": at, "status": row["status"], "recordCount": count}
    return [checks[instant] for instant in sorted(checks)[-MAX_CHECKS:]]
