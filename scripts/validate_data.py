#!/usr/bin/env python3
"""Validate the public snapshot and curated event data without network access."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def date(value):
    require(isinstance(value, str), "Dates must be ISO strings")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require("T" in value and parsed.tzinfo is not None, "Datetimes must include an explicit timezone")
    return parsed.astimezone(timezone.utc)


def link(value):
    require(isinstance(value, str) and len(value) <= 3000, "Source URL must be a bounded string")
    parsed = urlsplit(value)
    require(parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username and not parsed.password,
            "Sources require safe HTTP(S) URLs without credentials")
    require(not any(ord(character) < 33 for character in value), "Source URL contains whitespace or controls")


def strings(value, label, maximum=100):
    require(isinstance(value, list) and len(value) <= maximum, f"{label} must be a bounded array")
    require(all(isinstance(item, str) and len(item) <= 10000 for item in value), f"{label} must contain bounded strings")


def validate_event(event):
    require(isinstance(event, dict), "Each event must be an object")
    require(isinstance(event.get("id"), str) and re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", event["id"]), "Invalid event id")
    for field in ("title", "organization", "summary", "description", "severityBasis", "evidenceNote", "sourceId"):
        require(isinstance(event.get(field), str) and 0 < len(event[field]) <= 12000, f"{event['id']}: missing or invalid {field}")
    require(event.get("severity") in {"critical", "high", "medium", "low", "unknown"}, "Invalid severity")
    require(event.get("category") in {"Incident", "Vulnerability", "Advisory", "Patch", "News"}, "Invalid category")
    require(event.get("stream", "news" if event.get("category") == "News" else "intelligence") in {"intelligence", "news"}, "Invalid event stream")
    require(event.get("bangladeshScope") in {None, "national-advisory", "local-activity", "coverage"}, "Invalid Bangladesh scope")
    require(event.get("status") in {"investigating", "active", "mitigated", "resolved", "monitoring"}, "Invalid status")
    require(event.get("confidence") in {"confirmed", "reported"}, "Invalid confidence")
    require(isinstance(event.get("exploited"), bool), "exploited must be boolean")
    date(event.get("publishedAt"))
    date(event.get("updatedAt"))
    require(date(event["updatedAt"]) >= date(event["publishedAt"]), "updatedAt cannot precede publishedAt")
    for field in ("geography", "sectors", "cves", "tags", "impact", "recommendations"):
        strings(event.get(field), field, maximum=500 if field == "cves" else 100)
    if event.get("bangladeshScope"):
        require(any(value.lower() in {"bangladesh", "bd"} for value in event["geography"]), "Bangladesh-scoped events need explicit geography")
    require(all(re.fullmatch(r"CVE-\d{4}-\d{4,}", cve) for cve in event["cves"]), "Invalid CVE identifier")
    require(event["impact"] and event["recommendations"], "Impact and recommendations are required")
    require(isinstance(event.get("sources"), list) and 1 <= len(event["sources"]) <= 30, "Every event needs at least one source")
    for source in event["sources"]:
        require(isinstance(source.get("name"), str) and source["name"], "Every source needs a name")
        link(source.get("url"))
        if source.get("publishedAt") is not None:
            date(source["publishedAt"])
        require(source.get("kind") in {"primary", "secondary"}, "Invalid source kind")
    require(isinstance(event.get("timeline"), list) and len(event["timeline"]) <= 100, "Invalid timeline")
    for entry in event["timeline"]:
        date(entry.get("date"))
        require(all(isinstance(entry.get(field), str) and entry[field] for field in ("title", "description")), "Invalid timeline entry")
    if "technicalDetails" in event:
        details = event["technicalDetails"]
        require(isinstance(details, dict), "technicalDetails must be an object")
        fields = {"affectedSystems", "attackVector", "prerequisites", "detection", "mitigation", "limitations"}
        require(set(details) <= fields | {"reviewedAt"}, "Unsupported technicalDetails field")
        for field in fields:
            if field in details:
                values = details[field]
                require(isinstance(values, list) and len(values) <= 12, f"technicalDetails.{field} must be a bounded array")
                require(all(isinstance(value, str) and value.strip() and len(value) <= 1200 for value in values),
                        f"technicalDetails.{field} must contain nonempty bounded strings")
        if details.get("reviewedAt") is not None:
            date(details["reviewedAt"])


def validate_snapshot(data):
    require(isinstance(data, dict) and data.get("schemaVersion") == 1, "Unsupported snapshot schema")
    date(data.get("generatedAt"))
    for field in ("databaseUpdatedAt", "lastCheckedAt"):
        if field in data:
            require(isinstance(data[field], str) and "T" in data[field], f"{field} must include a full timestamp")
            require(date(data[field]) <= date(data["generatedAt"]), f"{field} cannot be later than snapshot generation")
    require(isinstance(data.get("events"), list) and len(data["events"]) <= 500, "Invalid event list")
    require(isinstance(data.get("sources"), list), "Missing source registry")
    source_ids = set()
    for source in data["sources"]:
        require(isinstance(source.get("id"), str) and source["id"] not in source_ids, "Duplicate or invalid source id")
        source_ids.add(source["id"])
        require(source.get("status") in {"ok", "error", "snapshot"}, "Invalid source status")
        require(source.get("kind") in {"primary", "secondary", "curated"}, "Invalid source kind")
        require(source.get("group", "intelligence") in {"intelligence", "news", "bangladesh"}, "Invalid source group")
        require(isinstance(source.get("itemCount"), int) and source["itemCount"] >= 0, "Invalid source item count")
        if source.get("url") is not None:
            link(source["url"])
        for field in ("lastSuccessAt", "lastAttemptAt"):
            if source.get(field) is not None:
                date(source[field])
    ids = set()
    for event in data["events"]:
        validate_event(event)
        require(event["id"] not in ids, "Duplicate event id")
        require(event["sourceId"] in source_ids, "Event sourceId has no registry entry")
        ids.add(event["id"])
    for source in data["sources"]:
        require(source["itemCount"] == sum(e["sourceId"] == source["id"] for e in data["events"]), "Source count does not match displayed records")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, default=ROOT / "dist/data/incidents.json")
    parser.add_argument("--curated", type=Path, default=ROOT / "data/curated.json")
    parser.add_argument("--bangladesh-curated", type=Path, default=ROOT / "data/bangladesh-curated.json")
    args = parser.parse_args()
    data = json.loads(args.file.read_text(encoding="utf-8"))
    validate_snapshot(data)
    curated_count = 0
    for path in (args.curated, args.bangladesh_curated):
        if not path.exists() and path == args.bangladesh_curated:
            continue
        curated = json.loads(path.read_text(encoding="utf-8"))
        require(isinstance(curated, list), "Curated file must contain an array")
        for event in curated:
            validate_event(event)
        curated_count += len(curated)
    print(f"Valid snapshot: {len(data['events'])} records; {len(data['sources'])} sources; {curated_count} curated records.")


if __name__ == "__main__":
    main()
