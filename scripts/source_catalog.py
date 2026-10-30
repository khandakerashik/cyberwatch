"""Administrator-managed publisher catalogue and deterministic relevance matching.

This module has no network side effects. Endpoints come from the checked-in
catalogue or a local administrator-supplied file, never an HTTP request.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

CATALOG_PATH = Path(__file__).resolve().parents[1] / "data/news-sources.json"
SOURCE_TYPES = {"mainstream", "security", "vendor", "government"}
FORMATS = {"rss", "atom", "auto", "nginx", "rdf", "kev", "cirt", "newspaper"}
RELEVANCE_RULES_PATH = Path(__file__).resolve().parents[1] / "data/news-relevance-rules.json"
RELEVANCE_RULES = json.loads(RELEVANCE_RULES_PATH.read_text(encoding="utf-8"))
RELEVANCE_VERSION = RELEVANCE_RULES["version"]
_COMPILED_SIGNALS = [(item, re.compile(item["pattern"], re.I),
                      re.compile(item["context"], re.I) if item.get("context") else None,
                      re.compile(item["reject"], re.I) if item.get("reject") else None)
                     for item in RELEVANCE_RULES["signals"]]
_STRICT_TITLES = [re.compile(pattern, re.I) for pattern in RELEVANCE_RULES["strictTitleExclusions"]]
_BOILERPLATE = [re.compile(pattern, re.I) for pattern in RELEVANCE_RULES["boilerplatePatterns"]]


def _clean(value, limit):
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def _publisher_lead(value):
    value = _clean(value, RELEVANCE_RULES["maxLeadChars"])
    return "" if any(pattern.search(value) for pattern in _BOILERPLATE) else value


def _signals(value):
    return [rule for rule, pattern, context, reject in _COMPILED_SIGNALS
            if pattern.search(value) and (context is None or context.search(value))
            and (reject is None or not reject.search(value))]


def _literal(term, value):
    return isinstance(term, str) and bool(term.strip()) and bool(
        re.search(r"(?<!\w)" + re.escape(term.strip()) + r"(?!\w)", value, re.I))


def news_relevance(title, body="", additional=(), excludes=()):
    """Assess an article's subject, not its publisher or stale derived tags.

    The bounded lead keeps incidental risk factors in an IPO article, source
    boilerplate and unrelated later paragraphs from qualifying the headline.
    Broad publisher newsletters may retain excluded items outside Newsboard.
    """
    title = _clean(title, RELEVANCE_RULES["maxTitleChars"])
    lead = _publisher_lead(body)
    value = title + " " + lead
    result = {"version": RELEVANCE_VERSION, "relevant": False, "matchedKeywords": [],
              "reason": "No clear cybersecurity subject in the article title or publisher lead."}
    if any(_literal(term, value) for term in excludes):
        result["reason"] = "Excluded by the configured keyword policy."
        return result
    title_signals = _signals(title)
    if any(pattern.search(title) for pattern in _STRICT_TITLES) and not any(rule["incident"] for rule in title_signals):
        result["reason"] = "General business, consumer privacy or technology coverage without a cybersecurity incident in the title."
        return result
    labels = list(dict.fromkeys(rule["label"] for rule in _signals(value)))
    for term in additional:
        if _literal(term, value) and term.strip() not in labels:
            labels.append(term.strip())
    if labels:
        result.update(relevant=True, matchedKeywords=labels[:40],
                      reason="Clear cybersecurity subject in the article title or publisher lead.")
    return result


def record_news_relevance(event, source=None):
    """Re-evaluate retained records using publisher text only.

    matchedKeywords, tags, recommendations and evidence notes are generated
    fields and are never allowed to manufacture relevance for a legacy item.
    """
    event = event if isinstance(event, dict) else {}
    source = source if isinstance(source, dict) else {}
    article = event.get("article")
    body = ""
    if isinstance(article, dict) and isinstance(article.get("paragraphs"), list):
        paragraphs = [_publisher_lead(item) for item in article["paragraphs"][:120] if isinstance(item, str)]
        body = _publisher_lead(" ".join(item for item in paragraphs if item))
    if not body:
        body = next((_publisher_lead(event.get(field)) for field in ("description", "summary")
                     if _publisher_lead(event.get(field))), "")
    return news_relevance(event.get("title", ""), body,
                          source.get("additionalKeywords", ()), source.get("excludeKeywords", ()))


def matched_keywords(title, body="", additional=(), excludes=()):
    """Return relevant topic labels for keyword-filtered general news feeds."""
    return news_relevance(title, body, additional, excludes)["matchedKeywords"]


def classify_source(source):
    if source.get("sourceType") in SOURCE_TYPES:
        return source["sourceType"]
    if source.get("group") == "newsboard":
        return "mainstream"
    if source.get("id") in {"cisa-kev", "cert-eu", "cirt-advisories", "cirt-alerts", "cirt-news", "bcsi"}:
        return "government"
    if source.get("kind") == "secondary":
        return "security" if source.get("group") == "news" else "mainstream"
    return "vendor"


def public_endpoint(value):
    if not isinstance(value, str) or len(value) > 3000 or any(ord(c) < 33 for c in value) or "\\" in value:
        return False
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in {None, 443} or not host:
            return False
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".test", ".invalid", ".example", ".")):
            return False
        try:
            address = ipaddress.ip_address(host)
            return address.is_global and not address.is_multicast
        except ValueError:
            return "." in host and not re.fullmatch(r"[0-9xXa-fA-F.]+", host) and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in host.split("."))
    except (ValueError, TypeError):
        return False


def load_sources(base_sources, path=CATALOG_PATH):
    """Return a validated union; an explicit disabled id can disable a base feed."""
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(config, dict) or config.get("version") != 1:
        raise ValueError("Source catalogue must have version 1")
    entries = config.get("sources")
    if not isinstance(entries, list) or len(entries) > 100:
        raise ValueError("Source catalogue requires at most 100 source entries")
    for field in ("additionalKeywords", "excludeKeywords"):
        values = config.get(field, [])
        if not isinstance(values, list) or len(values) > 50 or any(not isinstance(x, str) or not x.strip() or len(x) > 80 for x in values):
            raise ValueError(field + " must contain at most 50 nonempty phrases")
    by_id = {source["id"]: dict(source) for source in base_sources}
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", str(entry.get("id", ""))) or entry["id"] in seen:
            raise ValueError("Catalogue source ids must be unique safe identifiers")
        seen.add(entry["id"])
        if entry.get("enabled") is False:
            by_id.pop(entry["id"], None)
            continue
        source = {**by_id.get(entry["id"], {}), **entry}
        if not isinstance(source.get("name"), str) or not source["name"].strip() or len(source["name"]) > 180:
            raise ValueError("Each catalogue source needs a bounded name")
        if not public_endpoint(source.get("url")):
            raise ValueError("Catalogue source homepage must be public HTTPS")
        feeds = source.get("feedUrls")
        if not isinstance(feeds, list) or not 1 <= len(feeds) <= 3 or not all(public_endpoint(x) for x in feeds):
            raise ValueError("Catalogue feedUrls must contain one to three public HTTPS endpoints")
        if source.get("format") not in FORMATS or source.get("group", "intelligence") not in {"intelligence", "news", "bangladesh", "newsboard", "research"}:
            raise ValueError("Unsupported catalogue parser or group")
        if source.get("sourceType") not in SOURCE_TYPES:
            raise ValueError("Catalogue sourceType is required")
        if not isinstance(source.get("maxItems", 30), int) or isinstance(source.get("maxItems"), bool) or not 1 <= source.get("maxItems", 30) <= 100:
            raise ValueError("Source maxItems must be between 1 and 100")
        if source.get("group") == "research" and not isinstance(source.get("learning"), dict):
            raise ValueError("Research source learning metadata must be an object")
        retention_maximum = 3650 if source.get("group") == "research" and source.get("learning", {}).get("kind") == "release" else 365
        if not isinstance(source.get("retentionDays", 30), int) or isinstance(source.get("retentionDays"), bool) or not 1 <= source.get("retentionDays", 30) <= retention_maximum:
            raise ValueError("Source retentionDays is outside the permitted range")
        for host in source.get("redirectHosts", []):
            if not public_endpoint("https://" + str(host) + "/"):
                raise ValueError("Redirect hosts must be public exact hostnames")
        if source.get("changesUrl") and not public_endpoint(source["changesUrl"]):
            raise ValueError("Advisory changelog must be public HTTPS")
        by_id[source["id"]] = source
    result = []
    for source in by_id.values():
        source["sourceType"] = classify_source(source)
        source["additionalKeywords"] = list(config.get("additionalKeywords", []))
        source["excludeKeywords"] = list(config.get("excludeKeywords", []))
        result.append(source)
    return tuple(result)
