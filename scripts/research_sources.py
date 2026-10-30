"""Research Lab source metadata and conservative official-standard watches.

Feeds provide dated publications; edition pages provide observed markers only.
An observation date is never promoted into a publication/release date.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.parse import urljoin, urlsplit

try:
    from .source_catalog import load_sources, public_endpoint
    from .article_content import fetch_public
except ImportError:
    from source_catalog import load_sources, public_endpoint
    from article_content import fetch_public

RESEARCH_PATH = Path(__file__).resolve().parents[1] / "data/research-sources.json"
DOMAINS = {"web", "api", "mobile", "ai", "cloud", "identity", "detection", "general"}
PERSPECTIVES = {"offensive", "defensive"}
KINDS = {"release", "research", "guide", "tool", "project-update"}
RELEASE_STATUSES = {"published", "prerelease", "draft", "unknown"}
DATE_BASES = {"source-published", "source-updated", "observation"}
ADAPTERS = {"web-top10", "api-top10", "mobile-top10", "llm-top10", "agentic-top10", "ai-testing"}
MAX_WATCH_BYTES = 2 * 1024 * 1024
_TECHNICAL = re.compile(r"\b(?:vulnerabilit\w*|exploit\w*|pentest\w*|penetration[ -]test\w*|red[ -]team\w*|blue[ -]team\w*|threat[ -](?:hunt\w*|intelligence)|reverse[ -]engineer\w*|fuzz\w*|malware|infostealer\w*|phishing|backdoor\w*|forensic\w*|forensique\w*|prompt[ -]injection|SQL[ -]injection|SSRF|XSS|CSRF|request[ -]smuggling|authentication|authorization|Active[ -]Directory|Kerberos|OAuth|SAML|cryptograph\w*|cryptanalysis|sandbox\w*|security[ -](?:research|testing|assessment|guide|verification|tool\w*|control\w*)|code[ -](?:analysis|audit\w*)|static[ -]analysis|dynamic[ -]analysis|detection[ -](?:rule\w*|engineering)|attack[ -](?:path\w*|technique\w*|surface|simulation)|(?:active|passive)[ -]scann?\w*|Zest[ -]scripts?|intercepting[ -]prox\w*|Top\s*10|ASVS|MASVS|MASTG|WSTG|ATT&CK|STIX|YARA|Sigma)\b", re.I)
_PROMOTIONAL = re.compile(r"\b(?:hiring|careers?|job[ -]openings?|sponsorship|fundraising|funding[ -]round|acquisition|partnership|conference|summit|registration|webinar|award\w*|anniversary)\b", re.I)
_POLICY_PROMOTION = re.compile(r"\b(?:pledges?|signator(?:y|ies)|open[ -]letter)\b|\b(?:sign(?:s|ed|ing)?|endors(?:e|es|ed|ing)|join(?:s|ed|ing)?)\b.{0,80}\b(?:calls?|letters?|declarations?|pacts?|accords?|commitments?)\b", re.I)
_GUIDE_TITLE = re.compile(r"\b(?:guides?|guidance|handbooks?|tutorials?|walkthroughs?|step[ -]by[ -]step)\b|(?<![\w-])101(?![\w-])", re.I)


def _clean(value, limit=500):
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def validate_learning(value, *, config=False):
    if not isinstance(value, dict) or value.get("kind") not in KINDS:
        raise ValueError("Research learning metadata requires a supported kind")
    for key, choices in (("domains", DOMAINS), ("perspectives", PERSPECTIVES)):
        items = value.get(key)
        if not isinstance(items, list) or not 1 <= len(items) <= len(choices) or not all(isinstance(item, str) and item in choices for item in items) or len(items) != len(set(items)):
            raise ValueError("Invalid research " + key)
    if value.get("project") is not None and (not isinstance(value["project"], str) or not value["project"].strip() or len(value["project"]) > 180):
        raise ValueError("Invalid research project label")
    if value.get("releaseStatus", "unknown") not in RELEASE_STATUSES:
        raise ValueError("Invalid research release status")
    if value.get("dateBasis", "source-published") not in DATE_BASES:
        raise ValueError("Invalid research date basis")


def load_research_catalogue(path=RESEARCH_PATH):
    """Read trusted administrator configuration, never request-supplied URLs."""
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    sources = load_sources((), path)
    if len(sources) > 30:
        raise ValueError("Research catalogue has more than 30 feed channels")
    for source in sources:
        if source.get("group") != "research" or source.get("stream") != "news" or source.get("kind") != "primary":
            raise ValueError("Research channels must be primary research/news feeds")
        if source.get("format") not in {"rss", "atom", "auto", "rdf"}:
            raise ValueError("Research feeds require RSS or Atom")
        validate_learning(source.get("learning"), config=True)
        if source.get("watchRelease") is not None and not isinstance(source["watchRelease"], bool):
            raise ValueError("watchRelease must be boolean")
        if source.get("learningFilter") is not None and not isinstance(source["learningFilter"], bool):
            raise ValueError("learningFilter must be boolean")
        if source.get("watchRelease") and source["learning"]["kind"] != "release":
            raise ValueError("Only release feeds can create release watches")
    watches = config.get("watchPages", [])
    if not isinstance(watches, list) or len(watches) > 16:
        raise ValueError("Research catalogue permits at most 16 edition pages")
    ids, enabled = {source["id"] for source in sources}, []
    for item in watches:
        if not isinstance(item, dict) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,79}", str(item.get("id", ""))) or item["id"] in ids:
            raise ValueError("Edition watches need unique safe ids")
        ids.add(item["id"])
        if item.get("enabled") is False:
            continue
        if not isinstance(item.get("name"), str) or not item["name"].strip() or len(item["name"]) > 180:
            raise ValueError("Edition watches need bounded names")
        if not public_endpoint(item.get("url")) or item.get("adapter") not in ADAPTERS:
            raise ValueError("Invalid edition-watch URL or parser")
        if not isinstance(item.get("domains"), list) or not item["domains"] or any(domain not in DOMAINS for domain in item["domains"]):
            raise ValueError("Invalid edition-watch domains")
        hosts = item.get("allowedHosts", [])
        if not isinstance(hosts, list) or not 1 <= len(hosts) <= 5 or any(not public_endpoint("https://" + str(host) + "/") for host in hosts) or urlsplit(item["url"]).hostname not in hosts:
            raise ValueError("Edition watches require exact approved HTTPS hosts")
        enabled.append(item)
    if len(enabled) + sum(bool(source.get("watchRelease")) for source in sources) > 40:
        raise ValueError("Research watch count exceeds 40")
    return sources, tuple(enabled)


def release_status(title):
    """Published is a feed entry, not a claim that a standard is final/stable."""
    value = _clean(title)
    if re.search(r"\b(?:bleeding[ -]edge|nightly|draft|development|snapshot|unreleased)\b", value, re.I):
        return "draft"
    if re.search(r"\b(?:pre[ -]?release|release[ -]candidate|alpha|beta|rc\d*)\b|(?:^|[.\d-])(?:rc|alpha|beta)[.\d-]", value, re.I):
        return "prerelease"
    return "published"


def research_subject_matches(source, title, body=""):
    """Broad research-company feeds still need an article-level subject check."""
    if source.get("group") != "research" or not source.get("learningFilter"):
        return True
    title, lead = _clean(title, 1000), _clean(body, 2400)
    if (_PROMOTIONAL.search(title) or _POLICY_PROMOTION.search(title)) and not _TECHNICAL.search(title):
        return False
    return bool(_TECHNICAL.search(title + " " + lead))


def annotate_research_record(event, source):
    if not isinstance(source, dict) or source.get("group") != "research":
        return event
    metadata = source.get("learning")
    if not isinstance(metadata, dict):
        return event
    result = dict(event)
    learning = {key: list(value) if isinstance(value, list) else value for key, value in metadata.items()
                if key in {"kind", "domains", "perspectives", "project"}}
    # A descriptive format label, not a claim that a method is new or tested.
    # Only explicit headline wording changes research into a guide; standards
    # and tool names often contain "guide" but retain their source-defined kind.
    if learning["kind"] == "research" and _GUIDE_TITLE.search(_clean(event.get("title"), 1000)):
        learning["kind"] = "guide"
    # These are broad navigation aids, not formal OWASP or ATT&CK mappings.
    text = _clean(event.get("title"), 1000) + " " + _clean(event.get("description"), 2000)
    patterns = {"web": r"\b(?:web|browser|HTTP|XSS|CSRF|SSRF|SQL injection|request smuggling)\b",
                "api": r"\b(?:API|GraphQL|REST|BOLA|BFLA)\b",
                "mobile": r"\b(?:Android|iOS|mobile|MASVS|MASTG)\b",
                "ai": r"\b(?:LLM|AI|agentic|prompt injection|machine learning|generative)\b",
                "cloud": r"\b(?:cloud|Kubernetes|AWS|Azure|GCP|container)\b",
                "identity": r"\b(?:identity|Active Directory|Entra|Kerberos|OAuth|SAML|authentication)\b",
                "detection": r"\b(?:detection|Sigma|YARA|SIEM|telemetry|threat hunting)\b"}
    domains = set(learning.get("domains", []))
    domains.update(domain for domain, pattern in patterns.items() if re.search(pattern, text, re.I))
    if len(domains) > 1:
        domains.discard("general")
    learning["domains"] = sorted(domains or {"general"})
    learning["releaseStatus"] = release_status(event.get("title")) if learning["kind"] in {"release", "tool"} else "unknown"
    prior = event.get("learning", {})
    learning["dateBasis"] = prior.get("dateBasis") if isinstance(prior, dict) and prior.get("dateBasis") in {"source-published", "source-updated"} else "source-published"
    result["learning"] = learning
    result["tags"] = list(dict.fromkeys(["Research Lab", learning.get("project") or "Original research"] + learning["domains"]))
    result["severityBasis"] = "Research and standards publications are unrated learning resources; inclusion is not evidence of a local compromise or a severity assessment."
    result["impact"] = ["This publication may inform security testing, threat modeling, defensive validation, or study. Applicability depends on the full source and the environment being assessed."]
    result["recommendations"] = ["Read the original publication and verify its prerequisites, scope, version, and limitations.",
                                 "Practice applicable techniques in an authorized lab and record both the test evidence and a corresponding defensive validation.",
                                 "Compare the publication with your current methodology or control baseline before updating it."]
    note = "Research Lab classification uses the source catalogue and explicit topic words; it is a navigation aid, not a formal framework mapping."
    if learning["kind"] in {"release", "tool"}:
        note += " A repository release is not necessarily a new edition of a published standard. Draft and prerelease titles remain labelled."
    if learning["dateBasis"] == "source-updated":
        note += " This feed supplies an update timestamp rather than a separate original-publication timestamp."
    result["evidenceNote"] = note
    result.pop("newsRelevance", None)
    return result


class _EditionHTML(HTMLParser):
    """Extract small metadata markers, without retaining publisher page text."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.headings, self.parts = [], [], []
        self.hidden = 0
        self.heading = None
        self.anchor = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {"script", "style", "template"}:
            self.hidden += 1
        if tag in {"h1", "h2", "h3", "title"} and not self.hidden:
            self.heading = {"tag": tag, "id": attrs.get("id", ""), "parts": []}
        if tag == "a" and not self.hidden:
            self.anchor = {"href": attrs.get("href", ""), "parts": []}

    def handle_data(self, value):
        if self.hidden:
            return
        self.parts.append(value)
        if self.heading is not None:
            self.heading["parts"].append(value)
        if self.anchor is not None:
            self.anchor["parts"].append(value)

    def handle_endtag(self, tag):
        if tag in {"script", "style", "template"}:
            self.hidden = max(0, self.hidden - 1)
        if self.heading is not None and tag == self.heading["tag"]:
            self.headings.append((_clean(" ".join(self.heading["parts"])), self.heading["id"]))
            self.heading = None
        if tag == "a" and self.anchor is not None:
            self.links.append((_clean(" ".join(self.anchor["parts"])), self.anchor["href"]))
            self.anchor = None


def _approved_reference(url, watch):
    return public_endpoint(url) and urlsplit(url).hostname in watch["allowedHosts"]


def parse_edition_page(payload, watch, final_url=None):
    if not isinstance(payload, bytes) or len(payload) > MAX_WATCH_BYTES:
        raise ValueError("Invalid or oversized edition page")
    final_url = final_url or watch["url"]
    if not _approved_reference(final_url, watch):
        raise ValueError("Edition page redirected outside approved hosts")
    page = _EditionHTML()
    page.feed(payload.decode("utf-8", errors="replace"))
    headings = page.headings
    links = [(label, urljoin(final_url, href)) for label, href in page.links
             if href and _approved_reference(urljoin(final_url, href), watch)]
    adapter = watch["adapter"]
    label, reference = None, final_url
    if adapter == "web-top10":
        candidates = [(int(match.group(1)), link) for _text, link in links
                      if (match := re.search(r"/(20\d{2})/en(?:/|$)", urlsplit(link).path))]
        if candidates:
            year, reference = max(candidates)
            label = "OWASP Top 10:" + str(year)
    elif adapter == "api-top10":
        candidates = [(int(match.group(1)), link) for _text, link in links
                      if (match := re.search(r"/editions/(20\d{2})/en(?:/|$)", urlsplit(link).path))]
        if candidates:
            year = max(year for year, _link in candidates)
            current = [link for candidate_year, link in candidates if candidate_year == year]
            reference = next((link for link in current if "/0x00-header" in link), min(current, key=len))
            label = "OWASP API Security Top 10 " + str(year)
    elif adapter == "mobile-top10":
        candidates = []
        for heading, _anchor in headings:
            match = re.search(r"Mobile\s+Top\s*10\s*[:–—-]?\s*(20\d{2})", heading, re.I)
            if match:
                candidates.append(int(match.group(1)))
        if candidates:
            label = "OWASP Mobile Top 10 " + str(max(candidates))
    elif adapter in {"llm-top10", "agentic-top10"}:
        expression = (r"TOP\s*10\s+FOR\s+(?:GEN\s*AI|LLM\s+APPLICATIONS)\s*[:–—-]?\s*(20\d{2})" if adapter == "llm-top10" else
                      r"(?:OWASP\s+)?Top\s*10\s+for\s+Agentic\s+Applications\s+(?:for\s+)?(20\d{2})")
        found = next((match.group(1) for heading, _anchor in headings if (match := re.search(expression, heading, re.I))), None)
        if not found and adapter == "llm-top10":
            found = next((match.group(1) for heading, _anchor in headings
                          if (match := re.search(r"^(20\d{2})\s+Top\s*10\s+Risk.{0,60}\bLLMs?\b", heading, re.I))), None)
        if found:
            label = ("OWASP Top 10 for LLM Applications " if adapter == "llm-top10" else "OWASP Top 10 for Agentic Applications ") + found
            suffix = ("owasp-top-10-for-llm-applications-" if adapter == "llm-top10" else "owasp-top-10-for-agentic-applications-for-") + found
            reference = next((link for _text, link in links if "/resource/" + suffix in link), final_url)
    elif adapter == "ai-testing":
        found = next(((heading, anchor, match.group(1)) for heading, anchor in headings
                      if (match := re.search(r"\bVersion\s+(\d+(?:\.\d+)*)\s+Published\b", heading, re.I))), None)
        if found:
            heading, anchor, version = found
            label = "OWASP AI Testing Guide v" + version
            reference = final_url.split("#")[0] + ("#" + anchor if anchor else "")
    if not label:
        raise ValueError("Expected official edition marker was not found")
    return {"currentLabel": label, "referenceUrl": reference, "publishedAt": None,
            "releaseStatus": "unknown", "dateBasis": "observation", "watchType": "edition"}


def _prior_watch(previous, identifier):
    return next((item for item in previous.get("researchWatch", []) if isinstance(item, dict) and item.get("id") == identifier), {})


def _watch_result(base, marker, prior, timestamp, error=None):
    result = dict(base)
    if error:
        for key in ("currentLabel", "referenceUrl", "publishedAt", "releaseStatus", "dateBasis", "contentHash", "firstObservedAt", "changedAt", "lastSuccessAt"):
            result[key] = prior.get(key)
        result.update(status="error", error=error, lastCheckedAt=timestamp, changeDetected=False)
        result["currentLabel"] = result.get("currentLabel") or "Not yet verified"
        result["referenceUrl"] = result.get("referenceUrl") or base["url"]
        result["releaseStatus"] = result.get("releaseStatus") or "unknown"
        result["dateBasis"] = result.get("dateBasis") or "observation"
        return result
    fingerprint = sha256(json.dumps({key: marker.get(key) for key in ("currentLabel", "referenceUrl", "releaseStatus")}, sort_keys=True).encode()).hexdigest()
    changed = bool(prior.get("contentHash") and prior["contentHash"] != fingerprint)
    result.update(marker)
    result.update(contentHash=fingerprint, firstObservedAt=prior.get("firstObservedAt") or timestamp,
                  changedAt=timestamp if changed else prior.get("changedAt"), lastCheckedAt=timestamp,
                  lastSuccessAt=timestamp, status="ok", error=None, changeDetected=changed)
    return result


def collect_page_watch(watch, previous, timestamp, fetcher=fetch_public):
    base = {"id": watch["id"], "name": watch["name"], "url": watch["url"], "domains": list(watch["domains"]),
            "sourceId": watch["id"], "watchType": "edition"}
    prior = _prior_watch(previous, watch["id"])
    try:
        payload, final_url, kind = fetcher(watch["url"], set(watch["allowedHosts"]), max_bytes=MAX_WATCH_BYTES)
        if not any(value in str(kind) for value in ("text/html", "application/xhtml+xml")):
            raise ValueError("Edition page is not HTML")
        marker = parse_edition_page(payload, watch, final_url)
        result = _watch_result(base, marker, prior, timestamp)
    except (OSError, ValueError, TypeError) as error:
        # Never expose infrastructure, response text, or a proxy address.
        result = _watch_result(base, {}, prior, timestamp,
                               "Official edition page could not be verified (" + type(error).__name__ + "). Last verified observation is retained where available.")
    registry = {"id": watch["id"], "name": watch["name"] + " · Edition watch", "url": watch["url"],
                "kind": "primary", "group": "research", "sourceType": "security", "status": result["status"],
                "lastSuccessAt": result["lastSuccessAt"], "lastAttemptAt": timestamp, "itemCount": 0,
                "description": "Checks the official project's edition marker. Observation dates do not establish publication dates.",
                "error": result["error"]}
    return result, registry


def release_watches(sources, results, previous, timestamp):
    output = []
    result_map = {registry["id"]: (events, registry) for events, registry in results}
    for source in sources:
        if not source.get("watchRelease"):
            continue
        identifier = "watch-" + source["id"]
        prior = _prior_watch(previous, identifier)
        base = {"id": identifier, "name": source["learning"].get("project") or source["name"],
                "url": source["url"], "domains": list(source["learning"]["domains"]), "sourceId": source["id"], "watchType": "release"}
        events, registry = result_map.get(source["id"], ([], {}))
        candidates = sorted(events, key=lambda item: (item.get("publishedAt", ""), item.get("id", "")), reverse=True)
        preferred = [event for event in candidates if event.get("learning", {}).get("releaseStatus") == "published"]
        # Atom updated can be recent for a very old release (e.g. WSTG 4.0).
        # Prefer the highest explicit version observed in the feed; retain its
        # actual feed timestamp and avoid treating an edit as a newer version.
        def version_key(event):
            match = re.search(r"(?<![\w.])(\d{1,5}(?:\.\d{1,5}){1,4})(?![\w.])", str(event.get("title", "")), re.I)
            if match is None:
                match = re.search(r"\bv(\d{1,5}(?:\.\d{1,5}){1,4})(?![\w.])", str(event.get("title", "")), re.I)
            return tuple(int(part) for part in match.group(1).split(".")) if match else (-1,)
        pool = preferred or candidates
        event = max(pool, key=lambda item: (version_key(item), item.get("publishedAt", ""))) if pool else None
        if registry.get("status") != "ok" or event is None:
            result = _watch_result(base, {}, prior, timestamp, "Release feed could not supply a verified publication. Last observed release is retained where available.")
        else:
            marker = {"currentLabel": _clean(event["title"], 300), "referenceUrl": event["sources"][0]["url"],
                      "publishedAt": event["publishedAt"], "releaseStatus": event["learning"]["releaseStatus"],
                      "dateBasis": event["learning"].get("dateBasis", "source-published"), "watchType": "release"}
            result = _watch_result(base, marker, prior, timestamp)
        output.append(result)
    return output


def collect_research_watches(sources, watches, results, previous, timestamp, fetcher=fetch_public):
    with ThreadPoolExecutor(max_workers=min(6, max(1, len(watches)))) as pool:
        page_results = list(pool.map(lambda watch: collect_page_watch(watch, previous, timestamp, fetcher), watches))
    observed = [item for item, _registry in page_results]
    observed.extend(release_watches(sources, results, previous, timestamp))
    return observed, [registry for _item, registry in page_results]


def watch_content_fingerprint(watches):
    """Source health and polling do not manufacture content-update timestamps."""
    fields = ("id", "name", "url", "domains", "sourceId", "currentLabel", "referenceUrl", "publishedAt", "watchType", "releaseStatus", "dateBasis", "contentHash")
    content = [{key: item.get(key) for key in fields} for item in sorted(watches, key=lambda value: value["id"])]
    return sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
