#!/usr/bin/env python3
"""Collect public intelligence for a static CyberWatch deployment. Python 3.10+.

No credentials or external packages. Network is used only by main()/collect().
Feed dates, collection dates, and analyst assessments remain separate.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from hashlib import sha256
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import urlsplit, urljoin, urlunsplit, parse_qsl, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
MAX_RESPONSE = 8 * 1024 * 1024
TIMEOUT = 20
ATOM = {"a": "http://www.w3.org/2005/Atom"}
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
SOURCES = (
    {"id": "cisa-kev", "name": "CISA Known Exploited Vulnerabilities",
     "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
     "feedUrls": ["https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
                  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"], "format": "kev"},
    {"id": "cert-eu", "name": "CERT-EU Security Advisories",
     "url": "https://cert.europa.eu/publications/security-advisories/",
     "feedUrls": ["https://cert.europa.eu/publications/security-advisories-rss"], "format": "rss"},
    {"id": "chrome", "name": "Google Chrome Releases",
     "url": "https://chromereleases.googleblog.com/",
     "feedUrls": ["https://feeds.feedburner.com/GoogleChromeReleases"], "format": "atom"},
    {"id": "the-hacker-news", "name": "The Hacker News",
     "url": "https://thehackernews.com/", "group": "news", "kind": "secondary",
     "description": "Independent cybersecurity reporting, incident coverage and security news.",
     "feedUrls": ["https://feeds.feedburner.com/TheHackersNews"], "format": "rss"},
    {"id": "cybernews", "name": "Cybernews",
     "url": "https://cybernews.com/", "group": "news", "kind": "secondary", "headlineOnly": True,
     "description": "Cybernews cybersecurity reporting and investigations. Headlines link directly to the original articles.",
     "feedUrls": ["https://cybernews.com/feed/"], "format": "rss"},
    {"id": "bleepingcomputer", "name": "BleepingComputer",
     "url": "https://www.bleepingcomputer.com/", "group": "news", "kind": "secondary",
     "description": "Cybersecurity news, ransomware coverage, data breaches and software security updates.",
     "feedUrls": ["https://www.bleepingcomputer.com/feed/"], "format": "rss"},
    {"id": "securityweek", "name": "SecurityWeek",
     "url": "https://www.securityweek.com/", "group": "news", "kind": "secondary",
     "description": "Enterprise cybersecurity reporting, threat intelligence and security industry analysis.",
     "feedUrls": ["https://www.securityweek.com/feed/"], "format": "rss"},
    {"id": "help-net-security", "name": "Help Net Security",
     "url": "https://www.helpnetsecurity.com/", "group": "news", "kind": "secondary",
     "description": "Information security news, enterprise security analysis and research updates.",
     "feedUrls": ["https://www.helpnetsecurity.com/feed/"], "format": "rss"},
    {"id": "unit42", "name": "Palo Alto Networks · Unit 42",
     "url": "https://unit42.paloaltonetworks.com/", "group": "news",
     "description": "Threat research and incident analysis published by Palo Alto Networks Unit 42.",
     "feedUrls": ["https://unit42.paloaltonetworks.com/feed/"], "format": "rss"},
    {"id": "crowdstrike", "name": "CrowdStrike",
     "url": "https://www.crowdstrike.com/en-us/blog/", "group": "news",
     "description": "Threat intelligence, research and product security updates from CrowdStrike.",
     "feedUrls": ["https://www.crowdstrike.com/en-us/blog/feed"], "format": "rss"},
    {"id": "php", "name": "PHP · Official updates",
     "url": "https://www.php.net/", "group": "news",
     "description": "PHP project announcements, security notices and releases.",
     "feedUrls": ["https://www.php.net/feed.atom"], "format": "atom"},
    {"id": "microsoft-security", "name": "Microsoft Security",
     "url": "https://www.microsoft.com/en-us/security/blog/", "group": "news",
     "description": "Microsoft threat intelligence, security research and product updates.",
     "feedUrls": ["https://www.microsoft.com/en-us/security/blog/feed/"], "format": "rss"},
    {"id": "cisco-talos", "name": "Cisco Talos",
     "url": "https://blog.talosintelligence.com/", "group": "news",
     "description": "Talos threat research and the Threat Source newsletter.",
     "feedUrls": ["https://blog.talosintelligence.com/rss/"], "format": "rss"},
    {"id": "cirt-advisories", "name": "BGD e-GOV CIRT · Advisories",
     "url": "https://www.cirt.gov.bd/advisories", "group": "bangladesh",
     "description": "National advisories issued by Bangladesh's government incident response team.",
     "feedUrls": ["https://www.cirt.gov.bd/advisories"], "format": "cirt", "geography": ["Bangladesh"]},
    {"id": "cirt-alerts", "name": "BGD e-GOV CIRT · Alerts",
     "url": "https://www.cirt.gov.bd/alerts", "group": "bangladesh",
     "description": "Official Bangladesh cyber alerts. An alert alone does not establish a local compromise.",
     "feedUrls": ["https://www.cirt.gov.bd/alerts"], "format": "cirt", "geography": ["Bangladesh"]},
    {"id": "cirt-news", "name": "BGD e-GOV CIRT · Activities",
     "url": "https://www.cirt.gov.bd/news", "group": "bangladesh", "stream": "news",
     "description": "Published national cybersecurity programmes, training and institutional activity.",
     "feedUrls": ["https://www.cirt.gov.bd/news"], "format": "cirt", "geography": ["Bangladesh"]},
    {"id": "bcsi", "name": "Bangladesh Cyber Security Intelligence",
     "url": "https://bcsi.gov.bd/", "group": "bangladesh",
     "description": "Bangladesh advisories and threat reporting published by BCSI.",
     "feedUrls": ["https://bcsi.gov.bd/feed/"], "format": "rss", "geography": ["Bangladesh"]},
    {"id": "daily-star", "name": "The Daily Star",
     "url": "https://www.thedailystar.net/search?t=cyber#gsc.tab=0&gsc.q=cyber&gsc.page=1",
     "group": "bangladesh", "stream": "news", "kind": "secondary", "headlineOnly": True,
     "cyberHeadlinesOnly": True, "bangladeshScope": "coverage", "geography": ["Bangladesh"],
     "description": "English headlines containing cyber from The Daily Star's public front page, with publisher dates and original links. Retains collected headlines for 30 days. Regional publisher coverage does not establish a Bangladesh incident.",
     "feedUrls": ["https://www.thedailystar.net/"], "format": "newspaper",
     "articleHost": "www.thedailystar.net", "articlePath": r"^/(?:[a-z0-9-]+/)+[a-z0-9-]+-\d+/?$"},
    {"id": "dhaka-tribune", "name": "Dhaka Tribune",
     "url": "https://www.dhakatribune.com/", "group": "bangladesh", "stream": "news", "kind": "secondary",
     "headlineOnly": True, "cyberHeadlinesOnly": True, "bangladeshScope": "coverage", "geography": ["Bangladesh"],
     "description": "Official Dhaka Tribune RSS, filtered to English headlines containing cyber. Retains collected headlines for 30 days. Regional publisher coverage does not establish a Bangladesh incident.",
     "feedUrls": ["https://www.dhakatribune.com/feed/"], "format": "rss",
     "articleHost": "www.dhakatribune.com", "articlePath": r"^/(?:[a-z0-9-]+/)+\d+/[a-z0-9-]+/?$"},
    {"id": "tbs", "name": "The Business Standard",
     "url": "https://www.tbsnews.net/tags/cyber-attack", "group": "bangladesh", "stream": "news", "kind": "secondary",
     "headlineOnly": True, "cyberHeadlinesOnly": True, "bangladeshScope": "coverage", "geography": ["Bangladesh"],
     "description": "English cyber headlines from The Business Standard's public Cyber attack topic index, with publisher dates and original links. Retains collected headlines for 30 days. Regional publisher coverage does not establish a Bangladesh incident.",
     "feedUrls": ["https://www.tbsnews.net/tags/cyber-attack"], "format": "newspaper",
     "articleHost": "www.tbsnews.net", "articlePath": r"^/(?!tags/|search/|author/)[a-z0-9-]+(?:/[a-z0-9-]+)+/?$"},
    {"id": "financial-express", "name": "The Financial Express",
     "url": "https://thefinancialexpress.com.bd/", "group": "bangladesh", "stream": "news", "kind": "secondary",
     "headlineOnly": True, "cyberHeadlinesOnly": True, "bangladeshScope": "coverage", "geography": ["Bangladesh"],
     "description": "English headlines containing cyber from The Financial Express public front page, with publisher dates and original links. Retains collected headlines for 30 days. Regional publisher coverage does not establish a Bangladesh incident.",
     "feedUrls": ["https://thefinancialexpress.com.bd/"], "format": "newspaper",
     "articleHost": "thefinancialexpress.com.bd", "articlePath": r"^/(?!tags/|search/|author/)[a-z0-9-]+(?:/[a-z0-9-]+)+/?$"},
)


class PlainText(HTMLParser):
    """HTML is source data, never trusted markup. Drop executable element text."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "template"}:
            self.hidden += 1
        if tag in {"p", "br", "li", "div", "h1", "h2", "h3", "tr"}:
            self.parts.append(" ")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "template"}:
            self.hidden = max(0, self.hidden - 1)
        self.parts.append(" ")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def clip(value, maximum):
    if maximum is None or len(value) <= maximum:
        return value
    shortened = value[:maximum - 1].rsplit(" ", 1)[0]
    return (shortened or value[:maximum - 1]) + "…"


def text(value, maximum=1600):
    parser = PlainText()
    parser.feed(str(value or ""))
    return clip(re.sub(r"\s+", " ", "".join(parser.parts)).strip(), maximum)


def explicit_exploitation(value):
    """Conservative recognition of affirmative exploitation statements.

    These source-level labels are not per-CVE assertions for multi-CVE bulletins.
    Suppress common negations and speculative wording in the same sentence.
    """
    affirmative = re.compile(r"\b(?:aware of active exploitation|confirmed active exploitation|being actively exploited|exploit for .{0,100} exists in the wild)\b", re.I)
    negative = re.compile(r"\b(?:not aware|no evidence|no confirmed|has not confirmed|have not confirmed|hasn't confirmed|haven't confirmed|may be|could be|might be|likely to|cannot confirm)\b", re.I)
    return any(affirmative.search(sentence) and not negative.search(sentence)
               for sentence in re.split(r"(?<=[.!?])\s+", value))


def safe_url(value):
    value = str(value or "").strip()
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        if any(ord(char) < 33 for char in value) or len(value) > 3000:
            return None
        return value
    except ValueError:
        return None


def iso(value):
    """Normalize a provided date; never turn a missing upstream date into 'now'."""
    value = str(value or "").strip()
    if not value:
        raise ValueError("Missing publication date")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        value = re.sub(r"\sCEST$", " +0200", value)
        value = re.sub(r"\sCET$", " +0100", value)
        try:
            dt = parsedate_to_datetime(value)
        except (ValueError, TypeError):
            # CrowdStrike's public RSS uses e.g. Oct 21, 2026 00:00:00-0500.
            dt = datetime.strptime(value, "%b %d, %Y %H:%M:%S%z")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class PublisherRedirect(HTTPRedirectHandler):
    """Publisher metadata requests must stay on their configured HTTPS host."""
    def __init__(self, hostname):
        self.hostname = hostname

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if not safe_url(newurl) or parsed.scheme != "https" or parsed.hostname != self.hostname or parsed.port not in {None, 443}:
            raise ValueError("Refusing a redirect outside the configured publisher")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_bytes(url, *, publisher_host=None):
    if not safe_url(url) or not url.startswith("https://"):
        raise ValueError("Only valid HTTPS feed URLs are accepted")
    request = Request(url, headers={"User-Agent": "CyberWatch-Console/1.0 (+public security feed aggregation)",
                                   "Accept": "application/json, application/atom+xml, application/rss+xml, application/xml;q=0.9, text/html;q=0.8"})
    opener = build_opener(PublisherRedirect(publisher_host)).open if publisher_host else urlopen
    with opener(request, timeout=TIMEOUT) as response:
        if not response.geturl().startswith("https://"):
            raise ValueError("Refusing a feed redirect to insecure HTTP")
        payload = response.read(MAX_RESPONSE + 1)
    if len(payload) > MAX_RESPONSE:
        raise ValueError("Feed exceeds 8 MiB safety limit")
    return payload


def source_record(name, url, date, kind="primary"):
    return {"name": name, "url": url, "publishedAt": date, "kind": kind}


def parse_kev(payload, limit=20):
    data = json.loads(payload)
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("CISA KEV response does not contain vulnerabilities")
    events = []
    for item in sorted(data["vulnerabilities"], key=lambda i: str(i.get("dateAdded", "")), reverse=True):
        cve = str(item.get("cveID", "")).upper()
        if not CVE.fullmatch(cve):
            continue
        try:
            date = iso(item.get("dateAdded"))
        except (ValueError, TypeError):
            continue
        title = text(item.get("vulnerabilityName"), 220)
        description = text(item.get("shortDescription"), 2000)
        if not title or not description:
            continue
        action = text(item.get("requiredAction"), 1200)
        sources = [source_record("CISA KEV catalog", SOURCES[0]["url"], date)]
        # Keep the vendor advisory, if supplied, without following arbitrary links.
        for candidate in re.findall(r"https?://[^\s<>]+", str(item.get("notes", ""))):
            candidate = safe_url(candidate.rstrip(".;,)"))
            if candidate and not any(s["url"] == candidate for s in sources):
                sources.append(source_record("CISA-listed reference", candidate, None))
            if len(sources) == 4:
                break
        ransomware = item.get("knownRansomwareCampaignUse") == "Known"
        events.append({
            "id": "kev-" + cve.lower(), "title": title,
            "organization": text(item.get("vendorProject"), 100),
            "summary": clip(description, 350), "description": description,
            "category": "Vulnerability", "severity": "unknown", "status": "monitoring",
            "publishedAt": date, "updatedAt": date, "geography": [], "sectors": [],
            "cves": [cve], "tags": ["Known exploited", text(item.get("product"), 100)] + (["Ransomware use"] if ransomware else []),
            "impact": [description, "Relevance to your environment depends on affected versions, exposure, and vendor-specific exploitation prerequisites."],
            "recommendations": ["CISA required action: " + action,
                                "Analyst guidance: map the affected product to your asset inventory, confirm exposure, and validate the vendor remediation.",
                                "Analyst guidance: inspect relevant telemetry and vendor indicators where exploitation is plausible; preserve evidence before making changes."],
            "timeline": [{"date": date, "title": "Added to CISA KEV", "description": "CISA included this vulnerability in its Known Exploited Vulnerabilities catalog."}],
            "sources": sources, "confidence": "confirmed",
            "severityBasis": "CISA KEV does not provide a CVSS severity here. Unrated is deliberate; catalog inclusion establishes known exploitation, not a Critical rating.",
            "evidenceNote": "The displayed date is the KEV addition date, not the CVE publication date or first exploitation date. A catalog entry does not establish compromise of your organization. CISA directive deadlines apply to their defined scope; assess applicability separately.",
            "sourceId": "cisa-kev", "exploited": True,
        })
        if len(events) >= limit:
            break
    if not events:
        raise ValueError("CISA KEV returned no usable records")
    return events


def xml_root(payload):
    if b"<!doctype" in payload.lower() or b"<!entity" in payload.lower():
        raise ValueError("XML document types and entities are not accepted")
    return ET.fromstring(payload)


def organization(title, default):
    for term in ("GitLab", "PHP", "Cisco", "Citrix", "Microsoft", "Atlassian", "Check Point", "Ivanti", "SAP", "F5", "Google", "VMware", "Fortinet", "Oracle", "Apple"):
        if term.lower() in title.lower():
            return term
    return default


def news_event(source, title, body, url, date, update):
    """Newsletter-style cards use a short feed excerpt, never a fabricated risk rating."""
    # Headline-only sources keep publisher article text out of the snapshot.
    headline_only = source.get("headlineOnly", False)
    if headline_only:
        body = ""
    words = body.split()
    excerpt = " ".join(words[:24]) + ("…" if len(words) > 24 else "")
    excerpt = clip(excerpt, 300)
    description = ("Read the original " + source["name"] + " article for the complete report. CyberWatch displays its headline, publication date and source link."
                   if headline_only else excerpt or "This publisher supplies a headline and publication date without a feed summary. Open the original publication for the complete update.")
    geography = list(source.get("geography", []))
    # Match explicit country mentions in the visible headline/excerpt only.
    # The abbreviation BD is deliberately excluded: it has unrelated uses.
    mentions_bangladesh = bool(re.search(r"\bBangladesh(?:i)?\b|বাংলাদেশ", title + " " + excerpt, re.I))
    has_bangladesh = any(value.casefold() in {"bangladesh", "bd"} for value in geography)
    if mentions_bangladesh and not has_bangladesh:
        geography.append("Bangladesh")
        has_bangladesh = True
    scope = None
    if has_bangladesh:
        scope = source.get("bangladeshScope") or ("local-activity" if source["id"] == "cirt-news" else "coverage")
    evidence_note = (source["name"] + " is credited as the original publisher. This entry includes the original headline, publication date and article link; article text is not republished. Reported claims are not independently verified by CyberWatch."
                     if headline_only else "The publication is linked directly to its publisher. A short feed excerpt is shown where available; this does not independently verify every reported claim or establish a compromise of your organization.")
    if source.get("cyberHeadlinesOnly") and scope == "coverage":
        evidence_note += " The Bangladesh coverage tag identifies a Bangladesh-based English newspaper, not the location of affected victims. Only headlines containing cyber are included; this does not establish a confirmed incident in Bangladesh."
    elif mentions_bangladesh and scope == "coverage":
        evidence_note += " The Bangladesh coverage tag reflects an explicit country mention in the headline or displayed feed excerpt; it does not establish a confirmed incident in Bangladesh."
    return {
        "id": source["id"] + "-" + sha256(url.encode()).hexdigest()[:16],
        "title": title, "organization": source["name"],
        "summary": description, "description": description, "category": "News", "stream": "news",
        "severity": "unknown", "status": "monitoring", "publishedAt": date, "updatedAt": update,
        "geography": geography, "bangladeshScope": scope, "sectors": [],
        "cves": sorted(set(x.upper() for x in CVE.findall(title + " " + body))),
        "tags": ["Publisher update"],
        "impact": ["This is a publisher update. Its relevance and impact depend on the full publication and your organization's systems and exposure."],
        "recommendations": ["Review the original publication for the full context, affected products and supporting evidence.",
                            "Assess relevance to your environment before assigning local severity or taking operational action."],
        "timeline": [{"date": date, "title": "Published", "description": source["name"] + " published this update."}] +
                    ([{"date": update, "title": "Source updated", "description": "The publisher reports an updated publication."}] if update != date else []),
        "sources": [source_record(source["name"], url, date, source.get("kind", "primary"))],
        "confidence": "reported" if source.get("kind") == "secondary" else "confirmed",
        "severityBasis": "Newsletter and research entries are unrated. A headline or publication alone is not a local risk assessment.",
        "evidenceNote": evidence_note,
        "sourceId": source["id"], "exploited": False,
    }


def feed_event(source, title, body, url, published, updated=None):
    date = iso(published)
    update = iso(updated) if updated else date
    title, full_body = text(title, 220), text(body, None)
    body = clip(full_body, 2400)
    url = safe_url(url)
    if url and url.startswith("http://chromereleases.googleblog.com/"):
        url = "https://" + url[len("http://"):]
    if not title or not url:
        raise ValueError("Incomplete feed entry")
    if update < date:
        update = date
    if source.get("group") == "news" or source.get("stream") == "news":
        return news_event(source, title, full_body, url, date, update)
    if not body:
        raise ValueError("Incomplete advisory description")
    is_chrome = source["id"] == "chrome"
    # For Chrome a release can contain several severities. The highest
    # explicitly listed bulletin severity is used; it is not a per-CVE score.
    severity_text = full_body if is_chrome else title
    severity = next((level for level in ("critical", "high", "medium", "low")
                     if re.search(r"\b" + level + r"\b", severity_text, re.I)), "unknown")
    cves = sorted(set(x.upper() for x in CVE.findall(title + " " + full_body)))
    exploited = explicit_exploitation(full_body)
    return {
        "id": source["id"] + "-" + sha256(url.encode()).hexdigest()[:16],
        "title": re.sub(r"^\d{4}-\d+:\s*", "", title),
        "organization": "Google Chrome" if is_chrome else organization(title, source["name"] if source.get("group") == "bangladesh" else "Multiple vendors"),
        "summary": clip(body, 350), "description": body,
        "category": "Patch" if is_chrome else "Advisory", "severity": severity,
        "status": "mitigated" if is_chrome else "monitoring",
        "publishedAt": date, "updatedAt": update, "geography": list(source.get("geography", [])), "sectors": [], "cves": cves,
        "stream": "intelligence", "bangladeshScope": "national-advisory" if source.get("group") == "bangladesh" else None,
        "tags": (["Security update", "Browser"] if is_chrome else ["Security advisory"]) + (["Known exploited"] if exploited else []),
        "impact": ["Affected deployments may be exposed to the security issues described in the source advisory. Confirm affected products, versions, and prerequisites before assigning local risk.",
                   "This publication is a security bulletin; it is not evidence that your organization has experienced a breach."],
        "recommendations": ["Analyst guidance: review the linked advisory for affected versions, fixed releases, exploitation conditions, and any vendor workarounds.",
                            "Analyst guidance: prioritize exposed and business-critical assets, test the update, then verify the installed version after deployment.",
                            "Analyst guidance: assess relevant logs and vendor indicators if the affected product is present; track remediation and any accepted exception."],
        "timeline": [{"date": date, "title": "Source publication", "description": source["name"] + " published this bulletin."}] +
                    ([{"date": update, "title": "Source updated", "description": "The feed reports a later update to the publication."}] if update != date else []),
        "sources": [source_record(source["name"], url, date, source.get("kind", "primary"))], "confidence": "confirmed",
        "severityBasis": (("Highest explicit severity word in the source release notes; this is a bulletin-level label, not a CVSS score for each CVE." if is_chrome else "Severity label explicitly present in the source advisory headline; no independent CVSS validation is implied.") if severity != "unknown" else "The feed does not supply an explicit severity label; no score has been inferred."),
        "evidenceNote": "Source publication and update dates are preserved. " +
                        ("Mitigated means a vendor security update is available; it does not mean your devices have installed it." if is_chrome else "Recommendations below are analyst triage guidance; consult the source for exact vendor instructions.") +
                        " Automated feed summaries may be truncated; open the source for the complete advisory.",
        "sourceId": source["id"], "exploited": exploited,
    }


def parse_rss(payload, source, limit=10):
    root = xml_root(payload)
    events, valid_items = [], 0
    items = root.findall("./channel/item")[:100]
    for item in items:
        try:
            title = text(item.findtext("title"), 220)
            link = item.findtext("link")
            date = item.findtext("pubDate") or item.findtext("{http://purl.org/dc/elements/1.1/}date")
            if source.get("cyberHeadlinesOnly"):
                link = newspaper_url(source, link)
                if not title or not link:
                    continue
                iso(date)
                valid_items += 1
                if not cyber_headline(title):
                    continue
            events.append(feed_event(source, title, item.findtext("description"), link, date))
        except (ValueError, TypeError, OverflowError):
            continue
        if len(events) >= limit:
            break
    # A valid newspaper feed may have no cyber headline in its rolling window.
    healthy_filtered = (source.get("cyberHeadlinesOnly") and root.tag == "rss" and root.find("channel") is not None
                        and (valid_items or not items))
    if not events and not healthy_filtered:
        raise ValueError("RSS feed returned no usable dated records")
    return events


def atom_content(item):
    for name in ("content", "summary"):
        element = item.find("a:" + name, ATOM)
        if element is None:
            continue
        if list(element):
            # PHP uses Atom XHTML nodes, while Chrome uses an escaped HTML string.
            return " ".join(element.itertext())
        if element.text and element.text.strip():
            return element.text
    return ""


def parse_atom(payload, source, limit=8):
    root = xml_root(payload)
    events = []
    for item in root.findall("a:entry", ATOM)[:100]:
        title = item.findtext("a:title", "", ATOM)
        body = atom_content(item)
        # Exclude dev/beta/product-only announcements and duplicate mobile builds
        # without any explicit security-fix information.
        if source["id"] == "chrome" and ("stable" not in title.lower() or not re.search(r"security fixes|CVE-\d{4}-", body, re.I)):
            continue
        # PHP's archive/id is permanent, unlike the rolling homepage anchor.
        link = item.findtext("a:id", "", ATOM) if source["id"] == "php" else None
        link = safe_url(link) or next((i.attrib.get("href") for i in item.findall("a:link", ATOM)
                                      if i.attrib.get("rel", "alternate") == "alternate"), None)
        try:
            events.append(feed_event(source, title, body, link,
                                     item.findtext("a:published", "", ATOM),
                                     item.findtext("a:updated", "", ATOM)))
        except (ValueError, TypeError, OverflowError):
            continue
        if len(events) >= limit:
            break
    if not events:
        raise ValueError("Atom feed returned no usable dated records")
    return events


def cyber_headline(value):
    """Match English headline words starting with cyber, never article bodies."""
    title = text(value, 220)
    return bool(re.search(r"\bcyber[a-z]*\b", title, re.I)) and not bool(re.search(r"[\u0980-\u09ff]", title))


def newspaper_url(source, value):
    """Only fixed publisher hosts and article paths may be followed or stored."""
    url = safe_url(urljoin(source["feedUrls"][0], str(value or "")))
    if not url:
        return None
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname != source["articleHost"] or parsed.port not in {None, 443}
            or not re.fullmatch(source["articlePath"], parsed.path)):
        return None
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


class NewspaperIndex(HTMLParser):
    """Read visible article heading links; ignore navigation and article text."""
    HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.items, self.anchor, self.heading_depth, self.hidden = [], None, 0, 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "template"}:
            self.hidden += 1
        if self.hidden:
            return
        if tag in self.HEADINGS:
            self.heading_depth += 1
            if self.anchor is not None:
                self.anchor["heading"] = True
        if tag == "a":
            self.anchor = {"url": dict(attrs).get("href", ""), "title": "", "heading": bool(self.heading_depth)}

    def handle_data(self, data):
        if not self.hidden and self.anchor is not None:
            self.anchor["title"] += data

    def handle_endtag(self, tag):
        if tag in {"script", "style", "template"}:
            self.hidden = max(0, self.hidden - 1)
        if tag == "a" and self.anchor is not None:
            if self.anchor["heading"] and len(self.items) < 500:
                self.items.append(self.anchor)
            self.anchor = None
        if tag in self.HEADINGS:
            self.heading_depth = max(0, self.heading_depth - 1)


class NewspaperMetadata(HTMLParser):
    """Extract metadata and explicit date labels; never capture article bodies."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta, self.schemas, self.date_labels = {}, [], {}
        self.json_parts = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta":
            key = attrs.get("property") or attrs.get("name") or attrs.get("itemprop")
            if key and attrs.get("content"):
                self.meta[key.lower()] = attrs["content"]
        if tag == "script" and attrs.get("type", "").lower() == "application/ld+json":
            self.json_parts = []

    def handle_data(self, data):
        if self.json_parts is not None:
            self.json_parts.append(data)
        else:
            # The Daily Star supplies a visible calendar date rather than a
            # timezone-qualified publication timestamp. Ignore its time of day.
            match = re.fullmatch(r"\s*(Published|Updated)\s*:\s*(\d{1,2}\s+[A-Za-z]+\s+\d{4})(?:,\s*\d{1,2}:\d{2})?\s*", data, re.I)
            if match:
                self.date_labels[match[1].lower()] = datetime.strptime(match[2], "%d %B %Y").date().isoformat()

    def handle_endtag(self, tag):
        if tag == "script" and self.json_parts is not None:
            try:
                self.schemas.append(json.loads("".join(self.json_parts)))
            except (ValueError, TypeError):
                pass
            self.json_parts = None


def article_schemas(value, depth=0):
    if depth > 8:
        return
    if isinstance(value, dict):
        types = value.get("@type", [])
        if isinstance(types, str):
            types = [types]
        if isinstance(types, list) and any(t in {"Article", "NewsArticle", "ReportageNewsArticle"} for t in types if isinstance(t, str)):
            yield value
        for child in value.values():
            if isinstance(child, (dict, list)):
                yield from article_schemas(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            yield from article_schemas(child, depth + 1)


def newspaper_date(value):
    """Keep the calendar date when a publisher does not specify a timezone."""
    raw = str(value or "").strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        return datetime.strptime(raw, "%Y-%m-%d").date().isoformat()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.date().isoformat()
    except ValueError:
        pass
    return iso(raw)


def parse_newspaper_article(payload, source, url):
    parser = NewspaperMetadata()
    parser.feed(payload.decode("utf-8"))
    article = next((item for schema in parser.schemas for item in article_schemas(schema)
                    if item.get("headline") and (not item.get("mainEntityOfPage") or
                       newspaper_url(source, item["mainEntityOfPage"].get("@id", "") if isinstance(item["mainEntityOfPage"], dict)
                                     else item["mainEntityOfPage"]) == url)), {})
    title = text(article.get("headline") or parser.meta.get("og:title"), 220)
    if not title:
        raise ValueError("Publisher article has no headline metadata")
    date = newspaper_date(parser.meta.get("article:published_time") or article.get("datePublished") or
                          parser.meta.get("datepublished") or parser.date_labels.get("published"))
    # A changed publisher headline that no longer matches is a valid exclusion.
    if not cyber_headline(title):
        return None
    updated = (parser.meta.get("article:modified_time") or article.get("dateModified") or
               parser.meta.get("datemodified") or parser.date_labels.get("updated"))
    update = newspaper_date(updated) if updated else date
    update = max(date, update)
    event = news_event(source, title, "", url, date, update)
    if len(date) == 10 or len(update) == 10:
        event["evidenceNote"] += " Where the publisher supplies no timezone, only its calendar date is retained."
    return event


class PartialNewspaperCollection(ValueError):
    def __init__(self, events):
        super().__init__("Some publisher article dates could not be verified")
        self.events = events


def parse_newspaper(payload, source, fetcher=fetch_bytes, limit=6):
    parser = NewspaperIndex()
    parser.feed(payload.decode("utf-8"))
    headlines = {}
    for item in parser.items:
        link = newspaper_url(source, item["url"])
        title = text(item["title"], 220)
        if link and title:
            headlines.setdefault(link, title)
    if not headlines:
        raise ValueError("Publisher index has no recognizable article headings")
    candidates = [link for link, title in headlines.items() if cyber_headline(title)][:limit]

    def inspect_article(link):
        try:
            return parse_newspaper_article(fetcher(link), source, link), False
        except (OSError, ValueError, TypeError, OverflowError):
            return None, True

    # At most six metadata requests, three at a time: bounded even when a
    # publisher is slow, inside the live refresh service's collection timeout.
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(inspect_article, candidates))
    events = [event for event, _ in results if event is not None]
    if any(failed for _, failed in results):
        raise PartialNewspaperCollection(events)
    return events


def retain_newspaper_headlines(source, events, previous, timestamp):
    """Keep a small 30-day history when stories rotate out of a public index."""
    cutoff = (datetime.fromisoformat(timestamp.replace("Z", "+00:00")) - timedelta(days=30)).date().isoformat()
    retained = {}
    for event in events + previous.get("events", []):
        if (event.get("sourceId") != source["id"] or not cyber_headline(event.get("title")) or
                str(event.get("publishedAt", "")) < cutoff or not event.get("sources") or
                not newspaper_url(source, event["sources"][0].get("url"))):
            continue
        retained.setdefault(event["id"], event)
    return sorted(retained.values(), key=lambda event: (event["publishedAt"], event["id"]), reverse=True)[:20]


class CirtIndex(HTMLParser):
    """Parse only the documented public index cards, never arbitrary page links."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.items, self.current, self.capture = [], None, None
        self.stack = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = attrs.get("class", "").split()
        if "post-item" in classes:
            if self.current:
                self.items.append(self.current)
            self.current = {}
            self.capture = None
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append(tag)
        if self.current is not None:
            for class_name, field in (("post-title", "title"), ("post-subtitle", "body"), ("post-time", "date")):
                if class_name in classes:
                    self.capture = (field, len(self.stack))
                    self.current[field] = ""
                    if field == "title":
                        self.current["url"] = attrs.get("href", "")

    def handle_data(self, value):
        if self.current is not None and self.capture:
            self.current[self.capture[0]] += value

    def handle_endtag(self, tag):
        if self.capture and len(self.stack) == self.capture[1]:
            self.capture = None
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()

    def finish(self):
        if self.current:
            self.items.append(self.current)
            self.current = None
        return self.items


def relevant_cirt_activity(title):
    """Keep cyber work and capacity-building, excluding personnel notices."""
    title = text(title, 500)
    personnel = (r"\b(?:obituar(?:y|ies)|mourning|condolences?|funeral|passed away|death of|"
                 r"bereavement|in memoriam|remembering|tribute to|recruitment|vacancies|vacancy|"
                 r"appointment|promotion|retirement|farewell|transfer order|leave notice|staff notice|resignation)\b"
                 r"|শোক|মৃত্যু|প্রয়াণ|প্রয়াণ|মরহুম|জানাজা|সমবেদনা|নিয়োগ|নিয়োগ|পদোন্নতি|অবসর|বিদায়|বিদায়|বদলি")
    if re.search(personnel, title, re.I):
        return False
    relevant = (r"\b(?:cyber(?:security)?|information security|security training|security awareness|"
                r"threats?|incident response|incident handling|malware|ransomware|phishing|"
                r"vulnerabilit(?:y|ies)|internship|training|seminar|workshop|drill|exercise|"
                r"capacity building|awareness|CII)\b"
                r"|সাইবার|নিরাপত্তা|প্রশিক্ষণ|ইন্টার্নশিপ|ইন্টার্নশীপ|সেমিনার|মহড়া|মহড়া|ড্রিল|কর্মশালা|সচেতনতা|হুমকি|ইনসিডেন্ট|ফিশিং")
    return bool(re.search(relevant, title, re.I))


def parse_cirt(payload, source, limit=10):
    parser = CirtIndex()
    parser.feed(payload.decode("utf-8"))
    events, dated_cards = [], 0
    for item in parser.finish()[:100]:
        try:
            # The index does not declare a timezone. Keep its calendar date,
            # rather than presenting an assumed local time as a verified instant.
            date = datetime.strptime(item.get("date", "").strip(), "%d-%b-%Y %H:%M:%S").date().isoformat()
            link = urljoin("https://www.cirt.gov.bd/", item.get("url", ""))
            if urlsplit(link).hostname != "www.cirt.gov.bd" or not urlsplit(link).path.startswith(urlsplit(source["url"]).path + "/"):
                continue
            if not text(item.get("title")):
                continue
            dated_cards += 1
            if source["id"] == "cirt-news" and not relevant_cirt_activity(item["title"]):
                continue
            event = feed_event(source, item.get("title"), item.get("body"), link, date)
            event["publishedAt"] = event["updatedAt"] = date
            event["sources"][0]["publishedAt"] = date
            event["timeline"][0]["date"] = date
            event["evidenceNote"] += " The CIRT index does not specify a timezone; only its publication date is retained."
            events.append(event)
        except (ValueError, TypeError, KeyError):
            continue
        if len(events) >= limit:
            break
    # A valid activities index containing only irrelevant personnel notices is
    # a successful empty collection, not an outage or a reason to restore them.
    if not events and not (source["id"] == "cirt-news" and dated_cards):
        raise ValueError("CIRT index returned no usable dated publication cards")
    return events


def read_json(path, default=None):
    if not path.exists():
        return default
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def collect_source(source, previous, timestamp, fetcher=fetch_bytes):
    errors, partial_events = [], []
    source_fetcher = fetcher
    if source.get("cyberHeadlinesOnly") and fetcher is fetch_bytes:
        source_fetcher = lambda url: fetch_bytes(url, publisher_host=source["articleHost"])
    for feed_url in source["feedUrls"]:
        try:
            payload = source_fetcher(feed_url)
            if source["format"] == "kev":
                events = parse_kev(payload)
            elif source["format"] == "rss":
                events = parse_rss(payload, source)
            elif source["format"] == "cirt":
                events = parse_cirt(payload, source)
            elif source["format"] == "newspaper":
                events = parse_newspaper(payload, source, fetcher=source_fetcher)
            else:
                events = parse_atom(payload, source)
            if source.get("cyberHeadlinesOnly"):
                events = retain_newspaper_headlines(source, events, previous, timestamp)
            return events, {"id": source["id"], "name": source["name"], "url": source["url"],
                            "kind": source.get("kind", "primary"), "group": source.get("group", "intelligence"),
                            "description": source.get("description", "Official security intelligence feed."),
                            "status": "ok", "lastSuccessAt": timestamp,
                            "lastAttemptAt": timestamp, "itemCount": len(events), "error": None}
        except (OSError, ValueError, TypeError, ET.ParseError) as error:
            if isinstance(error, PartialNewspaperCollection):
                partial_events.extend(error.events)
            # No response bodies or credentials are written into public metadata.
            errors.append("HTTP " + str(error.code) if hasattr(error, "code") else type(error).__name__)
    events = [event for event in previous.get("events", []) if event.get("sourceId") == source["id"]]
    if source.get("cyberHeadlinesOnly"):
        events = retain_newspaper_headlines(source, partial_events, previous, timestamp)
    prior = next((s for s in previous.get("sources", []) if s.get("id") == source["id"]), {})
    message = "Collection failed (" + ", ".join(errors) + "). " + ("Showing the last available records." if events else "No saved records available.")
    if partial_events and events:
        message = "Some publisher article dates could not be verified. Showing verified headlines and any previously collected records; the last complete success time is unchanged."
    return events, {"id": source["id"], "name": source["name"], "url": source["url"],
                    "kind": source.get("kind", "primary"), "group": source.get("group", "intelligence"),
                    "description": source.get("description", "Official security intelligence feed."),
                    "status": "error", "lastSuccessAt": prior.get("lastSuccessAt"),
                    "lastAttemptAt": timestamp, "itemCount": len(events), "error": message}


def canonical_url(value):
    parsed = urlsplit(value)
    query = urlencode([(key, item) for key, item in parse_qsl(parsed.query, keep_blank_values=True)
                       if not key.lower().startswith("utm_")])
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/"), query, parsed.fragment))


def content_fingerprint(events):
    """Health checks and timestamps are operational metadata, not a data update."""
    normalized = sorted(events, key=lambda event: event["id"])
    return sha256(json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def assemble(results, curated, timestamp, limit, previous=None, bangladesh_curated=None):
    previous = previous or {}
    events, sources = [], []
    for group, source in results:
        events.extend(group)
        sources.append(dict(source))
    sources.append({"id": "curated", "name": "Verified incident reports", "url": None,
                    "kind": "curated", "group": "intelligence", "status": "snapshot", "lastSuccessAt": None,
                    "description": "Researched incident reports and manually reviewed source context.",
                    "lastAttemptAt": None, "itemCount": len(curated), "error": None})
    if bangladesh_curated is not None:
        sources.append({"id": "bangladesh-curated", "name": "Bangladesh · Reviewed reports", "url": None,
                        "kind": "curated", "group": "bangladesh", "status": "snapshot", "lastSuccessAt": None,
                        "description": "Reviewed national advisories, local threat reports and cyber activities with explicit geographic context.",
                        "lastAttemptAt": None, "itemCount": len(bangladesh_curated), "error": None})
    # A curated record can replace the same stable ID. Different publications
    # about the same CVE are retained: their dates and evidence may differ.
    by_id = {event["id"]: event for event in events}
    for collection, source_id in ((curated, "curated"), (bangladesh_curated or [], "bangladesh-curated")):
        for event in collection:
            event = dict(event)
            event["sourceId"] = source_id
            stream = event.get("stream", "news" if event.get("category") == "News" else "intelligence")
            evidence_urls = {canonical_url(item["url"]) for item in event.get("sources", [])}
            # Prefer richer reviewed context to an auto-collected copy of that
            # same article. Keep independent publications and separate views.
            for event_id, candidate in list(by_id.items()):
                if candidate["sourceId"] in {"cisa-kev", "curated", "bangladesh-curated"} or not candidate.get("sources"):
                    continue
                if candidate.get("stream", "intelligence") == stream and canonical_url(candidate["sources"][0]["url"]) in evidence_urls:
                    del by_id[event_id]
            by_id[event["id"]] = event
    events = sorted(by_id.values(), key=lambda e: (e["updatedAt"], e["publishedAt"], e["id"]), reverse=True)[:limit]
    for source in sources:
        source["itemCount"] = sum(event["sourceId"] == source["id"] for event in events)
    changed = content_fingerprint(events) != content_fingerprint(previous.get("events", []))
    database_updated = timestamp if changed else previous.get("databaseUpdatedAt") or previous.get("generatedAt") or timestamp
    return {"schemaVersion": 1, "generatedAt": timestamp, "databaseUpdatedAt": database_updated,
            "lastCheckedAt": timestamp, "sources": sources, "events": events}


def write_atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".incidents-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/data/incidents.json")
    parser.add_argument("--curated", type=Path, default=ROOT / "data/curated.json")
    parser.add_argument("--bangladesh-curated", type=Path, default=ROOT / "data/bangladesh-curated.json")
    parser.add_argument("--limit", type=int, default=300, help="Maximum displayed records (1–500, default 300)")
    args = parser.parse_args()
    if not 1 <= args.limit <= 500:
        parser.error("--limit must be between 1 and 500")
    curated = read_json(args.curated, [])
    bangladesh_curated = read_json(args.bangladesh_curated, [])
    if not isinstance(curated, list) or not isinstance(bangladesh_curated, list):
        raise ValueError("Curated data must be a JSON array")
    from validate_data import validate_event, validate_snapshot
    for event in curated + bangladesh_curated:
        validate_event(event)
    try:
        previous = read_json(args.output, {})
        if previous:
            validate_snapshot(previous)
    except (ValueError, TypeError, KeyError):
        previous = {}
        print("Existing snapshot is invalid; it cannot be used as an outage fallback.", file=sys.stderr)
    timestamp = now_iso()
    with ThreadPoolExecutor(max_workers=min(8, len(SOURCES))) as pool:
        results = list(pool.map(lambda source: collect_source(source, previous, timestamp), SOURCES))
    snapshot = assemble(results, curated, timestamp, args.limit, previous, bangladesh_curated)
    validate_snapshot(snapshot)
    if not snapshot["events"]:
        raise SystemExit("No usable records collected or retained; existing output was not changed.")
    write_atomic(args.output, snapshot)
    for source in snapshot["sources"]:
        print(f"{source['id']}: {source['status']} | {source['itemCount']} displayed records" +
              (f" | {source['error']}" if source["error"] else ""))
    print(f"Saved {len(snapshot['events'])} records to {args.output}")


if __name__ == "__main__":
    main()
