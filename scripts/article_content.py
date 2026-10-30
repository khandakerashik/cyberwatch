#!/usr/bin/env python3
"""Bounded, publisher-controlled article text and image ingestion.

The public snapshot stores plain text, never untrusted publisher HTML. Full
publisher pages require explicit source permission, a fixed host allowlist and
robots permission. No browser, publisher credentials, paywall bypass or open
proxy endpoint exists. An administrator may explicitly configure one trusted
HTTP CONNECT egress proxy through CYBERWATCH_HTTPS_PROXY; ordinary HTTP_PROXY /
HTTPS_PROXY variables are never read automatically.
"""
from __future__ import annotations

from collections import deque
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
from html.parser import HTMLParser
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

USER_AGENT = "CyberWatch/1.5 (+public security news reader)"
REQUEST_TIMEOUT = 6
MAX_ARTICLE_BYTES = 2 * 1024 * 1024
MAX_ROBOTS_BYTES = 256 * 1024
MAX_PARAGRAPHS = 120
MAX_TEXT_CHARS = 80000
MAX_PARAGRAPH_CHARS = 4000
MAX_IMAGES = 6
MAX_ENRICH_SECONDS = 45
RETRY_HOURS = 6
CACHE_HOURS = 168
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home", ".test", ".invalid", ".example")
HIDDEN_TAGS = {"script", "style", "template", "noscript", "nav", "footer", "header", "aside", "form", "button", "svg", "iframe"}
BLOCK_TAGS = {"p", "li", "pre", "blockquote", "h1", "h2", "h3", "h4", "figcaption", "td"}
TEASER = re.compile(r"(?:continue reading|read (?:the )?(?:full|complete) (?:article|story)|read more)(?:[ .…»›>!]|at the (?:source|publisher))*$", re.I)
ACCESS_CHALLENGE = re.compile(r"verify (?:that )?you are human|enable javascript and cookies to continue|performing security verification|checking your browser before (?:accessing|continuing)", re.I)
PAYWALL = re.compile(r"subscribe to (?:continue|keep) reading|subscribe to read (?:the |this )?(?:full|complete) article|this (?:article|story|content) is (?:only )?(?:available|exclusive) (?:to|for) subscribers|subscription (?:is )?required to read|sign in to (?:continue|keep) reading", re.I)


def _text(value, maximum=5000):
    return re.sub(r"\s+", " ", str(value or "")).strip()[:maximum]


def _public_hostname(host):
    if not host or host.endswith(".") or host.lower() in {"localhost", "localhost.localdomain", "metadata.google.internal"}:
        return False
    host = host.lower()
    if host.endswith(BLOCKED_SUFFIXES):
        return False
    try:
        address = ipaddress.ip_address(host)
        return address.is_global and not address.is_multicast and not address.is_reserved
    except ValueError:
        # A fully-qualified DNS name prevents local search-domain lookups.
        # Numeric legacy IPv4 spellings must not be interpreted as DNS names.
        return bool("." in host and not re.fullmatch(r"[0-9xXa-fA-F.]+", host)
                    and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")))


def _safe_public_url(value, *, base_url="", allowed_hosts=None):
    """Parse a public HTTPS URL without triggering a DNS or HTTP request."""
    if not isinstance(value, str) or not value.strip() or len(value) > 3000:
        return None
    value = value.strip()
    if any(ord(char) < 33 or ord(char) == 127 for char in value) or "\\" in value:
        return None
    try:
        value = urljoin(base_url, value) if base_url else value
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in {None, 443}:
            return None
        if not _public_hostname(host):
            return None
        if allowed_hosts is not None and host not in {str(item).lower() for item in allowed_hosts}:
            return None
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    except (ValueError, TypeError):
        return None


def safe_image_url(value, *, base_url="", allowed_hosts=None):
    """Validate image links; block local hosts, unsafe schemes and active files.

    Pure parse/IP validation for both the collector and snapshot validator.
    Publisher-page requests separately resolve and pin public DNS addresses.
    """
    checked = _safe_public_url(value, base_url=base_url, allowed_hosts=allowed_hosts)
    if checked:
        parsed = urlsplit(checked)
        # Keep image output compatible with the stricter browser/snapshot
        # boundary: named public hosts or canonical IPv4, no literal IPv6.
        if ":" in parsed.hostname or re.search(r"[<>\"']", checked):
            return None
        if not re.search(r"\.(?:svg|html?|xhtml|js)$", parsed.path, re.I):
            return checked
    return None


def source_policy(source):
    policy = source.get("articlePolicy", {})
    policy = policy if isinstance(policy, dict) else {}
    host = urlsplit(str(source.get("url", ""))).hostname
    hosts = policy.get("allowedHosts") or ([host] if host else [])
    hosts = [str(item).lower() for item in hosts if isinstance(item, str) and _public_hostname(item)]
    images = policy.get("allowedImageHosts")
    if images is not None:
        images = [str(item).lower() for item in images if isinstance(item, str) and _public_hostname(item)]
    return {"allowFullText": policy.get("allowFullText") is True or source.get("publisherPermission") is True,
            "allowedHosts": hosts, "allowedImageHosts": images,
            "license": _text(policy.get("license"), 500), "attribution": _text(policy.get("attribution"), 250)}


def _licensed_note(note, source, policy):
    attribution = policy.get("attribution") or _text(source.get("name"), 180)
    additions = (["Attribution: " + attribution + "."] if attribution else []) + ([policy["license"]] if policy.get("license") else [])
    return (note + (" " + " ".join(additions) if additions else ""))[:1000]


class ContentParser(HTMLParser):
    """Extract text blocks and image metadata, preserving no HTML markup."""
    def __init__(self, base_url="", allowed_image_hosts=None):
        super().__init__(convert_charrefs=True)
        self.base_url, self.allowed_image_hosts = base_url, allowed_image_hosts
        self.stack = []
        self.blocks = []
        self.active = []
        self.images = []
        self.meta_images = []
        self.scripts = []
        self.json_buffer = None
        self.restricted = False
        self.truncated = False
        self.figure_image_start = None
        self.all_text = []

    def _block_text(self, fragments):
        value = re.sub(r"\s+", " ", "".join(fragments)).strip()
        if len(value) > MAX_TEXT_CHARS:
            self.truncated = True
        return value[:MAX_TEXT_CHARS + 1]

    def _scope(self):
        return "article" if any(frame[0] == "article" for frame in self.stack) else "main" if any(frame[0] == "main" for frame in self.stack) else "other"

    def _hidden(self):
        return any(frame[1] for frame in self.stack)

    def _image(self, url, attrs, scope):
        url = safe_image_url(url, base_url=self.base_url, allowed_hosts=self.allowed_image_hosts)
        if not url or any(image["url"] == url for image in self.images):
            return
        for dimension in ("width", "height"):
            raw = attrs.get(dimension, "")
            if str(raw).isdigit() and int(raw) < 80:
                return
        self.images.append({"url": url, "alt": _text(attrs.get("alt"), 500), "caption": "", "credit": _text(attrs.get("data-credit"), 300), "_scope": scope})

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and "ld+json" in attrs.get("type", "").lower():
            self.json_buffer = []
        if tag == "meta":
            name = (attrs.get("property") or attrs.get("name") or "").lower()
            if name in {"og:image", "twitter:image", "twitter:image:src"}:
                self.meta_images.append(attrs.get("content", ""))
        classes = (attrs.get("class", "") + " " + attrs.get("id", "")).lower()
        restricted = bool(re.search(r"(?:^|[ _-])(?:paywall|subscription-wall|metered-content)(?:$|[ _-])", classes))
        self.restricted = self.restricted or restricted
        hidden = tag in HIDDEN_TAGS or "hidden" in attrs or attrs.get("aria-hidden", "").lower() == "true"
        hidden = hidden or bool(re.search(r"(?:^|\s)(?:navigation|related-posts|recommended|newsletter|cookie-banner|social-share|site-header|site-footer)(?:$|\s)", classes))
        hidden = hidden or bool(re.search(r"display\s*:\s*none|visibility\s*:\s*hidden", attrs.get("style", ""), re.I))
        scope = self._scope()
        if tag == "figure":
            self.figure_image_start = len(self.images)
        if tag == "img" and not self._hidden() and not hidden:
            candidate = attrs.get("src") or attrs.get("data-src") or attrs.get("data-original") or ""
            if not safe_image_url(candidate, base_url=self.base_url, allowed_hosts=self.allowed_image_hosts):
                candidate = attrs.get("data-src") or attrs.get("data-original") or ""
            self._image(candidate, attrs, scope)
        if tag == "br" and self.active:
            self.active[-1][2].append(" ")
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append((tag, hidden))
            if tag in BLOCK_TAGS and not self._hidden():
                self.active.append([tag, self._scope(), []])

    def handle_endtag(self, tag):
        if tag == "script" and self.json_buffer is not None:
            self.scripts.append("".join(self.json_buffer)[:MAX_ARTICLE_BYTES])
            self.json_buffer = None
        if self.active and self.active[-1][0] == tag:
            name, scope, fragments = self.active.pop()
            value = self._block_text(fragments)
            if value:
                if name == "figcaption" and self.figure_image_start is not None:
                    for image in self.images[self.figure_image_start:]:
                        image["caption"] = value[:1000]
                else:
                    self.blocks.append((scope, value))
            if self.active:
                self.active[-1][2].append(" ")
        if tag == "figure":
            self.figure_image_start = None
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        if self.json_buffer is not None:
            self.json_buffer.append(data)
        if not self._hidden():
            self.all_text.append(data)
            if self.active:
                self.active[-1][2].append(data)

    def finish(self, require_article=False):
        self.close()
        for _, scope, fragments in self.active:
            value = self._block_text(fragments)
            if value:
                self.blocks.append((scope, value))
        schemas = []
        for raw in self.scripts:
            try:
                schemas.extend(_article_schemas(json.loads(raw)))
            except (ValueError, TypeError, RecursionError):
                continue
        for schema in schemas:
            if str(schema.get("isAccessibleForFree", "")).lower() == "false":
                self.restricted = True
        visible_text = " ".join(self.all_text)[:MAX_ARTICLE_BYTES]
        self.restricted = self.restricted or bool(PAYWALL.search(visible_text)) or bool(ACCESS_CHALLENGE.search(visible_text))
        article = [value for scope, value in self.blocks if scope == "article"]
        main = [value for scope, value in self.blocks if scope == "main"]
        paragraphs = article if sum(map(len, article)) >= 100 else main if sum(map(len, main)) >= 100 else []
        if not paragraphs:
            for schema in schemas:
                body = schema.get("articleBody")
                if isinstance(body, str) and len(body.strip()) >= 100:
                    nested = ContentParser(self.base_url, self.allowed_image_hosts)
                    nested.feed(body)
                    parsed = nested.finish()
                    paragraphs = parsed["paragraphs"]
                    self.restricted = self.restricted or parsed["restricted"]
                    self.truncated = self.truncated or parsed["truncated"]
                    break
        if not paragraphs and not require_article:
            paragraphs = [value for _, value in self.blocks]
            if not paragraphs:
                value = self._block_text([" ".join(self.all_text)])
                paragraphs = [value] if value else []
        cleaned, seen, total = [], set(), 0
        for paragraph_index, value in enumerate(paragraphs):
            if not value or value in seen:
                continue
            if total >= MAX_TEXT_CHARS:
                self.truncated = True
                break
            seen.add(value)
            # Split large source paragraphs at word boundaries; never publish a
            # field too large for the snapshot schema or silently duplicate it.
            while value and total < MAX_TEXT_CHARS and len(cleaned) < MAX_PARAGRAPHS:
                available = min(MAX_PARAGRAPH_CHARS, MAX_TEXT_CHARS - total)
                segment = value[:available]
                if len(value) > available and " " in segment:
                    segment = segment.rsplit(" ", 1)[0]
                cleaned.append(segment)
                total += len(segment)
                value = value[len(segment):].lstrip()
            if value:
                self.truncated = True
            if len(cleaned) >= MAX_PARAGRAPHS:
                self.truncated = self.truncated or paragraph_index + 1 < len(paragraphs)
                break
        scoped_images = [image for image in self.images if image["_scope"] in {"article", "main"}]
        images = scoped_images or ([] if require_article else self.images)
        images = [{key: value for key, value in image.items() if not key.startswith("_")} for image in images[:MAX_IMAGES]]
        for candidate in self.meta_images:
            url = safe_image_url(candidate, base_url=self.base_url, allowed_hosts=self.allowed_image_hosts)
            if url and not any(image["url"] == url for image in images) and len(images) < MAX_IMAGES:
                images.append({"url": url, "alt": "", "caption": "", "credit": ""})
        teaser = bool(cleaned and TEASER.search(cleaned[-1][-500:]))
        return {"paragraphs": cleaned, "images": images, "restricted": self.restricted, "truncated": self.truncated, "teaser": teaser}


def _article_schemas(value, depth=0):
    if depth > 12:
        return []
    if isinstance(value, list):
        return [item for child in value[:100] for item in _article_schemas(child, depth + 1)]
    if not isinstance(value, dict):
        return []
    kinds = value.get("@type", [])
    kinds = [kinds] if isinstance(kinds, str) else kinds
    found = [value] if any("Article" in str(kind) or kind == "BlogPosting" for kind in kinds) else []
    return found + [item for name in ("@graph", "mainEntity", "hasPart") if name in value for item in _article_schemas(value[name], depth + 1)]


def _excerpt(paragraphs, words=120):
    value = " ".join(paragraphs)
    items = value.split()
    return [" ".join(items[:words]) + ("…" if len(items) > words else "")] if items else []


def ingest_feed_content(source, *, summary="", content="", image_candidates=(), article_url="", timestamp=None):
    """Return text/images explicitly supplied in a feed, under source policy."""
    policy = source_policy(source)
    headline_only = source.get("headlineOnly") is True and not policy["allowFullText"]
    raw = "" if headline_only else str(content or summary or "")
    parser = ContentParser(article_url, policy["allowedImageHosts"])
    parser.feed(str(raw)[:MAX_ARTICLE_BYTES])
    result = parser.finish()
    result["truncated"] = result["truncated"] or len(raw) > MAX_ARTICLE_BYTES
    full = bool(content and policy["allowFullText"] and not result["restricted"] and not result["truncated"] and not result["teaser"])
    paragraphs = result["paragraphs"] if full else _excerpt(result["paragraphs"])
    images = result["images"]
    for candidate in list(image_candidates or ())[:30]:
        candidate = {"url": candidate} if isinstance(candidate, str) else candidate
        if not isinstance(candidate, dict):
            continue
        url = safe_image_url(candidate.get("url"), base_url=article_url, allowed_hosts=policy["allowedImageHosts"])
        if not url or any(image["url"] == url for image in images) or len(images) >= MAX_IMAGES:
            continue
        images.append({"url": url, "alt": _text(candidate.get("alt"), 500),
                       "caption": _text(candidate.get("caption"), 1000), "credit": _text(candidate.get("credit"), 300)})
    status = "restricted" if result["restricted"] else "full" if full and paragraphs else "excerpt" if paragraphs else "unavailable"
    note = ("Full text supplied in the publisher feed; redistribution is enabled for this source." if status == "full" else
            "Publisher-supplied excerpt. Open the original article for the full report." if status == "excerpt" else
            "The publisher limits access to the complete article. Open the original source." if status == "restricted" else
            "This source is configured for headline-only coverage. Open the original source to read it." if headline_only else
            "The feed does not supply readable article text. Open the original source.")
    if status == "full":
        note = _licensed_note(note, source, policy)
    return {"status": status, "paragraphs": paragraphs, "images": images, "origin": "feed", "fetchedAt": timestamp, "note": note}


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, address, timeout):
        super().__init__(host, 443, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        # Connecting to the already-validated IP closes the DNS-rebinding window.
        sock = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def _configured_proxy():
    """Return the explicit trusted admin proxy, never an HTTP request value.

    Internal proxy hostnames/IPs are allowed because corporate egress proxies
    commonly live on private networks. Publisher targets remain public-only.
    Proxy credentials are deliberately unsupported and never logged/forwarded.
    """
    value = os.environ.get("CYBERWATCH_HTTPS_PROXY", "").strip()
    if not value:
        return None
    message = "Invalid CYBERWATCH_HTTPS_PROXY: use http://host:port without credentials, path, query or fragment"
    if len(value) > 2000 or any(ord(char) < 33 or ord(char) == 127 for char in value) or "\\" in value:
        raise ValueError(message)
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "http":
            raise ValueError("CYBERWATCH_HTTPS_PROXY supports an HTTP CONNECT proxy (http://host:port); HTTPS proxy transport is not supported")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("CYBERWATCH_HTTPS_PROXY does not support proxy credentials; use an approved unauthenticated egress proxy")
        host = parsed.hostname
        port = parsed.port if parsed.port is not None else 80
        if not host or not 1 <= port <= 65535 or parsed.path not in {"", "/"} or "?" in value or "#" in value or parsed.netloc.endswith(":"):
            raise ValueError(message)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label) for label in host.split(".")):
                raise ValueError(message)
        return host, port
    except ValueError as error:
        # Parser exceptions can include supplied values: keep errors static.
        if str(error).startswith(("Invalid CYBERWATCH_HTTPS_PROXY", "CYBERWATCH_HTTPS_PROXY supports", "CYBERWATCH_HTTPS_PROXY does not support")):
            raise
        raise ValueError(message) from None


class _TrustedProxyHTTPSConnection(http.client.HTTPSConnection):
    """HTTP CONNECT to an explicit proxy, then verified TLS to the publisher.

    The proxy receives only CONNECT hostname:443; target TLS still validates the
    publisher hostname using the system trust store. Local DNS validation is
    retained, but target-IP pinning is unavailable through this mode: the trusted
    proxy must enforce public destination resolution and prevent DNS rebinding.
    """
    def __init__(self, target_host, proxy_host, proxy_port, timeout):
        super().__init__(proxy_host, proxy_port, timeout=timeout, context=ssl.create_default_context())
        self.set_tunnel(target_host, 443)


def _resolve_public(host):
    addresses = []
    for result in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM):
        address = result[4][0]
        parsed = ipaddress.ip_address(address)
        if not parsed.is_global or parsed.is_multicast or parsed.is_reserved:
            raise ValueError("Publisher resolves to a non-public address")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError("Publisher has no public address")
    return addresses


def fetch_public(url, allowed_hosts, *, max_bytes=MAX_ARTICLE_BYTES, deadline=None):
    """Fetch HTTPS bytes with exact-host redirects and pinned public DNS.

    Returns (payload, final_url, content_type). Direct mode pins public DNS.
    Only CYBERWATCH_HTTPS_PROXY enables a trusted HTTP CONNECT proxy; then the
    proxy owns final target DNS/public-destination enforcement while local
    validation and verified target TLS remain in effect. Proxy credentials,
    cookies, publisher authorization and arbitrary headers are not accepted.
    """
    proxy = _configured_proxy()
    deadline = deadline if deadline is not None else time.monotonic() + 12
    for _ in range(5):
        checked = _safe_public_url(url, allowed_hosts=allowed_hosts)
        if checked is None:
            raise ValueError("Publisher URL is outside the approved public HTTPS hosts")
        parsed = urlsplit(checked)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Reader fetch budget exhausted")
        addresses = _resolve_public(parsed.hostname)
        timeout = min(REQUEST_TIMEOUT, remaining)
        connection = (_TrustedProxyHTTPSConnection(parsed.hostname, proxy[0], proxy[1], timeout)
                      if proxy else _PinnedHTTPSConnection(parsed.hostname, addresses[0], timeout))
        try:
            connection.request("GET", urlunsplit(("", "", parsed.path or "/", parsed.query, "")),
                               headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/atom+xml, application/xml, application/json, text/html, text/plain;q=0.9", "Accept-Encoding": "identity"})
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                if not location:
                    raise ValueError("Publisher redirect has no location")
                url = urljoin(checked, location)
                continue
            if response.status != 200:
                raise ValueError(f"Publisher returned HTTP {response.status}")
            length = response.getheader("Content-Length", "")
            if length.isdigit() and int(length) > max_bytes:
                raise ValueError("Publisher response exceeds the reader size limit")
            if response.getheader("Content-Encoding", "identity").lower() not in {"", "identity"}:
                raise ValueError("Unexpected compressed publisher response")
            chunks, count = [], 0
            while count <= max_bytes:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Reader fetch budget exhausted")
                if connection.sock is not None:
                    connection.sock.settimeout(min(REQUEST_TIMEOUT, remaining))
                # read1 returns available data instead of waiting to fill a
                # large buffer, allowing an absolute deadline between reads.
                chunk = response.read1(min(65536, max_bytes + 1 - count))
                if not chunk:
                    break
                chunks.append(chunk)
                count += len(chunk)
            if count > max_bytes:
                raise ValueError("Publisher response exceeds the reader size limit")
            return b"".join(chunks), checked, response.getheader("Content-Type", "").lower()
        except http.client.HTTPException as error:
            raise ValueError("Publisher returned an invalid HTTP response") from error
        finally:
            connection.close()
    raise ValueError("Publisher redirect limit exceeded")


def robots_allows(payload, url):
    """Apply matching robots groups, longest-path precedence and wildcards."""
    groups, agents, rules, delay = [], [], [], 0.0
    collecting_rules = False
    for raw in payload.decode("utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if collecting_rules:
                groups.append((agents, rules, delay))
                agents, rules, delay, collecting_rules = [], [], 0.0, False
            agents.append(value.lower())
        elif agents and key in {"allow", "disallow", "crawl-delay"}:
            collecting_rules = True
            if key == "crawl-delay":
                try:
                    delay = max(delay, float(value))
                except ValueError:
                    pass
            elif value:
                rules.append((key == "allow", value))
    if agents:
        groups.append((agents, rules, delay))
    best = -1
    selected = []
    for agents, rules, delay in groups:
        score = max((0 if agent == "*" else len(agent) for agent in agents if agent == "*" or agent in USER_AGENT.lower()), default=-1)
        if score > best:
            best, selected = score, [(rules, delay)]
        elif score == best and score >= 0:
            selected.append((rules, delay))
    path = urlsplit(url).path or "/"
    if urlsplit(url).query:
        path += "?" + urlsplit(url).query
    matched = []
    for rules, _ in selected:
        for allow, pattern in rules:
            anchored = pattern.endswith("$")
            pattern = pattern[:-1] if anchored else pattern
            expression = "^" + re.escape(pattern).replace(r"\*", ".*") + ("$" if anchored else "")
            if re.search(expression, path):
                matched.append((len(pattern.replace("*", "")), allow))
    allowed = max(matched, default=(0, True))[1]
    return allowed, max((delay for _, delay in selected), default=0.0)


def _cached_article(event, previous, timestamp):
    old = previous.get(event.get("id"))
    if not old or old.get("updatedAt") != event.get("updatedAt") or old.get("sources", [{}])[0].get("url") != event.get("sources", [{}])[0].get("url"):
        return None
    article = old.get("article")
    if not isinstance(article, dict) or article.get("origin") != "publisher" or not article.get("fetchedAt"):
        return None
    try:
        elapsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00")) - datetime.fromisoformat(article["fetchedAt"].replace("Z", "+00:00"))
        ttl = CACHE_HOURS if article.get("status") == "full" else RETRY_HOURS
        if 0 <= elapsed.total_seconds() < ttl * 3600:
            return deepcopy(article)
    except (ValueError, TypeError):
        pass
    return None


def enrich_events(events, sources_by_id, previous=None, timestamp=None, *, max_articles=12, workers=4, fetcher=fetch_public, clock=time.monotonic):
    """Enrich a bounded selection of permitted publisher articles in place.

    Existing feed excerpts are retained on network, access or extraction errors.
    Failed requests are cached for six hours; complete articles for seven days,
    unless the publisher update timestamp changes. Every run has a total budget.
    """
    timestamp = timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    if not isinstance(sources_by_id, dict):
        sources_by_id = {source["id"]: source for source in sources_by_id}
    prior_events = (previous or {}).get("events", []) if isinstance(previous, dict) else (previous or [])
    prior = {event["id"]: event for event in prior_events if isinstance(event, dict) and "id" in event}
    pending, candidates = [], {}
    deadline = clock() + MAX_ENRICH_SECONDS
    max_articles = max(0, min(int(max_articles), 30))
    for event in events:
        source = sources_by_id.get(event.get("sourceId"), {})
        # A reviewed analyst summary must not be presented as publisher text.
        if not source or source.get("kind") == "curated":
            continue
        policy = source_policy(source)
        # Events without feed content still receive a transparent reader state.
        if "article" not in event:
            event["article"] = ingest_feed_content(source, summary=event.get("summary", ""), article_url=event.get("sources", [{}])[0].get("url", ""), timestamp=timestamp)
        if not policy["allowFullText"] or not policy["allowedHosts"]:
            continue
        cached = _cached_article(event, prior, timestamp)
        if cached:
            event["article"] = cached
            continue
        if event["article"].get("status") == "full":
            continue
        candidates.setdefault(event.get("sourceId"), []).append((event, source, policy))
    # Give each eligible publisher a turn so a large first feed cannot consume
    # the entire article budget before another vendor gets a readable update.
    buckets = [deque(sorted(items, key=lambda item: item[0].get("publishedAt", item[0].get("updatedAt", "")), reverse=True)) for items in candidates.values()]
    while buckets and len(pending) < max_articles:
        for bucket in buckets:
            if bucket and len(pending) < max_articles:
                pending.append(bucket.popleft())
        buckets = [bucket for bucket in buckets if bucket]
    robots_cache, robots_lock, host_locks, host_last = {}, threading.Lock(), {}, {}

    def work(item):
        event, source, policy = item
        current = deepcopy(event["article"])
        current.update(origin="publisher", fetchedAt=timestamp)
        url = event.get("sources", [{}])[0].get("url", "")
        try:
            if clock() >= deadline:
                return
            parsed = urlsplit(url)
            if parsed.hostname not in policy["allowedHosts"]:
                raise ValueError("Article is outside the configured publisher hosts")
            origin = "https://" + parsed.netloc
            with robots_lock:
                lock = host_locks.setdefault(origin, threading.Lock())
            # Per-publisher serialization prevents simultaneous article requests.
            with lock:
                if clock() >= deadline:
                    return
                if origin not in robots_cache:
                    # Cache failures too; do not retry robots for every item.
                    robots_cache[origin] = None
                    payload, _, kind = fetcher(origin + "/robots.txt", policy["allowedHosts"], max_bytes=MAX_ROBOTS_BYTES, deadline=deadline)
                    if "html" in kind or not payload.strip() or b"<html" in payload[:1000].lower():
                        raise ValueError("Publisher robots policy could not be verified")
                    robots_cache[origin] = payload
                    host_last[origin] = clock()
                if robots_cache[origin] is None:
                    raise ValueError("Publisher robots policy could not be verified")
                allowed, crawl_delay = robots_allows(robots_cache[origin], url)
                if not allowed:
                    current.update(status="restricted", note="The publisher robots policy does not allow article collection. Feed content and the original link remain available.")
                    event["article"] = current
                    return
                if crawl_delay > 10:
                    raise ValueError("Publisher crawl delay exceeds this reader's request budget")
                wait = max(0, host_last.get(origin, 0) + crawl_delay - clock())
                if clock() + wait >= deadline:
                    return
                if wait:
                    time.sleep(wait)
                payload, final_url, kind = fetcher(url, policy["allowedHosts"], deadline=deadline)
                host_last[origin] = clock()
            if not any(value in kind for value in ("text/html", "application/xhtml+xml", "text/plain")):
                raise ValueError("Publisher did not return readable article content")
            parser = ContentParser(final_url, policy["allowedImageHosts"])
            charset = re.search(r"charset=([a-zA-Z0-9_-]+)", kind)
            try:
                markup = payload.decode(charset.group(1) if charset else "utf-8", errors="replace")
            except LookupError:
                markup = payload.decode("utf-8", errors="replace")
            parser.feed(markup)
            content = parser.finish(require_article="text/plain" not in kind)
            if content["restricted"]:
                current.update(status="restricted", note="The publisher page indicates restricted access. Feed content and the original link remain available.")
            elif sum(map(len, content["paragraphs"])) < 150:
                current["note"] = "A complete article could not be extracted from the publisher page. Available feed content is shown."
            else:
                limited = content["truncated"] or content["teaser"]
                current.update(status="excerpt" if limited else "full", paragraphs=content["paragraphs"], images=content["images"] or current["images"],
                               note=("The publisher supplies a partial article or its text exceeds the reader limit. Available text is shown; open the original to continue." if limited else
                                     _licensed_note("Article text collected from a permitted public publisher page. Formatting is simplified; consult the original for authoritative details.", source, policy)))
                if limited:
                    current["note"] = _licensed_note(current["note"], source, policy)
        except Exception as error:
            # Do not leak raw URLs, response bodies or infrastructure details.
            reason = "Reader fetch unavailable" if not isinstance(error, ValueError) else str(error)[:180]
            current["note"] = reason + ". Available feed content and the original source link remain available."
        event["article"] = current

    if pending:
        with ThreadPoolExecutor(max_workers=max(1, min(int(workers), 4))) as pool:
            list(pool.map(work, pending))
    return events
