"""Offline reader tests: publisher access, extraction and network trust boundary."""
from copy import deepcopy
from datetime import datetime, timezone
import io
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import article_content as reader

STAMP = "2026-10-30T12:00:00Z"
SOURCE = {"id": "vendor", "name": "Example Vendor", "url": "https://vendor.example.org/",
          "articlePolicy": {"allowFullText": True, "allowedHosts": ["vendor.example.org"]}}
LONG_TEXT = "This security advisory describes the affected software versions, the circumstances required for exploitation, the available fixed release, and recommended actions for administrators."


def event(identifier="event-1", url="https://vendor.example.org/advisory", updated=STAMP):
    return {"id": identifier, "sourceId": "vendor", "updatedAt": updated, "summary": "Feed security update.",
            "sources": [{"url": url}]}


def page(body=None):
    return ("<html><main><article><h1>Security update</h1><p>" + (body or LONG_TEXT) +
            "</p><figure><img src='/security.jpg' alt='Security bulletin'><figcaption>Publisher illustration</figcaption></figure>"
            "</article></main></html>").encode()


def fake_fetch(url, hosts, **kwargs):
    if url.endswith("robots.txt"):
        return b"User-agent: *\nAllow: /", url, "text/plain"
    return page(), url, "text/html; charset=utf-8"


class ReaderURLTests(unittest.TestCase):
    def test_images_block_unsafe_schemes_credentials_and_private_hosts(self):
        for url in ("http://vendor.example.org/image.jpg", "javascript:alert(1)", "data:image/png;base64,a",
                    "https://user:pass@vendor.example.org/a.jpg", "https://127.0.0.1/a.jpg", "https://[::1]/a.jpg",
                    "https://192.168.1.2/a.jpg", "https://10.0.0.3/a.jpg", "https://169.254.169.254/a.jpg",
                    "https://localhost/a.jpg", "https://printer/a.jpg", "https://printer.local/a.jpg",
                    "https://2130706433/a.jpg", "https://0x7f.0.0.1/a.jpg", "https://vendor.example.org:444/a.jpg",
                    "https://vendor.example.org/a.svg", "https://vendor.example.org/a.html", "https://[2001:4860:4860::8888]/a.jpg", "https://vendor.example.org/a'b.jpg",
                    "https://vendor.example.org/\nimage.jpg", "https://vendor.example.org\\@127.0.0.1/a.jpg"):
            with self.subTest(url=url):
                self.assertIsNone(reader.safe_image_url(url))

    def test_relative_images_resolve_against_article_and_respect_host_policy(self):
        self.assertEqual(reader.safe_image_url("/image.jpg", base_url="https://vendor.example.org/story"),
                         "https://vendor.example.org/image.jpg")
        self.assertIsNone(reader.safe_image_url("https://other.example.org/image.jpg", allowed_hosts=["vendor.example.org"]))
        self.assertEqual(reader.safe_image_url("https://vendor.example.org/image.jpg#preview"),
                         "https://vendor.example.org/image.jpg")

    def test_dns_resolution_rejects_private_or_mixed_public_private_answers(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
                     (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch.object(reader.socket, "getaddrinfo", return_value=addresses):
            with self.assertRaisesRegex(ValueError, "non-public"):
                reader._resolve_public("vendor.example.org")

    def test_fetch_rejects_hosts_before_dns(self):
        with patch.object(reader.socket, "getaddrinfo") as dns:
            for url in ("https://internal.example.org/", "http://vendor.example.org/", "https://vendor.example.org@127.0.0.1/"):
                with self.assertRaises(ValueError):
                    reader.fetch_public(url, ["vendor.example.org"])
            dns.assert_not_called()

    def test_redirect_cannot_escape_allowlist(self):
        class Response:
            status = 302
            def getheader(self, key, default=None):
                return "https://127.0.0.1/secrets" if key == "Location" else default
        class Connection:
            def __init__(self, *args):
                pass
            def request(self, *args, **kwargs):
                pass
            def getresponse(self):
                return Response()
            def close(self):
                pass
        with patch.object(reader, "_resolve_public", return_value=["8.8.8.8"]) as dns, patch.object(reader, "_PinnedHTTPSConnection", Connection):
            with self.assertRaises(ValueError):
                reader.fetch_public("https://vendor.example.org/story", ["vendor.example.org"])
            self.assertEqual(dns.call_count, 1)

    def test_fetch_allows_html_paths_but_bounds_response_bytes(self):
        class Response:
            status = 200
            def __init__(self):
                self.body = io.BytesIO(b"<html>abcdef</html>")
            def getheader(self, key, default=None):
                return "text/html" if key == "Content-Type" else default
            def read1(self, size):
                return self.body.read(size)
        class Connection:
            sock = None
            def __init__(self, *args):
                pass
            def request(self, *args, **kwargs):
                pass
            def getresponse(self):
                return Response()
            def close(self):
                pass
        with patch.object(reader, "_resolve_public", return_value=["8.8.8.8"]), patch.object(reader, "_PinnedHTTPSConnection", Connection):
            payload, final, kind = reader.fetch_public("https://vendor.example.org/security.html", ["vendor.example.org"])
            self.assertIn(b"abcdef", payload)
            self.assertEqual(kind, "text/html")
            with self.assertRaisesRegex(ValueError, "size limit"):
                reader.fetch_public(final, ["vendor.example.org"], max_bytes=5)


class ReaderProxyTests(unittest.TestCase):
    def test_proxy_is_explicit_opt_in_and_ignores_standard_environment(self):
        with patch.dict(reader.os.environ, {"CYBERWATCH_HTTPS_PROXY": "", "HTTPS_PROXY": "http://ignored.example.org:8080", "HTTP_PROXY": "http://also-ignored.example.org:8080"}):
            self.assertIsNone(reader._configured_proxy())
        with patch.dict(reader.os.environ, {"CYBERWATCH_HTTPS_PROXY": "http://egress.internal:3128"}):
            self.assertEqual(reader._configured_proxy(), ("egress.internal", 3128))
        with patch.dict(reader.os.environ, {"CYBERWATCH_HTTPS_PROXY": "http://10.0.0.2/"}):
            self.assertEqual(reader._configured_proxy(), ("10.0.0.2", 80))

    def test_malformed_proxy_and_credentials_are_rejected_without_disclosure(self):
        for value in ("https://proxy.example.org:8080", "socks5://proxy.example.org:1080", "http://proxy.example.org:0", "http://proxy.example.org:65536",
                      "http://proxy.example.org/path", "http://proxy.example.org?target=value", "http://proxy.example.org#value", "http://proxy.example.org:",
                      "http://proxy.example.org/\nheader", "http://user:SECRET_PASSWORD@proxy.example.org:8080", "http://@proxy.example.org"):
            with self.subTest(proxy=value), patch.dict(reader.os.environ, {"CYBERWATCH_HTTPS_PROXY": value}):
                with self.assertRaises(ValueError) as result:
                    reader._configured_proxy()
                self.assertNotIn("SECRET_PASSWORD", str(result.exception))
                self.assertNotIn("user:", str(result.exception))

    def test_connect_preserves_target_hostname_and_verified_tls_without_origin_credentials(self):
        connection = reader._TrustedProxyHTTPSConnection("vendor.example.org", "egress.internal", 3128, 6)
        self.assertTrue(connection._context.check_hostname)
        self.assertEqual(connection._context.verify_mode, reader.ssl.CERT_REQUIRED)
        self.assertEqual(connection.host, "egress.internal")
        self.assertEqual(connection._tunnel_host, "vendor.example.org")
        self.assertNotIn("Proxy-Authorization", connection._tunnel_headers)
        sock = Mock()
        sock.makefile.return_value = io.BytesIO(b"HTTP/1.0 200 Connection established\r\n\r\n")
        connection._create_connection = Mock(return_value=sock)
        tls_context = Mock()
        connection._context = tls_context
        connection.connect()
        connection._create_connection.assert_called_once()
        sent = b"".join(call.args[0] for call in sock.sendall.call_args_list)
        self.assertIn(b"CONNECT vendor.example.org:443", sent)
        self.assertNotIn(b"Proxy-Authorization", sent)
        tls_context.wrap_socket.assert_called_once_with(sock, server_hostname="vendor.example.org")
        connection.close()

    def test_proxy_fetch_still_validates_target_dns_and_does_not_use_direct_socket(self):
        class Response:
            status = 200
            def __init__(self):
                self.body = io.BytesIO(b"<p>security advisory</p>")
            def getheader(self, key, default=None):
                return "text/html" if key == "Content-Type" else default
            def read1(self, size):
                return self.body.read(size)
        connection = Mock()
        connection.sock = None
        connection.getresponse.return_value = Response()
        with patch.dict(reader.os.environ, {"CYBERWATCH_HTTPS_PROXY": "http://egress.internal:3128"}), patch.object(reader, "_resolve_public", return_value=["8.8.8.8"]) as dns, patch.object(reader, "_TrustedProxyHTTPSConnection", return_value=connection) as proxied, patch.object(reader, "_PinnedHTTPSConnection") as direct:
            payload, _, _ = reader.fetch_public("https://vendor.example.org/advisory", ["vendor.example.org"])
            self.assertIn(b"security", payload)
            dns.assert_called_once_with("vendor.example.org")
            self.assertEqual(proxied.call_args.args[:3], ("vendor.example.org", "egress.internal", 3128))
            direct.assert_not_called()
            headers = connection.request.call_args.kwargs["headers"]
            self.assertNotIn("Proxy-Authorization", headers)
            self.assertNotIn("Authorization", headers)

    def test_proxy_cannot_enable_private_target_or_unsafe_redirect(self):
        connection = Mock()
        connection.getresponse.return_value.status = 302
        connection.getresponse.return_value.getheader.return_value = "https://127.0.0.1/secret"
        with patch.dict(reader.os.environ, {"CYBERWATCH_HTTPS_PROXY": "http://egress.internal:3128"}), patch.object(reader, "_resolve_public", return_value=["8.8.8.8"]) as dns, patch.object(reader, "_TrustedProxyHTTPSConnection", return_value=connection) as proxied:
            with self.assertRaises(ValueError):
                reader.fetch_public("https://vendor.example.org/advisory", ["vendor.example.org"])
            self.assertEqual(dns.call_count, 1)
            self.assertEqual(proxied.call_count, 1)
        with patch.dict(reader.os.environ, {"CYBERWATCH_HTTPS_PROXY": "http://egress.internal:3128"}), patch.object(reader, "_resolve_public", side_effect=ValueError("Publisher resolves to a non-public address")), patch.object(reader, "_TrustedProxyHTTPSConnection") as proxied:
            with self.assertRaises(ValueError):
                reader.fetch_public("https://vendor.example.org/advisory", ["vendor.example.org"])
            proxied.assert_not_called()


class ReaderExtractionTests(unittest.TestCase):
    def test_default_news_reader_shows_feed_excerpt_not_unpermitted_full_text(self):
        article = reader.ingest_feed_content({"url": "https://news.example.org"}, summary="A security report.",
                                              content="<p>" + "word " * 300 + "</p>", timestamp=STAMP)
        self.assertEqual(article["status"], "excerpt")
        self.assertLessEqual(len(article["paragraphs"][0].split()), 120)
        self.assertEqual(article["origin"], "feed")

    def test_full_feed_text_requires_explicit_policy_and_content(self):
        article = reader.ingest_feed_content(SOURCE, content="<p>" + LONG_TEXT + "</p>", timestamp=STAMP)
        self.assertEqual(article["status"], "full")
        self.assertEqual(article["paragraphs"], [LONG_TEXT])
        summary = reader.ingest_feed_content(SOURCE, summary=LONG_TEXT, timestamp=STAMP)
        self.assertEqual(summary["status"], "excerpt")

    def test_extractor_removes_scripts_navigation_and_hidden_text(self):
        parser = reader.ContentParser("https://vendor.example.org/advisory")
        parser.feed("<nav>Navigation<p>Other stories</p></nav><main><article><p>" + LONG_TEXT +
                    "<script>alert('secret')</script><span hidden>hidden content</span></p>"
                    "<aside><p>Advertisement</p></aside></article></main><footer><p>Footer</p></footer>")
        content = parser.finish(require_article=True)
        self.assertEqual(content["paragraphs"], [LONG_TEXT])

    def test_jsonld_body_is_supported_without_emitting_script_markup(self):
        import json
        parser = reader.ContentParser("https://vendor.example.org/story")
        parser.feed('<script type="application/ld+json">' + json.dumps({"@type": "NewsArticle", "articleBody": LONG_TEXT}) + '</script>')
        self.assertEqual(parser.finish(require_article=True)["paragraphs"], [LONG_TEXT])

    def test_jsonld_restricted_access_and_paywall_text_prevent_full_status(self):
        for markup in ('<article><p>' + LONG_TEXT + '</p><script type="application/ld+json">{"@type":"NewsArticle","isAccessibleForFree":false}</script></article>',
                       '<article><p>' + LONG_TEXT + '</p><div>Subscribe to continue reading</div></article>'):
            article = reader.ingest_feed_content(SOURCE, content=markup)
            self.assertEqual(article["status"], "restricted")

    def test_images_keep_caption_and_credit_and_drop_tracking_pixels(self):
        article = reader.ingest_feed_content(SOURCE, content='<article><p>' + LONG_TEXT +
            '</p><img src="https://vendor.example.org/pixel.gif" width="1" height="1">'
            '<figure><img src="/photo.jpg" alt="Advisory" data-credit="Example Vendor"><figcaption>Patch available</figcaption></figure></article>',
            article_url="https://vendor.example.org/advisory", image_candidates=["javascript:bad", "https://127.0.0.1/a.jpg"])
        self.assertEqual(article["images"], [{"url": "https://vendor.example.org/photo.jpg", "alt": "Advisory", "caption": "Patch available", "credit": "Example Vendor"}])

    def test_bounds_and_teaser_are_never_labelled_full_article(self):
        for markup in ("<p>" + "security " * 12000 + "</p>",
                       "<article><p>" + LONG_TEXT + "</p><p>Read more</p></article>"):
            with self.subTest(size=len(markup)):
                article = reader.ingest_feed_content(SOURCE, content=markup)
                self.assertEqual(article["status"], "excerpt")

    def test_headline_only_policy_does_not_silently_republish_feed_text(self):
        source = {"url": "https://vendor.example.org/", "headlineOnly": True}
        article = reader.ingest_feed_content(source, summary=LONG_TEXT, content=LONG_TEXT)
        self.assertEqual(article["status"], "unavailable")
        self.assertEqual(article["paragraphs"], [])

    def test_access_challenge_is_restricted_content(self):
        parser = reader.ContentParser()
        parser.feed("<main><p>Verify you are human.</p><p>" + LONG_TEXT + "</p></main>")
        self.assertTrue(parser.finish(require_article=True)["restricted"])

    def test_empty_feed_has_honest_unavailable_state_and_can_keep_image(self):
        article = reader.ingest_feed_content(SOURCE, image_candidates=["https://vendor.example.org/photo.jpg"])
        self.assertEqual(article["status"], "unavailable")
        self.assertEqual(article["paragraphs"], [])
        self.assertEqual(len(article["images"]), 1)

    def test_article_requires_content_scope_and_does_not_extract_whole_navigation_page(self):
        parser = reader.ContentParser()
        parser.feed("<div><p>" + LONG_TEXT + "</p></div>")
        self.assertEqual(parser.finish(require_article=True)["paragraphs"], [])

    def test_large_paragraphs_split_within_snapshot_field_limits(self):
        article = reader.ingest_feed_content(SOURCE, content="<p>" + "security " * 700 + "</p>")
        self.assertGreater(len(article["paragraphs"]), 1)
        self.assertTrue(all(len(value) <= 4000 for value in article["paragraphs"]))
        self.assertEqual(" ".join(article["paragraphs"]), ("security " * 700).strip())


class ReaderRobotsTests(unittest.TestCase):
    def test_longest_rule_and_allow_tie(self):
        rules = b"User-agent: *\nDisallow: /\nAllow: /security/\nDisallow: /security/private\n"
        self.assertTrue(reader.robots_allows(rules, "https://vendor.example.org/security/article")[0])
        self.assertFalse(reader.robots_allows(rules, "https://vendor.example.org/security/private/a")[0])

    def test_specific_agent_overrides_wildcard_and_supports_wildcards(self):
        rules = b"User-agent: *\nAllow: /\nUser-agent: CyberWatch\nDisallow: /*?preview=\nDisallow: /private$\nCrawl-delay: 2\n"
        self.assertEqual(reader.robots_allows(rules, "https://vendor.example.org/a?preview=1"), (False, 2.0))
        self.assertFalse(reader.robots_allows(rules, "https://vendor.example.org/private")[0])
        self.assertTrue(reader.robots_allows(rules, "https://vendor.example.org/private-more")[0])


class ReaderEnrichmentTests(unittest.TestCase):
    def test_permitted_public_article_is_readable_and_images_are_kept(self):
        items = [event()]
        reader.enrich_events(items, {"vendor": SOURCE}, timestamp=STAMP, fetcher=fake_fetch)
        article = items[0]["article"]
        self.assertEqual(article["status"], "full")
        self.assertIn(LONG_TEXT, article["paragraphs"])
        self.assertEqual(article["origin"], "publisher")
        self.assertEqual(article["fetchedAt"], STAMP)
        self.assertEqual(article["images"][0]["url"], "https://vendor.example.org/security.jpg")

    def test_no_permission_means_no_page_or_robots_request(self):
        def unexpected(*args, **kwargs):
            self.fail("Unpermitted publisher was fetched")
        items = [event()]
        reader.enrich_events(items, {"vendor": {"url": SOURCE["url"]}}, timestamp=STAMP, fetcher=unexpected)
        self.assertEqual(items[0]["article"]["status"], "excerpt")

    def test_robots_deny_retains_feed_excerpt_without_fetching_article(self):
        calls = []
        def denied(url, hosts, **kwargs):
            calls.append(url)
            return b"User-agent: *\nDisallow: /", url, "text/plain"
        items = [event()]
        reader.enrich_events(items, {"vendor": SOURCE}, timestamp=STAMP, fetcher=denied)
        self.assertEqual(items[0]["article"]["status"], "restricted")
        self.assertEqual(items[0]["article"]["paragraphs"], ["Feed security update."])
        self.assertEqual(len(calls), 1)

    def test_robots_network_failure_fails_closed_and_keeps_feed(self):
        calls = []
        def failure(url, hosts, **kwargs):
            calls.append(url)
            raise OSError("offline")
        items = [event()]
        reader.enrich_events(items, {"vendor": SOURCE}, timestamp=STAMP, fetcher=failure)
        self.assertEqual(items[0]["article"]["status"], "excerpt")
        self.assertEqual(items[0]["article"]["paragraphs"], ["Feed security update."])
        self.assertEqual(len(calls), 1)

    def test_paywall_page_is_never_published_as_full(self):
        def limited(url, hosts, **kwargs):
            if url.endswith("robots.txt"):
                return fake_fetch(url, hosts, **kwargs)
            return page(LONG_TEXT + " Subscribe to continue reading."), url, "text/html"
        items = [event()]
        reader.enrich_events(items, {"vendor": SOURCE}, timestamp=STAMP, fetcher=limited)
        self.assertEqual(items[0]["article"]["status"], "restricted")
        self.assertEqual(items[0]["article"]["paragraphs"], ["Feed security update."])

    def test_completed_article_cache_avoids_repeated_requests(self):
        old = [event()]
        reader.enrich_events(old, {"vendor": SOURCE}, timestamp=STAMP, fetcher=fake_fetch)
        def unexpected(*args, **kwargs):
            self.fail("Cached publisher article fetched again")
        items = [event()]
        reader.enrich_events(items, {"vendor": SOURCE}, previous={"events": old}, timestamp="2026-10-30T13:00:00Z", fetcher=unexpected)
        self.assertEqual(items[0]["article"], old[0]["article"])

    def test_publisher_update_invalidates_cached_content(self):
        old = [event()]
        reader.enrich_events(old, {"vendor": SOURCE}, timestamp=STAMP, fetcher=fake_fetch)
        calls = []
        def counted(url, hosts, **kwargs):
            calls.append(url)
            return fake_fetch(url, hosts, **kwargs)
        items = [event(updated="2026-10-30T13:00:00Z")]
        reader.enrich_events(items, {"vendor": SOURCE}, previous={"events": old}, timestamp="2026-10-30T13:00:00Z", fetcher=counted)
        self.assertEqual(len(calls), 2)

    def test_request_budget_and_one_robots_fetch_per_host(self):
        calls = []
        def counted(url, hosts, **kwargs):
            calls.append(url)
            return fake_fetch(url, hosts, **kwargs)
        items = [event(str(index), url=f"https://vendor.example.org/security/{index}") for index in range(5)]
        reader.enrich_events(items, {"vendor": SOURCE}, timestamp=STAMP, max_articles=2, fetcher=counted)
        self.assertEqual(sum(url.endswith("robots.txt") for url in calls), 1)
        self.assertEqual(len(calls), 3)
        self.assertEqual(sum(item["article"]["status"] == "full" for item in items), 2)

    def test_reviewed_summary_is_not_misattributed_as_publisher_excerpt(self):
        reviewed = event()
        reviewed["sourceId"] = "curated"
        reader.enrich_events([reviewed], {"vendor": SOURCE}, timestamp=STAMP, fetcher=fake_fetch)
        self.assertNotIn("article", reviewed)

    def test_partial_or_oversized_publisher_article_remains_excerpt(self):
        for body in (LONG_TEXT + " Read more", "security " * 12000):
            def partial(url, hosts, **kwargs):
                if url.endswith("robots.txt"):
                    return fake_fetch(url, hosts, **kwargs)
                return page(body), url, "text/html"
            items = [event()]
            reader.enrich_events(items, {"vendor": SOURCE}, timestamp=STAMP, fetcher=partial)
            self.assertEqual(items[0]["article"]["status"], "excerpt")

    def test_article_budget_is_shared_across_publishers(self):
        second = deepcopy(SOURCE)
        second["id"] = "second"
        second["url"] = "https://other.example.org/"
        second["articlePolicy"]["allowedHosts"] = ["other.example.org"]
        items = [event(str(index), url=f"https://vendor.example.org/{index}") for index in range(5)]
        other = event("other", url="https://other.example.org/advisory")
        other["sourceId"] = "second"
        items.append(other)
        reader.enrich_events(items, {"vendor": SOURCE, "second": second}, timestamp=STAMP, max_articles=2, fetcher=fake_fetch)
        self.assertEqual(other["article"]["status"], "full")
        self.assertEqual(sum(item["article"]["status"] == "full" for item in items), 2)

    def test_full_content_retains_license_and_attribution_note(self):
        source = deepcopy(SOURCE)
        source["articlePolicy"]["license"] = "CC BY-SA 4.0"
        source["articlePolicy"]["attribution"] = "Example Vendor authors"
        article = reader.ingest_feed_content(source, content="<p>" + LONG_TEXT + "</p>")
        self.assertIn("CC BY-SA 4.0", article["note"])
        self.assertIn("Example Vendor authors", article["note"])
        items = [event()]
        reader.enrich_events(items, {"vendor": source}, timestamp=STAMP, fetcher=fake_fetch)
        self.assertIn("CC BY-SA 4.0", items[0]["article"]["note"])

    def test_failed_robots_is_not_retried_for_each_same_host_article(self):
        calls = []
        def failure(url, hosts, **kwargs):
            calls.append(url)
            raise OSError("offline")
        items = [event(str(index), url=f"https://vendor.example.org/{index}") for index in range(3)]
        reader.enrich_events(items, {"vendor": SOURCE}, timestamp=STAMP, fetcher=failure)
        self.assertEqual(len(calls), 1)
        self.assertTrue(all(item["article"]["status"] == "excerpt" for item in items))

    def test_reader_cannot_follow_event_url_to_unapproved_host(self):
        calls = []
        def unexpected(*args, **kwargs):
            calls.append(args)
        items = [event(url="https://attacker.example.org/article")]
        reader.enrich_events(items, {"vendor": SOURCE}, timestamp=STAMP, fetcher=unexpected)
        self.assertFalse(calls)
        self.assertEqual(items[0]["article"]["status"], "excerpt")


if __name__ == "__main__":
    unittest.main()
