"""Offline regression tests for feed trust boundaries and outage behavior."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from urllib.request import Request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from fetch_feeds import SOURCES, assemble, collect_source, explicit_exploitation, feed_event, iso, parse_kev, parse_rss, parse_atom, parse_cirt, safe_url, text
from fetch_feeds import PublisherRedirect, cyber_headline, newspaper_date, newspaper_url, parse_newspaper, parse_newspaper_article
from validate_data import validate_snapshot


def kev_payload():
    return json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-12345", "vendorProject": "Example Vendor",
        "product": "Gateway", "vulnerabilityName": "Example command injection",
        "shortDescription": "An authenticated attacker can execute commands on affected releases.",
        "requiredAction": "Apply the vendor update.", "dateAdded": "2026-10-21",
        "knownRansomwareCampaignUse": "Unknown", "notes": "https://example.com/advisory"}]}).encode()


class FeedTests(unittest.TestCase):
    def source(self, identifier):
        return next(source for source in SOURCES if source["id"] == identifier)

    def test_markup_and_unsafe_links_are_not_trusted(self):
        self.assertEqual(text("<p>Hello<script>steal()</script><b> world</b></p>"), "Hello world")
        for value in ("javascript:alert(1)", "data:text/html,test", "https://user:pass@example.com/", "https://example.com/\nattack"):
            self.assertIsNone(safe_url(value))
        self.assertEqual(safe_url("https://example.com/advisory?q=1"), "https://example.com/advisory?q=1")

    def test_kev_does_not_invent_severity_or_publication_date(self):
        event = parse_kev(kev_payload())[0]
        self.assertEqual(event["severity"], "unknown")
        self.assertTrue(event["exploited"])
        self.assertEqual(event["publishedAt"], "2026-10-21T00:00:00Z")
        self.assertIn("addition date", event["evidenceNote"])
        self.assertEqual(event["category"], "Vulnerability")

    def test_cest_date_is_converted_correctly(self):
        self.assertEqual(iso("Thu, 22 Oct 2026 11:14:22 CEST"), "2026-10-22T09:14:22Z")

    def test_xml_entities_and_missing_dates_cannot_enter_data(self):
        with self.assertRaises(ValueError):
            parse_rss(b'<!DOCTYPE rss [<!ENTITY x "unsafe">]><rss/>', SOURCES[1])
        with self.assertRaises(ValueError):
            parse_rss(b'<rss><channel><item><title>Critical issue</title><link>https://example.com/</link><description>test</description></item></channel></rss>', SOURCES[1])

    def test_chrome_skips_nonsecurity_announcements(self):
        data = b'''<feed xmlns="http://www.w3.org/2005/Atom">
          <entry><title>Chrome Dev update</title><content>CVE-2026-12345 security fixes</content><published>2026-10-22T10:00:00Z</published><link href="https://example.com/dev"/></entry>
          <entry><title>Stable Channel Update</title><content>This release includes High CVE-2026-12345 security fixes.</content><published>2026-10-21T10:00:00Z</published><link href="https://example.com/stable"/></entry>
        </feed>'''
        events = parse_atom(data, SOURCES[2])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["severity"], "high")
        self.assertEqual(events[0]["sources"][0]["url"], "https://example.com/stable")

    def test_full_identifiers_and_risk_evidence_survive_display_truncation(self):
        # The previous collector cut a real CVE-2026-113092 at the description
        # limit and incorrectly produced CVE-2026-1130 as an identifier.
        body = "A " * 1193 + "CVE-2026-113092 Critical security fix. The vendor confirmed active exploitation."
        event = feed_event(SOURCES[2], "Stable security update", body,
                           "https://example.com/stable", "2026-10-21")
        self.assertEqual(event["cves"], ["CVE-2026-113092"])
        self.assertEqual(event["severity"], "critical")
        self.assertTrue(event["exploited"])
        self.assertNotIn("CVE-2026-1130", event["description"])
        self.assertLessEqual(len(event["description"]), 2400)

    def test_explicit_exploitation_includes_confirmations_but_not_negations(self):
        self.assertTrue(explicit_exploitation("Citrix has confirmed active exploitation of these 2 critical vulnerabilities in the wild."))
        self.assertTrue(explicit_exploitation("The vendor confirmed active exploitation in the wild."))
        self.assertTrue(explicit_exploitation("The Cisco PSIRT is aware of active exploitation of this vulnerability."))
        self.assertFalse(explicit_exploitation("The vendor has not confirmed active exploitation."))
        self.assertFalse(explicit_exploitation("The vendor is not aware of active exploitation."))
        self.assertFalse(explicit_exploitation("Attackers may be exploiting this vulnerability."))

    def test_outage_preserves_records_and_original_success_time(self):
        original = parse_kev(kev_payload())
        prior = {"events": original, "sources": [{"id": "cisa-kev", "lastSuccessAt": "2026-10-22T08:00:00Z"}]}
        def unavailable(_):
            raise OSError("offline")
        events, source = collect_source(SOURCES[0], prior, "2026-10-23T08:00:00Z", fetcher=unavailable)
        self.assertEqual(events, original)
        self.assertEqual(source["status"], "error")
        self.assertEqual(source["lastSuccessAt"], "2026-10-22T08:00:00Z")
        self.assertEqual(source["lastAttemptAt"], "2026-10-23T08:00:00Z")
        self.assertIn("last available", source["error"])

    def test_snapshot_rejects_executable_links_and_counts_match_limit(self):
        events, source = collect_source(SOURCES[0], {}, "2026-10-23T08:00:00Z", fetcher=lambda _: kev_payload())
        data = assemble([(events, source)], [], "2026-10-23T08:00:00Z", 40)
        validate_snapshot(data)
        bad = deepcopy(data)
        bad["events"][0]["sources"][0]["url"] = "javascript:alert(1)"
        with self.assertRaises(ValueError):
            validate_snapshot(bad)
        extra = deepcopy(events[0])
        extra["id"] = "test-extra"
        data = assemble([(events + [extra], source)], [], "2026-10-23T08:00:00Z", 1)
        self.assertEqual(data["sources"][0]["itemCount"], 1)
        validate_snapshot(data)

    def test_news_does_not_infer_risk_from_a_headline(self):
        news = feed_event(self.source("the-hacker-news"), "High stakes: Critical industry discussion",
                          "A " * 100, "https://example.com/news", "2026-10-22")
        self.assertEqual(news["category"], "News")
        self.assertEqual(news["stream"], "news")
        self.assertEqual(news["severity"], "unknown")
        self.assertFalse(news["exploited"])
        self.assertEqual(news["sources"][0]["kind"], "secondary")
        self.assertLessEqual(len(news["description"].split()), 24)

    def test_news_country_mentions_are_conservative_and_do_not_change_risk(self):
        source = self.source("the-hacker-news")
        for title, body in (("Report covers bangladesh", "Regional update."),
                            ("BANGLADESHI organizations in research", "Regional update."),
                            ("Regional research", "বাংলাদেশ নিয়ে প্রকাশিত হালনাগাদ তথ্য।")):
            with self.subTest(title=title, body=body):
                event = feed_event(source, title, body, "https://example.com/update", "2026-10-22")
                self.assertIn("Bangladesh", event["geography"])
                self.assertEqual(event["bangladeshScope"], "coverage")
                self.assertIn("does not establish a confirmed incident in Bangladesh", event["evidenceNote"])
                self.assertEqual(event["severity"], "unknown")
                self.assertFalse(event["exploited"])
        for title, body in (("BD research team", "Global update."),
                            ("Embedded database research", "A global update about CBD."),
                            ("Global update", "word " * 30 + "Bangladesh")):
            with self.subTest(title=title, body=body):
                event = feed_event(source, title, body, "https://example.com/update", "2026-10-22")
                self.assertEqual(event["geography"], [])
                self.assertIsNone(event["bangladeshScope"])
        local = feed_event(self.source("cirt-news"), "Bangladesh cyber exercise", "Training update.",
                           "https://www.cirt.gov.bd/news/exercise", "2026-10-22")
        self.assertEqual(local["bangladeshScope"], "local-activity")
        self.assertNotIn("coverage tag", local["evidenceNote"])
        national_source = dict(source, geography=["Bangladesh"], bangladeshScope="national-advisory")
        national = feed_event(national_source, "Bangladesh bulletin", "National guidance.",
                              "https://example.com/bulletin", "2026-10-22")
        self.assertEqual(national["bangladeshScope"], "national-advisory")

    def test_crowdstrike_date_and_missing_summary_are_supported(self):
        payload = b'''<rss><channel><item><title>Research update</title>
          <link>https://www.crowdstrike.com/en-us/blog/update/</link>
          <pubDate>Oct 21, 2026 00:00:00-0500</pubDate></item></channel></rss>'''
        event = parse_rss(payload, self.source("crowdstrike"))[0]
        self.assertEqual(event["publishedAt"], "2026-10-21T05:00:00Z")
        self.assertIn("without a feed summary", event["description"])

    def test_cybernews_keeps_headline_attribution_link_and_date_without_article_text(self):
        payload = b'''<rss><channel><item><title>Critical PHP update CVE-2026-12345</title>
          <link>https://cybernews.com/security/example-update/</link>
          <description>Article-only text mentioning Bangladesh and CVE-2026-99999.</description>
          <pubDate>Fri, 23 Oct 2026 14:15:27 +0000</pubDate></item></channel></rss>'''
        event = parse_rss(payload, self.source("cybernews"))[0]
        self.assertEqual(event["title"], "Critical PHP update CVE-2026-12345")
        self.assertEqual(event["publishedAt"], "2026-10-23T14:15:27Z")
        self.assertEqual(event["organization"], "Cybernews")
        self.assertEqual(event["sources"][0]["url"], "https://cybernews.com/security/example-update/")
        self.assertEqual(event["sources"][0]["kind"], "secondary")
        self.assertNotIn("Article-only text", json.dumps(event))
        self.assertEqual(event["cves"], ["CVE-2026-12345"])
        self.assertEqual(event["geography"], [])
        self.assertEqual(event["severity"], "unknown")
        self.assertEqual(event["stream"], "news")

    def test_expanded_news_publishers_keep_safe_rss_and_outage_semantics(self):
        timestamp = "2026-10-23T15:00:00Z"
        payload = b'''<rss><channel><item><title>Critical product vulnerability reported</title>
          <link>https://example.com/publication</link><description>A short published update.</description>
          <pubDate>Fri, 23 Oct 2026 12:00:00 +0000</pubDate></item></channel></rss>'''
        for identifier in ("cybernews", "bleepingcomputer", "securityweek", "help-net-security"):
            with self.subTest(publisher=identifier):
                source = self.source(identifier)
                events, registry = collect_source(source, {}, timestamp, fetcher=lambda _: payload)
                self.assertEqual(registry["status"], "ok")
                self.assertEqual(registry["kind"], "secondary")
                self.assertEqual(events[0]["sourceId"], identifier)
                self.assertEqual(events[0]["severity"], "unknown")
                self.assertFalse(events[0]["exploited"])
                previous = {"events": events, "sources": [registry]}
                def unavailable(_):
                    raise OSError("offline")
                retained, failed = collect_source(source, previous, "2026-10-23T15:30:00Z", fetcher=unavailable)
                self.assertEqual(retained, events)
                self.assertEqual(failed["lastSuccessAt"], timestamp)
                self.assertEqual(failed["status"], "error")

    def test_php_xhtml_and_permanent_article_link_are_preserved(self):
        payload = b'''<feed xmlns="http://www.w3.org/2005/Atom"><entry>
          <title>PHP update</title><id>https://www.php.net/archive/2026.php#release</id>
          <published>2026-10-21T00:35:26+00:00</published><updated>2026-10-21T00:35:26+00:00</updated>
          <link rel="alternate" href="https://www.php.net/#release"/>
          <content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml"><p>A security update.</p><p>Review the release notes.</p></div></content>
          </entry></feed>'''
        event = parse_atom(payload, self.source("php"))[0]
        self.assertIn("A security update.", event["summary"])
        self.assertEqual(event["sources"][0]["url"], "https://www.php.net/archive/2026.php#release")
        self.assertEqual(event["stream"], "news")
        with self.assertRaises(ValueError):
            parse_atom(payload.replace(b'<published>2026-10-21T00:35:26+00:00</published>', b''), self.source("php"))

    def test_newspaper_filter_matches_english_cyber_headlines_only(self):
        for title in ("A cyber alert", "CYBERSECURITY update", "Cybercrime investigation", "New cyber-attacks reported", "Cyberattack reported"):
            with self.subTest(title=title):
                self.assertTrue(cyber_headline(title))
        for title in ("Security update", "Noncyber business report", "A cyber সংবাদ", "সাইবার নিরাপত্তা", "<script>cyber</script>Regional news"):
            with self.subTest(title=title):
                self.assertFalse(cyber_headline(title))
        payload = '''<rss><channel>
          <item><title>Ordinary headline</title><description>A cyberattack mentioned only in the body.</description><link>https://www.dhakatribune.com/business/123/body-only</link><pubDate>Fri, 23 Oct 2026 12:00:00 +0600</pubDate></item>
          <item><title>Cybercrime investigation</title><description>Article body must not be republished.</description><link>https://www.dhakatribune.com/bangladesh/124/cybercrime</link><pubDate>Fri, 23 Oct 2026 12:00:00 +0600</pubDate></item>
          <item><title>Cyber security সংবাদ</title><link>https://www.dhakatribune.com/bangladesh/125/bangla</link><pubDate>Fri, 23 Oct 2026 12:00:00 +0600</pubDate></item>
          <item><title>Cyber external link</title><link>https://other.example/bangladesh/126/cybercrime</link><pubDate>Fri, 23 Oct 2026 12:00:00 +0600</pubDate></item>
          </channel></rss>'''.encode()
        events = parse_rss(payload, self.source("dhaka-tribune"))
        self.assertEqual([event["title"] for event in events], ["Cybercrime investigation"])
        event = events[0]
        self.assertEqual(event["publishedAt"], "2026-10-23T06:00:00Z")
        self.assertEqual(event["stream"], "news")
        self.assertEqual(event["bangladeshScope"], "coverage")
        self.assertEqual(event["sources"][0]["kind"], "secondary")
        self.assertIn("not the location of affected victims", event["evidenceNote"])
        self.assertNotIn("Article body must not", json.dumps(event))
        self.assertNotIn("Cybernews", event["description"])

    def test_newspaper_rss_empty_match_is_healthy_but_invalid_document_is_not(self):
        source = self.source("dhaka-tribune")
        payload = b'''<rss><channel><item><title>A business update</title>
          <link>https://www.dhakatribune.com/business/123/update</link><description>cyber appears only here</description>
          <pubDate>Fri, 23 Oct 2026 12:00:00 +0600</pubDate></item></channel></rss>'''
        events, registry = collect_source(source, {}, "2026-10-23T10:00:00Z", fetcher=lambda _: payload)
        self.assertEqual(events, [])
        self.assertEqual(registry["status"], "ok")
        self.assertEqual(registry["lastSuccessAt"], "2026-10-23T10:00:00Z")
        self.assertEqual(parse_rss(b"<rss><channel/></rss>", source), [])
        with self.assertRaises(ValueError):
            parse_rss(b"<html><body>Access denied</body></html>", source)
        with self.assertRaises(ValueError):
            parse_rss(b'<rss><channel><item><title>Cyber update</title><link>https://www.dhakatribune.com/business/123/update</link></item></channel></rss>', source)

    def test_newspaper_index_reads_headings_and_bounded_same_publisher_metadata(self):
        source = self.source("financial-express")
        base = "https://thefinancialexpress.com.bd/sci-tech/"
        payload = ('<nav><a href="/sci-tech/navigation-cyber">Cyber navigation</a></nav>'
                   '<h2><a href="https://attacker.example/sci-tech/cyber">Cyber external</a></h2>'
                   '<h2><a href="/sci-tech/ordinary">Business update</a></h2><p>cyber in body only</p>' +
                   ''.join(f'<a href="/sci-tech/cyber-{i}"><h3>Cyber report {i}</h3></a>' for i in range(10))).encode()
        requested = []
        def metadata(url):
            requested.append(url)
            return b'''<meta property="og:title" content="Cyber report">
              <meta property="article:published_time" content="2026-10-22T20:25:12+06:00">
              <meta property="article:modified_time" content="2026-10-22T20:30:54+06:00">
              <article>Unstored article body.</article>'''
        events = parse_newspaper(payload, source, fetcher=metadata)
        self.assertEqual(len(events), 6)
        self.assertEqual(set(requested), {base + "cyber-" + str(i) for i in range(6)})
        self.assertEqual(events[0]["publishedAt"], "2026-10-22T14:25:12Z")
        self.assertEqual(events[0]["updatedAt"], "2026-10-22T14:30:54Z")
        self.assertNotIn("Unstored article body", json.dumps(events))
        self.assertTrue(all(event["severity"] == "unknown" and not event["exploited"] for event in events))

    def test_daily_star_date_only_publication_is_not_given_an_invented_time(self):
        source = self.source("daily-star")
        url = "https://www.thedailystar.net/business/news/cyber-report-1234567"
        schema = {"@graph": [{"@type": "NewsArticle", "headline": "Cyber report", "mainEntityOfPage": url}]}
        payload = ('<script type="application/ld+json">' + json.dumps(schema) + '</script>'
                   '<span>Published : 23 October 2026</span><span>Updated : 23 October 2026, 19:33</span>'
                   '<p>Article body is not an excerpt.</p>').encode()
        event = parse_newspaper_article(payload, source, url)
        self.assertEqual(event["publishedAt"], "2026-10-23")
        self.assertEqual(event["updatedAt"], "2026-10-23")
        self.assertEqual(event["sources"][0]["publishedAt"], "2026-10-23")
        self.assertEqual(event["timeline"][0]["date"], "2026-10-23")
        self.assertIn("only its calendar date", event["evidenceNote"])
        self.assertNotIn("Article body is not", json.dumps(event))
        self.assertEqual(newspaper_date("2026-10-22T19:30:00"), "2026-10-22")
        with self.assertRaises(ValueError):
            parse_newspaper_article(b'<meta property="og:title" content="Cyber report"><meta property="article:modified_time" content="2026-10-23T12:00:00Z">', source, url)

    def test_newspaper_index_zero_matches_retains_recent_headlines_without_redating(self):
        source = self.source("daily-star")
        recent = feed_event(source, "Cyber report", "", "https://www.thedailystar.net/business/news/cyber-report-1234567", "2026-10-22")
        old = feed_event(source, "Old cyber report", "", "https://www.thedailystar.net/business/news/old-cyber-report-1234560", "2026-08-01")
        previous = {"events": [recent, old], "sources": [{"id": source["id"], "lastSuccessAt": "2026-10-22T13:00:00Z"}]}
        payload = b'<h5><a href="/business/news/business-report-1234569">Business report</a></h5><p>cyber in body</p>'
        events, registry = collect_source(source, previous, "2026-10-23T13:00:00Z", fetcher=lambda _: payload)
        self.assertEqual(events, [recent])
        self.assertEqual(registry["status"], "ok")
        self.assertEqual(registry["lastSuccessAt"], "2026-10-23T13:00:00Z")
        self.assertEqual(events[0]["publishedAt"], recent["publishedAt"])
        validate_snapshot(assemble([(events, registry)], [], "2026-10-23T13:00:00Z", 300))
        with self.assertRaises(ValueError):
            parse_newspaper(b"<html><h1>Access denied</h1></html>", source, fetcher=lambda _: b"")

    def test_newspaper_partial_collection_keeps_verified_items_and_reports_incomplete_check(self):
        source = self.source("tbs")
        prior_event = feed_event(source, "Prior cyber report", "", "https://www.tbsnews.net/tech/prior-cyber-123", "2026-10-21")
        previous = {"events": [prior_event], "sources": [{"id": source["id"], "lastSuccessAt": "2026-10-22T13:00:00Z"}]}
        index = b'<h3><a href="/tech/new-cyber-124">New cyber report</a></h3><h3><a href="/tech/unavailable-cyber-125">Cyber report</a></h3>'
        def fetcher(url):
            if url == source["feedUrls"][0]:
                return index
            if "unavailable" in url:
                raise OSError("offline")
            return b'<meta property="og:title" content="New cyber report"><meta property="article:published_time" content="2026-10-23T12:00:00+06:00">'
        events, registry = collect_source(source, previous, "2026-10-23T13:00:00Z", fetcher=fetcher)
        self.assertEqual({event["title"] for event in events}, {"New cyber report", "Prior cyber report"})
        self.assertEqual(registry["status"], "error")
        self.assertEqual(registry["lastSuccessAt"], "2026-10-22T13:00:00Z")
        self.assertEqual(registry["lastAttemptAt"], "2026-10-23T13:00:00Z")
        self.assertIn("last complete success time is unchanged", registry["error"])
        def unavailable(_):
            raise OSError("offline")
        retained, failed = collect_source(source, previous, "2026-10-23T13:30:00Z", fetcher=unavailable)
        self.assertEqual(retained, [prior_event])
        self.assertEqual(failed["lastSuccessAt"], "2026-10-22T13:00:00Z")
        self.assertEqual(failed["status"], "error")

    def test_newspaper_links_and_redirects_remain_on_configured_https_host(self):
        source = self.source("daily-star")
        good = "https://www.thedailystar.net/business/news/cyber-report-1234567"
        self.assertEqual(newspaper_url(source, good + "?utm_source=feed#fragment"), good)
        for url in ("https://www.thedailystar.net.attacker.example/business/news/cyber-report-1234567",
                    "http://www.thedailystar.net/business/news/cyber-report-1234567",
                    "https://user:pass@www.thedailystar.net/business/news/cyber-report-1234567",
                    "https://www.thedailystar.net:8443/business/news/cyber-report-1234567", "https://www.thedailystar.net/search?t=cyber"):
            with self.subTest(url=url):
                self.assertIsNone(newspaper_url(source, url))
        redirect = PublisherRedirect(source["articleHost"])
        for destination in ("https://attacker.example/article", "http://www.thedailystar.net/article", "https://127.0.0.1/article"):
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                redirect.redirect_request(Request(good), None, 302, "Found", {}, destination)

    def test_cirt_date_only_cards_and_local_scope(self):
        payload = b'''<div class="post-item"><img src="/thumb.png"><div class="post-details">
          <a class="post-title" href="/advisories/example">National alert</a>
          <div class="post-subtitle">A published advisory excerpt.</div><div class="post-time">22-Oct-2026 11:00:00</div>
          </div></div><div class="post-item"><a class="post-title" href="https://other.example/advisories/bad">Other site</a>
          <div class="post-subtitle">Ignored.</div><div class="post-time">22-Oct-2026 12:00:00</div></div>'''
        events = parse_cirt(payload, self.source("cirt-advisories"))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["publishedAt"], "2026-10-22")
        self.assertEqual(event["sources"][0]["publishedAt"], "2026-10-22")
        self.assertEqual(event["geography"], ["Bangladesh"])
        self.assertEqual(event["bangladeshScope"], "national-advisory")
        self.assertIn("does not specify a timezone", event["evidenceNote"])

    def test_cirt_activities_filter_personnel_notices_in_english_and_bengali(self):
        source = self.source("cirt-news")
        titles = [
            "We are mourning for our co-worker Khondokar Aminul Islam",
            "Appointment of a Cyber Security Officer",
            "সাইবার নিরাপত্তা কর্মকর্তার মৃত্যুতে শোক প্রকাশ",
            "কর্মকর্তাদের বদলি ও পদোন্নতি",
            "CIRT welcomes MIST internship participants",
            "Five-Day Advanced Cyber Security Training",
            "Seminar Held on National ICT & Cybersecurity Rating System",
            "সাইবার ড্রিল ২০২৩ চূড়ান্ত পর্ব অনুষ্ঠিত",
            "আর্থিক প্রতিষ্ঠানের জন্য নিরাপত্তা প্রশিক্ষণ ও কর্মশালা",
            "Press Release: Alert on Cyber Threats",
        ]
        def cards(values):
            return "".join(f'<div class="post-item"><a class="post-title" href="/news/item-{i}">{title}</a>'
                           '<div class="post-subtitle">A publisher activity summary.</div>'
                           '<div class="post-time">22-Oct-2026 11:00:00</div></div>'
                           for i, title in enumerate(values)).encode("utf-8")
        events = parse_cirt(cards(titles), source)
        self.assertEqual([event["title"] for event in events], titles[4:])
        self.assertTrue(all(event["publishedAt"] == "2026-10-22" for event in events))
        self.assertTrue(all(event["bangladeshScope"] == "local-activity" for event in events))
        self.assertEqual(parse_cirt(cards(titles[:4]), source), [])

    def test_unchanged_pull_advances_check_but_not_database_update(self):
        first_time, next_time = "2026-10-22T08:00:00Z", "2026-10-23T08:00:00Z"
        result = collect_source(SOURCES[0], {}, first_time, fetcher=lambda _: kev_payload())
        before = assemble([result], [], first_time, 200)
        next_result = collect_source(SOURCES[0], before, next_time, fetcher=lambda _: kev_payload())
        after = assemble([next_result], [], next_time, 200, previous=before)
        self.assertEqual(after["databaseUpdatedAt"], first_time)
        self.assertEqual(after["lastCheckedAt"], next_time)
        self.assertEqual(after["sources"][0]["lastSuccessAt"], next_time)
        validate_snapshot(after)

    def test_changed_content_updates_database_and_failure_does_not(self):
        first_time, next_time, failed_time = "2026-10-21T08:00:00Z", "2026-10-22T08:00:00Z", "2026-10-23T08:00:00Z"
        initial = collect_source(SOURCES[0], {}, first_time, fetcher=lambda _: kev_payload())
        before = assemble([initial], [], first_time, 200)
        changed_payload = kev_payload().replace(b"Apply the vendor update.", b"Apply the revised vendor update.")
        changed = collect_source(SOURCES[0], before, next_time, fetcher=lambda _: changed_payload)
        updated = assemble([changed], [], next_time, 200, previous=before)
        self.assertEqual(updated["databaseUpdatedAt"], next_time)
        def unavailable(_):
            raise OSError("unavailable")
        failed = collect_source(SOURCES[0], updated, failed_time, fetcher=unavailable)
        retained = assemble([failed], [], failed_time, 200, previous=updated)
        self.assertEqual(retained["databaseUpdatedAt"], next_time)
        self.assertEqual(retained["lastCheckedAt"], failed_time)
        self.assertEqual(retained["sources"][0]["lastSuccessAt"], next_time)
        self.assertEqual(retained["events"], updated["events"])

    def test_bangladesh_curated_replaces_same_article_without_duplicate(self):
        source = self.source("cirt-advisories")
        auto = feed_event(source, "National warning", "Original excerpt.", "https://www.cirt.gov.bd/advisories/example", "2026-10-22")
        reviewed = deepcopy(auto)
        reviewed.update(id="bd-reviewed", description="Reviewed local context.", severity="high")
        registry = {"id": source["id"], "name": source["name"], "url": source["url"], "kind": "primary", "group": "bangladesh", "status": "ok", "lastSuccessAt": "2026-10-23T08:00:00Z", "lastAttemptAt": "2026-10-23T08:00:00Z", "itemCount": 1}
        data = assemble([([auto], registry)], [], "2026-10-23T08:00:00Z", 200, bangladesh_curated=[reviewed])
        self.assertEqual(len(data["events"]), 1)
        self.assertEqual(data["events"][0]["sourceId"], "bangladesh-curated")
        self.assertEqual(data["events"][0]["description"], "Reviewed local context.")
        self.assertEqual(data["sources"][0]["itemCount"], 0)
        self.assertEqual(data["sources"][-1]["itemCount"], 1)
        validate_snapshot(data)

    def test_source_failures_do_not_borrow_another_publishers_records(self):
        original = feed_event(self.source("the-hacker-news"), "Publication", "A short excerpt.", "https://example.com/news", "2026-10-22")
        def unavailable(_):
            raise OSError("offline")
        result, source = collect_source(self.source("crowdstrike"), {"events": [original]}, "2026-10-23T08:00:00Z", fetcher=unavailable)
        self.assertEqual(result, [])
        self.assertIsNone(source["lastSuccessAt"])
        self.assertEqual(source["group"], "news")


if __name__ == "__main__":
    unittest.main()
