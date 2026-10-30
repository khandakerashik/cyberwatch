"""Article-level relevance through collection, retention and source budgets."""
from copy import deepcopy
from html import escape
import unittest

from scripts.fetch_feeds import (
    SOURCES, annotate_news_record, assemble, collect_source, fair_limit,
    news_event, parse_atom, parse_rss, retain_source_records,
)

STAMP = "2026-10-30T18:00:00Z"
OLD_CHECK = "2026-10-29T18:00:00Z"
GM_TITLE = "GM cracks the petty cash box for multistate driver tracking settlement"
GM_BODY = "The settlement concerns driver location tracking and the sale of driving telemetry without consent."
BREACH_TITLE = "Company agrees to settlement after customer data breach"
BREACH_BODY = "Attackers stole customer records after gaining unauthorized access to the company's servers."


def source(identifier="the-register", **changes):
    item = deepcopy(next(item for item in SOURCES if item["id"] == identifier))
    item.update(changes)
    return item


def news(src, title, body, slug="story", date="2026-10-30T08:00:00Z"):
    return news_event(src, title, body, "https://news.example.org/" + slug, date, date)


def rss(items):
    records = []
    for index, (title, body) in enumerate(items):
        records.append("<item><title>" + escape(title) + "</title><link>https://news.example.org/story-" +
                       str(index) + "</link><pubDate>Fri, 30 Oct 2026 08:00:00 GMT</pubDate><description>" +
                       escape(body) + "</description></item>")
    return ("<rss><channel>" + "".join(records) + "</channel></rss>").encode()


def registry(src, count):
    return {"id": src["id"], "name": src["name"], "url": src["url"],
            "kind": src.get("kind", "secondary"), "group": src.get("group", "news"),
            "status": "ok", "lastSuccessAt": STAMP, "lastAttemptAt": STAMP,
            "itemCount": count, "error": None}


class NewsRelevanceCollectionTests(unittest.TestCase):
    def test_specialist_publisher_has_no_newsboard_relevance_exemption(self):
        for identifier in ("the-register", "the-hacker-news", "cybernews", "securityweek", "dark-reading"):
            with self.subTest(source=identifier):
                src = source(identifier, keywordFilter=False)
                events = parse_rss(rss([(GM_TITLE, GM_BODY), (BREACH_TITLE, BREACH_BODY)]), src)
                by_title = {event["title"]: event for event in events}
                # Broader Newsletters still retains the publisher update.
                self.assertIn(GM_TITLE, by_title)
                self.assertFalse(by_title[GM_TITLE]["newsRelevance"]["relevant"])
                self.assertEqual(by_title[GM_TITLE]["newsRelevance"]["version"], 1)
                self.assertTrue(by_title[BREACH_TITLE]["newsRelevance"]["relevant"])

    def test_source_boilerplate_and_stale_keywords_do_not_grant_relevance(self):
        src = source()
        event = news(src, GM_TITLE, GM_BODY)
        event["matchedKeywords"] = ["cybersecurity", "malware"]
        event["tags"] = ["Security", "Cybersecurity", "Threat intelligence"]
        event["recommendations"] = ["Review cybersecurity exposure and monitor for malware."]
        event["evidenceNote"] = "Security reporting should be verified against cyberattack evidence."
        event["newsRelevance"] = {"version": 0, "relevant": True, "matchedKeywords": ["cybersecurity"], "reason": "Old publisher allowlist"}
        assessed = annotate_news_record(event, src)
        self.assertFalse(assessed["newsRelevance"]["relevant"])
        self.assertTrue(event["newsRelevance"]["relevant"], "Do not mutate previous snapshot data")

    def test_relevant_publisher_lead_is_considered_beyond_short_card_summary(self):
        src = source()
        event = news(src, "Company explains the disruption", "Operations were interrupted.")
        event["article"] = {"origin": "feed", "status": "excerpt", "paragraphs": [
            "The company says a ransomware attack encrypted its production servers."
        ], "images": [], "note": "Publisher excerpt."}
        self.assertTrue(annotate_news_record(event, src)["newsRelevance"]["relevant"])

    def test_retention_reassesses_existing_records_without_redating(self):
        src = source()
        event = news(src, GM_TITLE, GM_BODY, date="2026-10-29T08:00:00Z")
        event["newsRelevance"] = {"version": 0, "relevant": True, "matchedKeywords": ["cybersecurity"], "reason": "Old rule"}
        event["matchedKeywords"] = ["cybersecurity"]
        previous = {"events": [event]}
        kept = retain_source_records(src, [], previous, STAMP)
        self.assertEqual(len(kept), 1, "Broader publisher update remains available to Newsletters")
        self.assertFalse(kept[0]["newsRelevance"]["relevant"])
        self.assertEqual(kept[0]["publishedAt"], event["publishedAt"])
        self.assertTrue(previous["events"][0]["newsRelevance"]["relevant"])

    def test_outage_reassesses_retained_news_and_preserves_last_success(self):
        for identifier in ("the-register", "cirt-news"):
            with self.subTest(source=identifier):
                src = source(identifier)
                irrelevant = news(src, GM_TITLE, GM_BODY)
                irrelevant.pop("newsRelevance", None)
                relevant = news(src, BREACH_TITLE, BREACH_BODY, slug="breach")
                previous = {"events": [irrelevant, relevant], "sources": [dict(registry(src, 2), lastSuccessAt=OLD_CHECK)]}
                def offline(_url):
                    raise OSError("Publisher temporarily unavailable")
                events, channel = collect_source(src, previous, STAMP, fetcher=offline)
                by_title = {event["title"]: event for event in events}
                self.assertFalse(by_title[GM_TITLE]["newsRelevance"]["relevant"])
                self.assertTrue(by_title[BREACH_TITLE]["newsRelevance"]["relevant"])
                self.assertEqual(channel["status"], "error")
                self.assertEqual(channel["lastSuccessAt"], OLD_CHECK)

    def test_rss_budget_prioritizes_later_security_article(self):
        src = source(maxItems=1)
        events = parse_rss(rss([(GM_TITLE, GM_BODY), (BREACH_TITLE, BREACH_BODY)]), src, limit=1)
        self.assertEqual([item["title"] for item in events], [BREACH_TITLE])

    def test_atom_budget_prioritizes_later_security_article(self):
        src = source(maxItems=1)
        entries = "".join("<entry><title>" + escape(title) + "</title><link href=\"https://news.example.org/atom-" +
                          str(index) + "\"/><published>2026-10-30T08:00:00Z</published><summary>" + escape(body) +
                          "</summary></entry>" for index, (title, body) in enumerate([(GM_TITLE, GM_BODY), (BREACH_TITLE, BREACH_BODY)]))
        events = parse_atom(("<feed xmlns=\"http://www.w3.org/2005/Atom\">" + entries + "</feed>").encode(), src, limit=1)
        self.assertEqual([item["title"] for item in events], [BREACH_TITLE])

    def test_retention_and_snapshot_budgets_prioritize_security_articles(self):
        src = source(maxItems=1)
        newer = news(src, GM_TITLE, GM_BODY, date="2026-10-30T12:00:00Z")
        older = news(src, BREACH_TITLE, BREACH_BODY, slug="breach", date="2026-10-29T08:00:00Z")
        self.assertEqual(retain_source_records(src, [newer, older], {}, STAMP)[0]["id"], older["id"])
        self.assertEqual(fair_limit([newer, older], 1)[0]["id"], older["id"])

    def test_assembly_reassesses_legacy_news_and_preserves_other_streams(self):
        src = source()
        irrelevant = news(src, GM_TITLE, GM_BODY)
        irrelevant.pop("newsRelevance", None)
        irrelevant["matchedKeywords"] = ["cybersecurity"]
        advisory = dict(news(src, "Official security bulletin", "A product security update."),
                        id="vendor-advisory", stream="intelligence", category="Advisory")
        advisory.pop("newsRelevance", None)
        snapshot = assemble([([irrelevant, advisory], registry(src, 2))], [], STAMP, 30)
        by_id = {event["id"]: event for event in snapshot["events"]}
        self.assertFalse(by_id[irrelevant["id"]]["newsRelevance"]["relevant"])
        self.assertNotIn("newsRelevance", by_id[advisory["id"]])

    def test_current_catalogue_keywords_survive_assembly(self):
        src = source(additionalKeywords=["TelemetrySentry"], keywordFilter=True)
        event = parse_rss(rss([("TelemetrySentry release bulletin", "The project published its new bulletin.")]), src)[0]
        snapshot = assemble([([event], registry(src, 1))], [], STAMP, 30, source_configs=[src])
        self.assertTrue(snapshot["events"][0]["newsRelevance"]["relevant"])
        self.assertIn("TelemetrySentry", snapshot["events"][0]["newsRelevance"]["matchedKeywords"])

    def test_filtered_feed_with_no_current_match_remains_healthy(self):
        src = source("bbc-world")
        events, channel = collect_source(src, {}, STAMP, fetcher=lambda _: rss([(GM_TITLE, GM_BODY)]))
        self.assertEqual(events, [])
        self.assertEqual(channel["status"], "ok")


if __name__ == "__main__":
    unittest.main()
