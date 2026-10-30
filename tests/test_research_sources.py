"""Research publications, edition observations and failure-retention boundaries."""
from copy import deepcopy
from html import escape
import json
from pathlib import Path
import tempfile
import unittest

from scripts.fetch_feeds import (RESEARCH_SOURCES, RESEARCH_WATCHES, assemble, collect_source,
                                 parse_atom, parse_rss, retain_source_records)
from scripts.research_sources import (RESEARCH_PATH, collect_page_watch, load_research_catalogue,
                                      parse_edition_page, release_status, release_watches,
                                      research_subject_matches, watch_content_fingerprint)
from scripts.validate_data import validate_event, validate_snapshot

STAMP = "2026-10-30T18:00:00Z"
LATER = "2026-10-31T18:00:00Z"


def source(identifier):
    return deepcopy(next(item for item in RESEARCH_SOURCES if item["id"] == identifier))


def watch(identifier):
    return deepcopy(next(item for item in RESEARCH_WATCHES if item["id"] == identifier))


def atom(entries):
    body = "".join('<entry><title>' + escape(title) + '</title><link href="https://github.com/OWASP/ASVS/releases/tag/' + str(index) + '"/>' +
                   '<updated>' + updated + '</updated><content type="html">&lt;p&gt;Release notes.&lt;/p&gt;</content></entry>'
                   for index, (title, updated) in enumerate(entries))
    return ('<feed xmlns="http://www.w3.org/2005/Atom">' + body + '</feed>').encode()


def rss(title, body):
    return ('<rss><channel><item><title>' + escape(title) + '</title><description>' + escape(body) +
            '</description><link>https://research.example.org/story</link><pubDate>Fri, 30 Oct 2026 08:00:00 GMT</pubDate></item></channel></rss>').encode()


def page_fetch(markup):
    def fetch(url, hosts, **kwargs):
        return markup, url, "text/html; charset=utf-8"
    return fetch


class ResearchSourcesTests(unittest.TestCase):
    def test_catalogue_has_primary_sources_and_explicit_edition_watches(self):
        feeds, watches = load_research_catalogue()
        self.assertEqual(len(feeds), 22)
        self.assertEqual(len(watches), 6)
        self.assertTrue({"research-owasp-asvs", "research-owasp-mastg", "research-owasp-masvs", "research-portswigger", "research-mitre"} <= {item["id"] for item in feeds})
        self.assertTrue(all(item["group"] == "research" and item["kind"] == "primary" for item in feeds))
        self.assertNotIn("https://github.com/OWASP/Top10/releases.atom", [url for item in feeds for url in item["feedUrls"]])

    def test_expanded_channels_preserve_primary_source_and_reuse_boundaries(self):
        feeds, _ = load_research_catalogue()
        by_id = {item["id"]: item for item in feeds}
        for identifier in ("research-zap-blog", "research-doyensec", "research-microsoft-ti", "research-checkpoint"):
            with self.subTest(source=identifier):
                self.assertTrue(by_id[identifier]["learningFilter"])
                self.assertFalse(by_id[identifier]["articlePolicy"]["allowFullText"])
        for identifier in ("research-zap-releases", "research-sigma", "research-garak", "research-mobsf"):
            with self.subTest(source=identifier):
                self.assertEqual(by_id[identifier]["learning"]["kind"], "tool")
                self.assertFalse(by_id[identifier]["watchRelease"])
        for identifier in ("research-owasp-wstg", "research-owasp-asvs", "research-owasp-mastg", "research-owasp-masvs"):
            policy = by_id[identifier]["articlePolicy"]
            self.assertTrue(policy["allowFullText"])
            self.assertFalse(policy["allowPageFetch"])
            self.assertIn("CC BY-SA 4.0", policy["license"])

    def test_practitioner_guidance_and_forensics_survive_subject_filter(self):
        src = source("research-zap-blog")
        for title in ("View, edit, and replay your recorded Zest scripts", "Forensic AWS EKS: data sources and investigation", "Understanding Active Directory trust", "Investigating an infostealer campaign"):
            with self.subTest(title=title):
                self.assertTrue(research_subject_matches(src, title, "Original technical article."))
        self.assertFalse(research_subject_matches(src, "Join us at our company anniversary", "Our testing tools help security research."))

    def test_release_titles_are_not_dropped_by_news_keyword_filter(self):
        events = parse_atom(atom([("v5.0.0", "2025-05-30T10:00:00Z")]), source("research-owasp-asvs"))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["learning"]["kind"], "release")
        self.assertEqual(event["learning"]["dateBasis"], "source-updated")
        self.assertEqual(event["publishedAt"], "2025-05-30T10:00:00Z")
        self.assertNotIn("newsRelevance", event)
        self.assertIn("rather than a separate", event["evidenceNote"])
        self.assertEqual(event["timeline"][0]["title"], "Source feed updated")
        validate_event(event)

    def test_draft_and_prerelease_labels_are_not_published_standard_claims(self):
        for title, expected in (("Bleeding Edge", "draft"), ("20230928-Prerelease", "prerelease"),
                                ("v1.0.0-rc1", "prerelease"), ("v5.0.0", "published"), ("nightly build", "draft")):
            with self.subTest(title=title):
                self.assertEqual(release_status(title), expected)

    def test_official_practice_tools_preserve_prerelease_status(self):
        for identifier in ("research-juice-shop", "research-crapi"):
            src = source(identifier)
            events = parse_atom(atom([("v1.5.0-rc1", STAMP)]), src)
            self.assertEqual(events[0]["learning"]["kind"], "tool")
            self.assertEqual(events[0]["learning"]["releaseStatus"], "prerelease")
            self.assertEqual(events[0]["learning"]["dateBasis"], "source-updated")
            self.assertFalse(src["watchRelease"])

    def test_broad_research_blogs_need_technical_subject_evidence(self):
        src = source("research-trailofbits")
        for title, body in (("We are hiring", "Security research is part of the job."),
                            ("Company announces new funding round", "Work includes vulnerability research."),
                            ("GM cracks the petty cash box for multistate driver tracking settlement", "The company compromised consumer privacy.")):
            with self.subTest(title=title):
                self.assertFalse(research_subject_matches(src, title, body))
                events, registry = collect_source(src, {}, STAMP, fetcher=lambda _url: rss(title, body))
                self.assertEqual(events, [])
                self.assertEqual(registry["status"], "ok")
        self.assertTrue(research_subject_matches(src, "Scalable Vector Grief", "This research explains a browser vulnerability and a testing method."))
        self.assertTrue(research_subject_matches(src, "Webinar: authentication testing methods", "Practitioner workshop."))

    def test_signed_policy_calls_are_excluded_but_real_technical_announcements_remain(self):
        src = source("research-specterops")
        self.assertFalse(research_subject_matches(src, "Why SpecterOps Signed OpenAI’s Call for Collective Cyber Defense", "Our security research informs this pledge."))
        self.assertFalse(research_subject_matches(src, "Company endorses an open letter on cyber policy", "The company studies authentication vulnerabilities."))
        self.assertTrue(research_subject_matches(src, "Signed, Sealed, and Relayed, NTLM-style: Bypassing LDAP Signing Through Reauthentication", "Authentication protocol research."))
        self.assertTrue(research_subject_matches(source("research-owasp-genai"), "OWASP GenAI Security Project Unveils 2026 Top 10 for LLM Applications and Sponsors", "Official project announcement."))

    def test_explicit_guide_titles_receive_format_label_without_claiming_novelty(self):
        src = source("research-bishopfox")
        for title in ("Responder Guidance for PHP vulnerabilities", "Rust Testing Handbook", "Authentication testing tutorial", "Step-by-step API security assessment", "CTEM 101: Validating security controls"):
            with self.subTest(title=title):
                event = parse_rss(rss(title, "Security testing and vulnerability research."), src)[0]
                self.assertEqual(event["learning"]["kind"], "guide")
                self.assertEqual(event["learning"]["releaseStatus"], "unknown")
        for title, body in (("Scalable Vector Grief", "A vulnerability research report with practical guidance."),
                            ("Guidewire authentication vulnerability", "A security research report.")):
            with self.subTest(title=title):
                event = parse_rss(rss(title, body), src)[0]
                self.assertEqual(event["learning"]["kind"], "research")
        release = parse_atom(atom([("Web Security Testing Guide v4.2", STAMP)]), source("research-owasp-wstg"))[0]
        self.assertEqual(release["learning"]["kind"], "release")

    def test_retention_reclassifies_metadata_and_keeps_old_published_standards(self):
        src = source("research-owasp-wstg")
        event = parse_atom(atom([("v4.2", "2020-12-03T00:00:00Z")]), src)[0]
        event["learning"]["kind"] = "tool"
        event["learning"]["releaseStatus"] = "draft"
        previous = {"events": [event]}
        result = retain_source_records(src, [], previous, STAMP)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["learning"]["kind"], "release")
        self.assertEqual(result[0]["learning"]["releaseStatus"], "published")
        self.assertEqual(result[0]["publishedAt"], "2020-12-03T00:00:00Z")
        self.assertEqual(event["learning"]["kind"], "tool", "Prior snapshot must not be mutated")

    def test_retention_rechecks_broad_feed_subjects(self):
        src = source("research-specterops")
        allowed = deepcopy(src)
        allowed["learningFilter"] = False
        event = parse_rss(rss("A conference registration reminder", "Meet our security team."), allowed)[0]
        self.assertEqual(retain_source_records(src, [], {"events": [event]}, STAMP), [])

    def test_page_parsers_use_actual_edition_markers_not_footer_years(self):
        examples = [
            ("watch-owasp-web", b'<h1>Redirecting to OWASP Top 10:2025</h1><a href="./2025/en/">Continue</a><footer>2030</footer>', "OWASP Top 10:2025"),
            ("watch-owasp-api", b'<a href="editions/2023/en/0x00-header/">API Top 10 2023</a><a href="editions/2019/en/0x00-header/">2019</a><footer>2030</footer>', "OWASP API Security Top 10 2023"),
            ("watch-owasp-mobile", b'<h3 id="mobile-top-10-2024-final-release-updates">Mobile Top 10 2024: Final Release Updates</h3><footer>2030 Strategic Plan</footer>', "OWASP Mobile Top 10 2024"),
            ("watch-owasp-llm", b'<h2>TOP 10 FOR GEN AI 2025</h2><a href="/resource/owasp-top-10-for-llm-applications-2025/">Download</a><h2>Community Summit 2030</h2>', "OWASP Top 10 for LLM Applications 2025"),
            ("watch-owasp-llm", b'<h2>2025 Top 10 Risk &amp; Mitigations for LLMs and Gen AI Apps</h2><h2>InfoSec World 2030</h2>', "OWASP Top 10 for LLM Applications 2025"),
            ("watch-owasp-agentic", b'<h1>OWASP Top 10 for Agentic Applications for 2026</h1><a href="/resource/owasp-top-10-for-agentic-applications-for-2026/">Download Now</a>', "OWASP Top 10 for Agentic Applications 2026"),
            ("watch-owasp-aitg", b'<h3 id="26-november-2025-version-1-published">26 November 2025 - Version 1 Published</h3>', "OWASP AI Testing Guide v1"),
        ]
        for identifier, markup, expected in examples:
            with self.subTest(identifier=identifier):
                marker = parse_edition_page(markup, watch(identifier))
                self.assertEqual(marker["currentLabel"], expected)
                self.assertIsNone(marker["publishedAt"])
                self.assertEqual(marker["dateBasis"], "observation")

    def test_missing_or_unapproved_page_marker_fails_closed(self):
        src = watch("watch-owasp-web")
        for markup in (b'<footer>Copyright 2029</footer>', b'<a href="https://attacker.invalid/2030/en/">Top10</a>', b'<script>OWASP Top 10 2030</script>'):
            with self.assertRaises(ValueError):
                parse_edition_page(markup, src)
        with self.assertRaises(ValueError):
            parse_edition_page(b'<a href="/2025/en/">Continue</a>', src, "https://other.example.org/")

    def test_observation_change_and_outage_retention_have_distinct_dates(self):
        src = watch("watch-owasp-web")
        first, registry = collect_page_watch(src, {}, STAMP, page_fetch(b'<a href="/2025/en/">Top10</a>'))
        self.assertFalse(first["changeDetected"])
        self.assertIsNone(first["changedAt"])
        self.assertEqual(first["firstObservedAt"], STAMP)
        self.assertIsNone(first["publishedAt"])
        prior = {"researchWatch": [first]}
        same, _ = collect_page_watch(src, prior, LATER, page_fetch(b'<a href="/2025/en/">Top10</a><footer>New arbitrary footer 2040</footer>'))
        self.assertFalse(same["changeDetected"])
        self.assertEqual(watch_content_fingerprint([first]), watch_content_fingerprint([same]))
        changed, _ = collect_page_watch(src, prior, LATER, page_fetch(b'<a href="/2027/en/">Top10</a>'))
        self.assertTrue(changed["changeDetected"])
        self.assertEqual(changed["changedAt"], LATER)
        self.assertEqual(changed["firstObservedAt"], STAMP)
        failed, status = collect_page_watch(src, prior, LATER, page_fetch(b'<html>Temporary outage</html>'))
        self.assertEqual(status["status"], "error")
        self.assertEqual(failed["currentLabel"], first["currentLabel"])
        self.assertEqual(failed["lastSuccessAt"], STAMP)
        self.assertEqual(failed["lastCheckedAt"], LATER)
        self.assertFalse(failed["changeDetected"])

    def test_release_watch_prefers_published_entry_without_calling_it_an_edition(self):
        src = source("research-owasp-asvs")
        events, registry = collect_source(src, {}, STAMP, fetcher=lambda _url: atom([
            ("Bleeding Edge", "2026-10-30T09:00:00Z"), ("5.0.0", "2025-05-30T09:00:00Z")]))
        observed = release_watches([src], [(events, registry)], {}, STAMP)[0]
        self.assertEqual(observed["currentLabel"], "5.0.0")
        self.assertEqual(observed["watchType"], "release")
        self.assertEqual(observed["dateBasis"], "source-updated")
        self.assertFalse(observed["changeDetected"])
        self.assertIn("/releases/tag/", observed["referenceUrl"])

    def test_watch_polling_does_not_advance_database_content_timestamp(self):
        src = watch("watch-owasp-web")
        first, registry = collect_page_watch(src, {}, STAMP, page_fetch(b'<a href="/2025/en/">Top10</a>'))
        snapshot = assemble([([], registry)], [], STAMP, 100, research_watch=[first])
        validate_snapshot(snapshot)
        same, later_registry = collect_page_watch(src, snapshot, LATER, page_fetch(b'<a href="/2025/en/">Top10</a>'))
        second = assemble([([], later_registry)], [], LATER, 100, previous=snapshot, research_watch=[same])
        self.assertEqual(second["databaseUpdatedAt"], STAMP)
        self.assertEqual(second["lastCheckedAt"], LATER)
        changed, changed_registry = collect_page_watch(src, snapshot, LATER, page_fetch(b'<a href="/2027/en/">Top10</a>'))
        third = assemble([([], changed_registry)], [], LATER, 100, previous=snapshot, research_watch=[changed])
        self.assertEqual(third["databaseUpdatedAt"], LATER)

    def test_recent_edit_to_older_release_does_not_replace_highest_version(self):
        src = source("research-owasp-wstg")
        events, registry = collect_source(src, {}, STAMP, fetcher=lambda _url: atom([
            ("Version 4.0", "2026-09-11T00:30:19Z"), ("Version 4.2", "2020-12-03T00:00:00Z"),
            ("20230928-Prerelease", "2026-10-30T09:00:00Z")]))
        observed = release_watches([src], [(events, registry)], {}, STAMP)[0]
        self.assertEqual(observed["currentLabel"], "Version 4.2")
        self.assertEqual(observed["publishedAt"], "2020-12-03T00:00:00Z")

    def test_schema_rejects_invented_edition_dates_and_bad_metadata(self):
        src = watch("watch-owasp-web")
        first, registry = collect_page_watch(src, {}, STAMP, page_fetch(b'<a href="/2025/en/">Top10</a>'))
        snapshot = assemble([([], registry)], [], STAMP, 100, research_watch=[first])
        for change in ({"publishedAt": STAMP}, {"changeDetected": "true"}, {"domains": ["banking"]}, {"contentHash": "bad"}):
            candidate = deepcopy(snapshot)
            candidate["researchWatch"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_snapshot(candidate)
        event = parse_atom(atom([("v5.0.0", STAMP)]), source("research-owasp-asvs"))[0]
        for change in ({"kind": "incident"}, {"domains": []}, {"perspectives": ["offensive", "offensive"]}):
            candidate = deepcopy(event)
            candidate["learning"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_event(candidate)

    def test_catalogue_rejects_local_watch_hosts_and_unbounded_learning_fields(self):
        for change in ("host", "learning"):
            data = json.loads(RESEARCH_PATH.read_text())
            if change == "host":
                data["watchPages"][0]["allowedHosts"] = ["localhost"]
            else:
                data["sources"][0]["learning"]["project"] = "x" * 181
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "research.json"
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    load_research_catalogue(path)


if __name__ == "__main__":
    unittest.main()
