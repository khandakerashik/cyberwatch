"""Publication boundaries for world news, reader content, and source metadata."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import tempfile

from scripts.validate_data import validate_article, validate_event, validate_snapshot

ROOT = Path(__file__).resolve().parents[1]


class NewsSchemaTests(unittest.TestCase):
    def setUp(self):
        self.article = {
            "status": "full", "origin": "publisher", "paragraphs": ["A vendor's public security advisory."],
            "images": [{"url": "https://images.example.com/advisory.jpg", "alt": "Advisory diagram", "caption": "", "credit": "Vendor"}],
            "fetchedAt": "2026-10-30T10:00:00Z", "note": "Public vendor advisory.",
        }

    def test_reader_content_and_legacy_event_are_compatible(self):
        record = json.loads((ROOT / "data/curated.json").read_text())[0]
        validate_event(record)
        record.update(article=self.article, matchedKeywords=["vulnerability"], sourceType="vendor")
        validate_event(record)

    def test_invalid_content_and_dangerous_images_are_rejected(self):
        cases = [
            {"status": "confirmed"}, {"origin": "browser"}, {"paragraphs": [None]},
            {"paragraphs": ["x" * 4001]}, {"paragraphs": ["x" * 1000] * 101},
            {"paragraphs": []}, {"fetchedAt": "not a date"},
        ]
        for change in cases:
            with self.subTest(change=change):
                item = deepcopy(self.article)
                item.update(change)
                with self.assertRaises(ValueError):
                    validate_article(item)
        for url in ["javascript:alert(1)", "data:image/svg+xml,script", "http://images.example.com/a.jpg",
                    "https://127.0.0.1/a", "https://169.254.169.254/a", "https://192.168.1.2/a",
                    "https://localhost/a", "https://server.internal/a", "https://2130706433/a",
                    "https://127.1/a", "https://user:secret@images.example.com/a"]:
            with self.subTest(url=url):
                item = deepcopy(self.article)
                item["images"][0]["url"] = url
                with self.assertRaises(ValueError):
                    validate_article(item)

    def test_unavailable_reader_has_an_honest_empty_fallback(self):
        article = deepcopy(self.article)
        article.update(status="restricted", paragraphs=[], images=[], note="Publisher requires access.")
        validate_article(article)

    def test_larger_news_snapshot_and_new_source_group_are_valid(self):
        data = json.loads((ROOT / "dist/data/incidents.json").read_text())
        base = deepcopy(next(event for event in data["events"] if not event.get("learning")))
        source = deepcopy(next(item for item in data["sources"] if item["id"] == base["sourceId"]))
        source.update(group="newsboard", sourceType="mainstream", itemCount=501)
        data["sources"] = [source]
        data["events"] = [dict(base, id=f"world-report-{i}", sourceType="mainstream") for i in range(501)]
        # This fixture constructs a different source registry; edition watches
        # from the bundled snapshot cannot reference that artificial registry.
        data["researchWatch"] = []
        validate_snapshot(data)
        data["events"] += [dict(base, id=f"world-extra-{i}") for i in range(1500)]
        with self.assertRaises(ValueError):
            validate_snapshot(data)

    def test_oversized_collection_cannot_replace_previous_snapshot(self):
        from scripts.fetch_feeds import write_atomic
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "snapshot.json"
            path.write_text('{"previous":"valid"}')
            with patch("scripts.fetch_feeds.MAX_SNAPSHOT_BYTES", 20):
                with self.assertRaises(ValueError):
                    write_atomic(path, {"oversized": "x" * 50})
            self.assertEqual(path.read_text(), '{"previous":"valid"}')


if __name__ == "__main__":
    unittest.main()
