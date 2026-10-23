"""Validate optional editorial context at the collector's data boundary."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_data import validate_event


class DetailSchemaTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads((ROOT / "data/curated.json").read_text())[0]

    def test_legacy_records_and_bounded_optional_context_are_valid(self):
        legacy = deepcopy(self.record)
        legacy.pop("technicalDetails", None)
        validate_event(legacy)
        enriched = deepcopy(legacy)
        enriched["technicalDetails"] = {
            "affectedSystems": ["A specified product and version."],
            "attackVector": [],
            "detection": ["Review local exposure; this is guidance."],
            "reviewedAt": "2026-10-23",
        }
        validate_event(enriched)

    def test_invalid_technical_context_is_rejected_before_publication(self):
        cases = [
            None, [], "not structured",
            {"arbitraryHtml": "<script>"},
            {"affectedSystems": "not an array"},
            {"detection": [None]},
            {"attackVector": [" "]},
            {"mitigation": ["x" * 1201]},
            {"prerequisites": ["A condition"] * 13},
            {"limitations": [{"text": "Unbounded nested object"}]},
            {"reviewedAt": "2026-02-31"},
            {"reviewedAt": "2026-10-23T12:00:00"},
        ]
        for details in cases:
            with self.subTest(details=details):
                record = deepcopy(self.record)
                record["technicalDetails"] = details
                with self.assertRaises(ValueError):
                    validate_event(record)

    def test_enriched_records_retain_primary_evidence_and_explicit_limitations(self):
        records = json.loads((ROOT / "data/curated.json").read_text())
        enriched = [record for record in records if record.get("technicalDetails")]
        self.assertGreaterEqual(len(enriched), 4)
        for record in enriched:
            with self.subTest(event=record["id"]):
                validate_event(record)
                self.assertTrue(any(source["kind"] == "primary" for source in record["sources"]))
                self.assertTrue(record["technicalDetails"]["limitations"])
                self.assertTrue(record["technicalDetails"]["reviewedAt"])


if __name__ == "__main__":
    unittest.main()
