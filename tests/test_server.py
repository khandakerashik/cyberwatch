"""Offline checks for refresh coordination, publication, and HTTP boundaries."""
from copy import deepcopy
from datetime import datetime, timezone
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from server.app import Application, CooldownError, RefreshManager, UnknownJobError, iso_time


class Clock:
    def __init__(self):
        self.wall = datetime(2026, 10, 23, 16, tzinfo=timezone.utc).timestamp()
        self.monotonic = 1000.0

    def advance(self, seconds):
        self.wall += seconds
        self.monotonic += seconds


def fixture(timestamp):
    event = {
        "id": "example-event", "title": "Example advisory", "organization": "Example",
        "summary": "A bounded source report.", "description": "A bounded source report with context.",
        "severityBasis": "No rating was supplied.", "evidenceNote": "Read the original publisher.",
        "sourceId": "example", "severity": "unknown", "category": "Advisory", "stream": "intelligence",
        "status": "monitoring", "confidence": "confirmed", "exploited": False,
        "publishedAt": "2026-10-22T00:00:00Z", "updatedAt": "2026-10-22T00:00:00Z",
        "geography": [], "sectors": [], "cves": [], "tags": [],
        "impact": ["Assess exposure."], "recommendations": ["Read the publisher's advisory."],
        "sources": [{"name": "Example", "url": "https://example.com/advisory", "kind": "primary"}],
        "timeline": [],
    }
    return {
        "schemaVersion": 1, "generatedAt": timestamp, "databaseUpdatedAt": timestamp,
        "lastCheckedAt": timestamp, "events": [event],
        "sources": [{"id": "example", "name": "Example", "kind": "primary", "group": "intelligence",
                     "url": "https://example.com/", "status": "ok", "itemCount": 1,
                     "lastAttemptAt": timestamp, "lastSuccessAt": timestamp, "error": None}],
    }


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clock = Clock()
        self.seed = fixture(iso_time(self.clock.wall - 1801))
        self.seed_path = self.root / "seed.json"
        self.seed_path.write_text(json.dumps(self.seed))
        self.calls = []
        self.log_patch = patch("server.app.LOG")
        self.log_patch.start()
        self.addCleanup(self.log_patch.stop)
        self.manager = self.make_manager()
        self.static = self.root / "dist"
        self.static.mkdir()
        (self.static / "index.html").write_text("<!doctype html><title>CyberWatch</title>")
        (self.static / "app.js").write_text("export const name='CyberWatch';")
        self.app = Application(self.manager, self.static, allowed_origins=["https://reader.example"])

    def runner(self, output):
        self.calls.append(output)
        result = deepcopy(self.seed)
        result["generatedAt"] = result["lastCheckedAt"] = iso_time(self.clock.wall)
        for source in result["sources"]:
            source["lastAttemptAt"] = source["lastSuccessAt"] = result["lastCheckedAt"]
        output.write_text(json.dumps(result))

    def make_manager(self, **kwargs):
        manager = RefreshManager(data_dir=self.root / ("runtime-" + str(len(list(self.root.glob('runtime-*'))))),
                                 seed_path=self.seed_path, runner=kwargs.pop("runner", self.runner),
                                 clock=lambda: self.clock.wall, monotonic=lambda: self.clock.monotonic,
                                 **kwargs)
        self.addCleanup(manager.close)
        return manager

    def finish(self, manager=None):
        manager = manager or self.manager
        manager._worker.join(timeout=2)
        self.assertFalse(manager._worker.is_alive(), "Offline collector did not finish")

    def call(self, path, method="GET", origin=None, body=b"{}", headers=None, app=None, query=""):
        environ = {
            "REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": query,
            "wsgi.url_scheme": "http", "HTTP_HOST": "localhost:8000",
            "wsgi.input": BytesIO(body), "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/json", "HTTP_X_CYBERWATCH_REQUEST": "refresh",
        }
        if origin is not None:
            environ["HTTP_ORIGIN"] = origin
        environ.update(headers or {})
        captured = {}
        def start_response(status, response_headers):
            captured["code"] = int(status.split()[0])
            captured["headers"] = dict(response_headers)
        payload = b"".join((app or self.app)(environ, start_response))
        captured["body"] = payload
        if payload and captured["headers"]["Content-Type"].startswith("application/json"):
            captured["json"] = json.loads(payload)
        return captured

    def test_manual_requests_coalesce_while_one_check_is_running(self):
        started, release = threading.Event(), threading.Event()
        def blocked(output):
            started.set()
            self.assertTrue(release.wait(2))
            self.runner(output)
        manager = self.make_manager(runner=blocked)
        first = manager.request_refresh()
        self.assertTrue(started.wait(1))
        second = manager.request_refresh()
        self.assertEqual(first["refresh"]["id"], second["refresh"]["id"])
        self.assertTrue(second["coalesced"])
        self.assertEqual(second["refresh"]["status"], "running")
        release.set()
        self.finish(manager)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(manager.status()["refresh"]["status"], "succeeded")

    def test_script_and_module_entrypoints_import_from_project_root(self):
        project = Path(__file__).resolve().parents[1]
        environment = dict(os.environ, PYTHONPATH="")
        for entry in ([str(project / "server/app.py")], ["-m", "server.app"]):
            with self.subTest(entry=entry):
                result = subprocess.run([sys.executable, *entry, "--help"], cwd=project,
                                        env=environment, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("--port", result.stdout)

    def test_completed_check_has_shared_cooldown_with_retry_after(self):
        self.manager.request_refresh()
        self.finish()
        response = self.call("/api/refresh", "POST", "http://localhost:8000")
        self.assertEqual(response["code"], 429)
        self.assertEqual(response["json"]["retryAfter"], 60)
        self.assertEqual(response["headers"]["Retry-After"], "60")
        self.assertEqual(len(self.calls), 1)
        self.clock.advance(60)
        self.assertEqual(self.call("/api/refresh", "POST", "http://localhost:8000")["code"], 202)
        self.finish()

    def test_process_failure_never_replaces_the_published_snapshot(self):
        before = self.manager.snapshot()
        def failed(output):
            output.write_text("damaged candidate")
            raise subprocess.CalledProcessError(1, ["collector"])
        self.manager._runner = failed
        self.manager.request_refresh()
        self.finish()
        self.assertEqual(self.manager.snapshot(), before)
        self.assertEqual(self.manager.snapshot_path.read_bytes(), before)
        self.assertEqual(self.manager.status()["lastCheckedAt"], self.seed["lastCheckedAt"])
        self.assertEqual(self.manager.status()["refresh"]["status"], "failed")
        self.assertFalse(list(self.manager.data_dir.glob("pending-*")))

    def test_invalid_success_output_is_not_published(self):
        before = self.manager.snapshot()
        self.manager._runner = lambda output: output.write_text('{"events": []}')
        self.manager.request_refresh()
        self.finish()
        self.assertEqual(self.manager.status()["refresh"]["status"], "failed")
        self.assertEqual(self.manager.snapshot(), before)

    def test_timeout_reports_failure_and_keeps_old_data(self):
        before = self.manager.snapshot()
        def timed_out(_output):
            raise subprocess.TimeoutExpired(["collector"], 180)
        self.manager._runner = timed_out
        self.manager.request_refresh()
        self.finish()
        self.assertEqual(self.manager.snapshot(), before)
        self.assertIn("180 seconds", self.manager.status()["refresh"]["error"])

    def test_partial_collection_publishes_source_failure_information(self):
        def partial(output):
            self.runner(output)
            data = json.loads(output.read_text())
            data["sources"].append({"id": "unavailable", "name": "Unavailable", "kind": "secondary",
                "group": "news", "url": "https://news.example/", "status": "error", "itemCount": 0,
                "lastAttemptAt": iso_time(self.clock.wall), "lastSuccessAt": None, "error": "Timed out"})
            output.write_text(json.dumps(data))
        self.manager._runner = partial
        self.manager.request_refresh()
        self.finish()
        self.assertEqual(self.manager.status()["refresh"]["status"], "partial")
        self.assertEqual(self.manager.status()["lastCheckedAt"], iso_time(self.clock.wall))
        self.assertEqual(json.loads(self.manager.snapshot())["sources"][1]["status"], "error")

    def test_job_status_remains_addressable_after_a_new_job(self):
        manager = self.make_manager(history_limit=2)
        first = manager.request_refresh()["refresh"]["id"]
        self.finish(manager)
        self.clock.advance(60)
        second = manager.request_refresh()["refresh"]["id"]
        self.finish(manager)
        self.assertEqual(manager.status(first)["refresh"]["id"], first)
        self.assertEqual(manager.status(first)["refresh"]["status"], "succeeded")
        self.clock.advance(60)
        manager.request_refresh()
        self.finish(manager)
        with self.assertRaises(UnknownJobError):
            manager.status(first)
        self.assertEqual(manager.status(second)["refresh"]["status"], "succeeded")

    def test_scheduler_runs_every_half_hour_without_waiting_in_real_time(self):
        first = self.manager.run_scheduled_if_due()
        self.assertEqual(first["refresh"]["trigger"], "scheduled")
        self.finish()
        self.assertIsNone(self.manager.run_scheduled_if_due())
        self.clock.advance(1200)
        self.manager.request_refresh()
        self.finish()
        self.clock.advance(599)
        self.assertIsNone(self.manager.run_scheduled_if_due())
        self.clock.advance(1)
        self.assertIsNotNone(self.manager.run_scheduled_if_due())
        self.finish()
        self.assertEqual(len(self.calls), 3)

    def test_recent_seed_waits_until_due_instead_of_fetching_at_startup(self):
        self.seed_path.write_text(json.dumps(fixture(iso_time(self.clock.wall - 30))))
        manager = self.make_manager()
        self.assertIsNone(manager.run_scheduled_if_due())
        self.clock.advance(1770)
        self.assertIsNotNone(manager.run_scheduled_if_due())
        self.finish(manager)

    def test_status_and_snapshot_contracts_are_explicit_and_uncached(self):
        response = self.call("/api/status")
        self.assertEqual(response["code"], 200)
        self.assertEqual(response["json"]["service"], "cyberwatch")
        self.assertEqual(response["json"]["apiVersion"], 1)
        self.assertEqual(response["json"]["refreshIntervalSeconds"], 1800)
        self.assertEqual(response["json"]["refresh"]["status"], "idle")
        self.assertEqual(response["headers"]["Cache-Control"], "no-store")
        for path in ("/api/snapshot", "/data/incidents.json"):
            result = self.call(path)
            self.assertEqual(result["json"], self.seed)
            self.assertEqual(result["headers"]["Cache-Control"], "no-store")
        job = self.manager.request_refresh()["refresh"]["id"]
        self.finish()
        self.assertEqual(self.call("/api/status", query="job=" + job)["json"]["refresh"]["id"], job)
        self.assertEqual(self.call("/api/status", query="job=" + "0" * 32)["code"], 404)
        self.assertEqual(self.call("/api/status", query="job=../../secret")["code"], 400)

    def test_cross_origin_refresh_requires_exact_allowlist(self):
        for origin in (None, "null", "https://evil.example", "https://reader.example.evil.test", "https://user@reader.example"):
            with self.subTest(origin=origin):
                response = self.call("/api/refresh", "POST", origin)
                self.assertEqual(response["code"], 403)
                self.assertNotIn("Access-Control-Allow-Origin", response["headers"])
        accepted = self.call("/api/refresh", "POST", "https://reader.example")
        self.assertEqual(accepted["code"], 202)
        self.assertEqual(accepted["headers"]["Access-Control-Allow-Origin"], "https://reader.example")
        self.assertNotIn("Access-Control-Allow-Credentials", accepted["headers"])
        self.finish()

    def test_header_json_and_body_boundaries_block_unintended_refresh(self):
        for headers, body, expected in [
            ({"HTTP_X_CYBERWATCH_REQUEST": ""}, b"{}", 403),
            ({"CONTENT_TYPE": "text/plain"}, b"{}", 415),
            ({}, b'{"url":"http://internal.example"}', 400),
            ({}, b"invalid", 400),
            ({"CONTENT_LENGTH": "2048"}, b"{}", 413),
            ({"CONTENT_LENGTH": "bad"}, b"{}", 411),
        ]:
            with self.subTest(headers=headers, body=body):
                self.assertEqual(self.call("/api/refresh", "POST", "http://localhost:8000", body, headers)["code"], expected)
        self.assertEqual(self.manager.status()["refresh"]["status"], "idle")
        self.assertEqual(self.call("/api/refresh")["code"], 405)

    def test_preflight_does_not_reflect_unapproved_methods_or_headers(self):
        headers = {"HTTP_ACCESS_CONTROL_REQUEST_METHOD": "POST", "HTTP_ACCESS_CONTROL_REQUEST_HEADERS": "Content-Type, X-CyberWatch-Request"}
        result = self.call("/api/refresh", "OPTIONS", "https://reader.example", headers=headers)
        self.assertEqual(result["code"], 204)
        self.assertEqual(result["body"], b"")
        self.assertNotIn("Access-Control-Allow-Credentials", result["headers"])
        headers["HTTP_ACCESS_CONTROL_REQUEST_HEADERS"] = "Authorization"
        self.assertEqual(self.call("/api/refresh", "OPTIONS", "https://reader.example", headers=headers)["code"], 403)
        self.assertEqual(self.manager.status()["refresh"]["status"], "idle")

    def test_explicit_public_origin_supports_tls_termination(self):
        app = Application(self.manager, self.static, allowed_origins=[], public_origin="https://cyberwatch.example")
        result = self.call("/api/refresh", "POST", "https://cyberwatch.example", app=app)
        self.assertEqual(result["code"], 202)
        self.finish()

    def test_static_files_have_no_listing_or_directory_escape(self):
        (self.root / "secret.json").write_text('{"private":true}')
        (self.static / "leak.json").symlink_to(self.root / "secret.json")
        (self.static / "folder").mkdir()
        self.assertEqual(self.call("/")["code"], 200)
        self.assertIn("text/javascript", self.call("/app.js")["headers"]["Content-Type"])
        self.assertEqual(self.call("/app.js", "HEAD")["body"], b"")
        for path in ("/../secret.json", "/%2e%2e/secret.json", "/.env", "/folder/", "/leak.json", "/..\\secret.json", "/%00"):
            with self.subTest(path=path):
                self.assertEqual(self.call(path)["code"], 404)

    def test_wildcards_and_urls_with_paths_are_not_origin_configuration(self):
        for origin in ("*", "https://*.example", "https://example.com/path", "https://example.com?token=x"):
            with self.subTest(origin=origin):
                with self.assertRaises(ValueError):
                    Application(self.manager, self.static, allowed_origins=[origin])


if __name__ == "__main__":
    unittest.main()
