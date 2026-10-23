"""Serve CyberWatch and collect its fixed public feeds on demand.

Run one process / one instance. Waitress supplies production HTTP handling;
the collector remains a bounded subprocess and never accepts request URLs.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
from datetime import datetime, timezone
import json
import ipaddress
import logging
import math
import mimetypes
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, unquote, urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
# Both ``python -m server.app`` and ``python server/app.py`` use the same
# repository-local collector/validator imports.
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from scripts.validate_data import validate_snapshot

DIST = ROOT / "dist"
INTERVAL = 1800
COOLDOWN = 60
COLLECT_TIMEOUT = 180
MAX_SNAPSHOT = 8 * 1024 * 1024
LOG = logging.getLogger("cyberwatch")


def iso_time(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def snapshot_bytes(path):
    with Path(path).open("rb") as handle:
        payload = handle.read(MAX_SNAPSHOT + 1)
    if len(payload) > MAX_SNAPSHOT:
        raise ValueError("Snapshot exceeds the size limit")
    data = json.loads(payload)
    validate_snapshot(data)
    if not data["events"]:
        raise ValueError("Snapshot contains no records")
    return payload, data


def atomic_bytes(path, payload):
    descriptor, temporary = tempfile.mkstemp(prefix=".cyberwatch-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class CooldownError(Exception):
    def __init__(self, retry_after):
        self.retry_after = retry_after


class UnknownJobError(Exception):
    pass


class RefreshManager:
    """Single-instance collection coordinator with atomic publication."""

    def __init__(self, data_dir=None, seed_path=None, runner=None, clock=time.time,
                 monotonic=time.monotonic, interval=INTERVAL, cooldown=COOLDOWN,
                 history_limit=10):
        self.data_dir = Path(data_dir or os.environ.get("CYBERWATCH_DATA_DIR", ROOT / "runtime"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.snapshot_path = self.data_dir / "snapshot.json"
        self.seed_path = Path(seed_path or DIST / "data/incidents.json")
        self._clock, self._monotonic = clock, monotonic
        self.interval, self.cooldown, self.history_limit = interval, cooldown, history_limit
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._jobs = OrderedDict()
        self._current_id = None
        self._active_id = None
        self._last_start = float("-inf")
        self._worker = self._scheduler = self._process = None
        self._runner = runner or self._run_collector
        try:
            self._payload, self._snapshot = snapshot_bytes(self.snapshot_path)
        except (OSError, ValueError, TypeError, KeyError):
            self._payload, self._snapshot = snapshot_bytes(self.seed_path)
            atomic_bytes(self.snapshot_path, self._payload)
        now = self._clock()
        try:
            checked = datetime.fromisoformat(self._snapshot["lastCheckedAt"].replace("Z", "+00:00")).timestamp()
        except (KeyError, ValueError, TypeError):
            checked = 0
        # A future timestamp must not prevent startup collection indefinitely.
        delay = max(0, checked + interval - now) if checked <= now else 0
        self._next_tick = self._monotonic() + min(interval, delay)

    def _status_locked(self, job_id=None):
        if job_id is not None and job_id not in self._jobs:
            raise UnknownJobError(job_id)
        selected = job_id or self._current_id
        refresh = dict(self._jobs[selected]) if selected else {
            "id": None, "status": "idle", "startedAt": None, "finishedAt": None, "error": None,
        }
        delay = max(0, self._next_tick - self._monotonic())
        return {
            "service": "cyberwatch", "apiVersion": 1,
            "refreshIntervalSeconds": self.interval,
            "nextCheckAt": iso_time(self._clock() + delay),
            "refresh": refresh,
            "lastCheckedAt": self._snapshot.get("lastCheckedAt"),
        }

    def status(self, job_id=None):
        with self._lock:
            return self._status_locked(job_id)

    def snapshot(self):
        with self._lock:
            return self._payload

    def request_refresh(self, trigger="manual"):
        with self._lock:
            if self._stop.is_set():
                raise RuntimeError("Service is shutting down")
            if self._active_id:
                result = self._status_locked(self._active_id)
                result["coalesced"] = True
                return result
            remaining = self.cooldown - (self._monotonic() - self._last_start)
            if remaining > 0:
                raise CooldownError(max(1, math.ceil(remaining)))
            job_id = uuid4().hex
            self._jobs[job_id] = {
                "id": job_id, "status": "running", "startedAt": iso_time(self._clock()),
                "finishedAt": None, "error": None, "trigger": trigger,
            }
            self._current_id = self._active_id = job_id
            self._last_start = self._monotonic()
            while len(self._jobs) > self.history_limit:
                self._jobs.popitem(last=False)
            self._worker = threading.Thread(target=self._collect, args=(job_id,), daemon=True,
                                            name="cyberwatch-collector")
            self._worker.start()
            result = self._status_locked(job_id)
            result["coalesced"] = False
            return result

    def _run_collector(self, output):
        command = [sys.executable, str(ROOT / "scripts/fetch_feeds.py"),
                   "--output", str(output), "--limit", "300"]
        with self._lock:
            if self._stop.is_set():
                raise RuntimeError("Service is shutting down")
            process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            self._process = process
        try:
            stdout, stderr = process.communicate(timeout=COLLECT_TIMEOUT)
            if process.returncode:
                LOG.error("Collector exited %s: %s", process.returncode, stderr[-1500:])
                raise subprocess.CalledProcessError(process.returncode, command)
            LOG.info("Collector completed: %s", stdout.strip()[-1500:])
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        finally:
            with self._lock:
                if self._process is process:
                    self._process = None

    def _collect(self, job_id):
        candidate = self.data_dir / ("pending-" + job_id + ".json")
        status, error = "failed", None
        try:
            # The existing snapshot is the collector's outage fallback. Stage
            # the whole run so any global failure leaves the published file intact.
            atomic_bytes(candidate, self.snapshot())
            self._runner(candidate)
            payload, data = snapshot_bytes(candidate)
            channels = [source for source in data["sources"] if source["kind"] != "curated"]
            failures = sum(source["status"] == "error" for source in channels)
            status = "partial" if failures else "succeeded"
            if channels and failures == len(channels):
                # Retained event records remain valid; source-level failures and
                # the attempted-check timestamp are still published honestly.
                status = "failed"
                error = "All publisher checks failed. Last available records are retained."
            with self._lock:
                if self._stop.is_set():
                    raise RuntimeError("Service is shutting down")
                os.replace(candidate, self.snapshot_path)
                self._payload, self._snapshot = payload, data
        except subprocess.TimeoutExpired:
            status = "failed"
            error = "The publisher check exceeded 180 seconds. Previous data is retained."
            LOG.warning("Collection %s timed out", job_id)
        except Exception:
            status = "failed"
            error = "The publisher check could not be completed. Previous data is retained."
            LOG.exception("Collection %s failed", job_id)
        finally:
            candidate.unlink(missing_ok=True)
            with self._lock:
                self._jobs[job_id].update(status=status, finishedAt=iso_time(self._clock()), error=error)
                self._active_id = None

    def run_scheduled_if_due(self):
        """A clock-injectable scheduling step; manual checks do not postpone it."""
        with self._lock:
            now = self._monotonic()
            if self._stop.is_set() or now < self._next_tick:
                return None
            while self._next_tick <= now:
                self._next_tick += self.interval
        try:
            return self.request_refresh(trigger="scheduled")
        except CooldownError:
            # A just-started/finished manual check already covers this tick.
            return None
        except RuntimeError:
            if self._stop.is_set():
                return None
            raise

    def start_scheduler(self):
        with self._lock:
            if self._scheduler is not None:
                return
            self._scheduler = threading.Thread(target=self._schedule_loop, daemon=True,
                                               name="cyberwatch-scheduler")
            self._scheduler.start()

    def _schedule_loop(self):
        while not self._stop.is_set():
            self.run_scheduled_if_due()
            with self._lock:
                delay = max(.1, self._next_tick - self._monotonic())
            self._stop.wait(delay)

    def close(self):
        self._stop.set()
        with self._lock:
            process = self._process
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
        for thread in (self._scheduler, self._worker):
            if thread and thread is not threading.current_thread():
                thread.join(timeout=2)


def valid_origin(value):
    """Return a normalized HTTP origin, never a URL path or wildcard."""
    if not isinstance(value, str) or len(value) > 500 or any(ord(c) <= 32 for c in value):
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or
                parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
            return None
        port = parsed.port
        host = parsed.hostname.lower()
        if ":" in host:
            ipaddress.IPv6Address(host)
            host = "[" + host + "]"
        elif not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
            return None
        suffix = "" if port is None or (parsed.scheme, port) in {("http", 80), ("https", 443)} else f":{port}"
        return f"{parsed.scheme}://{host}{suffix}"
    except ValueError:
        return None


class Application:
    def __init__(self, manager, static_dir=DIST, allowed_origins=None, public_origin=None):
        self.manager = manager
        self.static_dir = Path(static_dir).resolve()
        if allowed_origins is None:
            allowed_origins = os.environ.get("CYBERWATCH_ALLOWED_ORIGINS", "").split(",")
        self.allowed_origins = set()
        for item in allowed_origins:
            if not item.strip():
                continue
            normalized = valid_origin(item.strip())
            if not normalized:
                raise ValueError("CYBERWATCH_ALLOWED_ORIGINS must contain exact HTTP(S) origins")
            self.allowed_origins.add(normalized)
        configured = public_origin or os.environ.get("CYBERWATCH_PUBLIC_ORIGIN") or os.environ.get("RENDER_EXTERNAL_URL")
        self.public_origin = valid_origin(configured) if configured else None
        if configured and not self.public_origin:
            raise ValueError("CYBERWATCH_PUBLIC_ORIGIN must be an exact HTTP(S) origin")

    def _allowed_origin(self, environ):
        origin = valid_origin(environ.get("HTTP_ORIGIN"))
        if not origin:
            return None
        # Under a TLS-terminating proxy, configure PUBLIC_ORIGIN; Render sets
        # RENDER_EXTERNAL_URL automatically. Never trust arbitrary proxy headers.
        own = self.public_origin or valid_origin(environ.get("wsgi.url_scheme", "http") + "://" + environ.get("HTTP_HOST", ""))
        return environ["HTTP_ORIGIN"] if origin == own or origin in self.allowed_origins else None

    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        raw_path = environ.get("PATH_INFO", "/")
        origin = self._allowed_origin(environ)
        common = [("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer")]
        if raw_path.startswith("/api/"):
            common.extend([("Cache-Control", "no-store"), ("Vary", "Origin")])
            if origin:
                common.append(("Access-Control-Allow-Origin", origin))

        def respond(code, payload, content_type="application/json; charset=utf-8", headers=()):
            if isinstance(payload, dict):
                payload = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            statuses = {200: "OK", 202: "Accepted", 204: "No Content", 400: "Bad Request", 403: "Forbidden",
                        404: "Not Found", 405: "Method Not Allowed", 411: "Length Required",
                        413: "Content Too Large", 415: "Unsupported Media Type", 429: "Too Many Requests", 503: "Service Unavailable"}
            start_response(f"{code} {statuses[code]}", common + [("Content-Type", content_type), ("Content-Length", str(len(payload)))] + list(headers))
            return [b"" if method == "HEAD" else payload]

        if raw_path.startswith("/api/") and environ.get("HTTP_ORIGIN") and not origin:
            return respond(403, {"error": "This origin is not allowed."})
        if method == "OPTIONS":
            requested = environ.get("HTTP_ACCESS_CONTROL_REQUEST_METHOD", "").upper()
            headers = {v.strip().lower() for v in environ.get("HTTP_ACCESS_CONTROL_REQUEST_HEADERS", "").split(",") if v.strip()}
            if (not origin or raw_path not in {"/api/status", "/api/snapshot", "/api/refresh"} or
                    requested not in {"GET", "POST"} or not headers <= {"content-type", "x-cyberwatch-request"}):
                return respond(403, {"error": "Preflight is not allowed."})
            return respond(204, b"", headers=[("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
                ("Access-Control-Allow-Headers", "Content-Type, X-CyberWatch-Request"), ("Access-Control-Max-Age", "600")])
        if raw_path == "/api/refresh":
            if method != "POST":
                return respond(405, {"error": "Use POST to request a publisher check."}, headers=[("Allow", "POST, OPTIONS")])
            if not origin or environ.get("HTTP_X_CYBERWATCH_REQUEST") != "refresh":
                return respond(403, {"error": "A valid application origin and refresh header are required."})
            if environ.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower() != "application/json":
                return respond(415, {"error": "An application/json request is required."})
            try:
                length = int(environ.get("CONTENT_LENGTH", ""))
            except ValueError:
                return respond(411, {"error": "Content-Length is required."})
            if length < 0 or length > 1024:
                return respond(413, {"error": "Refresh request is too large."})
            try:
                body = json.loads(environ["wsgi.input"].read(length))
                if body != {}:
                    raise ValueError("Only an empty object is accepted")
            except (ValueError, UnicodeError):
                return respond(400, {"error": "Send an empty JSON object; feed URLs and commands cannot be supplied."})
            try:
                return respond(202, self.manager.request_refresh())
            except CooldownError as exc:
                result = self.manager.status()
                result.update(retryAfter=exc.retry_after, message="A feed check was just requested. Try again after the cooldown.")
                return respond(429, result, headers=[("Retry-After", str(exc.retry_after))])
            except RuntimeError:
                return respond(503, {"error": "The refresh service is restarting. Try again shortly."})
        if raw_path == "/api/status":
            if method not in {"GET", "HEAD"}:
                return respond(405, {"error": "Use GET for collection status."}, headers=[("Allow", "GET, HEAD, OPTIONS")])
            try:
                query = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True, max_num_fields=2)
                if set(query) - {"job"} or ("job" in query and (len(query["job"]) != 1 or not re.fullmatch(r"[a-f0-9]{32}", query["job"][0]))):
                    raise ValueError("Invalid query")
                return respond(200, self.manager.status(query.get("job", [None])[0]))
            except ValueError:
                return respond(400, {"error": "Invalid status query."})
            except UnknownJobError:
                return respond(404, {"error": "This refresh job is no longer in the recent history."})
        if raw_path in {"/api/snapshot", "/data/incidents.json"}:
            if method not in {"GET", "HEAD"}:
                return respond(405, {"error": "Use GET for the snapshot."}, headers=[("Allow", "GET, HEAD, OPTIONS")])
            headers = [] if raw_path.startswith("/api/") else [("Cache-Control", "no-store")]
            return respond(200, self.manager.snapshot(), headers=headers)
        if raw_path.startswith("/api/"):
            return respond(404, {"error": "Unknown API route."})
        if raw_path == "/healthz":
            if method not in {"GET", "HEAD"}:
                return respond(405, {"error": "Use GET for health."}, headers=[("Allow", "GET, HEAD")])
            return respond(200, {"status": "ok", "service": "cyberwatch"}, headers=[("Cache-Control", "no-store")])
        if method not in {"GET", "HEAD"}:
            return respond(405, {"error": "Method not allowed."}, headers=[("Allow", "GET, HEAD")])
        try:
            path = unquote(raw_path, errors="strict")
            if "\x00" in path or "\\" in path or not path.startswith("/") or any(part.startswith(".") for part in path.split("/") if part):
                raise ValueError("Unsafe path")
            target = (self.static_dir / (path.lstrip("/") or "index.html")).resolve()
            if not target.is_relative_to(self.static_dir) or not target.is_file():
                raise ValueError("Not a static file")
            if target.suffix.lower() not in {".html", ".css", ".js", ".json", ".png", ".svg", ".ico", ".zip"}:
                raise ValueError("Not a public asset")
            content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if target.suffix == ".js":
                content_type = "text/javascript"
            if target.suffix in {".html", ".css", ".js", ".json", ".svg"}:
                content_type += "; charset=utf-8"
            return respond(200, target.read_bytes(), content_type, [("Cache-Control", "no-cache")])
        except (OSError, ValueError, UnicodeError):
            return respond(404, {"error": "Not found."})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    from waitress import serve
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    manager = RefreshManager()
    application = Application(manager)
    manager.start_scheduler()

    def stop_service(_signum, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop_service)
    try:
        serve(application, host=args.host, port=args.port, threads=4,
              max_request_body_size=1024, channel_timeout=30, expose_tracebacks=False)
    finally:
        manager.close()


if __name__ == "__main__":
    main()
