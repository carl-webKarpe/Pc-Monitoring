"""Runs the agent: heartbeat loop, file monitor and a sender that drains the offline queue."""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path

from . import VERSION
from .api_client import ApiClient, ApiError
from .config import AgentConfig
from .file_monitor import FileMonitor
from .antivirus import engines_status
from .outbox import Outbox
from .quarantine import Quarantine, QuarantineError
from .scanner import ScanError, scan_file
from .system_info import heartbeat_payload

log = logging.getLogger("mst_agent")

BATCH_SIZE = 100
ENGINE_REFRESH_SECONDS = 3600  # re-check which antivirus engines are available (Defender can be switched on/off)


class Agent:
    def __init__(self, config: AgentConfig, offline: bool = False):
        self.config = config
        self.offline = offline  # offline: print events locally instead of sending them (for testing)
        self.outbox = Outbox(config.queue_file)
        self.client = ApiClient(config)
        self.monitor = FileMonitor(config, self._queue_event)
        self._stop = threading.Event()
        self._server_reachable: bool | None = None
        self._unsent: list[tuple[str, dict]] = []  # scan / action results waiting for the server
        self.quarantine = Quarantine(config.quarantine_folder, config.watch_folders, config.max_hash_bytes)
        self._engines: list[dict] | None = None
        self._engines_checked = 0.0

    def engines(self) -> list[dict]:
        """Antivirus engines installed on this PC (checked at start and then hourly)."""
        if self._engines is None or time.monotonic() - self._engines_checked > ENGINE_REFRESH_SECONDS:
            self._engines = engines_status(self.config.antivirus, self.config.defender_path, self.config.clamav_path, self.config.clamav_database)
            self._engines_checked = time.monotonic()
        return self._engines

    # ---- events -----------------------------------------------------------
    def _queue_event(self, event: dict) -> None:
        if self.offline:
            print("EVENT", json.dumps(event))
            return
        self.outbox.put(event)

    def flush(self) -> int:
        """Sends queued events in batches. Returns how many were delivered."""
        delivered = 0
        while not self._stop.is_set():
            batch = self.outbox.peek(BATCH_SIZE)
            if not batch:
                break
            try:
                self.client.send_events([event for _, event in batch])
            except ApiError as error:
                if error.permanent:
                    # Keeping a batch the server rejects would block every newer event behind it.
                    log.error("MST server rejected %d event(s) (%s); they are skipped", len(batch), error)
                    self.outbox.remove([row_id for row_id, _ in batch])
                    continue
                self._report_connection(False, error)
                break
            self.outbox.remove([row_id for row_id, _ in batch])
            delivered += len(batch)
            self._report_connection(True)
        return delivered

    # ---- scans and quarantine actions requested by the MST server -------------------------
    def process_scan_jobs(self) -> int:
        """Runs pending scans and quarantine actions for this PC and reports the results. Returns how many results were delivered."""
        try:
            jobs, actions = self.client.scan_jobs()
        except ApiError as error:
            self._report_connection(False, error)
            return 0
        for job in jobs:
            path = Path(str(job.get("filePath", "")))
            log.info("Scan #%s requested by MST: %s", job.get("scanId"), path)
            result = {"scanId": job.get("scanId")}
            try:
                result.update(scan_file(path, self.monitor.watched or self.config.watch_folders, job.get("expectedSha256"), self.config.max_hash_bytes, self.engines(), self.config.scan_timeout_seconds), outcome="completed")
                verdicts = ", ".join(f"{engine['name']}: {engine['result']}" for engine in result["engines"]) or "no antivirus engine"
                log.info("Scan #%s finished: %s; %d indicator(s)", job.get("scanId"), verdicts, len(result["indicators"]))
            except ScanError as error:
                result.update(outcome="failed", error=str(error), durationMs=0)
                log.warning("Scan #%s failed: %s", job.get("scanId"), error)
            except Exception:  # never let one scan stop the agent
                log.exception("Scan #%s failed unexpectedly", job.get("scanId"))
                result.update(outcome="failed", error="Unexpected error while scanning", durationMs=0)
            self._unsent.append(("scan", result))
        for action in actions:
            self._unsent.append(("action", self.run_action(action)))
        return self._send_results()

    def run_action(self, action: dict) -> dict:
        kind, item_id = action.get("action"), action.get("itemId")
        result = {"itemId": item_id, "action": kind}
        original = str(action.get("originalPath", ""))
        sha256 = str(action.get("sha256", ""))
        log.info("Quarantine action #%s requested by MST: %s %s", item_id, kind, original)
        try:
            self.monitor.suppress(Path(original))  # MST moves the file itself: not a user's file activity
            if kind == "quarantine":
                result["quarantineName"] = self.quarantine.quarantine(int(item_id), original, sha256)
            elif kind == "release":
                self.quarantine.release(str(action.get("quarantineName")), original, sha256)
            elif kind == "delete":
                self.quarantine.delete(str(action.get("quarantineName")), sha256)
            else:
                raise QuarantineError("Unknown action")
            result["outcome"] = "completed"
            log.info("Quarantine action #%s (%s) completed", item_id, kind)
        except QuarantineError as error:
            result.update(outcome="failed", error=str(error))
            log.warning("Quarantine action #%s (%s) failed: %s", item_id, kind, error)
        except Exception:
            log.exception("Quarantine action #%s failed unexpectedly", item_id)
            result.update(outcome="failed", error="Unexpected error on the computer")
        return result

    def _send_results(self) -> int:
        delivered = 0
        while self._unsent:
            kind, result = self._unsent[0]
            try:
                if kind == "scan":
                    self.client.send_scan_result(result)
                else:
                    self.client.send_action_result(result)
            except ApiError as error:
                if error.permanent:
                    log.error("MST server rejected a %s result (%s); it is skipped", kind, error)
                    self._unsent.pop(0)
                    continue
                self._report_connection(False, error)
                break
            self._unsent.pop(0)
            delivered += 1
        return delivered

    # ---- heartbeat --------------------------------------------------------
    def send_heartbeat(self) -> bool:
        payload = heartbeat_payload(self.config.server_url)
        if self.offline:
            print("HEARTBEAT", json.dumps(payload))
            return True
        try:
            self.client.heartbeat(payload)
        except ApiError as error:
            self._report_connection(False, error)
            return False
        self._report_connection(True)
        return True

    def _report_connection(self, ok: bool, error: ApiError | None = None) -> None:
        # Log connection changes once instead of on every retry.
        if ok and self._server_reachable is not True:
            log.info("Connected to MST server %s", self.config.server_url)
        elif not ok and self._server_reachable is not False:
            log.warning("%s (events are kept and will be sent later)", error)
        self._server_reachable = ok

    # ---- main loop ----------------------------------------------------------
    def run(self) -> None:
        watched = self.monitor.start()
        log.info("MST Monitoring Agent %s started for %s", VERSION, self.config.device_id)
        log.info("Watching %d folder(s): %s", len(watched), ", ".join(str(folder) for folder in watched) or "none")
        engines = self.engines()
        for engine in engines:
            log.info("Antivirus engine: %s %s - %s", engine["name"], engine.get("version") or "", engine["detail"])
        if not any(engine["available"] for engine in engines):
            log.warning("No antivirus engine is available on this PC: scans rely on VirusTotal and static analysis only")
        if not self.offline and len(self.outbox):
            log.info("%d queued event(s) waiting to be sent", len(self.outbox))
        heartbeat_thread = threading.Thread(target=self._heartbeat_loop, name="mst-heartbeat", daemon=True)
        heartbeat_thread.start()
        try:
            while not self._stop.wait(self.config.send_interval_seconds):
                if not self.offline:
                    self.flush()
                    self.process_scan_jobs()
        finally:
            self.stop()

    def _heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.send_heartbeat()
            except Exception:
                log.exception("Heartbeat failed")
            self._stop.wait(self.config.heartbeat_interval_seconds)

    def stop(self) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        self.monitor.stop()
        self.outbox.close()
        log.info("MST Monitoring Agent stopped")
