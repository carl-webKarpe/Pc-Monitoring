"""Runs the agent: heartbeat loop, file monitor and a sender that drains the offline queue."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from . import VERSION
from .api_client import ApiClient, ApiError
from .config import AgentConfig
from .file_monitor import FileMonitor
from .outbox import Outbox
from .scanner import ScanError, scan_file
from .system_info import heartbeat_payload

log = logging.getLogger("mst_agent")

BATCH_SIZE = 100


class Agent:
    def __init__(self, config: AgentConfig, offline: bool = False):
        self.config = config
        self.offline = offline  # offline: print events locally instead of sending them (for testing)
        self.outbox = Outbox(config.queue_file)
        self.client = ApiClient(config)
        self.monitor = FileMonitor(config, self._queue_event)
        self._stop = threading.Event()
        self._server_reachable: bool | None = None
        self._unsent_results: list[dict] = []  # scan results waiting for the server

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
                self._report_connection(False, error)
                break
            self.outbox.remove([row_id for row_id, _ in batch])
            delivered += len(batch)
            self._report_connection(True)
        return delivered

    # ---- scans requested by the admin ------------------------------------------
    def process_scan_jobs(self) -> int:
        """Runs pending scans for this PC and reports the results. Returns how many results were delivered."""
        try:
            jobs = self.client.scan_jobs()
        except ApiError as error:
            self._report_connection(False, error)
            return 0
        for job in jobs:
            path = Path(str(job.get("filePath", "")))
            log.info("Scan #%s requested by MST admin: %s", job.get("scanId"), path)
            result = {"scanId": job.get("scanId")}
            try:
                result.update(scan_file(path, self.monitor.watched or self.config.watch_folders, job.get("expectedSha256"), self.config.max_hash_bytes), outcome="completed")
                log.info("Scan #%s finished: %d finding(s)", job.get("scanId"), len(result["findings"]))
            except ScanError as error:
                result.update(outcome="failed", error=str(error), durationMs=0)
                log.warning("Scan #%s failed: %s", job.get("scanId"), error)
            except Exception:  # never let one scan stop the agent
                log.exception("Scan #%s failed unexpectedly", job.get("scanId"))
                result.update(outcome="failed", error="Unexpected error while scanning", durationMs=0)
            self._unsent_results.append(result)
        delivered = 0
        while self._unsent_results:
            try:
                self.client.send_scan_result(self._unsent_results[0])
            except ApiError as error:
                self._report_connection(False, error)
                break
            self._unsent_results.pop(0)
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
