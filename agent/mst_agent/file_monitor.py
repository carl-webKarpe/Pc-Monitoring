"""Watches the configured folders and turns new, modified, renamed and deleted files into MST file events.

Only file metadata (name, location, size, time), a SHA-256 fingerprint and download evidence are collected.
File contents are read solely to compute the hash and are never uploaded.

How a file arrived is reported as "origin":
  local             - the file appeared; nothing shows it was downloaded
  browser_download  - a browser finished a download (its temporary .crdownload/.part file was renamed)
  internet          - Windows "Mark of the Web" confirms it came from the internet (with the source site when the
                      browser recorded it); this is the only download-source information MST reports
"""

from __future__ import annotations

import hashlib
import logging
import os
import queue
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .config import AgentConfig

log = logging.getLogger("mst_agent.files")

STABLE_CHECKS = 2          # size must be unchanged for this many consecutive checks
CHECK_INTERVAL = 1.0       # seconds between size checks
MAX_WAIT_SECONDS = 300     # give up waiting for very slow downloads after 5 minutes
HASH_CHUNK = 1024 * 1024
VANISHED_MEMORY_SECONDS = 15  # a file that appeared and vanished unreported: ignore its delete for this long
WORKERS = 4                # new files are checked in parallel so a burst of files is not delayed
BROWSER_TEMP_EXTENSIONS = {".crdownload", ".part", ".partial", ".download", ".opdownload"}
KNOWN_HASHES_LIMIT = 5000  # remembered file hashes, to report "modified" only when the content really changed


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_of(path: Path, max_bytes: int) -> str | None:
    """SHA-256 of a file, or None if it is larger than max_bytes or cannot be read (e.g. locked)."""
    for attempt in range(3):
        try:
            if path.stat().st_size > max_bytes:
                return None
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(HASH_CHUNK), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except PermissionError:
            time.sleep(1 + attempt)  # Windows: the file may still be locked by the program writing it.
        except OSError:
            return None
    return None


def clean_url(url: str | None) -> str | None:
    """Scheme, host and path only: query strings can hold personal tokens."""
    if not url:
        return None
    try:
        parts = urlsplit(url.strip())
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    return f"{parts.scheme.lower()}://{parts.hostname}{port}{parts.path}"[:490]


def mark_of_the_web(path: Path) -> dict | None:
    """Windows 'Mark of the Web' (Zone.Identifier): ZoneId 3 (Internet) / 4 (Restricted) means downloaded.
    Browsers also record the download source there (HostUrl)."""
    if os.name != "nt":
        return None
    zone, host_url = None, None
    try:
        with open(f"{path}:Zone.Identifier", encoding="utf-8", errors="ignore") as stream:
            for line in stream:
                key, _, value = line.strip().partition("=")
                if key.lower() == "zoneid" and value.strip().isdigit():
                    zone = int(value.strip())
                elif key.lower() == "hosturl":
                    host_url = clean_url(value)
    except OSError:
        return None
    return None if zone is None else {"zone": max(0, min(4, zone)), "hostUrl": host_url}


class FileMonitor:
    def __init__(self, config: AgentConfig, on_event: Callable[[dict], None]):
        self.config = config
        self.on_event = on_event
        self._own_files = {config.queue_file.resolve(), config.log_file.resolve(), config.quarantine_folder.resolve()}
        self._pending: set[str] = set()
        self._vanished: dict[str, float] = {}  # path -> time it vanished before it was ever reported
        self._pending_lock = threading.Lock()
        self._suppressed: dict[str, float] = {}  # paths the agent itself moves (quarantine/release) -> until
        self._known_hashes: dict[str, str | None] = {}
        self._work: queue.Queue[tuple | None] = queue.Queue()
        self._observer = Observer()
        self._workers = [threading.Thread(target=self._process_created, name=f"mst-file-worker-{number}", daemon=True) for number in range(WORKERS)]
        self.watched: list[Path] = []

    # ---- filtering -------------------------------------------------------
    def is_ignored(self, path: Path) -> bool:
        name = path.name
        if not name or name.startswith(self.config.ignore_name_prefixes):
            return True
        if path.suffix.lower() in self.config.ignore_extensions:
            return True
        resolved = path.resolve() if path.exists() else path
        # Never report the agent's own queue/log files (or SQLite's journal files next to them).
        return any(str(resolved).startswith(str(own)) for own in self._own_files)

    # ---- lifecycle -------------------------------------------------------
    def start(self) -> list[Path]:
        handler = _Handler(self)
        for folder in self.config.watch_folders:
            if folder.is_dir():
                self._observer.schedule(handler, str(folder), recursive=self.config.recursive)
                self.watched.append(folder)
            else:
                log.warning("Watch folder does not exist and is skipped: %s", folder)
        for worker in self._workers:
            worker.start()
        self._observer.start()
        return self.watched

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=5)
        for worker in self._workers:
            self._work.put(None)
        for worker in self._workers:
            worker.join(timeout=5)

    # ---- events ----------------------------------------------------------
    def suppress(self, path: Path, seconds: float = 30.0) -> None:
        """Ignore events for a path the agent is about to move itself (quarantine / release)."""
        with self._pending_lock:
            self._suppressed[str(path)] = time.monotonic() + seconds

    def _is_suppressed(self, path: Path) -> bool:
        with self._pending_lock:
            now = time.monotonic()
            self._suppressed = {key: until for key, until in self._suppressed.items() if until > now}
            return str(path) in self._suppressed

    def created(self, path: Path, browser_download: bool = False) -> None:
        self._queue("created", path, browser_download=browser_download)

    def modified(self, path: Path) -> None:
        self._queue("modified", path)

    def renamed(self, source: Path, destination: Path) -> None:
        self._queue("renamed", destination, previous=source)

    def _queue(self, kind: str, path: Path, browser_download: bool = False, previous: Path | None = None) -> None:
        if self.is_ignored(path) or self._is_suppressed(path):
            return
        with self._pending_lock:
            if str(path) in self._pending:
                return  # watchdog can fire several events for the same file while it is being written
            self._pending.add(str(path))
        self._work.put((kind, path, utc_now(), browser_download, previous))

    def deleted(self, path: Path) -> None:
        if self.is_ignored(path) or self._is_suppressed(path):
            return
        with self._pending_lock:
            vanished_at = self._vanished.pop(str(path), None)
            if str(path) in self._pending or (vanished_at is not None and time.monotonic() - vanished_at < VANISHED_MEMORY_SECONDS):
                # The file was never reported as new: either it is still being checked (the worker reports it
                # only if it still exists) or it already vanished unreported (Firefox's placeholder replaced by
                # the finished download, a short-lived temp file). Reporting its deletion would be a false alarm.
                return
            self._known_hashes.pop(str(path), None)
        self._emit("deleted", path, detected_at=utc_now())

    def _remember(self, path: Path, sha256: str | None) -> None:
        with self._pending_lock:
            self._known_hashes.pop(str(path), None)
            self._known_hashes[str(path)] = sha256
            while len(self._known_hashes) > KNOWN_HASHES_LIMIT:
                self._known_hashes.pop(next(iter(self._known_hashes)))

    def _process_created(self) -> None:
        while True:
            item = self._work.get()
            if item is None:
                return
            kind, path, detected_at, browser_download, previous = item
            try:
                size = self._wait_until_stable(path)
                if size is None:
                    with self._pending_lock:
                        now = time.monotonic()
                        self._vanished = {key: at for key, at in self._vanished.items() if now - at < VANISHED_MEMORY_SECONDS}
                        self._vanished[str(path)] = now
                    continue
                with self._pending_lock:
                    known = previous is not None and str(previous) in self._known_hashes
                    previous_hash = self._known_hashes.pop(str(previous), None) if previous is not None else self._known_hashes.get(str(path))
                    seen_before = str(path) in self._known_hashes
                sha256 = previous_hash if kind == "renamed" and known else sha256_of(path, self.config.max_hash_bytes)
                if kind == "modified" and seen_before and sha256 == previous_hash:
                    continue  # only the timestamp or metadata changed
                self._remember(path, sha256)
                origin, url = "local", None
                download = mark_of_the_web(path)
                if download and download["zone"] >= 3:
                    origin, url = "internet", download["hostUrl"]
                elif browser_download:
                    origin = "browser_download"
                self._emit(kind, path, detected_at=detected_at, size=size, sha256=sha256, previous=previous, origin=origin, download_url=url)
            except Exception:  # never let one bad file stop the monitor
                log.exception("Could not process file event for %s", path)
            finally:
                with self._pending_lock:
                    self._pending.discard(str(path))

    def _wait_until_stable(self, path: Path) -> int | None:
        """Waits until the file stops growing (e.g. a download finished). Returns its size, or None if it vanished."""
        last_size, stable, waited = -1, 0, 0.0
        while waited < MAX_WAIT_SECONDS:
            try:
                size = path.stat().st_size
            except FileNotFoundError:
                return None
            stable = stable + 1 if size == last_size else 0
            if stable >= STABLE_CHECKS:
                return size
            last_size = size
            time.sleep(CHECK_INTERVAL)
            waited += CHECK_INTERVAL
        return last_size if last_size >= 0 else None

    def _emit(self, event_type: str, path: Path, detected_at: str, size: int | None = None, sha256: str | None = None,
              previous: Path | None = None, origin: str | None = None, download_url: str | None = None) -> None:
        event = {
            "uid": str(uuid.uuid4()),
            "type": event_type,
            "fileName": path.name[:255],
            "filePath": str(path)[:1024],
            "previousPath": str(previous)[:1024] if previous is not None else None,
            "fileSize": size,
            "sha256": sha256,
            "detectedAt": detected_at,
            "origin": origin,
            "downloadUrl": download_url,
        }
        detail = f" ({size} bytes)" if size is not None else ""
        log.info("File %s: %s%s%s", event_type, f"{previous} -> " if previous else "", path, detail + (f" [{origin}]" if origin and origin != "local" else ""))
        self.on_event(event)


class _Handler(FileSystemEventHandler):
    def __init__(self, monitor: FileMonitor):
        self.monitor = monitor

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.monitor.created(Path(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.monitor.modified(Path(event.src_path))

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.monitor.deleted(Path(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        source, destination = Path(event.src_path), Path(event.dest_path)
        if source.suffix.lower() in BROWSER_TEMP_EXTENSIONS:
            # Browsers download to "file.crdownload" / "file.part" and rename it when the download is complete.
            self.monitor.created(destination, browser_download=True)
        elif self.monitor.is_ignored(source):
            self.monitor.created(destination)   # e.g. an editor saving through a temporary file
        elif self.monitor.is_ignored(destination):
            self.monitor.deleted(source)
        else:
            self.monitor.renamed(source, destination)
