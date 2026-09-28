"""Watches the configured folders and turns new/deleted files into MST file events.

Only file metadata (name, location, size, time) and a SHA-256 fingerprint are collected.
File contents are read solely to compute the hash and are never uploaded.
"""

from __future__ import annotations

import hashlib
import logging
import queue
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .config import AgentConfig

log = logging.getLogger("mst_agent.files")

STABLE_CHECKS = 2          # size must be unchanged for this many consecutive checks
CHECK_INTERVAL = 1.0       # seconds between size checks
MAX_WAIT_SECONDS = 300     # give up waiting for very slow downloads after 5 minutes
HASH_CHUNK = 1024 * 1024
WORKERS = 4                # new files are checked in parallel so a burst of files is not delayed


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


class FileMonitor:
    def __init__(self, config: AgentConfig, on_event: Callable[[dict], None]):
        self.config = config
        self.on_event = on_event
        self._own_files = {config.queue_file.resolve(), config.log_file.resolve()}
        self._pending: set[str] = set()
        self._pending_lock = threading.Lock()
        self._work: queue.Queue[tuple[Path, str] | None] = queue.Queue()
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
    def created(self, path: Path) -> None:
        if self.is_ignored(path):
            return
        with self._pending_lock:
            if str(path) in self._pending:
                return  # watchdog can fire "created" more than once for the same file
            self._pending.add(str(path))
        self._work.put((path, utc_now()))

    def deleted(self, path: Path) -> None:
        if self.is_ignored(path):
            return
        with self._pending_lock:
            self._pending.discard(str(path))
        self._emit("deleted", path, detected_at=utc_now())

    def _process_created(self) -> None:
        while True:
            item = self._work.get()
            if item is None:
                return
            path, detected_at = item
            try:
                size = self._wait_until_stable(path)
                if size is not None:
                    self._emit("created", path, detected_at=detected_at, size=size, sha256=sha256_of(path, self.config.max_hash_bytes))
            except Exception:  # never let one bad file stop the monitor
                log.exception("Could not process new file %s", path)
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

    def _emit(self, event_type: str, path: Path, detected_at: str, size: int | None = None, sha256: str | None = None) -> None:
        event = {
            "uid": str(uuid.uuid4()),
            "type": event_type,
            "fileName": path.name[:255],
            "filePath": str(path)[:1024],
            "fileSize": size,
            "sha256": sha256,
            "detectedAt": detected_at,
        }
        log.info("File %s: %s%s", event_type, path, f" ({size} bytes)" if size is not None else "")
        self.on_event(event)


class _Handler(FileSystemEventHandler):
    def __init__(self, monitor: FileMonitor):
        self.monitor = monitor

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.monitor.created(Path(event.src_path))

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.monitor.deleted(Path(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        # Browsers download to "file.crdownload" and rename it when finished; the rename is the real "new file".
        if not event.is_directory:
            self.monitor.deleted(Path(event.src_path))
            self.monitor.created(Path(event.dest_path))
