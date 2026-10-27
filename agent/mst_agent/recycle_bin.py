"""Detects files deleted to the Windows Recycle Bin (the Delete key in File Explorer), from any folder on the drive.

When File Explorer deletes a file, Windows moves it to <drive>:\\$Recycle.Bin\\<user SID>\\$R<id><ext> and writes a small
record $I<id><ext> next to it with the file's ORIGINAL path, its size and the exact time it was deleted. The agent
reads only these records (never the deleted file itself) and reports:

  recycle_bin          - moved to the Recycle Bin (with the original path and the real delete time)
  recycle_bin_removed  - removed from the Recycle Bin (emptied, or deleted from it): now permanently gone

A small state file remembers the records already seen, so items deleted while the agent was not running are still
reported (with their real delete time) the next time it starts. Restoring an item from the Recycle Bin is not a
deletion and is not reported as one.
"""

from __future__ import annotations

import json
import logging
import os
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .config_store import write_json

log = logging.getLogger("mst_agent.recycle")

RESTORE_CHECK_SECONDS = 2.0   # after a record disappears, wait this long before deciding "restored" or "removed"
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def parse_index(data: bytes) -> dict | None:
    """Parses a $I record. Version 1 (Windows Vista-8.1): fixed 260-character path. Version 2 (Windows 10/11):
    path length + path. Returns {"originalPath", "size", "deletedAt"} or None if the record is not valid."""
    try:
        version, size, filetime = struct.unpack_from("<qqq", data, 0)
        if version == 1:
            raw = data[24:24 + 520]
        elif version == 2:
            (length,) = struct.unpack_from("<i", data, 24)
            if not 0 < length <= 32768:
                return None
            raw = data[28:28 + length * 2]
        else:
            return None
        path = raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
        deleted_at = FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
    except (struct.error, OverflowError, ValueError):
        return None
    if not path or size < 0:
        return None
    return {"originalPath": path, "size": size, "deletedAt": deleted_at.strftime("%Y-%m-%dT%H:%M:%SZ")}


def is_index_name(name: str) -> bool:
    return name.startswith("$I") and len(name) > 2


def default_recycle_folders(drives: list[Path]) -> list[Path]:
    """This Windows user's Recycle Bin folder on every drive (other users' folders are not readable, and skipped)."""
    folders: list[Path] = []
    for drive in drives:
        root = drive / "$Recycle.Bin"
        try:
            children = [child for child in root.iterdir() if child.is_dir()]
        except OSError:
            continue
        for child in children:
            try:
                os.listdir(child)  # readable = this user's own Recycle Bin
            except OSError:
                continue
            folders.append(child)
    return folders


class RecycleBinWatcher:
    """Watches Recycle Bin folders and calls back with what was moved into / removed from the Recycle Bin."""

    def __init__(self, folders: list[Path], state_file: Path,
                 on_recycled: Callable[[dict], None], on_removed: Callable[[dict, bool], None]):
        self.folders = folders
        self.state_file = state_file
        self.on_recycled = on_recycled      # record (+ "isFolder") moved into the Recycle Bin
        self.on_removed = on_removed        # record removed from the Recycle Bin; flag: noticed while the agent was off
        self._known: dict[str, dict] = {}   # $I path -> record
        self._lock = threading.Lock()
        self._observer = Observer()

    # ---- state -----------------------------------------------------------
    def _load_state(self) -> dict[str, dict] | None:
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _save_state(self) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            write_json(self.state_file, self._known)
        except OSError as error:
            log.warning("Could not save the Recycle Bin state: %s", error)

    @staticmethod
    def _read(index: Path) -> dict | None:
        for _ in range(5):  # the record may still be being written
            try:
                record = parse_index(index.read_bytes())
            except OSError:
                record = None
            if record is not None:
                data_file = index.with_name("$R" + index.name[2:])
                record["isFolder"] = data_file.is_dir()
                return record
            time.sleep(0.2)
        return None

    def _scan(self) -> dict[str, dict]:
        found: dict[str, dict] = {}
        for folder in self.folders:
            try:
                names = os.listdir(folder)
            except OSError:
                continue
            for name in names:
                if is_index_name(name):
                    record = self._read(folder / name)
                    if record is not None:
                        found[str(folder / name)] = record
        return found

    # ---- lifecycle ---------------------------------------------------------
    def start(self) -> list[Path]:
        current = self._scan()
        previous = self._load_state()
        with self._lock:
            self._known = dict(current)
        if previous is None:
            log.info("Recycle Bin: %d item(s) already there are taken as the starting point", len(current))
        else:
            # Changes while the agent was not running.
            for key, record in current.items():
                if key not in previous:
                    self.on_recycled(record)
            for key, record in previous.items():
                if key not in current and isinstance(record, dict) and not Path(record.get("originalPath", "")).exists():
                    self.on_removed(record, True)
        self._save_state()
        handler = _Handler(self)
        watched = []
        for folder in self.folders:
            try:
                self._observer.schedule(handler, str(folder), recursive=False)
                watched.append(folder)
            except OSError as error:
                log.warning("Cannot watch the Recycle Bin folder %s: %s", folder, error)
        self._observer.start()
        return watched

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=5)

    # ---- events ------------------------------------------------------------
    def index_added(self, index: Path) -> None:
        if not is_index_name(index.name):
            return
        with self._lock:
            if str(index) in self._known:
                return
        record = self._read(index)
        if record is None:
            return
        with self._lock:
            if str(index) in self._known:
                return
            self._known[str(index)] = record
            self._save_state()
        self.on_recycled(record)

    def index_removed(self, index: Path) -> None:
        if not is_index_name(index.name):
            return
        with self._lock:
            record = self._known.pop(str(index), None)
            self._save_state()
        if record is None:
            return
        # Restoring moves the item back to its original place: that is not a deletion.
        threading.Timer(RESTORE_CHECK_SECONDS, self._decide_removed, args=(record,)).start()

    def _decide_removed(self, record: dict) -> None:
        if not Path(record["originalPath"]).exists():
            self.on_removed(record, False)


class _Handler(FileSystemEventHandler):
    def __init__(self, watcher: RecycleBinWatcher):
        self.watcher = watcher

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.watcher.index_added(Path(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.watcher.index_added(Path(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        self.watcher.index_removed(Path(event.src_path))
        self.watcher.index_added(Path(event.dest_path))

    def on_deleted(self, event: FileSystemEvent) -> None:
        self.watcher.index_removed(Path(event.src_path))
