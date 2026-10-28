"""Detects files deleted to the Windows Recycle Bin (the Delete key in File Explorer), from any folder on the drive.

When File Explorer deletes a file, Windows moves it to <drive>:\\$Recycle.Bin\\<user SID>\\$R<id><ext> and writes a small
record $I<id><ext> next to it with the file's ORIGINAL path, its size and the exact time it was deleted. The agent
reads only these records (never the deleted file itself) and reports:

  recycle_bin          - moved to the Recycle Bin (with the original path and the real delete time)
  recycle_bin_removed  - removed from the Recycle Bin (emptied, or deleted from it): now permanently gone

A small state file remembers the records already seen, so items deleted while the agent was not running are still
reported (with their real delete time) the next time it starts. Restoring an item from the Recycle Bin is not a
deletion and is not reported as one.

Windows creates a user's Recycle Bin folder on a drive only at the first delete there, so the folders are looked for
again while the agent runs (and right before a delete would be called "permanent", see FileMonitor).
"""

from __future__ import annotations

import json
import logging
import os
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .config_store import write_json

log = logging.getLogger("mst_agent.recycle")

RESTORE_CHECK_SECONDS = 2.0   # after a record disappears, wait this long before deciding "restored" or "removed"
FOLDER_CHECK_SECONDS = 10.0   # how often new Recycle Bin folders (first delete on a drive, new user) are looked for
URGENT_FOLDER_CHECK_SECONDS = 2.0  # at most this often when a delete is waiting on a drive whose bin is not watched yet
FAILED_WATCH_RETRY_SECONDS = 600.0  # a bin folder that cannot be watched is tried again (and logged) this rarely
SAVE_DELAY_SECONDS = 1.0      # state changes are written at most this often (emptying a big bin = one write, not 5000)
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def parse_index(data: bytes) -> dict | None:
    """Parses a $I record. Version 1 (Windows Vista-8.1): fixed 260-character path. Version 2 (Windows 10/11):
    path length + path. Returns {"originalPath", "size", "deletedAt"}, or None if the record is not valid or not
    completely written yet (a half-written record would give a cut-off path)."""
    try:
        version, size, filetime = struct.unpack_from("<qqq", data, 0)
        if version == 1:
            raw = data[24:24 + 520]
            if len(raw) < 520:
                return None
        elif version == 2:
            (length,) = struct.unpack_from("<i", data, 24)
            if not 1 < length <= 32768:
                return None
            raw = data[28:28 + length * 2]
            if len(raw) < length * 2 or raw[-2:] != b"\0\0":  # the path ends with its terminating null character
                return None
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


def drive_of(path: Path | str) -> str:
    """'C:' for C:\\..., '' when the path has no drive letter."""
    return PureWindowsPath(str(path)).drive.upper()


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
    """Watches Recycle Bin folders and calls back with what was moved into / removed from the Recycle Bin.

    find_folders: returns the folders to watch now (called at start and again every FOLDER_CHECK_SECONDS), or None
    when the folders are fixed (configured). covers(path): whether a delete at `path` would leave a record here."""

    def __init__(self, folders: list[Path], state_file: Path,
                 on_recycled: Callable[[dict], None], on_removed: Callable[[dict, bool], None],
                 find_folders: Callable[[], list[Path]] | None = None):
        self.folders: list[Path] = []
        self._initial = list(folders)
        self._find_folders = find_folders
        self.state_file = state_file
        self.on_recycled = on_recycled      # record (+ "isFolder") moved into the Recycle Bin
        self.on_removed = on_removed        # record removed from the Recycle Bin; flag: noticed while the agent was off
        self._known: dict[str, dict] = {}   # $I path -> record (kept until a removal is decided, so it survives a stop)
        self._removals: dict[str, float] = {}  # $I path -> decide "restored" or "removed" after this time
        self._lock = threading.RLock()
        self._dirty_since: float | None = None
        self._observer = Observer()
        self._handler = _Handler(self)
        self._started_at = ""
        self._last_folder_check = 0.0
        self._unreadable: dict[str, tuple[int, float]] = {}  # $I path -> (size, mtime) of a record that cannot be parsed
        self._watches: dict[str, object] = {}       # folder key -> watchdog watch
        self._failed_watch: dict[str, float] = {}   # folder key -> do not try again before

    # ---- state -----------------------------------------------------------
    def _load_state(self) -> dict[str, dict] | None:
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _mark_dirty(self) -> None:
        if self._dirty_since is None:
            self._dirty_since = time.monotonic()

    def save(self) -> None:
        with self._lock:
            snapshot, dirty_since, self._dirty_since = dict(self._known), self._dirty_since, None
            try:
                self.state_file.parent.mkdir(parents=True, exist_ok=True)
                write_json(self.state_file, snapshot)
            except OSError as error:
                log.warning("Could not save the Recycle Bin state (will try again): %s", error)
                self._dirty_since = dirty_since or time.monotonic()

    @staticmethod
    def _read(index: Path, attempts: int = 5) -> dict | None:
        record, _ = RecycleBinWatcher._read_status(index, attempts)
        return record

    @staticmethod
    def _read_status(index: Path, attempts: int = 5) -> tuple[dict | None, str]:
        """(record, "ok") | (None, "locked") when the file could not be opened | (None, "invalid") when it was read
        but is not (yet) a complete record."""
        status = "invalid"
        for attempt in range(attempts):  # the record may still be being written
            try:
                record = parse_index(index.read_bytes())
                status = "invalid"
            except OSError:
                record, status = None, "locked"
            if record is not None:
                record["isFolder"] = index.with_name("$R" + index.name[2:]).is_dir()
                return record, "ok"
            if attempt + 1 < attempts:
                time.sleep(0.2)
        return None, status

    def _scan(self, folders: list[Path], attempts: int = 1) -> dict[str, dict]:
        found: dict[str, dict] = {}
        for folder in folders:
            try:
                names = os.listdir(folder)
            except OSError:
                continue
            for name in names:
                if is_index_name(name):
                    record = self._read(folder / name, attempts=attempts)
                    if record is not None:
                        found[str(folder / name)] = record
        return found

    def covers(self, path: Path | str) -> bool:
        """True when a delete at `path` leaves a record in a Recycle Bin folder this watcher reads."""
        if self._find_folders is None:
            return bool(self.folders)  # configured folders: they stand for every path (tests, special setups)
        drives = {drive_of(folder) for folder in self.folders}
        return drive_of(path) in drives

    # ---- lifecycle ---------------------------------------------------------
    def start(self) -> list[Path]:
        self._started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        folders = list(self._initial)
        current = self._scan(folders, attempts=5)
        previous = self._load_state()
        known = dict(current)
        if previous is None:
            log.info("Recycle Bin: %d item(s) already there are taken as the starting point", len(current))
        else:
            # Changes while the agent was not running.
            for key, record in current.items():
                if key not in previous:
                    self.on_recycled(record)
            for key, record in previous.items():
                if key in current or not isinstance(record, dict):
                    continue
                if not self._readable(Path(key).parent) or Path(key).exists():
                    # Its bin is not readable now (a USB drive that is unplugged) or the record is only busy:
                    # keep it as it was, nothing is reported.
                    known[key] = record
                elif not Path(record.get("originalPath", "")).exists():
                    self.on_removed(record, True)
        with self._lock:
            self._known = known
        self.save()
        for folder in folders:
            if self._readable(folder):  # a bin on an unplugged USB drive is picked up again when it is back
                self._watch(folder)
        self._observer.start()
        self._last_folder_check = time.monotonic()
        return list(self.folders)

    @staticmethod
    def _readable(folder: Path) -> bool:
        try:
            os.listdir(folder)
            return True
        except OSError:
            return False

    def _watch(self, folder: Path) -> bool:
        key = os.path.normcase(str(folder))
        if self._failed_watch.get(key, 0) > time.monotonic():
            return False
        try:
            watch = self._observer.schedule(self._handler, str(folder), recursive=False)
        except OSError as error:
            log.warning("Cannot watch the Recycle Bin folder %s (trying again in %d minutes): %s", folder, FAILED_WATCH_RETRY_SECONDS // 60, error)
            self._failed_watch[key] = time.monotonic() + FAILED_WATCH_RETRY_SECONDS
            return False
        self._failed_watch.pop(key, None)
        self._watches[key] = watch
        self.folders.append(folder)
        return True

    def _forget(self, folder: Path) -> None:
        """A watched bin that went away (USB drive unplugged): stop watching it, so it is watched again when back."""
        watch = self._watches.pop(os.path.normcase(str(folder)), None)
        try:
            if watch is not None:
                self._observer.unschedule(watch)
        except (KeyError, ValueError, OSError):
            pass
        self.folders = [other for other in self.folders if other != folder]
        log.info("Recycle Bin folder %s is no longer available", folder)

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=5)
        self.save()  # undecided removals stay in the state: they are decided at the next start

    # ---- called regularly by the file monitor -----------------------------
    def tick(self) -> None:
        now = time.monotonic()
        if self._find_folders is not None and now - self._last_folder_check >= FOLDER_CHECK_SECONDS:
            self.refresh_folders()
        self._decide_removals(now)
        if self._dirty_since is not None and now - self._dirty_since >= SAVE_DELAY_SECONDS:
            self.save()

    def refresh_folders(self) -> None:
        """Starts watching Recycle Bin folders that appeared since the start (the first delete on a drive creates
        the folder). Records in a new folder that were deleted after the agent started are reported."""
        if self._find_folders is None:
            return
        self._last_folder_check = time.monotonic()
        for folder in list(self.folders):
            if not self._readable(folder):
                self._forget(folder)
        known = {os.path.normcase(str(folder)) for folder in self.folders}
        for folder in self._find_folders():
            if os.path.normcase(str(folder)) in known or not self._watch(folder):
                continue
            log.info("Watching a new Recycle Bin folder: %s", folder)
            for key, record in self._scan([folder]).items():
                with self._lock:
                    if key in self._known:
                        continue
                    self._known[key] = record
                    self._mark_dirty()
                if record["deletedAt"] >= self._started_at:
                    self.on_recycled(record)

    def poll(self, refresh: bool = False, force: bool = False) -> None:
        """Looks at the Recycle Bin right now (records, and new folders when `refresh`), without waiting for file
        notifications. Called before a delete is reported as permanent, so a slow or missed notification cannot
        mislabel it. Reads each record once, without waiting: a half-written one is read again on the next call."""
        if refresh and (force or time.monotonic() - self._last_folder_check >= URGENT_FOLDER_CHECK_SECONDS):
            self.refresh_folders()
        for folder in list(self.folders):
            try:
                names = os.listdir(folder)
            except OSError:
                continue
            for name in names:
                if is_index_name(name):
                    self.index_added(folder / name, attempts=1)

    # ---- events ------------------------------------------------------------
    def index_added(self, index: Path, attempts: int = 5) -> None:
        if not is_index_name(index.name):
            return
        with self._lock:
            if str(index) in self._known:
                self._removals.pop(str(index), None)  # it came back (e.g. rewritten): not removed
                return
        try:
            info = index.stat()
            signature = (info.st_size, info.st_mtime)
        except OSError:
            return
        if self._unreadable.get(str(index)) == signature:
            return  # a record that could not be parsed: read again only once the file changes
        record, status = self._read_status(index, attempts)
        if record is None:
            if status == "invalid":  # a locked record (Explorer still holds it) is simply read again next time
                self._unreadable[str(index)] = signature
            return
        self._unreadable.pop(str(index), None)
        with self._lock:
            if str(index) in self._known:
                return
            self._known[str(index)] = record
            self._mark_dirty()
        self.on_recycled(record)

    def index_removed(self, index: Path) -> None:
        if not is_index_name(index.name):
            return
        with self._lock:
            if str(index) in self._known:
                # Restoring moves the item back to its original place: decided after a short wait, in tick().
                self._removals[str(index)] = time.monotonic() + RESTORE_CHECK_SECONDS

    def _decide_removals(self, now: float) -> None:
        with self._lock:
            due = [key for key, when in self._removals.items() if when <= now]
            decided = []
            for key in due:
                self._removals.pop(key, None)
                if Path(key).exists():
                    continue  # the record is back
                record = self._known.pop(key, None)
                if record is not None:
                    decided.append(record)
                    self._mark_dirty()
        for record in decided:
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
