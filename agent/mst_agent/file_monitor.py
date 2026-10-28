"""Watches the configured folders and turns new, modified, renamed and deleted files into MST file events.

Only file metadata (name, location, size, time), a SHA-256 fingerprint and download evidence are collected.
File contents are read solely to compute the hash and are never uploaded.

How a file was deleted is reported as "deleteMode" (Phase 16):
  recycle_bin          - moved to the Recycle Bin (File Explorer's Delete key), from any folder on the drive, with the
                         original path and the real delete time (see recycle_bin.py)
  permanent            - deleted without the Recycle Bin (Shift+Delete, a USB drive, a program, the command line):
                         reported only when that drive's Recycle Bin is watched (or it is a USB drive, which has none)
  recycle_bin_removed  - removed from the Recycle Bin (emptied): now permanently gone
  (none)               - the agent cannot tell (Recycle Bin watching is off or that drive's bin is not readable)

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
from .folders import fixed_drives, removable_drives
from .recycle_bin import RecycleBinWatcher, default_recycle_folders, drive_of

log = logging.getLogger("mst_agent.files")

STABLE_CHECKS = 2          # size must be unchanged for this many consecutive checks
CHECK_INTERVAL = 1.0       # seconds between size checks
MAX_WAIT_SECONDS = 300     # give up waiting for very slow downloads after 5 minutes
HASH_CHUNK = 1024 * 1024
VANISHED_MEMORY_SECONDS = 15  # a file that appeared and vanished unreported: ignore its delete for this long
WORKERS = 4                # new files are checked in parallel so a burst of files is not delayed
BROWSER_TEMP_EXTENSIONS = {".crdownload", ".part", ".partial", ".download", ".opdownload"}
KNOWN_HASHES_LIMIT = 5000  # remembered file hashes, to report "modified" only when the content really changed
DELETE_GRACE_SECONDS = 3.0 # a delete waits this long for its Recycle Bin record before it is reported as permanent
RECYCLED_MEMORY_SECONDS = 30.0
DRIVE_CHECK_SECONDS = 10.0 # how often plugged-in USB drives are looked for
AGENT_FOLDER = Path(__file__).resolve().parents[1]


def now_monotonic() -> float:
    return time.monotonic()


def _inside(path: Path, folder: Path) -> bool:
    try:
        path.relative_to(folder)
        return True
    except ValueError:
        return False


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
        # Never report the agent's own files: its folder (program, .venv, config), queue, log, quarantine and state.
        own_dirs = [AGENT_FOLDER, config.quarantine_folder]
        own_files = [config.queue_file, config.log_file, config.queue_file.with_name("mst_recycle_state.json")]
        # Both spellings of each path (as configured and resolved: a mapped/subst drive or a junction differs).
        spell = lambda paths: {path.absolute() for path in paths} | {path.resolve() for path in paths}
        self._own_files = spell(own_dirs) | spell(own_files)
        self._own_dir_keys = tuple(sorted({self._key(path) for path in spell(own_dirs)}))
        self._own_file_keys = tuple(sorted({self._key(path) for path in spell(own_files)}))
        self._recycle_lock = threading.Lock()  # one thread at a time looks at the Recycle Bin (housekeeping / stop)
        self._pending_deletes: dict[str, tuple[Path, str, float]] = {}  # path key -> (path, detected at, report after)
        self._recycled_recently: dict[str, float] = {}                 # path key -> forget after
        self._removable: dict[str, object] = {}                        # USB drive root -> watchdog watch
        self._drives_lock = threading.Lock()                           # _removable changes while events are filtered
        self._housekeeper: threading.Thread | None = None
        self._recycle: RecycleBinWatcher | None = None
        self._stop = threading.Event()
        self._handler = None
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
        # Cheapest checks first: this runs for every change under the watched folders (AppData included).
        name = path.name
        if not name or name.startswith(self.config.ignore_name_prefixes):
            return True
        if path.suffix.lower() in self.config.ignore_extensions:
            return True
        if self._in_ignored_folder(path, whole_path=False):
            return True
        # Never report the agent's own files (or SQLite's journal files next to its queue). No disk access needed:
        # watchdog reports absolute paths.
        return self._is_own(self._key(path))

    def _is_own(self, key: str) -> bool:
        """The path is one of the agent's own folders or something inside it, or one of its own files or a side file
        of one (queue.db-wal, state.json.tmp). A sibling that only shares the start of the name (agent_backup,
        agent-old, quarantine-2024) is not."""
        for own in self._own_dir_keys:
            if key == own or key.startswith(own + os.sep):
                return True
        for own in self._own_file_keys:
            if key == own or (key.startswith(own) and key[len(own)] in "-." and os.sep not in key[len(own):]):
                return True
        return False

    def _roots(self) -> list[Path]:
        with self._drives_lock:
            removable = [Path(key) for key in self._removable]
        return [*self.watched, *removable]

    def _in_ignored_folder(self, path: Path, whole_path: bool = True) -> bool:
        """True when a folder between the watched folder and the file is noise (AppData, Temp, .git, ...).
        whole_path: also check the folders above the watched folders (Recycle Bin records can come from anywhere)."""
        roots = [root for root in self._roots() if path == root or _inside(path, root)]
        if roots:
            parts = path.relative_to(max(roots, key=lambda root: len(str(root)))).parts[:-1]
        elif whole_path:
            parts = path.parts[:-1]
        else:
            return False
        return any(part.lower() in self.config.ignore_folders for part in parts)

    @staticmethod
    def _key(path: Path | str) -> str:
        return os.path.normcase(str(path))

    # ---- lifecycle -------------------------------------------------------
    def start(self) -> list[Path]:
        self._handler = handler = _Handler(self)
        for folder in self.config.watch_folders:
            if folder.is_dir():
                self._observer.schedule(handler, str(folder), recursive=self.config.recursive)
                self.watched.append(folder)
            else:
                log.warning("Watch folder does not exist and is skipped: %s", folder)
        for worker in self._workers:
            worker.start()
        self._observer.start()
        self._housekeeper = threading.Thread(target=self._housekeeping, name="mst-file-housekeeping", daemon=True)
        self._housekeeper.start()
        if self.config.watch_removable_drives:
            self._check_removable_drives()
        if self.config.watch_recycle_bin:
            find = None if self.config.recycle_bin_folders else (lambda: default_recycle_folders(fixed_drives() + removable_drives()))
            folders = self.config.recycle_bin_folders or find()
            self._recycle = RecycleBinWatcher(folders, self.config.queue_file.resolve().with_name("mst_recycle_state.json"),
                                              self.recycled, self.removed_from_recycle_bin, find_folders=find)
            recycle_watched = self._recycle.start()
            log.info("Watching the Recycle Bin on %d drive(s): deletes with File Explorer are reported from any folder", len(recycle_watched))
        return self.watched

    def stop(self) -> None:
        # Order matters: no new file events, then one last look at the Recycle Bin so a delete made just before the
        # stop gets its real label, then the remaining deletes, then save the Recycle Bin state.
        self._stop.set()
        if self._housekeeper is not None:
            self._housekeeper.join(timeout=10)  # never two threads checking the Recycle Bin at once
        self._observer.stop()
        self._observer.join(timeout=5)
        with self._recycle_lock:  # even if the housekeeper is still finishing a pass, it cannot run at the same time
            if self._recycle is not None:
                try:
                    self._recycle.poll(refresh=True, force=True)
                except Exception:
                    log.exception("Last Recycle Bin check failed")
            self._flush_pending_deletes(force=True, poll=False)
            if self._recycle is not None:
                self._recycle.stop()
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
            key = self._key(path)
            if self._recently_recycled(key):
                return  # already reported from its (or its folder's) Recycle Bin record
            # Wait briefly for a Recycle Bin record: then it is "moved to the Recycle Bin", otherwise "permanent".
            self._pending_deletes[key] = (path, utc_now(), now_monotonic() + DELETE_GRACE_SECONDS)

    def _recently_recycled(self, key: str) -> bool:
        """The path itself, or a folder above it, was just reported from a Recycle Bin record (call with the lock)."""
        now = now_monotonic()
        candidate = key
        while True:
            if self._recycled_recently.get(candidate, 0) > now:
                return True
            parent = os.path.dirname(candidate)
            if not parent or parent == candidate:
                return False
            candidate = parent

    def _delete_mode_when_no_record(self, path: Path) -> str | None:
        """'permanent' only when the agent would have seen a Recycle Bin record; otherwise it cannot tell (None)."""
        if self._recycle is not None and self._recycle.covers(path):
            return "permanent"
        with self._drives_lock:
            usb = {drive_of(root) for root in self._removable}
        return "permanent" if drive_of(path) and drive_of(path) in usb else None  # USB drives have no Recycle Bin

    # ---- Recycle Bin (Phase 16) -------------------------------------------
    def recycled(self, record: dict) -> None:
        """A file or folder was moved to the Recycle Bin (from any folder). Reported with its original path and the
        real delete time; replaces the plain delete the folder watcher may have seen for the same path."""
        path = Path(record["originalPath"])
        if path.name.startswith(self.config.ignore_name_prefixes) or (not record.get("isFolder") and path.suffix.lower() in self.config.ignore_extensions):
            return
        if self._in_ignored_folder(path):
            return
        key = self._key(path)
        with self._pending_lock:
            self._pending_deletes.pop(key, None)
            if record.get("isFolder"):  # files of a deleted folder are covered by the folder's record
                for pending in [other for other in self._pending_deletes if other.startswith(key + os.sep)]:
                    self._pending_deletes.pop(pending, None)
            self._recycled_recently[key] = now_monotonic() + RECYCLED_MEMORY_SECONDS
        self._emit("deleted", path, detected_at=record["deletedAt"], size=record.get("size"), delete_mode="recycle_bin", is_folder=bool(record.get("isFolder")))

    def removed_from_recycle_bin(self, record: dict, while_agent_off: bool) -> None:
        path = Path(record["originalPath"])
        if self._in_ignored_folder(path):
            return
        self._emit("deleted", path, detected_at=utc_now(), size=record.get("size"), delete_mode="recycle_bin_removed",
                   is_folder=bool(record.get("isFolder")), note="while the agent was off" if while_agent_off else None)

    def _flush_pending_deletes(self, force: bool = False, poll: bool = True) -> None:
        now = now_monotonic()
        with self._pending_lock:
            self._recycled_recently = {key: until for key, until in self._recycled_recently.items() if until > now}
            any_due = any(force or report_after <= now for _, _, report_after in self._pending_deletes.values())
        if not any_due:
            return
        # Before calling anything "permanent", read the Recycle Bin directly: a record whose notification is late
        # (many files deleted at once) or missing (the bin folder was only just created) is matched now.
        if poll and self._recycle is not None:
            with self._pending_lock:
                due_paths = [path for path, _, report_after in self._pending_deletes.values() if force or report_after <= now]
            try:
                # New bin folders are looked for only when a due delete's drive has none watched yet.
                self._recycle.poll(refresh=any(not self._recycle.covers(path) for path in due_paths))
            except Exception:
                log.exception("Recycle Bin check failed")
        now = now_monotonic()
        with self._pending_lock:
            due = [key for key, (_, _, report_after) in self._pending_deletes.items() if force or report_after <= now]
            items = [self._pending_deletes.pop(key) for key in due]
            items = [item for key, item in zip(due, items) if not self._recently_recycled(key)]
            self._recycled_recently = {key: until for key, until in self._recycled_recently.items() if until > now}
        for path, detected_at, _ in items:
            self._emit("deleted", path, detected_at=detected_at, delete_mode=self._delete_mode_when_no_record(path))

    # ---- USB drives (Phase 16) ---------------------------------------------
    def _check_removable_drives(self) -> None:
        current = {str(drive): drive for drive in removable_drives()}
        with self._drives_lock:
            known = set(self._removable)
        for root in current:
            if root not in known:
                try:
                    watch = self._observer.schedule(self._handler, root, recursive=self.config.recursive)
                except OSError as error:
                    log.warning("Cannot watch USB drive %s: %s", root, error)
                    continue
                with self._drives_lock:
                    self._removable[root] = watch
                log.info("USB drive %s plugged in: watching it", root)
        for root in [root for root in known if root not in current]:
            with self._drives_lock:
                watch = self._removable.pop(root, None)
            try:
                if watch is not None:
                    self._observer.unschedule(watch)
            except (KeyError, ValueError, OSError):
                pass
            log.info("USB drive %s removed", root)

    def _housekeeping(self) -> None:
        last_drive_check = now_monotonic()
        while not self._stop.wait(0.5):
            try:
                with self._recycle_lock:
                    self._flush_pending_deletes()
                    if self._recycle is not None:
                        self._recycle.tick()
                if self.config.watch_removable_drives and now_monotonic() - last_drive_check >= DRIVE_CHECK_SECONDS:
                    last_drive_check = now_monotonic()
                    self._check_removable_drives()
            except Exception:
                log.exception("File monitor housekeeping failed")

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
              previous: Path | None = None, origin: str | None = None, download_url: str | None = None,
              delete_mode: str | None = None, is_folder: bool = False, note: str | None = None) -> None:
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
            "deleteMode": delete_mode,
            "isFolder": is_folder,
        }
        detail = f" ({size} bytes)" if size is not None else ""
        label = {"recycle_bin": " [moved to Recycle Bin]", "permanent": " [deleted permanently]", "recycle_bin_removed": " [removed from Recycle Bin]"}.get(delete_mode or "", "")
        label += f" [{origin}]" if origin and origin != "local" else ""
        label += f" ({note})" if note else ""
        log.info("%s %s: %s%s%s", "Folder" if is_folder else "File", event_type, f"{previous} -> " if previous else "", path, detail + label)
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
