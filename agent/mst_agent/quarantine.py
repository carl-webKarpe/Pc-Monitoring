"""Quarantine on the lab PC, carried out only when an Admin requests it from the MST dashboard.

Quarantine moves the file out of the user's folders into the agent's quarantine folder, renamed to
"<id>-<hash>.quarantined" (so it cannot be opened or run by double-clicking) and made read-only. A small
.json file next to it records where it came from. Every step checks the SHA-256, so MST only ever moves,
restores or deletes the exact file that was scanned. Retried requests are safe (they finish what was done).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path

from .file_monitor import sha256_of
from .scanner import is_inside

NAME_PATTERN = re.compile(r"^\d{1,10}-[0-9a-f]{16}\.quarantined$")


class QuarantineError(Exception):
    """The action could not be carried out; the message is shown to the Admin."""


class Quarantine:
    def __init__(self, folder: Path, watch_folders: list[Path], max_hash_bytes: int):
        self.folder = folder
        self.watch_folders = watch_folders
        self.max_hash_bytes = max_hash_bytes

    def _path(self, name: str | None) -> Path:
        if not name or not NAME_PATTERN.match(name):
            raise QuarantineError("Invalid quarantine file name")
        return self.folder / name

    def _check_hash(self, path: Path, sha256: str, what: str) -> None:
        actual = sha256_of(path, self.max_hash_bytes)
        if actual is None:
            raise QuarantineError(f"{what} could not be read or is too large to verify")
        if actual.lower() != sha256.lower():
            raise QuarantineError(f"{what} has changed since it was scanned (SHA-256 differs); scan it again first")

    @staticmethod
    def _writable(path: Path) -> None:
        try:
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        except OSError:
            pass

    def quarantine(self, item_id: int, original_path: str, sha256: str) -> str:
        name = f"{item_id}-{sha256[:16].lower()}.quarantined"
        target = self.folder / name
        source = Path(original_path)
        if target.exists() and not source.exists():
            return name  # already moved by an earlier attempt whose answer did not reach the server
        if not source.is_file():
            raise QuarantineError("The file no longer exists at its original location")
        if not is_inside(source, self.watch_folders):
            raise QuarantineError("The file is outside the monitored folders")
        self._check_hash(source, sha256, "The file")
        self.folder.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(source), str(target))
        except PermissionError as error:
            raise QuarantineError("The file is open in another program or access was denied") from error
        except OSError as error:
            raise QuarantineError(f"The file could not be moved ({error.__class__.__name__})") from error
        (self.folder / f"{name}.json").write_text(json.dumps({"originalPath": str(source), "sha256": sha256.lower(), "quarantinedAt": datetime.now(timezone.utc).isoformat()}), encoding="utf-8")
        try:
            os.chmod(target, stat.S_IREAD)  # read-only: it cannot be changed while it is in quarantine
        except OSError:
            pass
        return name

    def release(self, name: str, original_path: str, sha256: str) -> None:
        source = self._path(name)
        target = Path(original_path)
        if not source.exists():
            if target.is_file() and sha256_of(target, self.max_hash_bytes) == sha256.lower():
                return  # already restored by an earlier attempt
            raise QuarantineError("The quarantined file was not found")
        if not target.parent.is_dir() or not is_inside(target.parent, self.watch_folders):
            raise QuarantineError("The original folder no longer exists or is outside the monitored folders")
        if target.exists():
            raise QuarantineError("A file with the same name now exists at the original location")
        self._check_hash(source, sha256, "The quarantined file")
        self._writable(source)
        shutil.move(str(source), str(target))
        (self.folder / f"{name}.json").unlink(missing_ok=True)

    def delete(self, name: str, sha256: str) -> None:
        path = self._path(name)
        if path.exists():
            self._check_hash(path, sha256, "The quarantined file")
            self._writable(path)
            path.unlink()
        (self.folder / f"{name}.json").unlink(missing_ok=True)
