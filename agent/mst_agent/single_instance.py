"""Makes sure only one agent runs per config: two copies would report every file twice."""

from __future__ import annotations

import os
from pathlib import Path


class AlreadyRunning(Exception):
    """Another agent process already holds the lock."""


class SingleInstance:
    def __init__(self, lock_file: Path):
        self.lock_file = lock_file
        self._handle = None

    def acquire(self) -> None:
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self.lock_file, "a+")
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            handle.close()
            raise AlreadyRunning(f"Another MST agent is already running (lock: {self.lock_file})") from error
        self._handle = handle  # the operating system releases the lock when the process ends

    def release(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
