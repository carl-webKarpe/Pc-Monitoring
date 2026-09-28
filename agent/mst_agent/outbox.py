"""A small SQLite queue so events survive network outages and agent restarts."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path


class Outbox:
    def __init__(self, path: Path, max_items: int = 50_000):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._max_items = max_items
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)")
        self._db.commit()

    def put(self, event: dict) -> None:
        with self._lock:
            self._db.execute("INSERT INTO outbox (payload) VALUES (?)", (json.dumps(event),))
            # Bound the queue if the server is unreachable for a very long time: drop the oldest events.
            self._db.execute("DELETE FROM outbox WHERE id <= (SELECT MAX(id) FROM outbox) - ?", (self._max_items,))
            self._db.commit()

    def peek(self, limit: int = 100) -> list[tuple[int, dict]]:
        with self._lock:
            rows = self._db.execute("SELECT id, payload FROM outbox ORDER BY id LIMIT ?", (limit,)).fetchall()
        return [(row_id, json.loads(payload)) for row_id, payload in rows]

    def remove(self, ids: list[int]) -> None:
        if not ids:
            return
        with self._lock:
            self._db.executemany("DELETE FROM outbox WHERE id = ?", [(row_id,) for row_id in ids])
            self._db.commit()

    def __len__(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._db.close()
