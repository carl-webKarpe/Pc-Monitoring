"""Reads and updates config.json in place (used by enrollment and when the server's address changes)."""

from __future__ import annotations

import json
import os
from pathlib import Path


def read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_json(path: Path, data: dict) -> None:
    """Writes the whole file at once (a temporary file is renamed), so a crash never leaves half a config."""
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def update_config(path: Path, changes: dict) -> None:
    data = read_json(path)
    data.update(changes)
    write_json(path, data)
