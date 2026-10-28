"""setup-agent.bat helpers: is this PC enrolled, and finding a config.json downloaded from the website
(Computers > Add Computers > One PC), so adding one PC never needs an enrollment key."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from .config_store import read_json

# Browsers save a second download as "config (1).json"; Windows may hide a doubled ".json" or a Notepad ".txt".
CANDIDATE_PATTERNS = ("config*.json", "config*.json.txt", "config*.txt")
SKIP_NAMES = {"config.json", "config.example.json"}


def is_enrolled_config(data: dict) -> bool:
    """True for a config with this PC's device ID, a real device token and a server address."""
    token = data.get("device_token")
    device = data.get("device_id")
    server = data.get("server_url")
    return (isinstance(token, str) and len(token) >= 32 and "PASTE" not in token.upper()
            and isinstance(device, str) and device.strip() != ""
            and isinstance(server, str) and server.startswith(("http://", "https://")))


def is_enrolled(config_path: Path) -> bool:
    return is_enrolled_config(read_json(config_path))


def downloads_folder() -> Path | None:
    home = os.environ.get("USERPROFILE") or os.environ.get("HOME")
    return Path(home) / "Downloads" if home else None


def find_downloaded_config(agent_dir: Path, downloads: Path | None = None) -> Path | None:
    """The newest One-PC config.json in the agent folder (under another name) or in Downloads, or None."""
    found: list[tuple[float, Path]] = []
    for folder in (agent_dir, downloads):
        if folder is None or not folder.is_dir():
            continue
        for pattern in CANDIDATE_PATTERNS:
            for path in folder.glob(pattern):
                if (path.parent == agent_dir and path.name.lower() in SKIP_NAMES) or not path.is_file():
                    continue
                try:
                    if path.stat().st_size > 64 * 1024:
                        continue
                    if is_enrolled_config(read_json(path)):
                        found.append((path.stat().st_mtime, path))
                except OSError:
                    continue
    unique = {path.resolve(): (mtime, path) for mtime, path in found}
    return max(unique.values())[1] if unique else None


def import_config(source: Path, config_path: Path) -> dict:
    """Copies the downloaded config to config.json (the old config.json is kept as config.json.bak)."""
    if config_path.exists():
        shutil.copy2(config_path, config_path.with_name(config_path.name + ".bak"))
    shutil.copyfile(source, config_path)
    return read_json(config_path)
