"""Loads and validates the agent's JSON configuration file."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .folders import onedrive_fallback, resolve_known_folder

DEVICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,40}$")


class ConfigError(ValueError):
    """Raised when config.json is missing or invalid."""


@dataclass
class AgentConfig:
    server_url: str
    device_id: str
    device_token: str
    watch_folders: list[Path]
    heartbeat_interval_seconds: int = 30
    send_interval_seconds: int = 5
    recursive: bool = True
    ignore_extensions: set[str] = field(default_factory=set)
    ignore_name_prefixes: tuple[str, ...] = ()
    max_hash_size_mb: int = 200
    queue_file: Path = Path("mst_agent_queue.db")
    log_file: Path = Path("mst_agent.log")
    request_timeout_seconds: int = 10
    tls_ca_bundle: Path | None = None  # certificate file for an HTTPS server with a self-signed/lab certificate

    @property
    def max_hash_bytes(self) -> int:
        return self.max_hash_size_mb * 1024 * 1024


def _expand(path: str, base: Path) -> Path:
    """Expands %VAR% / $VAR / ~ and resolves relative paths against the config file's folder."""
    expanded = Path(os.path.expandvars(os.path.expanduser(path)))
    return expanded if expanded.is_absolute() else (base / expanded)


def _watch_folder(value: str, base: Path) -> Path:
    """{Downloads}/{Desktop}/{Documents} use Windows' real folder locations; a missing folder under the
    user profile is looked up in OneDrive too (OneDrive folder backup moves Desktop and Documents)."""
    if value.startswith("{") and value.endswith("}"):
        known = resolve_known_folder(value)
        if known is not None:
            return known
    folder = _expand(value, base)
    if not folder.is_dir():
        return onedrive_fallback(folder) or folder
    return folder


def load_config(path: str | Path, require_token: bool = True) -> AgentConfig:
    config_path = Path(path).resolve()
    if not config_path.is_file():
        raise ConfigError(f"Config file not found: {config_path}. Copy config.example.json to config.json and edit it.")
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ConfigError(f"{config_path} is not valid JSON: {error}") from error

    base = config_path.parent
    errors: list[str] = []

    server_url = str(raw.get("server_url", "")).rstrip("/")
    if not server_url.startswith(("http://", "https://")):
        errors.append("server_url must start with http:// or https:// (e.g. http://192.168.1.10:8081/api)")

    device_id = str(raw.get("device_id", ""))
    if not DEVICE_ID_PATTERN.match(device_id):
        errors.append("device_id must be 3-40 letters, numbers, dots, dashes or underscores (e.g. MST-PC-002)")

    device_token = str(raw.get("device_token", ""))
    if require_token and (len(device_token) < 32 or "PASTE" in device_token):
        errors.append("device_token is missing: run backend/tools/register-agent.php on the MST server and paste the token")

    folders = [_watch_folder(str(folder), base) for folder in raw.get("watch_folders", [])]
    if not folders:
        errors.append("watch_folders must list at least one folder")

    def positive_int(key: str, default: int, minimum: int = 1) -> int:
        value = raw.get(key, default)
        if not isinstance(value, int) or value < minimum:
            errors.append(f"{key} must be a whole number >= {minimum}")
            return default
        return value

    config = AgentConfig(
        server_url=server_url,
        device_id=device_id,
        device_token=device_token,
        watch_folders=folders,
        heartbeat_interval_seconds=positive_int("heartbeat_interval_seconds", 30, 5),
        send_interval_seconds=positive_int("send_interval_seconds", 5, 1),
        recursive=bool(raw.get("recursive", True)),
        ignore_extensions={str(ext).lower() for ext in raw.get("ignore_extensions", [])},
        ignore_name_prefixes=tuple(str(prefix) for prefix in raw.get("ignore_name_prefixes", [])),
        max_hash_size_mb=positive_int("max_hash_size_mb", 200),
        queue_file=_expand(str(raw.get("queue_file", "mst_agent_queue.db")), base),
        log_file=_expand(str(raw.get("log_file", "mst_agent.log")), base),
        request_timeout_seconds=positive_int("request_timeout_seconds", 10),
        tls_ca_bundle=_expand(str(raw["tls_ca_bundle"]), base) if raw.get("tls_ca_bundle") else None,
    )
    if config.tls_ca_bundle is not None and not config.tls_ca_bundle.is_file():
        errors.append(f"tls_ca_bundle file not found: {config.tls_ca_bundle}")
    if errors:
        raise ConfigError("Invalid config.json:\n  - " + "\n  - ".join(errors))
    return config
