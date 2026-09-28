"""On-PC file scan requested by the MST admin.

The agent re-hashes the file and applies simple, explainable rules. The server adds the hash-blocklist
check and decides the final verdict. Only files inside the configured watch folders can be scanned,
and file contents never leave the computer.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from .file_monitor import sha256_of

EXECUTABLE_EXTENSIONS = {".exe", ".msi", ".bat", ".cmd", ".com", ".scr", ".pif", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".jar", ".dll", ".cpl", ".reg"}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".avi", ".zip", ".rar"}
# Windows program files legitimately start with "MZ"; any other extension with that header is a disguised program.
PE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv", ".efi", ".mui", ".ax", ".pyd", ".node"}


class ScanError(Exception):
    """The file could not be scanned (missing, unreadable, or outside the monitored folders)."""


def is_inside(path: Path, folders: list[Path]) -> bool:
    try:
        resolved = path.resolve(strict=True)
    except (FileNotFoundError, OSError):
        return False
    for folder in folders:
        try:
            resolved.relative_to(folder.resolve())
            return True
        except (ValueError, OSError):
            continue
    return False


def internet_zone(path: Path) -> int | None:
    """Windows 'Mark of the Web': ZoneId 3 (Internet) or 4 (Restricted) means the file was downloaded."""
    if os.name != "nt":
        return None
    try:
        with open(f"{path}:Zone.Identifier", encoding="utf-8", errors="ignore") as stream:
            for line in stream:
                if line.strip().lower().startswith("zoneid="):
                    return int(line.split("=", 1)[1].strip())
    except (OSError, ValueError):
        return None
    return None


def scan_file(path: Path, watch_folders: list[Path], expected_sha256: str | None, max_hash_bytes: int) -> dict:
    """Returns {sha256, fileSize, findings, durationMs}. Raises ScanError if the file cannot be scanned."""
    started = time.monotonic()
    if not is_inside(path, watch_folders):
        raise ScanError("File no longer exists or is outside the monitored folders")
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            header = handle.read(2)
    except PermissionError as error:
        raise ScanError("File is locked or access was denied") from error
    except OSError as error:
        raise ScanError("File could not be read") from error

    sha256 = sha256_of(path, max_hash_bytes)
    findings: list[dict] = []
    suffixes = [suffix.lower() for suffix in path.suffixes]
    extension = suffixes[-1] if suffixes else ""
    executable = extension in EXECUTABLE_EXTENSIONS

    if len(suffixes) >= 2 and suffixes[-2] in DOCUMENT_EXTENSIONS and executable:
        findings.append({"rule": "double_extension", "severity": "HIGH", "detail": f"'{path.name}' looks like a {suffixes[-2]} file but is a {extension} program"})
    if header == b"MZ" and extension not in PE_EXTENSIONS:
        findings.append({"rule": "disguised_executable", "severity": "HIGH", "detail": f"File content is a Windows program but the extension is '{extension or 'none'}'"})

    zone = internet_zone(path)
    downloaded = zone is not None and zone >= 3
    if executable and downloaded:
        findings.append({"rule": "executable_from_internet", "severity": "MEDIUM", "detail": f"Program or script downloaded from the internet (zone {zone})"})
    elif executable:
        findings.append({"rule": "executable_type", "severity": "LOW", "detail": f"Program or script file ({extension})"})
    elif downloaded:
        findings.append({"rule": "internet_download", "severity": "INFO", "detail": f"Downloaded from the internet (zone {zone})"})

    if expected_sha256 and sha256 and sha256.lower() != expected_sha256.lower():
        findings.append({"rule": "hash_changed", "severity": "INFO", "detail": "File content changed since it was first detected"})

    return {"sha256": sha256, "fileSize": size, "findings": findings, "durationMs": int((time.monotonic() - started) * 1000)}
