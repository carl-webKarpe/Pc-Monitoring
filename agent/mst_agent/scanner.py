"""On-PC file scan requested by the MST server (by an Admin, or automatically for new files).

The agent hashes the file, identifies its real type, looks for risk indicators and runs the installed antivirus
engines (Microsoft Defender / ClamAV). The server adds VirusTotal and the hash blocklist and decides the risk
level. Only files inside the configured watch folders can be scanned, and file contents never leave the PC.
"""

from __future__ import annotations

import time
from pathlib import Path

from .analysis import ANALYZER_VERSION, EXECUTABLE_EXTENSIONS, identify, indicators
from .antivirus import scan_with_engines
from .file_monitor import mark_of_the_web, sha256_of


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


def scan_file(path: Path, watch_folders: list[Path], expected_sha256: str | None, max_hash_bytes: int, engines: list[dict], timeout: int) -> dict:
    """Returns the scan evidence for the server. Raises ScanError if the file cannot be scanned."""
    started = time.monotonic()
    if not is_inside(path, watch_folders):
        raise ScanError("File no longer exists or is outside the monitored folders")
    try:
        size = path.stat().st_size
        file_type = identify(path)
    except PermissionError as error:
        raise ScanError("File is locked or access was denied") from error
    except OSError as error:
        raise ScanError("File could not be read") from error

    sha256 = sha256_of(path, max_hash_bytes)
    found = indicators(path, file_type)
    download = mark_of_the_web(path)
    downloaded = download is not None and download["zone"] >= 3
    source = f" from {download['hostUrl']}" if downloaded and download["hostUrl"] else ""
    executable = file_type["family"] in ("pe", "elf", "macho") or file_type["extension"] in EXECUTABLE_EXTENSIONS
    if executable and downloaded:
        found.append({"rule": "executable_from_internet", "severity": "LOW", "detail": f"Program or script downloaded from the internet{source} (zone {download['zone']})"})
    elif downloaded:
        found.append({"rule": "internet_download", "severity": "INFO", "detail": f"Downloaded from the internet{source} (zone {download['zone']})"})
    if expected_sha256 and sha256 and sha256.lower() != expected_sha256.lower():
        found.append({"rule": "hash_changed", "severity": "INFO", "detail": "File content changed since it was first detected"})

    results = scan_with_engines(path, engines, timeout)
    return {
        "sha256": sha256,
        "fileSize": size,
        "fileType": file_type,
        "indicators": found,
        "engines": results,
        "analyzerVersion": ANALYZER_VERSION,
        "download": download,
        "durationMs": int((time.monotonic() - started) * 1000),
    }
