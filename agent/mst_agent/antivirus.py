"""Antivirus engines on the lab PC: Microsoft Defender (built into Windows) and ClamAV.

Files are scanned in place and never run. Defender is called with -DisableRemediation, so it only reports;
MST decides what happens to the file (the Admin can quarantine it from the dashboard).
"""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

DEFENDER = "Microsoft Defender"
CLAMAV = "ClamAV"
INFO_CACHE_SECONDS = 3600
_info_cache: dict[str, tuple[float, dict]] = {}


def _run(command: list[str], timeout: int) -> tuple[int, str, bool]:
    """Runs a program without a shell. Returns (exit code, output, timed out)."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(command, capture_output=True, timeout=timeout, creationflags=flags, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return -1, "", True
    except OSError as error:
        return -1, str(error), False
    output = (completed.stdout or b"") + (completed.stderr or b"")
    return completed.returncode, output.decode("utf-8", errors="replace")[:65536], False


def _cached(key: str, load) -> dict:
    now = time.monotonic()
    if key in _info_cache and now - _info_cache[key][0] < INFO_CACHE_SECONDS:
        return _info_cache[key][1]
    info = load()
    _info_cache[key] = (now, info)
    return info


def _result(engine: dict, result: str, signature: str | None, detail: str) -> dict:
    return {"name": engine["name"], "version": engine.get("version"), "signatureVersion": engine.get("signatureVersion"), "result": result, "signature": signature, "detail": detail[:200]}


# ---- Microsoft Defender -------------------------------------------------------------------------------

def defender_path(configured: str = "") -> str | None:
    if configured:
        return configured if Path(configured).is_file() else None
    if os.name != "nt":
        return None
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    platforms = glob.glob(os.path.join(program_data, "Microsoft", "Windows Defender", "Platform", "*", "MpCmdRun.exe"))

    def version_key(path: str) -> tuple:
        return tuple(int(part) if part.isdigit() else 0 for part in re.split(r"[.-]", Path(path).parent.name))

    for candidate in sorted(platforms, key=version_key, reverse=True) + [os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")]:
        if Path(candidate).is_file():
            return candidate
    return None


def defender_status(configured_path: str = "") -> dict:
    engine = {"name": DEFENDER, "available": False, "version": None, "signatureVersion": None, "detail": ""}
    path = defender_path(configured_path)
    if path is None:
        return {**engine, "detail": "MpCmdRun.exe was not found" if os.name == "nt" else "Only available on Windows"}

    def load() -> dict:
        code, output, _ = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Get-MpComputerStatus | Select-Object AMProductVersion,AntivirusSignatureVersion,AntivirusEnabled | ConvertTo-Json -Compress"], 30)
        try:
            data = json.loads(output) if code == 0 else None
        except ValueError:
            data = None
        if not isinstance(data, dict):
            return {"version": Path(path).parent.name if "Platform" in path else None, "signatures": None, "enabled": None}
        return {"version": data.get("AMProductVersion"), "signatures": data.get("AntivirusSignatureVersion"), "enabled": data.get("AntivirusEnabled")}

    info = _cached("defender", load)
    if info["enabled"] is False:
        return {**engine, "version": info["version"], "detail": "Microsoft Defender Antivirus is turned off (another antivirus may be active)"}
    return {**engine, "available": True, "version": info["version"], "signatureVersion": info["signatures"], "detail": "Ready", "path": path}


def scan_defender(path: Path, engine: dict, timeout: int) -> dict:
    code, output, timed_out = _run([engine["path"], "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"], timeout)
    if timed_out:
        return _result(engine, "error", None, f"Scan timed out after {timeout} seconds")
    if not path.exists():
        return _result(engine, "error", None, "The file disappeared during the scan (real-time protection may have removed it)")
    if code == 2 or re.search(r"found\s+[1-9]\d*\s+threats?", output, re.I):
        match = re.search(r"Threat\s*:\s*([^\r\n]+)", output)
        return _result(engine, "detected", (match.group(1).strip() if match else "a threat")[:120], "Signature match")
    if code == 0:
        return _result(engine, "clean", None, "No threats found")
    reason = re.search(r"(failed with hr = 0x[0-9A-Fa-f]+|ERROR[^\r\n]*)", output)
    return _result(engine, "error", None, f"MpCmdRun could not scan the file ({reason.group(1) if reason else f'exit code {code}'})")


# ---- ClamAV -----------------------------------------------------------------------------------------

def clamav_path(configured: str = "") -> str | None:
    if configured:
        return configured if Path(configured).is_file() else None
    for name in ("clamscan", "clamdscan"):
        found = shutil.which(name)
        if found:
            return found
    if os.name == "nt":
        candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClamAV" / "clamscan.exe"
        if candidate.is_file():
            return str(candidate)
    return None


def clamav_status(configured_path: str = "", database: str = "") -> dict:
    engine = {"name": CLAMAV, "available": False, "version": None, "signatureVersion": None, "detail": ""}
    path = clamav_path(configured_path)
    if path is None:
        return {**engine, "detail": "ClamAV is not installed (set clamav_path in config.json)"}

    def load() -> dict:
        code, output, _ = _run([path, *([f"--database={database}"] if database else []), "--version"], 30)
        match = re.search(r"ClamAV\s+([\d.]+)(?:/(\d+))?", output) if code == 0 else None
        return {"version": match.group(1) if match else None, "signatures": match.group(2) if match else None}

    info = _cached("clamav", load)
    if info["version"] is None:
        return {**engine, "detail": "ClamAV did not respond to --version"}
    return {**engine, "available": True, "version": info["version"], "signatureVersion": info["signatures"], "detail": "Ready", "path": path, "database": database}


def scan_clamav(path: Path, engine: dict, timeout: int) -> dict:
    daemon = "clamdscan" in Path(engine["path"]).name.lower()
    command = [engine["path"], "--no-summary", "--fdpass", str(path)] if daemon else [engine["path"], "--no-summary", "--stdout", *([f"--database={engine['database']}"] if engine.get("database") else []), str(path)]
    code, output, timed_out = _run(command, timeout)
    if timed_out:
        return _result(engine, "error", None, f"Scan timed out after {timeout} seconds")
    match = re.search(r":\s*(\S[^\r\n]*?)\s+FOUND", output)
    if code == 1 and match:
        return _result(engine, "detected", match.group(1)[:120], "Signature match")
    if code == 0:
        return _result(engine, "clean", None, "No threats found")
    if "No supported database files found" in output:
        return _result(engine, "unavailable", None, "ClamAV has no virus signatures: run freshclam")
    return _result(engine, "error", None, f"ClamAV could not scan the file (exit code {code})")


# ---- all engines ------------------------------------------------------------------------------------

def engines_status(mode: str, defender: str = "", clamav: str = "", clamav_database: str = "") -> list[dict]:
    """Engines this PC can use. mode: auto (every installed engine) | defender | clamav | none."""
    engines = []
    if mode in ("auto", "defender"):
        engines.append(defender_status(defender))
    if mode in ("auto", "clamav"):
        engines.append(clamav_status(clamav, clamav_database))
    return [engine for engine in engines if engine["available"] or mode != "auto"]


def scan_with_engines(path: Path, engines: list[dict], timeout: int) -> list[dict]:
    results = []
    for engine in engines:
        if not engine["available"]:
            results.append(_result(engine, "unavailable", None, engine["detail"]))
        elif engine["name"] == DEFENDER:
            results.append(scan_defender(path, engine, timeout))
        else:
            results.append(scan_clamav(path, engine, timeout))
    return results
