"""Finds the real Downloads / Desktop / Documents folders, including when OneDrive has moved them."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

# Windows "known folder" IDs. Windows knows where these folders really are, even after OneDrive
# folder backup moved Desktop and Documents to %OneDrive%\Desktop and %OneDrive%\Documents.
KNOWN_FOLDERS = {
    "downloads": "374DE290-123F-4565-9164-39C4925E467B",
    "desktop": "B4BFCC3A-DB2C-424C-B029-7FE99A87C641",
    "documents": "FDD39AD0-238F-46AF-ADB4-6C85480369C7",
}


def windows_known_folder(name: str) -> Path | None:
    """Asks Windows (SHGetKnownFolderPath) for the folder's real location. None if unavailable."""
    if os.name != "nt" or name not in KNOWN_FOLDERS:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD), ("Data4", wintypes.BYTE * 8)]

        raw = uuid.UUID(KNOWN_FOLDERS[name]).bytes_le
        guid = GUID.from_buffer_copy(raw)
        path_pointer = ctypes.c_wchar_p()
        if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(path_pointer)) != 0:
            return None
        try:
            return Path(path_pointer.value)
        finally:
            ctypes.windll.ole32.CoTaskMemFree(path_pointer)
    except Exception:
        return None


def resolve_known_folder(token: str) -> Path | None:
    """'{Downloads}', '{Desktop}' or '{Documents}' -> the folder's real path."""
    name = token.strip("{}").lower()
    if name not in KNOWN_FOLDERS:
        return None
    return windows_known_folder(name) or Path.home() / name.capitalize()


def onedrive_fallback(path: Path) -> Path | None:
    """If `path` is <user profile>\\X but OneDrive moved X, return <OneDrive>\\X when that exists."""
    profile = os.environ.get("USERPROFILE") or str(Path.home())
    try:
        relative = path.relative_to(profile)
    except ValueError:
        return None
    for variable in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        root = os.environ.get(variable)
        if root and (Path(root) / relative).is_dir():
            return Path(root) / relative
    return None
