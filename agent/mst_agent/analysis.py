"""Static (non-executing) file analysis: the real file type from its content, and structural risk indicators.

The same rules run on the MST server for uploaded files (backend/helpers/FileAnalyzer.php). Files are only
read, never opened by another program or run.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

ANALYZER_VERSION = "1.0"
CONTENT_SCAN_BYTES = 16 * 1024 * 1024

EXECUTABLE_EXTENSIONS = {"exe", "msi", "bat", "cmd", "com", "scr", "pif", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "jar", "dll", "cpl", "reg"}
DOCUMENT_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4", "avi", "zip", "rar"}
SCRIPT_EXTENSIONS = {"ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta", "sh", "reg"}
HEADERLESS_EXTENSIONS = {"com", "bin", "dat"}  # no recognizable header, so the content cannot contradict the extension

# family -> (label, extensions that are normal for it)
FAMILIES: dict[str, tuple[str, set[str]]] = {
    "pe": ("Windows program (PE)", {"exe", "dll", "sys", "scr", "com", "cpl", "ocx", "drv", "efi", "mui", "ax", "pyd", "node", "msstyles", "winmd"}),
    "elf": ("Linux program (ELF)", {"", "so", "bin", "elf", "run", "o"}),
    "macho": ("macOS program (Mach-O)", {"", "dylib", "bundle", "so"}),
    "pdf": ("PDF document", {"pdf"}),
    "ooxml": ("Microsoft Office document (OOXML)", {"docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm", "xlam", "pptx", "pptm", "ppsx", "ppsm", "potx", "vsdx", "zip"}),
    "zip": ("ZIP archive", {"zip", "jar", "apk", "odt", "ods", "odp", "epub", "xpi", "nupkg", "msix", "appx", "whl", "kmz", "docx", "xlsx", "pptx", "3mf", "crx"}),
    "ole": ("Microsoft Office 97-2003 / Installer (OLE)", {"doc", "dot", "xls", "xlt", "xla", "ppt", "pps", "pot", "msi", "msp", "msg", "vsd", "pub", "mpp", "ole"}),
    "rar": ("RAR archive", {"rar"}),
    "7z": ("7-Zip archive", {"7z"}),
    "gzip": ("GZIP archive", {"gz", "tgz"}),
    "cab": ("Windows cabinet archive", {"cab", "msu"}),
    "iso": ("Disk image (ISO)", {"iso", "img"}),
    "png": ("PNG image", {"png"}),
    "jpeg": ("JPEG image", {"jpg", "jpeg", "jpe", "jfif"}),
    "gif": ("GIF image", {"gif"}),
    "bmp": ("BMP image", {"bmp", "dib"}),
    "webp": ("WebP image", {"webp"}),
    "ico": ("Icon image", {"ico", "cur"}),
    "mp3": ("MP3 audio", {"mp3"}),
    "mp4": ("MP4/MOV video", {"mp4", "m4a", "m4v", "mov", "3gp", "heic", "heif", "avif"}),
    "riff": ("RIFF media (AVI/WAV)", {"avi", "wav"}),
    "rtf": ("Rich Text document", {"rtf", "doc"}),
    "lnk": ("Windows shortcut (LNK)", {"lnk"}),
    "html": ("HTML document", {"html", "htm", "hta", "xhtml", "mht", "svg"}),
    "script": ("Script (text)", {"ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta", "sh", "py", "pl", "rb", "php", "reg"}),
    "text": ("Text", {"txt", "csv", "log", "md", "json", "xml", "ini", "cfg", "conf", "yml", "yaml", "html", "htm", "css", "js", "ps1", "bat", "cmd", "vbs", "py", "sql", "reg", "svg", "tsv", "srt", "c", "h", "cpp", "java", "cs", "php", "sh", "inf", "nfo", "rtf"}),
    "empty": ("Empty file", set()),
    "unknown": ("Unrecognized binary data", set()),
}

SCRIPT_PATTERNS = [
    (re.compile(rb"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}", re.I), "encoded PowerShell command"),
    (re.compile(rb"FromBase64String", re.I), "Base64 decoding"),
    (re.compile(rb"DownloadString|DownloadFile|Invoke-WebRequest|\biwr\s+http|Net\.WebClient|Start-BitsTransfer|bitsadmin\s+/transfer", re.I), "downloads content from the internet"),
    (re.compile(rb"Invoke-Expression|\biex\s*[\(\$]", re.I), "runs generated code (Invoke-Expression)"),
    (re.compile(rb"certutil(\.exe)?\s+[^\r\n]*-(urlcache|decode)", re.I), "certutil download/decode"),
    (re.compile(rb"WScript\.Shell|Shell\.Application|CreateObject\(\s*\"(WScript|Shell)", re.I), "starts other programs (WScript.Shell)"),
    (re.compile(rb"mshta(\.exe)?\s+(http|vbscript|javascript)", re.I), "mshta remote script"),
    (re.compile(rb"-w(indowstyle)?\s+hidden", re.I), "hidden window"),
]
TITLES = {
    "double_extension": "Double file extension", "disguised_executable": "Disguised program", "type_mismatch": "File type does not match its extension",
    "office_macros": "Office document with macros", "archive_executable": "Archive contains programs", "encrypted_archive": "Password-protected archive",
    "rtf_embedded_object": "RTF with embedded objects", "pdf_active_content": "PDF with active content", "suspicious_script": "Suspicious script commands",
    "pdf_embedded_file": "PDF with embedded files", "shortcut_file": "Windows shortcut", "executable_type": "Program or script file",
    "executable_from_internet": "Program downloaded from the internet", "internet_download": "Downloaded from the internet", "hash_changed": "File changed since it was detected",
}


def extension_of(name: str) -> str:
    return name.rsplit(".", 1)[1].lower() if "." in name else ""


def has_double_extension(name: str) -> bool:
    parts = name.lower().split(".")[1:]
    return len(parts) >= 2 and parts[-2] in DOCUMENT_EXTENSIONS and parts[-1] in EXECUTABLE_EXTENSIONS


def _looks_like_text(head: bytes) -> bool:
    sample = head[:8192]
    if not sample:
        return False
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return True
    if b"\0" in sample:
        return False
    control = sum(1 for byte in sample if byte < 9 or 13 < byte < 32 and byte != 27 or byte == 127)
    return control <= len(sample) * 0.02


def zip_entries(path: Path) -> dict:
    """Lists a ZIP archive's entries without extracting anything."""
    result = {"ooxml": False, "vba": False, "encrypted": False, "executables": []}
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist()[:20000]:
                lower = info.filename.lower()
                if lower == "[content_types].xml":
                    result["ooxml"] = True
                if lower.endswith("vbaproject.bin"):
                    result["vba"] = True
                if info.flag_bits & 0x1:
                    result["encrypted"] = True
                if extension_of(lower) in EXECUTABLE_EXTENSIONS and len(result["executables"]) < 20:
                    result["executables"].append(lower.replace("\\", "/").rsplit("/", 1)[-1])
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError):
        pass
    return result


def _family(head: bytes, iso_marker: bytes, path: Path) -> str:
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if b"%PDF-" in head[:1024]:
        return "pdf"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "ooxml" if zip_entries(path)["ooxml"] else "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"MSCF"):
        return "cab"
    if iso_marker == b"CD001":
        return "iso"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if head.startswith(b"BM") and len(head) > 14 and int.from_bytes(head[2:6], "little") > 14:
        return "bmp"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "webp"
    if head.startswith(b"RIFF") and head[8:12] in (b"AVI ", b"WAVE"):
        return "riff"
    if head.startswith(b"\x00\x00\x01\x00") and len(head) > 6:
        return "ico"
    if head.startswith((b"ID3", b"\xff\xfb", b"\xff\xf3")):
        return "mp3"
    if head[4:8] == b"ftyp":
        return "mp4"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if head.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if _looks_like_text(head):
        text = head.lstrip(b"\xef\xbb\xbf").lstrip().lower()
        if text.startswith((b"<!doctype html", b"<html", b"<hta:application")):
            return "html"
        return "script" if text.startswith(b"#!") else "text"
    return "unknown"


def identify(path: Path) -> dict:
    """{family, label, extension, extensionMatches} from the file's content."""
    extension = extension_of(path.name)
    size = path.stat().st_size
    with path.open("rb") as handle:
        head = handle.read(65536)
        iso_marker = b""
        if size > 0x8006:
            handle.seek(0x8001)
            iso_marker = handle.read(5)
    family = "empty" if size == 0 else _family(head, iso_marker, path)
    label, extensions = FAMILIES[family]
    if extension in HEADERLESS_EXTENSIONS or family in ("unknown", "empty"):
        matches = True
    elif family == "text":
        matches = extension == "" or extension in extensions or extension in SCRIPT_EXTENSIONS
    else:
        matches = extension in extensions
    return {"family": family, "label": label, "extension": extension[:16], "extensionMatches": matches}


def indicators(path: Path, file_type: dict) -> list[dict]:
    found: list[dict] = []

    def add(rule: str, severity: str, detail: str) -> None:
        found.append({"rule": rule, "title": TITLES.get(rule, rule), "severity": severity, "detail": detail[:200]})

    name, extension, family = path.name, file_type["extension"], file_type["family"]
    executable_family = family in ("pe", "elf", "macho")
    if has_double_extension(name):
        add("double_extension", "HIGH", f"'{name}' pretends to be a document but ends in .{extension}")
    if executable_family and not file_type["extensionMatches"]:
        add("disguised_executable", "HIGH", f"The content is a {file_type['label']} but the extension is '.{extension or 'none'}'")
    elif not file_type["extensionMatches"]:
        add("type_mismatch", "MEDIUM", f"The content is a {file_type['label']} but the extension is '.{extension or 'none'}'")

    try:
        with path.open("rb") as handle:
            content = handle.read(CONTENT_SCAN_BYTES)
    except OSError:
        content = b""
    if family in ("ooxml", "zip"):
        entries = zip_entries(path)
        if entries["vba"]:
            add("office_macros", "MEDIUM", "The document contains VBA macros (vbaProject.bin)")
        if entries["executables"]:
            add("archive_executable", "MEDIUM", "The archive contains program/script files: " + ", ".join(entries["executables"][:5]))
        if entries["encrypted"]:
            add("encrypted_archive", "MEDIUM", "The archive is password-protected, so its contents cannot be inspected")
    if family == "ole" and ("_VBA_PROJECT".encode("utf-16-le") in content or b"Attribute VB_" in content):
        add("office_macros", "MEDIUM", "The document contains VBA macros")
    if family == "rtf" and re.search(rb"\\objdata|\\objupdate", content, re.I):
        add("rtf_embedded_object", "MEDIUM", "The RTF document contains embedded objects (often used by document exploits)")
    if family == "pdf":
        active = []
        if re.search(rb"/(JavaScript|JS)[\s/(<\[]", content):
            active.append("JavaScript")
        if re.search(rb"/Launch[\s/<]", content):
            active.append("Launch action (can start programs)")
        if active:
            add("pdf_active_content", "MEDIUM", "The PDF contains " + " and ".join(active))
        if re.search(rb"/EmbeddedFile[\s/<]", content):
            add("pdf_embedded_file", "LOW", "The PDF contains embedded files")
    if extension in SCRIPT_EXTENSIONS or family == "script":
        hits = [label for pattern, label in SCRIPT_PATTERNS if pattern.search(content)]
        if hits:
            add("suspicious_script", "MEDIUM", "Script " + ", ".join(hits[:4]))
    if family == "lnk":
        add("shortcut_file", "LOW", "Windows shortcut file: check which program it starts")
    if (executable_family or extension in EXECUTABLE_EXTENSIONS) and not any(item["severity"] == "HIGH" for item in found):
        add("executable_type", "LOW", f"Program or script file ({file_type['label']})")
    return found
