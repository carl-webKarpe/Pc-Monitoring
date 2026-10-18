"""Adds this PC to MST with an enrollment key (Computers > Add Computers) and writes config.json."""

from __future__ import annotations

from pathlib import Path

import requests

from . import VERSION
from .config_store import read_json, write_json
from .discovery import DEFAULT_PORT, find_server, normalize_key, normalize_server
from .system_info import heartbeat_payload


class EnrollError(Exception):
    pass


def enroll(key: str, config_path: Path, example_path: Path, server: str | None = None, data_dir: str | None = None,
           timeout: float = 15) -> dict:
    """Returns {"serverUrl", "deviceId", "reused"}; config.json then holds the server address, device ID and token."""
    clean_key = normalize_key(key)
    if clean_key is None:
        raise EnrollError("That is not an enrollment key. It looks like ABCD-EFGH-JKMN-PQRS (Computers > Add Computers).")
    if server:
        server_url = normalize_server(server)
    else:
        server_url = find_server(clean_key, port=DEFAULT_PORT)
        if server_url is None:
            raise EnrollError("The MST server was not found on this network. Check that this PC is connected to the same "
                              "network, that the API is running (start-server.bat) and that the key is still valid, "
                              "or give the address: --server 192.168.0.61")
    this_pc = heartbeat_payload(server_url)
    payload = {"key": clean_key, "hostname": this_pc["hostname"], "macAddress": this_pc.get("macAddress"),
               "operatingSystem": this_pc["operatingSystem"], "agentVersion": VERSION}
    try:
        response = requests.post(f"{server_url}/agent/enroll", json=payload, timeout=timeout, headers={"User-Agent": f"MST-Agent/{VERSION}"})
    except requests.RequestException as error:
        raise EnrollError(f"MST server not reachable at {server_url}: {error.__class__.__name__}") from error
    try:
        body = response.json()
    except ValueError:
        body = {}
    if response.status_code >= 400 or not body.get("success"):
        raise EnrollError(body.get("message") or f"The MST server refused the enrollment (HTTP {response.status_code})")
    data = body["data"]

    config = read_json(config_path) or read_json(example_path)
    if not config:
        raise EnrollError(f"{example_path.name} is missing next to run_agent.py")
    config.update(server_url=server_url, device_id=data["deviceId"], device_token=data["deviceToken"])
    if data_dir:
        # One installation used by every Windows account: each user keeps their own queue, log and quarantine.
        separator = "\\" if "\\" in data_dir or "%" in data_dir else "/"
        folder = data_dir.rstrip("\\/")
        config.update(queue_file=f"{folder}{separator}mst_agent_queue.db", log_file=f"{folder}{separator}mst_agent.log",
                      quarantine_folder=f"{folder}{separator}quarantine")
    write_json(config_path, config)
    return {"serverUrl": server_url, "deviceId": data["deviceId"], "reused": bool(data.get("reused"))}
