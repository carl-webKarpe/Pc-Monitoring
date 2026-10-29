"""Finds the MST server on the local network, so lab PCs need no IP address and keep working when it changes.

The agent tries every address of its own network (e.g. 192.168.0.1-254) on the server's port, then asks each
answering computer to prove it is the real MST server: for a random nonce the server must return
HMAC-SHA256(nonce) keyed with the SHA-256 of this PC's device token or of the enrollment key. Only the real
server stores that hash, and the token or key itself is never sent until the proof matches.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import re
import secrets
import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import psutil
import requests

from . import VERSION

log = logging.getLogger("mst_agent.discovery")

DEFAULT_PORT = 8081
# This lab's MST server (the admin laptop on the LAN cable). It is tried first; the rest of the network is still
# searched when the laptop gets another address. The server must prove itself (verify_server) like any other.
LAB_SERVER_IP = "192.168.0.224"
KEY_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
MAX_HOSTS_PER_NETWORK = 1022  # a /22; larger networks are searched in the /24 around this PC's own address


def normalize_key(key: str) -> str | None:
    """Enrollment keys are typed in any case, with or without dashes/spaces. None if it cannot be a key."""
    clean = re.sub(r"[\s-]+", "", key or "").upper()
    return clean if re.fullmatch(f"[{KEY_ALPHABET}]{{16}}", clean) else None


def normalize_server(value: str) -> str:
    """Accepts '192.168.0.61', '192.168.0.61:8081' or a full URL and returns http://host:port/api."""
    value = value.strip().rstrip("/")
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    parsed = urlparse(value)
    netloc = parsed.netloc if parsed.port else f"{parsed.hostname}:{DEFAULT_PORT}"
    path = parsed.path if parsed.path.endswith("/api") else parsed.path + "/api"
    return f"{parsed.scheme}://{netloc}{path}"


def proof(secret: str, nonce: str) -> str:
    """What the real server answers: HMAC keyed with the hash it stores (sha256 of the token or key)."""
    stored_hash = hashlib.sha256(secret.encode()).hexdigest()
    return hmac.new(stored_hash.encode(), nonce.encode(), hashlib.sha256).hexdigest()


def verify_server(url: str, secret: str, device_id: str | None = None, timeout: float = 3, verify=True) -> bool:
    """True when the server at `url` proves it knows this PC's token (or the enrollment key)."""
    nonce = secrets.token_hex(16)
    try:
        response = requests.post(f"{url}/agent/identify", json={"nonce": nonce, "deviceId": device_id}, timeout=timeout,
                                 verify=verify, headers={"User-Agent": f"MST-Agent/{VERSION}"})
        data = response.json().get("data") or {}
    except (requests.RequestException, ValueError, AttributeError):
        return False
    expected = proof(secret, nonce)
    return data.get("service") == "MST" and any(hmac.compare_digest(expected, str(item)) for item in data.get("proofs", []))


def local_networks() -> list[ipaddress.IPv4Network]:
    networks: list[ipaddress.IPv4Network] = []
    for addresses in psutil.net_if_addrs().values():
        for address in addresses:
            if address.family != socket.AF_INET or not address.netmask:
                continue
            ip = ipaddress.IPv4Address(address.address)
            if ip.is_loopback or ip.is_link_local:
                continue
            network = ipaddress.IPv4Interface(f"{address.address}/{address.netmask}").network
            if network.num_addresses - 2 > MAX_HOSTS_PER_NETWORK:
                network = ipaddress.IPv4Interface(f"{address.address}/24").network
            if network not in networks:
                networks.append(network)
    return networks


def _port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def find_server(secret: str, device_id: str | None = None, port: int = DEFAULT_PORT, scheme: str = "http",
                hints: tuple[str, ...] = (), timeout: float = 0.5, verify=True) -> str | None:
    """Searches the local network(s) for the MST server and returns its API URL (http://ip:port/api) or None."""
    hosts: list[str] = []
    for hint in (*hints, LAB_SERVER_IP):
        if hint and hint not in hosts:
            hosts.append(hint)
    for network in local_networks():
        hosts += [str(host) for host in network.hosts() if str(host) not in hosts]
    if not hosts:
        return None
    log.info("Searching %d address(es) for the MST server on port %d...", len(hosts), port)
    with ThreadPoolExecutor(max_workers=64) as pool:
        open_hosts = [host for host, is_open in zip(hosts, pool.map(lambda host: _port_open(host, port, timeout), hosts)) if is_open]
    for host in open_hosts:
        url = f"{scheme}://{host}:{port}/api"
        if verify_server(url, secret, device_id, verify=verify):
            return url
    return None
