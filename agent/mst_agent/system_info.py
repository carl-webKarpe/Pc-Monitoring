"""Collects this computer's identity and resource usage for the MST heartbeat."""

from __future__ import annotations

import os
import platform
import socket
import uuid
from urllib.parse import urlparse

import psutil

from . import VERSION


def primary_ip(server_url: str) -> str:
    """Returns the local IP address used to reach the MST server (the lab LAN interface)."""
    parsed = urlparse(server_url)
    host, port = parsed.hostname or "8.8.8.8", parsed.port or 80
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((host, port))  # UDP "connect" sends no packets; it only selects the route.
        return probe.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        probe.close()


def mac_address(ip: str) -> str | None:
    """MAC address of the network adapter that owns `ip`, formatted AA:BB:CC:DD:EE:FF."""
    for addresses in psutil.net_if_addrs().values():
        if any(address.family == socket.AF_INET and address.address == ip for address in addresses):
            for address in addresses:
                if address.family == psutil.AF_LINK and address.address:
                    return address.address.replace("-", ":").upper()
    node = uuid.getnode()
    return ":".join(f"{(node >> shift) & 0xFF:02X}" for shift in range(40, -1, -8))


def operating_system() -> str:
    if platform.system() == "Windows":
        release, version = platform.release(), platform.version()
        # Windows 11 still reports release "10"; build 22000+ is Windows 11.
        if release == "10" and version.split(".")[-1].isdigit() and int(version.split(".")[-1]) >= 22000:
            release = "11"
        return f"Windows {release} ({version})"[:80]
    return f"{platform.system()} {platform.release()}"[:80]


def system_drive() -> str:
    return (os.environ.get("SystemDrive", "C:") + "\\") if platform.system() == "Windows" else "/"


def heartbeat_payload(server_url: str) -> dict:
    ip = primary_ip(server_url)
    return {
        "hostname": socket.gethostname()[:120],
        "ipAddress": ip,
        "macAddress": mac_address(ip),
        "operatingSystem": operating_system(),
        "agentVersion": VERSION,
        "cpuUsage": round(psutil.cpu_percent(interval=1)),
        "memoryUsage": round(psutil.virtual_memory().percent),
        "diskUsage": round(psutil.disk_usage(system_drive()).percent),
    }
