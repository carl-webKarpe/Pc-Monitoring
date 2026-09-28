"""HTTP client for the MST PHP API (/api/agent/*), authenticated with this PC's device token."""

from __future__ import annotations

import requests

from . import VERSION
from .config import AgentConfig


class ApiError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class ApiClient:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {config.device_token}",
            "X-Device-Id": config.device_id,
            "User-Agent": f"MST-Agent/{VERSION}",
            "Content-Type": "application/json",
        })

    def _post(self, path: str, payload: dict) -> dict:
        try:
            response = self.session.post(f"{self.config.server_url}{path}", json=payload, timeout=self.config.request_timeout_seconds)
        except requests.RequestException as error:
            raise ApiError(f"MST server not reachable: {error.__class__.__name__}") from error
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code >= 400 or body.get("success") is False:
            message = body.get("message") or f"HTTP {response.status_code}"
            if response.status_code == 401:
                message = "Device not authorized: check device_id and device_token in config.json"
            raise ApiError(message, response.status_code)
        return body.get("data") or {}

    def heartbeat(self, payload: dict) -> dict:
        return self._post("/agent/heartbeat", payload)

    def send_events(self, events: list[dict]) -> dict:
        return self._post("/agent/events", {"events": events})
