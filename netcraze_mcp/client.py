"""NetCraze RCI HTTP client and credential helpers."""

import hashlib
import os
import re
from typing import Any

import httpx


class NetCrazeClient:
    """Async context manager that authenticates and wraps the NetCraze RCI API."""

    def __init__(self, host: str, user: str, password: str) -> None:
        self._host = host
        self._user = user
        self._password = password
        self._http: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "NetCrazeClient":
        self._http = httpx.AsyncClient(
            base_url=f"http://{self._host}",
            timeout=15.0,
        )
        await self._auth()
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._http is not None:
            await self._http.aclose()

    async def _auth(self) -> None:
        assert self._http is not None
        resp = await self._http.get("/auth")
        if resp.status_code == 200:
            return
        realm = resp.headers.get("X-NDM-Realm", "")
        challenge = resp.headers.get("X-NDM-Challenge", "")
        md5 = hashlib.md5(
            f"{self._user}:{realm}:{self._password}".encode()
        ).hexdigest()
        sha256 = hashlib.sha256(
            f"{challenge}{md5}".encode()
        ).hexdigest()
        auth_resp = await self._http.post(
            "/auth", json={"login": self._user, "password": sha256}
        )
        auth_resp.raise_for_status()

    async def rci(self, payload: dict | list) -> Any:
        assert self._http is not None
        resp = await self._http.post("/rci/", json=payload)
        resp.raise_for_status()
        return resp.json()

    async def rci_get(self, path: str) -> Any:
        assert self._http is not None
        resp = await self._http.get(f"/rci/{path}")
        resp.raise_for_status()
        return resp.json()

    async def ci_get_bytes(self, path: str) -> bytes:
        """Download binary from /ci/… (startup-config.txt, firmware, …)."""
        assert self._http is not None
        resp = await self._http.get(f"/ci/{path.lstrip('/')}")
        resp.raise_for_status()
        return resp.content

    async def rci_post(self, path: str, payload: dict | list) -> Any:
        """POST JSON to /rci/<path> (e.g. interface/wireguard/import)."""
        assert self._http is not None
        resp = await self._http.post(f"/rci/{path.lstrip('/')}", json=payload)
        resp.raise_for_status()
        return resp.json()


def _get_client() -> NetCrazeClient:
    host = os.environ.get("NETCRAZE_HOST", "")
    user = os.environ.get("NETCRAZE_USER", "admin")
    password = os.environ.get("NETCRAZE_PASS", "")
    if not host:
        raise RuntimeError(
            "NETCRAZE_HOST environment variable is not set. "
            "Example: NETCRAZE_HOST=192.168.1.1"
        )
    if not password:
        raise RuntimeError(
            "NETCRAZE_PASS environment variable is not set."
        )
    return NetCrazeClient(host=host, user=user, password=password)


def _sanitize_error(e: Exception) -> str:
    msg = str(e)
    msg = re.sub(
        r"(?i)(password|token|pass|private[_-]?key|preshared[_-]?key)[=:\s]+\S+",
        r"\1=<redacted>",
        msg,
    )
    # WireGuard base64 keys (32 bytes → 44 chars with padding)
    return re.sub(r"[A-Za-z0-9+/]{42,44}=", "***", msg)


def _raise_on_rci_errors(data: Any) -> None:
    """RCI returns HTTP 200 even on command errors — fail if status=error."""
    errors: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            status = value.get("status")
            if isinstance(status, list):
                for item in status:
                    if isinstance(item, dict) and item.get("status") == "error":
                        errors.append(str(item.get("message") or item))
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(data)
    if errors:
        raise RuntimeError("; ".join(errors))
