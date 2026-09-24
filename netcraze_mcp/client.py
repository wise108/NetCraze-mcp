"""NetCraze RCI HTTP client and credential helpers."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
from typing import Any

import httpx

logger = logging.getLogger("netcraze_mcp")


class NetCrazeError(RuntimeError):
    """Typed router/API error with actionable message (timeout/auth/HTTP)."""


class NetCrazeClient:
    """Async context manager that authenticates and wraps the NetCraze RCI API."""

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        *,
        timeout: float = 15.0,
        connect_timeout: float = 8.0,
    ) -> None:
        self._host = host
        self._user = user
        self._password = password
        self._timeout = httpx.Timeout(timeout, connect=connect_timeout)
        self._http: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "NetCrazeClient":
        self._http = httpx.AsyncClient(
            base_url=f"http://{self._host}",
            timeout=self._timeout,
        )
        try:
            await self._auth()
        except Exception:
            await self._http.aclose()
            self._http = None
            raise
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._http is not None:
            await self._http.aclose()

    def _wrap_http_error(self, exc: Exception, *, method: str, path: str) -> NetCrazeError:
        host = self._host
        if isinstance(exc, httpx.ConnectTimeout):
            return NetCrazeError(
                f"ConnectTimeout to {host} ({method} {path}): "
                f"router unreachable — check LAN/ZeroTier path, firewall, or power"
            )
        if isinstance(exc, httpx.ReadTimeout):
            return NetCrazeError(
                f"ReadTimeout to {host} ({method} {path}): "
                f"router slow or overloaded (timeout={self._timeout})"
            )
        if isinstance(exc, httpx.ConnectError):
            return NetCrazeError(
                f"ConnectError to {host} ({method} {path}): {exc}"
            )
        if isinstance(exc, httpx.HTTPStatusError):
            code = exc.response.status_code
            hint = ""
            if code in (401, 403):
                hint = " — auth failed (check NETCRAZE_USER/NETCRAZE_PASS or session expired)"
            elif code == 404:
                hint = " — RCI path not found on this firmware"
            body = (exc.response.text or "")[:120].replace("\n", " ")
            return NetCrazeError(
                f"HTTP {code} {method} {path} on {host}{hint}"
                + (f": {body}" if body else "")
            )
        return NetCrazeError(f"{type(exc).__name__} on {host} ({method} {path}): {exc}")

    async def _auth(self) -> None:
        assert self._http is not None
        try:
            resp = await self._http.get("/auth")
        except Exception as exc:  # noqa: BLE001
            raise self._wrap_http_error(exc, method="GET", path="/auth") from exc
        if resp.status_code == 200:
            return
        realm = resp.headers.get("X-NDM-Realm", "")
        challenge = resp.headers.get("X-NDM-Challenge", "")
        if not challenge:
            raise NetCrazeError(
                f"Auth challenge missing from {self._host} "
                f"(HTTP {resp.status_code}) — is this a NetCraze/Keenetic RCI?"
            )
        md5 = hashlib.md5(
            f"{self._user}:{realm}:{self._password}".encode()
        ).hexdigest()
        sha256 = hashlib.sha256(
            f"{challenge}{md5}".encode()
        ).hexdigest()
        try:
            auth_resp = await self._http.post(
                "/auth", json={"login": self._user, "password": sha256}
            )
            auth_resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            raise self._wrap_http_error(exc, method="POST", path="/auth") from exc

    async def rci(self, payload: dict | list) -> Any:
        assert self._http is not None
        try:
            resp = await self._http.post("/rci/", json=payload)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            raise self._wrap_http_error(exc, method="POST", path="/rci/") from exc

    async def rci_get(self, path: str, params: dict | None = None) -> Any:
        assert self._http is not None
        clean = path.lstrip("/")
        if clean.lower().startswith("rci/"):
            clean = clean[4:]
        logger.info("rci_get path=%s params=%s", clean, sorted((params or {}).keys()))
        try:
            resp = await self._http.get(f"/rci/{clean}", params=params or None)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            raise self._wrap_http_error(exc, method="GET", path=f"/rci/{clean}") from exc

    async def rci_continued(
        self,
        payload: dict,
        *,
        max_polls: int = 40,
        poll_interval: float = 0.35,
        overall_timeout: float = 20.0,
    ) -> dict:
        """POST /rci/ then poll with {\"continue\": true} until done (tools.ping/traceroute)."""
        assert self._http is not None
        messages: list[str] = []
        deadline = asyncio.get_event_loop().time() + overall_timeout
        try:
            resp = await self._http.post("/rci/", json=payload)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise self._wrap_http_error(exc, method="POST", path="/rci/") from exc

        def _collect(node: Any) -> tuple[list[str], bool]:
            found: list[str] = []
            continued = False

            def walk(value: Any) -> None:
                nonlocal continued
                if isinstance(value, dict):
                    if value.get("continued") is True:
                        continued = True
                    msg = value.get("message")
                    if isinstance(msg, list):
                        found.extend(str(item) for item in msg)
                    elif isinstance(msg, str):
                        found.append(msg)
                    for item in value.values():
                        walk(item)
                elif isinstance(value, list):
                    for item in value:
                        walk(item)

            walk(node)
            return found, continued

        chunk, continued = _collect(data)
        messages.extend(chunk)
        polls = 0
        while continued and polls < max_polls:
            if asyncio.get_event_loop().time() >= deadline:
                break
            await asyncio.sleep(poll_interval)
            polls += 1
            try:
                resp = await self._http.post("/rci/", json={"continue": True})
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:  # noqa: BLE001
                raise self._wrap_http_error(exc, method="POST", path="/rci/continue") from exc
            chunk, continued = _collect(data)
            messages.extend(chunk)
        return {
            "messages": messages,
            "continued": continued,
            "polls": polls,
            "raw_last": data,
        }

    async def ci_get_bytes(self, path: str) -> bytes:
        """Download binary from /ci/… (startup-config.txt, firmware, …)."""
        assert self._http is not None
        clean = path.lstrip("/")
        try:
            resp = await self._http.get(f"/ci/{clean}")
            resp.raise_for_status()
            return resp.content
        except Exception as exc:  # noqa: BLE001
            raise self._wrap_http_error(exc, method="GET", path=f"/ci/{clean}") from exc

    async def rci_post(self, path: str, payload: dict | list) -> Any:
        """POST JSON to /rci/<path> (e.g. interface/wireguard/import)."""
        assert self._http is not None
        clean = path.lstrip("/")
        logger.info("rci_post path=%s", clean)
        try:
            resp = await self._http.post(f"/rci/{clean}", json=payload)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            raise self._wrap_http_error(exc, method="POST", path=f"/rci/{clean}") from exc


def _get_client() -> NetCrazeClient:
    host = os.environ.get("NETCRAZE_HOST", "")
    user = os.environ.get("NETCRAZE_USER", "admin")
    password = os.environ.get("NETCRAZE_PASS", "")
    if not host:
        raise NetCrazeError(
            "NETCRAZE_HOST environment variable is not set. "
            "Example: NETCRAZE_HOST=192.168.1.1"
        )
    if not password:
        raise NetCrazeError(
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
        raise NetCrazeError("; ".join(errors))
