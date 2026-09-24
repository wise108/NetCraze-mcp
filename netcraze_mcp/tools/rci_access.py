"""Raw RCI GET access with automatic secret redaction."""

from __future__ import annotations

from typing import Any

from ..client import _get_client
from ..redact import is_denied_safe_path, normalize_rci_path, redact_value


async def rci_get(path: str, params: dict | None = None) -> dict:
    """GET /rci/<path> using the MCP auth session. Secrets are redacted.

    path — without leading /rci (e.g. show/system, show/interface, show/ip/route).
    Only GET. For POST/write use a separate dangerous tool with confirm=true.
    """
    clean = normalize_rci_path(path)
    async with _get_client() as client:
        data = await client.rci_get(clean, params=params)
    return {
        "path": clean,
        "ok": True,
        "data": redact_value(data),
    }


async def rci_get_safe(path: str) -> dict:
    """Like rci_get, but refuses paths that typically hold secrets.

    Deny-list includes: password, private-key, psk, secret, token, ipsec.secrets, …
    """
    clean = normalize_rci_path(path)
    if is_denied_safe_path(clean):
        return {
            "path": clean,
            "ok": False,
            "denied": True,
            "error": (
                "path blocked by rci_get_safe deny-list "
                "(likely contains secrets). Use a typed read-only tool instead."
            ),
        }
    async with _get_client() as client:
        data = await client.rci_get(clean)
    return {
        "path": clean,
        "ok": True,
        "data": redact_value(data),
    }


def register(mcp) -> None:
    mcp.tool()(rci_get)
    mcp.tool()(rci_get_safe)
