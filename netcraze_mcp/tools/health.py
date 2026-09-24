"""Running-config redacted view and health check."""

from __future__ import annotations

import os
import re
import time
from typing import Any

from ..client import NetCrazeError, _get_client
from ..redact import redact_cli_text

_SECTION_HEADERS = {
    "crypto": re.compile(r"^(crypto|ipsec)\b", re.I),
    "interface": re.compile(r"^interface\b", re.I),
    "ip": re.compile(r"^ip\b", re.I),
    "dns": re.compile(r"^(dns|dns-proxy|domain-object|ip name-server)\b", re.I),
    "system": re.compile(r"^system\b", re.I),
    "user": re.compile(r"^user\b", re.I),
    "service": re.compile(r"^service\b", re.I),
    "components": re.compile(r"^components\b", re.I),
}


def _filter_config_sections(text: str, filter_name: str) -> str:
    key = filter_name.strip().lower()
    if not key or key in ("*", "all"):
        return text
    matcher = _SECTION_HEADERS.get(key)
    if matcher is None:
        # substring match on first token of top-level commands
        matcher = re.compile(rf"^{re.escape(key)}\b", re.I)

    lines = text.splitlines()
    out: list[str] = []
    capturing = False
    for line in lines:
        stripped = line.strip()
        if not line.startswith(" ") and not line.startswith("\t") and stripped and stripped != "!":
            capturing = bool(matcher.match(stripped))
        if capturing or (stripped == "!" and capturing):
            out.append(line)
            if stripped == "!" and capturing:
                capturing = False
    return "\n".join(out)


async def get_running_config_redacted(filter: str = "") -> dict:
    """Safe show/running-config dump with secrets stripped.

    filter — optional section: crypto, interface, ip, dns, system, …
    """
    async with _get_client() as client:
        raw = await client.rci_get("show/running-config")
    messages = []
    if isinstance(raw, dict):
        messages = raw.get("message") or []
        if isinstance(messages, str):
            messages = [messages]
    elif isinstance(raw, list):
        messages = [str(item) for item in raw]
    else:
        messages = [str(raw)]
    text = "\n".join(str(line) for line in messages)
    if filter.strip():
        text = _filter_config_sections(text, filter.strip())
    redacted = redact_cli_text(text)
    return {
        "ok": True,
        "filter": filter.strip() or None,
        "lines": len(redacted.splitlines()),
        "config": redacted,
        "note": "Secrets (password/private-key/psk/…) replaced with <REDACTED>",
    }


async def health_check() -> dict:
    """Auth, firmware, uptime, WAN internet, latency to router — clear errors on failure."""
    host_env = os.environ.get("NETCRAZE_HOST", "")
    started = time.perf_counter()
    result: dict[str, Any] = {
        "ok": False,
        "host": host_env or None,
        "auth_ok": False,
    }
    try:
        async with _get_client() as client:
            auth_ms = round((time.perf_counter() - started) * 1000, 1)
            result["auth_ok"] = True
            result["latency_ms"] = auth_ms
            t1 = time.perf_counter()
            version = await client.rci_get("show/version")
            system = await client.rci_get("show/system")
            internet = await client.rci_get("show/internet/status")
            result["rci_latency_ms"] = round((time.perf_counter() - t1) * 1000, 1)
    except NetCrazeError as exc:
        result["error"] = str(exc)
        result["error_type"] = "NetCrazeError"
        return result
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["error_type"] = type(exc).__name__
        return result

    result.update({
        "ok": True,
        "model": (
            (version.get("model") or version.get("title"))
            if isinstance(version, dict) else None
        ),
        "firmware": version.get("release") if isinstance(version, dict) else None,
        "sandbox": version.get("sandbox") if isinstance(version, dict) else None,
        "hostname": system.get("hostname") if isinstance(system, dict) else None,
        "uptime": system.get("uptime") if isinstance(system, dict) else None,
        "wan_internet": internet.get("internet") if isinstance(internet, dict) else None,
        "wan_reliable": internet.get("reliable") if isinstance(internet, dict) else None,
        "gateway": (
            (internet.get("gateway") or {}).get("address")
            if isinstance(internet, dict) else None
        ),
        "gateway_interface": (
            (internet.get("gateway") or {}).get("interface")
            if isinstance(internet, dict) else None
        ),
    })
    return {k: v for k, v in result.items() if v is not None}


def register(mcp) -> None:
    mcp.tool()(get_running_config_redacted)
    mcp.tool()(health_check)
