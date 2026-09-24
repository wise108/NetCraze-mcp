"""Read-only diagnostics: ping / traceroute / nslookup with hard limits."""

from __future__ import annotations

import re
from typing import Any

from ..client import _get_client
from ..redact import redact_value

_HOST_RE = re.compile(r"^[A-Za-z0-9._\-:%]+$")


def _check_host(host: str) -> str:
    cleaned = (host or "").strip()
    if not cleaned or len(cleaned) > 253:
        raise ValueError("host is required (max 253 chars)")
    if not _HOST_RE.match(cleaned):
        raise ValueError("host contains invalid characters")
    if cleaned.startswith("-"):
        raise ValueError("host must not start with '-'")
    return cleaned


def _parse_ping_stats(messages: list[str]) -> dict:
    text = "\n".join(messages)
    transmitted = received = loss = None
    rtt = None
    for line in messages:
        if "packets transmitted" in line:
            # 2 packets transmitted, 2 packets received, 0% packet loss,
            m = re.search(
                r"(\d+)\s+packets transmitted,\s*(\d+)\s+packets received,\s*([\d.]+)%\s+packet loss",
                line,
            )
            if m:
                transmitted, received, loss = int(m.group(1)), int(m.group(2)), float(m.group(3))
        if "Round-trip" in line or "rtt" in line.lower():
            m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)", line)
            if m:
                rtt = {"min_ms": float(m.group(1)), "avg_ms": float(m.group(2)), "max_ms": float(m.group(3))}
    ok = received is not None and received > 0
    return {
        "ok": ok,
        "transmitted": transmitted,
        "received": received,
        "loss_percent": loss,
        "rtt": rtt,
        "output": text,
    }


async def router_ping(host: str, count: int = 3, interface: str = "") -> dict:
    """ICMP ping from the router (count≤5). Does not change routes."""
    target = _check_host(host)
    count = max(1, min(int(count), 5))
    payload: dict[str, Any] = {"tools": {"ping": {"host": target, "count": count}}}
    if interface.strip():
        payload["tools"]["ping"]["interface"] = interface.strip()
    async with _get_client() as client:
        result = await client.rci_continued(
            payload,
            max_polls=25,
            overall_timeout=min(5 + count * 2, 18),
        )
    stats = _parse_ping_stats(result.get("messages") or [])
    return redact_value({
        "host": target,
        "count": count,
        "interface": interface.strip() or None,
        **stats,
        "polls": result.get("polls"),
    })


async def router_traceroute(host: str, max_hops: int = 10, interface: str = "") -> dict:
    """Traceroute from the router (max_hops≤15) if NDMS supports tools.traceroute."""
    target = _check_host(host)
    max_hops = max(1, min(int(max_hops), 15))
    payload: dict[str, Any] = {
        "tools": {"traceroute": {"host": target, "max-ttl": max_hops}},
    }
    if interface.strip():
        payload["tools"]["traceroute"]["interface"] = interface.strip()
    async with _get_client() as client:
        try:
            result = await client.rci_continued(
                payload,
                max_polls=40,
                overall_timeout=min(8 + max_hops * 1.5, 25),
            )
        except Exception as exc:  # noqa: BLE001
            return {
                "ok": False,
                "supported": False,
                "unsupported": True,
                "host": target,
                "error": str(exc).split("\n")[0][:240],
            }
    messages = result.get("messages") or []
    text = "\n".join(messages)
    if "not found" in text.lower() or "no such command" in text.lower():
        return {
            "ok": False,
            "supported": False,
            "unsupported": True,
            "host": target,
            "reason": "tools.traceroute not available on this firmware",
            "output": text,
        }
    hops = [line for line in messages if re.match(r"^\s*\d+\s+", line)]
    return redact_value({
        "ok": True,
        "supported": True,
        "host": target,
        "max_hops": max_hops,
        "interface": interface.strip() or None,
        "hops": hops,
        "output": text,
        "polls": result.get("polls"),
    })


async def router_nslookup(name: str) -> dict:
    """Resolve a name via the router.

    NDMS 5.01 has no tools.nslookup/dig — uses tools.ping count=1 and parses the resolved A record.
    Does not change routes.
    """
    target = _check_host(name)
    async with _get_client() as client:
        # Prefer dedicated tools if firmware gains them later
        for payload in (
            {"tools": {"nslookup": {"name": target}}},
            {"tools": {"dig": {"name": target}}},
        ):
            try:
                data = await client.rci(payload)
            except Exception:  # noqa: BLE001
                continue
            text = str(data)
            if "not found" in text.lower() or '"status": "error"' in text.replace("'", '"'):
                continue
            return redact_value({"ok": True, "name": target, "method": "tools", "raw": data})

        result = await client.rci_continued(
            {"tools": {"ping": {"host": target, "count": 1}}},
            max_polls=15,
            overall_timeout=10,
        )
    messages = result.get("messages") or []
    text = "\n".join(messages)
    addresses: list[str] = []
    for line in messages:
        m = re.search(r"PING\s+\S+\s+\(([^)]+)\)", line)
        if m:
            addresses.append(m.group(1))
        m = re.search(r"bytes from\s+(\S+)\s+\(([^)]+)\)", line)
        if m and m.group(2) not in addresses:
            addresses.append(m.group(2))
    if not addresses:
        return {
            "ok": False,
            "name": target,
            "method": "ping-resolve",
            "error": "name did not resolve (or ping blocked)",
            "output": text,
        }
    return redact_value({
        "ok": True,
        "name": target,
        "addresses": addresses,
        "method": "ping-resolve",
        "note": "NDMS has no nslookup; resolved via tools.ping count=1",
        "output": text,
    })


def register(mcp) -> None:
    mcp.tool()(router_ping)
    mcp.tool()(router_traceroute)
    mcp.tool()(router_nslookup)
