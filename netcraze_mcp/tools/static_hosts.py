"""Static DNS host tools (ip host)."""

import ipaddress
import re

from ..client import _get_client
from ..config import assert_writable


def _is_private_ip(value: str) -> bool:
    """Return True only for RFC1918 private IPv4 ranges."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.version != 4:
        return False
    return any(
        ip in net
        for net in (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
    )


def _collect_static_a_entries(value, result: list[dict], *, in_static_a: bool = False) -> None:
    if isinstance(value, dict):
        if in_static_a:
            if ("host" in value or "name" in value) and ("ip" in value or "address" in value):
                result.append({
                    "host": str(value.get("host") or value.get("name")),
                    "ip": str(value.get("ip") or value.get("address")),
                })
            return

        for key, item in value.items():
            if key == "static_a":
                _collect_static_a_entries(item, result, in_static_a=True)
            else:
                _collect_static_a_entries(item, result, in_static_a=in_static_a)
        return
    if isinstance(value, list):
        for item in value:
            _collect_static_a_entries(item, result, in_static_a=in_static_a)
        return
    if isinstance(value, str) and value.strip():
        for line in value.splitlines():
            m = re.search(r"static_a\s*=\s*(\S+)\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                result.append({"host": m.group(1), "ip": m.group(2)})


def _normalize_static_entries(data) -> list[dict]:
    entries: list[dict] = []
    _collect_static_a_entries(data, entries)
    result: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        if not _is_private_ip(entry["ip"]):
            continue
        key = (entry["host"], entry["ip"])
        if key in seen:
            continue
        seen.add(key)
        result.append(entry)
    return result


async def list_static_hosts(sort_by: str = "", order: str = "asc") -> list[dict]:
    """List static DNS hosts from show dns-proxy, filtered by private IP ranges."""
    if sort_by and sort_by not in ("name", "ip"):
        raise ValueError("sort_by must be 'name' or 'ip'")
    if order not in ("asc", "desc"):
        raise ValueError("order must be 'asc' or 'desc'")
    if not sort_by and order != "asc":
        raise ValueError("order can be used only with sort_by")
    async with _get_client() as client:
        data = await client.rci_get("show/dns-proxy")
    entries = _normalize_static_entries(data)
    if sort_by == "name":
        entries.sort(key=lambda item: item["host"], reverse=order == "desc")
    if sort_by == "ip":
        entries.sort(
            key=lambda item: tuple(int(part) for part in item["ip"].split(".")),
            reverse=order == "desc",
        )
    return entries


async def add_static_host(host: str, ip: str) -> dict:
    """Add static DNS host and save configuration."""
    assert_writable()
    if not _is_private_ip(ip):
        raise ValueError("Only private IPv4 addresses are allowed.")
    async with _get_client() as client:
        await client.rci([
            {"ip": {"host": {"name": host, "address": ip}}},
            {"system": {"configuration": {"save": {}}}},
        ])
    return {"added": True, "host": host, "ip": ip}


async def delete_static_host(host: str) -> dict:
    """Delete static DNS host by name and save configuration."""
    assert_writable()
    entries = await list_static_hosts()
    ip = next((entry["ip"] for entry in entries if entry["host"] == host), "")
    if not ip:
        raise ValueError(f"Static host not found: {host}")
    async with _get_client() as client:
        await client.rci([
            {"ip": {"host": {"name": host, "address": ip, "no": True}}},
            {"system": {"configuration": {"save": {}}}},
        ])
    return {"deleted": True, "host": host, "ip": ip}


def register(mcp) -> None:
    mcp.tool()(list_static_hosts)
    mcp.tool()(add_static_host)
    mcp.tool()(delete_static_host)
