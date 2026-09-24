"""ZeroTier read-only tools (no network secrets/tokens)."""

from __future__ import annotations

from typing import Any

from ..client import _get_client
from ..redact import redact_value


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    return [value]


def _zt_summary(iface: dict) -> dict:
    zt = iface.get("zerotier") if isinstance(iface.get("zerotier"), dict) else {}
    return {
        key: value
        for key, value in {
            "id": iface.get("id") or iface.get("interface-name"),
            "description": iface.get("description") or None,
            "state": iface.get("state"),
            "link": iface.get("link"),
            "connected": iface.get("connected"),
            "address": iface.get("address"),
            "mask": iface.get("mask"),
            "mtu": iface.get("mtu"),
            "network_id": zt.get("network-id"),
            "network_name": zt.get("network-name"),
            "status": zt.get("status"),
            "local_id": zt.get("local-id"),
            "via": zt.get("via"),
            "local_endpoint": zt.get("local-endpoint-address"),
            "remote_endpoint": zt.get("remote-endpoint-address"),
        }.items()
        if value is not None and value != ""
    }


def _peer_summary(peer: dict) -> dict:
    paths = peer.get("path") or []
    if not isinstance(paths, list):
        paths = [paths] if paths else []
    latency = peer.get("latency")
    online = None
    if isinstance(latency, (int, float)):
        online = latency >= 0 and bool(paths)
    return {
        key: value
        for key, value in {
            "address": peer.get("address"),
            "latency_ms": latency if latency not in (-1, None) else None,
            "role": peer.get("role"),
            "version": peer.get("version") if peer.get("version") not in ("-1.-1.-1", None) else None,
            "path": paths or None,
            "online": online,
        }.items()
        if value is not None and value != ""
    }


async def _fetch_zt_ifaces(client) -> list[dict]:
    data = await client.rci_get("show/interface")
    if isinstance(data, dict):
        items = [v for v in data.values() if isinstance(v, dict)]
    elif isinstance(data, list):
        items = [item for item in data if isinstance(item, dict)]
    else:
        items = []
    return [
        item for item in items
        if item.get("type") == "ZeroTier" or str(item.get("id") or "").startswith("ZeroTier")
    ]


async def _fetch_peers(client, interface_id: str | None = None) -> list[dict]:
    """Peers via POST show.interface.zerotier.peers (UI path).

    NDMS requires an interface name — empty name returns an error.
    """
    payloads: list[dict] = []
    if interface_id:
        payloads.append({"show": {"interface": {"name": interface_id, "zerotier": {"peers": True}}}})
        payloads.append({"show": {"interface": [{"name": interface_id, "zerotier": {"peers": {}}}]}})
    for payload in payloads:
        try:
            data = await client.rci(payload)
        except Exception:  # noqa: BLE001
            continue
        node: Any = data
        for key in ("show", "interface", "zerotier", "peers"):
            if isinstance(node, dict) and key in node:
                node = node[key]
            elif isinstance(node, list) and node:
                first = node[0] if isinstance(node[0], dict) else {}
                if key in first:
                    node = first[key]
                elif "zerotier" in first:
                    node = first
                else:
                    break
            else:
                break
        if isinstance(node, dict) and "peer" in node:
            peers = _as_list(node.get("peer"))
            return [item for item in peers if isinstance(item, dict)]
        if isinstance(node, list) and node and isinstance(node[0], dict) and "address" in node[0]:
            return [item for item in node if isinstance(item, dict)]
    return []


async def list_zerotier() -> list[dict]:
    """List ZeroTier interfaces: network id/status/IPs (no tokens)."""
    async with _get_client() as client:
        ifaces = await _fetch_zt_ifaces(client)
        first_id = None
        if ifaces:
            first_id = str(ifaces[0].get("id") or ifaces[0].get("interface-name") or "") or None
        peers = await _fetch_peers(client, first_id)
    result = []
    for iface in ifaces:
        entry = _zt_summary(iface)
        if peers:
            entry["peers_count"] = len(peers)
            entry["peers"] = [_peer_summary(peer) for peer in peers]
        result.append(entry)
    result.sort(key=lambda item: item.get("id") or "")
    return redact_value(result)


async def get_zerotier(interface_id: str = "ZeroTier0") -> dict:
    """ZeroTier details for one interface including peers when available."""
    if not interface_id.strip():
        raise ValueError("interface_id is required")
    iface_id = interface_id.strip()
    async with _get_client() as client:
        data = await client.rci_get(f"show/interface/{iface_id}")
        if not isinstance(data, dict) or not data:
            raise ValueError(f"ZeroTier interface not found: {iface_id}")
        if data.get("type") and data.get("type") != "ZeroTier":
            raise ValueError(f"Interface is not ZeroTier: {iface_id}")
        peers = await _fetch_peers(client, iface_id)
    result = _zt_summary(data)
    result["peers"] = [_peer_summary(peer) for peer in peers]
    result["peers_count"] = len(peers)
    return redact_value(result)


def register(mcp) -> None:
    mcp.tool()(list_zerotier)
    mcp.tool()(get_zerotier)
