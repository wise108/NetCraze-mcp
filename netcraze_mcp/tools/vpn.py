"""Unified VPN / tunnel listing (WireGuard, OpenVPN, IPsec, ZeroTier, …)."""

from __future__ import annotations

from typing import Any

from ..client import _get_client
from ..redact import redact_value
from . import ipsec as ipsec_tools

# Interface types that appear under UI «Другие подключения» / VPN.
_VPN_IFACE_TYPES = frozenset({
    "Wireguard", "OpenVPN", "PPTP", "L2TP", "SSTP", "OpenConnect",
    "ZeroTier", "Gre", "GRE", "Ipip", "IPIP", "EoIP", "IKE", "IPSec",
})


def _enabled(iface: dict) -> bool:
    return iface.get("state") == "up"


def _from_iface(iface: dict) -> dict:
    itype = str(iface.get("type") or "unknown")
    return {
        key: value
        for key, value in {
            "id": iface.get("id") or iface.get("interface-name"),
            "type": itype,
            "description": iface.get("description") or None,
            "enabled": _enabled(iface),
            "connected": iface.get("connected") == "yes" or iface.get("link") == "up",
            "link": iface.get("link"),
            "state": iface.get("state"),
            "address": iface.get("address"),
            "mask": iface.get("mask"),
            "mtu": iface.get("mtu"),
            "source": "interface",
        }.items()
        if value is not None and value != ""
    }


def _from_ipsec(item: dict) -> dict:
    return {
        key: value
        for key, value in {
            "id": item.get("id") or item.get("name"),
            "type": "IPsec-S2S",
            "description": item.get("description") or item.get("name"),
            "enabled": item.get("enabled"),
            "connected": item.get("connected"),
            "state": item.get("state"),
            "remote_gateway": item.get("remote_gateway"),
            "source": "ipsec",
        }.items()
        if value is not None and value != ""
    }


async def list_vpn_connections() -> list[dict]:
    """Unified list of VPN/tunnels: WG, OpenVPN, PPTP/L2TP/SSTP, IPsec, GRE/IPIP/EoIP, ZeroTier."""
    async with _get_client() as client:
        data = await client.rci_get("show/interface")
    try:
        ipsec_list = await ipsec_tools.list_ipsec()
    except Exception:  # noqa: BLE001
        ipsec_list = []

    if isinstance(data, dict):
        ifaces = [v for v in data.values() if isinstance(v, dict)]
    elif isinstance(data, list):
        ifaces = [item for item in data if isinstance(item, dict)]
    else:
        ifaces = []

    result: list[dict] = []
    for iface in ifaces:
        itype = str(iface.get("type") or "")
        iid = str(iface.get("id") or "")
        if itype in _VPN_IFACE_TYPES or any(
            iid.startswith(prefix)
            for prefix in ("Wireguard", "OpenVPN", "ZeroTier", "PPTP", "L2TP", "SSTP", "Gre", "Ipip", "EoIP")
        ):
            result.append(_from_iface(iface))

    for item in ipsec_list:
        if isinstance(item, dict):
            result.append(_from_ipsec(item))

    # de-dupe by id
    seen: set[str] = set()
    unique: list[dict] = []
    for item in result:
        key = str(item.get("id") or "")
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        unique.append(item)
    unique.sort(key=lambda item: (str(item.get("type") or ""), str(item.get("id") or "")))
    return redact_value(unique)


async def get_vpn_connection(connection_id: str) -> dict:
    """Details for one VPN/tunnel by id (no secrets)."""
    if not connection_id.strip():
        raise ValueError("connection_id is required")
    cid = connection_id.strip()

    # IPsec S2S ids are map names, not interfaces
    try:
        ipsec = await ipsec_tools.get_ipsec(cid)
        if ipsec:
            return redact_value({"id": cid, "type": "IPsec-S2S", **ipsec})
    except ValueError:
        pass
    except Exception:  # noqa: BLE001
        pass

    async with _get_client() as client:
        data = await client.rci_get(f"show/interface/{cid}")
    if not isinstance(data, dict) or not data.get("id"):
        raise ValueError(f"VPN connection not found: {cid}")

    base = _from_iface(data)
    # attach type-specific non-secret blocks
    if data.get("type") == "Wireguard" and isinstance(data.get("wireguard"), dict):
        from .wireguard import _wg_details
        return redact_value({**base, **_wg_details(data), "type": "Wireguard"})
    if data.get("type") == "ZeroTier":
        from .zerotier import _fetch_peers, _peer_summary, _zt_summary
        async with _get_client() as client:
            peers = await _fetch_peers(client, cid)
        detail = _zt_summary(data)
        detail["peers"] = [_peer_summary(peer) for peer in peers]
        return redact_value({**base, **detail})
    # strip nested secrets from raw extras
    extras = {
        key: value
        for key, value in data.items()
        if key not in ("wireguard", "openvpn", "pptp", "l2tp") and not isinstance(value, (dict, list))
    }
    return redact_value({**base, "details": redact_value(extras)})


def register(mcp) -> None:
    mcp.tool()(list_vpn_connections)
    mcp.tool()(get_vpn_connection)
