"""WAN details and public IP probes (read-only)."""

from __future__ import annotations

import ipaddress
from typing import Any

from ..client import _get_client
from ..redact import redact_value

_WAN_TYPES = frozenset({
    "UsbQmi", "CdcEthernet", "WifiStation", "PPTP", "PPPoE", "L2TP", "SSTP",
    "OpenConnect", "GigabitEthernet", "Ethernet",
})


def _is_private_or_cgnat(addr: str | None) -> bool | None:
    if not addr:
        return None
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return None
    if ip.version != 4:
        return None
    if ip.is_private or ip.is_link_local or ip.is_loopback or ip.is_reserved:
        return True
    # CGNAT 100.64.0.0/10
    if ipaddress.ip_address(addr) in ipaddress.ip_network("100.64.0.0/10"):
        return True
    return False


def _pick_wan_iface(ifaces: dict[str, dict], internet: dict) -> dict | None:
    gw_iface = ((internet.get("gateway") or {}) if isinstance(internet, dict) else {}).get("interface")
    if gw_iface and gw_iface in ifaces:
        return ifaces[gw_iface]
    # highest priority global defaultgw
    candidates = [
        item for item in ifaces.values()
        if isinstance(item, dict)
        and item.get("global")
        and item.get("link") == "up"
        and (
            item.get("defaultgw")
            or item.get("type") in _WAN_TYPES
        )
    ]
    if not candidates:
        candidates = [
            item for item in ifaces.values()
            if isinstance(item, dict) and item.get("defaultgw")
        ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: int(item.get("priority") or 0), reverse=True)
    return candidates[0]


def _connection_type(iface: dict, rc: dict | None) -> str:
    itype = str(iface.get("type") or "")
    mapping = {
        "PPPoE": "PPPoE",
        "PPTP": "PPTP",
        "L2TP": "L2TP",
        "SSTP": "SSTP",
        "OpenConnect": "OpenConnect",
        "UsbQmi": "USB-QMI",
        "CdcEthernet": "USB-Ethernet",
        "WifiStation": "WiFi-client",
        "GigabitEthernet": "Ethernet",
        "Ethernet": "Ethernet",
    }
    if itype in mapping:
        base = mapping[itype]
    else:
        base = itype or "unknown"
    if isinstance(rc, dict):
        ip_cfg = rc.get("ip") if isinstance(rc.get("ip"), dict) else {}
        if isinstance(ip_cfg.get("address"), dict) and ip_cfg["address"].get("dhcp"):
            return f"{base}/DHCP"
        if rc.get("pppoe") or itype == "PPPoE":
            return "PPPoE"
    return base


def _ipv6_summary(iface: dict) -> list[dict]:
    ipv6 = iface.get("ipv6") if isinstance(iface.get("ipv6"), dict) else {}
    addrs = ipv6.get("addresses") or []
    if isinstance(addrs, dict):
        addrs = list(addrs.values())
    result = []
    for item in addrs if isinstance(addrs, list) else []:
        if not isinstance(item, dict):
            continue
        result.append({
            key: value
            for key, value in {
                "address": item.get("address"),
                "prefix_length": item.get("prefix-length"),
                "proto": item.get("proto"),
            }.items()
            if value is not None
        })
    return result


async def get_wan_details() -> dict:
    """Structured WAN view: address, gateway, DNS, MTU, public IP hint, behind_nat."""
    async with _get_client() as client:
        ifaces_raw = await client.rci_get("show/interface")
        internet = await client.rci_get("show/internet/status")
        ndns = await client.rci_get("show/ndns")
        routes = await client.rci_get("show/ip/route")
        rc_ifaces = None
        try:
            rc_ifaces = await client.rci_get("show/rc/interface")
        except Exception:  # noqa: BLE001
            rc_ifaces = None

    if isinstance(ifaces_raw, dict):
        ifaces = {k: v for k, v in ifaces_raw.items() if isinstance(v, dict)}
    elif isinstance(ifaces_raw, list):
        ifaces = {
            str(item.get("id") or index): item
            for index, item in enumerate(ifaces_raw)
            if isinstance(item, dict)
        }
    else:
        ifaces = {}

    wan = _pick_wan_iface(ifaces, internet if isinstance(internet, dict) else {})
    if not wan:
        return {"ok": False, "error": "No WAN/defaultgw interface found"}

    wan_id = str(wan.get("id") or "")
    rc = (rc_ifaces or {}).get(wan_id) if isinstance(rc_ifaces, dict) else None

    gateway = None
    if isinstance(internet, dict):
        gateway = ((internet.get("gateway") or {}) if isinstance(internet.get("gateway"), dict) else {}).get("address")
    if not gateway:
        route_list = routes if isinstance(routes, list) else (routes.get("route") if isinstance(routes, dict) else [])
        if not isinstance(route_list, list):
            route_list = [route_list] if route_list else []
        for route in route_list:
            if not isinstance(route, dict):
                continue
            dest = str(route.get("destination") or "")
            if dest in ("0.0.0.0/0", "default") and route.get("interface") in (wan_id, wan.get("interface-name")):
                gateway = route.get("gateway")
                break

    address = wan.get("address")
    private = _is_private_or_cgnat(str(address) if address else None)
    public_ip = None
    public_source = None
    if isinstance(ndns, dict):
        for key in ("address", "address6"):
            val = ndns.get(key)
            if val and str(val) not in ("", "::", "0.0.0.0"):
                # ignore if same as private WAN
                if key == "address" and val == address:
                    continue
                if private is True and key == "address" and _is_private_or_cgnat(str(val)):
                    continue
                if not _is_private_or_cgnat(str(val)):
                    public_ip = val
                    public_source = f"ndns.{key}"
                    break
        ttp = ndns.get("ttp") if isinstance(ndns.get("ttp"), dict) else {}
        if not public_ip and ttp.get("direct") and ttp.get("address") and not _is_private_or_cgnat(str(ttp.get("address"))):
            public_ip = ttp.get("address")
            public_source = "ndns.ttp"

    if private is True:
        behind_nat: bool | str = True
    elif private is False:
        behind_nat = False if not public_ip or public_ip == address else True
    else:
        behind_nat = "unknown"

    dns_isp: list[str] = []
    # DHCP-learned DNS sometimes appears on interface; also check name-server empty note
    for key in ("dns", "name-server", "nameserver"):
        raw = wan.get(key)
        if isinstance(raw, list):
            dns_isp.extend(str(item) for item in raw if item)
        elif isinstance(raw, str) and raw:
            dns_isp.append(raw)

    return redact_value({
        "ok": True,
        "interface": {
            "id": wan_id,
            "name": wan.get("interface-name") or wan_id,
            "description": wan.get("description") or None,
            "type": wan.get("type"),
            "connection_type": _connection_type(wan, rc if isinstance(rc, dict) else None),
            "state": wan.get("state"),
            "link": wan.get("link"),
            "connected": wan.get("connected"),
            "mtu": wan.get("mtu"),
            "priority": wan.get("priority"),
            "global": wan.get("global"),
            "defaultgw": wan.get("defaultgw"),
        },
        "ipv4": {
            "address": address,
            "mask": wan.get("mask"),
            "gateway": gateway,
            "dns_isp": dns_isp or None,
        },
        "ipv6": _ipv6_summary(wan) or None,
        "upstream_gateway": gateway,
        "public_ipv4": public_ip,
        "public_ip_source": public_source,
        "behind_nat": behind_nat,
        "internet": {
            key: value
            for key, value in {
                "internet": (internet or {}).get("internet") if isinstance(internet, dict) else None,
                "reliable": (internet or {}).get("reliable") if isinstance(internet, dict) else None,
                "gateway_accessible": (internet or {}).get("gateway-accessible") if isinstance(internet, dict) else None,
                "dns_accessible": (internet or {}).get("dns-accessible") if isinstance(internet, dict) else None,
            }.items()
            if value is not None
        },
        "ndns": redact_value({
            key: (ndns or {}).get(key)
            for key in ("domain", "address", "address6", "booked", "ttp")
            if isinstance(ndns, dict) and (ndns.get(key) not in (None, ""))
        }) or None,
    })


async def get_public_ip() -> dict:
    """Read-only public IP probe via NDNS/CrazeDNS if the router knows it.

    Does not change routes. Returns unsupported when NDMS has no public mapping.
    """
    async with _get_client() as client:
        ndns = await client.rci_get("show/ndns")
        internet = await client.rci_get("show/internet/status")
        ifaces_raw = await client.rci_get("show/interface")

    if isinstance(ifaces_raw, dict):
        ifaces = {k: v for k, v in ifaces_raw.items() if isinstance(v, dict)}
    else:
        ifaces = {}
    wan = _pick_wan_iface(ifaces, internet if isinstance(internet, dict) else {})
    wan_addr = wan.get("address") if wan else None

    candidates: list[dict[str, Any]] = []
    if isinstance(ndns, dict):
        for key in ("address", "address6"):
            val = ndns.get(key)
            if not val or str(val) in ("", "::", "0.0.0.0"):
                continue
            if key == "address" and val == wan_addr:
                continue
            if _is_private_or_cgnat(str(val)):
                continue
            candidates.append({"ip": val, "source": f"ndns.{key}"})
        ttp = ndns.get("ttp") if isinstance(ndns.get("ttp"), dict) else {}
        if ttp.get("direct") and ttp.get("address") and not _is_private_or_cgnat(str(ttp.get("address"))):
            candidates.append({"ip": ttp.get("address"), "source": "ndns.ttp.direct"})

    if not candidates:
        return {
            "ok": False,
            "supported": False,
            "unsupported": True,
            "reason": (
                "Router NDNS/CrazeDNS has no public IPv4 mapping "
                "(typical behind NAT). Probe from an external host or enable DynDNS."
            ),
            "wan_ipv4": wan_addr,
            "behind_nat": _is_private_or_cgnat(str(wan_addr) if wan_addr else None),
        }
    best = candidates[0]
    return {
        "ok": True,
        "supported": True,
        "public_ip": best["ip"],
        "source": best["source"],
        "candidates": candidates,
        "wan_ipv4": wan_addr,
    }


def register(mcp) -> None:
    mcp.tool()(get_wan_details)
    mcp.tool()(get_public_ip)
