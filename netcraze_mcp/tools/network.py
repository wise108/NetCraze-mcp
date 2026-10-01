"""Network and interface tools."""

import asyncio
import time
from typing import Any

from ..client import _get_client
from ..config import assert_writable

_WAN_TYPES = frozenset({"UsbQmi", "CdcEthernet", "WifiStation", "Wireguard", "PPTP", "PPPoE", "L2TP"})


async def get_interfaces() -> list[dict]:
    async with _get_client() as client:
        data = await client.rci_get("show/interface")
        if isinstance(data, dict):
            ifaces = [value for value in data.values() if isinstance(value, dict)]
        elif isinstance(data, list):
            ifaces = data
        else:
            ifaces = [data]
        return [_interface_to_dict(item) for item in ifaces]


async def get_interface(name: str) -> dict:
    async with _get_client() as client:
        data = await client.rci_get(f"show/interface/{name}")
        return _interface_to_dict(data)


async def get_connected_clients() -> list[dict]:
    async with _get_client() as client:
        hosts = await client.rci_get("show/ip/hotspot/host")
        if not isinstance(hosts, list):
            hosts = [hosts] if hosts else []
        return [_host_to_dict(item) for item in hosts]


async def get_hotspot(
    active_only: bool = False,
    name: str = "",
    ip: str = "",
    mac: str = "",
) -> dict:
    """Read-only hotspot hosts (show/ip/hotspot) with audit fields.

    Richer than get_connected_clients: policy/access/ssid/ap/rssi for DoH/Xbox-style checks.
    Does not change config.
    """
    name_s = (name or "").strip().lower()
    ip_s = (ip or "").strip()
    mac_s = (mac or "").strip().lower()

    async with _get_client() as client:
        raw = await client.rci_get("show/ip/hotspot")
    hosts_raw = []
    if isinstance(raw, dict):
        hosts_raw = raw.get("host") or []
    elif isinstance(raw, list):
        hosts_raw = raw
    if not isinstance(hosts_raw, list):
        hosts_raw = [hosts_raw] if hosts_raw else []

    hosts = []
    for item in hosts_raw:
        if not isinstance(item, dict):
            continue
        entry = _hotspot_host_to_dict(item)
        if active_only and not entry.get("active"):
            continue
        if name_s:
            blob = " ".join(
                str(entry.get(k) or "") for k in ("name", "hostname")
            ).lower()
            if name_s not in blob:
                continue
        if ip_s and entry.get("ip") != ip_s:
            continue
        if mac_s and str(entry.get("mac") or "").lower() != mac_s:
            continue
        hosts.append(entry)

    return {
        "ok": True,
        "source": "show/ip/hotspot",
        "count": len(hosts),
        "hosts": hosts,
        "note": (
            "Read-only. Filters are local. "
            "get_connected_clients remains the compact client list."
        ),
    }


async def get_speed(interval: float = 3.0) -> dict:
    interval = max(1.0, min(interval, 10.0))
    async with _get_client() as client:
        hosts1 = await client.rci_get("show/ip/hotspot/host")
        t1 = time.monotonic()
        await asyncio.sleep(interval)
        hosts2 = await client.rci_get("show/ip/hotspot/host")
        t2 = time.monotonic()

    dt = t2 - t1
    rx1 = sum((item.get("rxbytes") or 0) for item in hosts1 if item.get("active"))
    tx1 = sum((item.get("txbytes") or 0) for item in hosts1 if item.get("active"))
    rx2 = sum((item.get("rxbytes") or 0) for item in hosts2 if item.get("active"))
    tx2 = sum((item.get("txbytes") or 0) for item in hosts2 if item.get("active"))
    dl_mbps = round((rx2 - rx1) / dt * 8 / 1_000_000, 2)
    ul_mbps = round((tx2 - tx1) / dt * 8 / 1_000_000, 2)

    by_mac2 = {item["mac"]: item for item in hosts2 if "mac" in item}
    by_mac1 = {item["mac"]: item for item in hosts1 if "mac" in item}
    top_clients: list[dict[str, float | str]] = []
    for mac, item2 in by_mac2.items():
        if not item2.get("active") or mac not in by_mac1:
            continue
        item1 = by_mac1[mac]
        d_rx = ((item2.get("rxbytes") or 0) - (item1.get("rxbytes") or 0)) / dt * 8 / 1_000_000
        d_tx = ((item2.get("txbytes") or 0) - (item1.get("txbytes") or 0)) / dt * 8 / 1_000_000
        if d_rx + d_tx > 0.01:
            top_clients.append(
                {
                    "name": item2.get("hostname") or item2.get("name") or mac,
                    "dl_mbps": round(d_rx, 2),
                    "ul_mbps": round(d_tx, 2),
                }
            )
    top_clients.sort(key=lambda item: item["dl_mbps"] + item["ul_mbps"], reverse=True)
    return {
        "download_mbps": dl_mbps,
        "upload_mbps": ul_mbps,
        "interval_sec": round(dt, 1),
        "top_clients": top_clients[:10],
    }


async def get_wifi_associations() -> list[dict]:
    async with _get_client() as client:
        data = await client.rci_get("show/associations")
        stations = data if isinstance(data, list) else data.get("station", [])
        if not isinstance(stations, list):
            stations = [stations] if stations else []
        return [_station_to_dict(item) for item in stations]


async def get_routes() -> list[dict]:
    async with _get_client() as client:
        data = await client.rci_get("show/ip/route")
        routes = data if isinstance(data, list) else data.get("route", [])
        if not isinstance(routes, list):
            routes = [routes] if routes else []
        return [_route_to_dict(item) for item in routes]


def _is_wan_interface(iface: dict) -> bool:
    return bool(
        iface.get("link") == "up"
        and (
            iface.get("type", "") in _WAN_TYPES
            or (iface.get("type") == "GigabitEthernet" and iface.get("address"))
        )
    )


async def get_interface_counters(
    interface: str,
    second_sample_after_ms: int = 0,
) -> dict:
    """Interface rx/tx bytes/packets/errors/drops via show interface stat.

    Optional second_sample_after_ms (100..30000) returns delta rates for A/B tests.
    Works for WireguardN / ZeroTier0 / GigabitEthernet1 / …
    """
    name = (interface or "").strip()
    if not name:
        raise ValueError("interface is required")
    delay_ms = int(second_sample_after_ms or 0)
    if delay_ms and not (100 <= delay_ms <= 30_000):
        raise ValueError("second_sample_after_ms must be 0 or 100..30000")

    async def _one(client) -> dict:
        data = await client.rci({"show": {"interface": {"stat": {"name": name}}}})
        stat = ((data.get("show") or {}).get("interface") or {}).get("stat") or {}
        if isinstance(stat, list):
            stat = stat[0] if stat else {}
        if not isinstance(stat, dict) or not stat:
            raise ValueError(f"no counters for interface: {name}")
        return {
            "rx_bytes": int(stat.get("rxbytes") or 0),
            "tx_bytes": int(stat.get("txbytes") or 0),
            "rx_packets": int(stat.get("rxpackets") or 0),
            "tx_packets": int(stat.get("txpackets") or 0),
            "rx_errors": int(stat.get("rxerrors") or 0),
            "tx_errors": int(stat.get("txerrors") or 0),
            "rx_dropped": int(stat.get("rxdropped") or 0),
            "tx_dropped": int(stat.get("txdropped") or 0),
            "rx_speed_bps": int(stat.get("rxspeed") or 0),
            "tx_speed_bps": int(stat.get("txspeed") or 0),
            "timestamp": stat.get("timestamp"),
        }

    async with _get_client() as client:
        # validate iface exists
        raw = await client.rci_get("show/interface")
        exists = isinstance(raw, dict) and (
            name in raw
            or any(
                isinstance(v, dict) and (v.get("id") == name or v.get("description") == name)
                for v in raw.values()
            )
        )
        if not exists:
            raise ValueError(f"interface not found: {name}")
        first = await _one(client)
        delta = None
        if delay_ms:
            t0 = time.monotonic()
            await asyncio.sleep(delay_ms / 1000.0)
            second = await _one(client)
            dt = max(time.monotonic() - t0, 0.001)
            delta = {
                "interval_sec": round(dt, 3),
                "rx_bytes": second["rx_bytes"] - first["rx_bytes"],
                "tx_bytes": second["tx_bytes"] - first["tx_bytes"],
                "rx_packets": second["rx_packets"] - first["rx_packets"],
                "tx_packets": second["tx_packets"] - first["tx_packets"],
                "rx_mbps": round((second["rx_bytes"] - first["rx_bytes"]) * 8 / dt / 1_000_000, 3),
                "tx_mbps": round((second["tx_bytes"] - first["tx_bytes"]) * 8 / dt / 1_000_000, 3),
                "after": second,
            }

    return {
        "ok": True,
        "interface": name,
        "snapshot": first,
        "delta": delta,
    }


async def get_wan_status() -> dict:
    async with _get_client() as client:
        data = await client.rci_get("show/internet/status")
        return data if isinstance(data, dict) else {"raw": data}


async def get_wan_speed() -> list[dict]:
    async with _get_client() as client:
        ifaces_raw = await client.rci_get("show/interface")
        if isinstance(ifaces_raw, dict):
            ifaces = {name: item for name, item in ifaces_raw.items() if isinstance(item, dict)}
        elif isinstance(ifaces_raw, list):
            ifaces = {item.get("id", str(index)): item for index, item in enumerate(ifaces_raw) if isinstance(item, dict)}
        else:
            ifaces = {}
        wan_names = [name for name, item in ifaces.items() if _is_wan_interface(item)]
        if not wan_names:
            return []
        data = await client.rci({"show": {"interface": {"stat": [{"name": name} for name in wan_names]}}})
        stats = data.get("show", {}).get("interface", {}).get("stat", [])
        if not isinstance(stats, list):
            stats = [stats] if stats else []

    result = []
    for name, stat in zip(wan_names, stats):
        if not isinstance(stat, dict):
            continue
        iface = ifaces.get(name, {})
        entry = {
            "interface": name,
            "type": iface.get("type"),
            "dl_mbps": round((stat.get("rxspeed") or 0) * 8 / 1_000_000, 2),
            "ul_mbps": round((stat.get("txspeed") or 0) * 8 / 1_000_000, 2),
        }
        if iface.get("description"):
            entry["description"] = iface["description"]
        result.append(entry)
    result.sort(key=lambda item: item["dl_mbps"] + item["ul_mbps"], reverse=True)
    return result


async def set_interface_state(name: str, up: bool) -> dict:
    assert_writable()
    action = "up" if up else "down"
    async with _get_client() as client:
        await client.rci({"interface": {name: {action: True}}})
        return {"interface": name, "state": action}


def _interface_to_dict(iface: Any) -> dict:
    if not isinstance(iface, dict):
        return {"raw": iface}
    return {key: value for key, value in {
        "id": iface.get("id"),
        "description": iface.get("description"),
        "type": iface.get("type"),
        "state": iface.get("state"),
        "link": iface.get("link"),
        "mtu": iface.get("mtu"),
        "mac": iface.get("mac"),
        "address": iface.get("address"),
        "mask": iface.get("mask"),
        "rx_bytes": iface.get("rxbytes"),
        "tx_bytes": iface.get("txbytes"),
        "rx_packets": iface.get("rxpackets"),
        "tx_packets": iface.get("txpackets"),
    }.items() if value is not None}


def _host_to_dict(host: Any) -> dict:
    if not isinstance(host, dict):
        return {"raw": host}
    return {key: value for key, value in {
        "mac": host.get("mac"),
        "ip": host.get("ip"),
        "hostname": host.get("name") or host.get("hostname"),
        "interface": host.get("interface", {}).get("name") or host.get("interface") if isinstance(host.get("interface"), dict) else host.get("interface"),
        "active": host.get("active"),
        "registered": host.get("registered"),
        "rx_bytes": host.get("rxbytes"),
        "tx_bytes": host.get("txbytes"),
        "uptime": host.get("uptime"),
    }.items() if value is not None}


def _hotspot_host_to_dict(host: Any) -> dict:
    if not isinstance(host, dict):
        return {"raw": host}
    iface = host.get("interface")
    iface_id = iface.get("id") if isinstance(iface, dict) else None
    iface_name = iface.get("name") if isinstance(iface, dict) else iface
    return {key: value for key, value in {
        "mac": host.get("mac"),
        "ip": host.get("ip"),
        "hostname": host.get("hostname") or None,
        "name": host.get("name") or None,
        "interface": iface_name,
        "interface_id": iface_id,
        "active": host.get("active"),
        "registered": host.get("registered"),
        "access": host.get("access"),
        "policy": host.get("policy") or None,
        "rx_bytes": host.get("rxbytes"),
        "tx_bytes": host.get("txbytes"),
        "uptime": host.get("uptime"),
        "last_seen": host.get("last-seen"),
        "ssid": host.get("ssid"),
        "ap": host.get("ap"),
        "rssi": host.get("rssi"),
        "security": host.get("security"),
        "link": host.get("link"),
    }.items() if value is not None}


def _station_to_dict(station: Any) -> dict:
    if not isinstance(station, dict):
        return {"raw": station}
    return {key: value for key, value in {
        "mac": station.get("mac"),
        "ssid": station.get("ssid"),
        "interface": station.get("ap"),
        "rssi": station.get("rssi"),
        "snr": station.get("snr"),
        "rate_tx": station.get("txrate"),
        "rate_rx": station.get("rxrate"),
        "band": station.get("band"),
    }.items() if value is not None}


def _route_to_dict(route: Any) -> dict:
    if not isinstance(route, dict):
        return {"raw": route}
    return {key: value for key, value in {
        "destination": route.get("destination"),
        "gateway": route.get("gateway"),
        "interface": route.get("interface"),
        "metric": route.get("metric"),
        "proto": route.get("proto"),
        "flags": route.get("flags"),
    }.items() if value is not None}


def register(mcp) -> None:
    mcp.tool()(get_interfaces)
    mcp.tool()(get_interface)
    mcp.tool()(get_interface_counters)
    mcp.tool()(get_connected_clients)
    mcp.tool()(get_hotspot)
    mcp.tool()(get_speed)
    mcp.tool()(get_wifi_associations)
    mcp.tool()(get_routes)
    mcp.tool()(get_wan_status)
    mcp.tool()(get_wan_speed)
    mcp.tool()(set_interface_state)
