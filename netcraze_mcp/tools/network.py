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
    mcp.tool()(get_connected_clients)
    mcp.tool()(get_speed)
    mcp.tool()(get_wifi_associations)
    mcp.tool()(get_routes)
    mcp.tool()(get_wan_status)
    mcp.tool()(get_wan_speed)
    mcp.tool()(set_interface_state)
