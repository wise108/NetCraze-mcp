"""Static IP route tools (ip route)."""

import ipaddress

from ..client import _get_client, _raise_on_rci_errors
from ..config import assert_writable


def _parse_destination(destination: str) -> dict:
    """Convert CIDR (or host/32) to RCI network+mask fields."""
    try:
        net = ipaddress.ip_network(destination, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid destination CIDR: {destination}") from e
    if net.version != 4:
        raise ValueError("Only IPv4 destinations are supported.")
    return {
        "network": str(net.network_address),
        "mask": str(net.netmask),
        "destination": str(net),
    }


def _route_entry(item: dict) -> dict:
    network = str(item.get("network") or "")
    mask = str(item.get("mask") or "")
    destination = ""
    if network and mask:
        try:
            destination = str(ipaddress.ip_network(f"{network}/{mask}", strict=False))
        except ValueError:
            destination = f"{network}/{mask}"
    return {key: value for key, value in {
        "destination": destination or None,
        "network": network or None,
        "mask": mask or None,
        "gateway": item.get("gateway") or None,
        "interface": item.get("interface") or None,
        "metric": item.get("metric"),
        "index": item.get("index") or None,
        "comment": item.get("comment") or None,
    }.items() if value is not None and value != ""}


async def list_static_routes() -> list[dict]:
    """List configured static IP routes from show sc ip route (not kernel/boot)."""
    async with _get_client() as client:
        data = await client.rci_get("show/sc/ip/route")
    routes = data if isinstance(data, list) else data.get("route", []) if isinstance(data, dict) else []
    if not isinstance(routes, list):
        routes = [routes] if routes else []
    return [_route_entry(item) for item in routes if isinstance(item, dict)]


async def add_static_route(
    destination: str,
    gateway: str,
    interface: str,
    metric: int | None = None,
) -> dict:
    """Add static IP route and save configuration."""
    assert_writable()
    parsed = _parse_destination(destination)
    if not gateway:
        raise ValueError("gateway is required")
    if not interface:
        raise ValueError("interface is required")
    payload = {
        "network": parsed["network"],
        "mask": parsed["mask"],
        "gateway": gateway,
        "interface": interface,
    }
    if metric is not None:
        payload["metric"] = metric
    async with _get_client() as client:
        resp = await client.rci([
            {"ip": {"route": payload}},
            {"system": {"configuration": {"save": {}}}},
        ])
        _raise_on_rci_errors(resp)
    return {
        "added": True,
        "destination": parsed["destination"],
        "gateway": gateway,
        "interface": interface,
        **({"metric": metric} if metric is not None else {}),
    }


async def delete_static_route(destination: str = "", index: str = "") -> dict:
    """Delete static IP route by destination CIDR or config index, then save."""
    assert_writable()
    if not destination and not index:
        raise ValueError("Specify destination CIDR or index")
    routes = await list_static_routes()
    if index:
        match = next((item for item in routes if item.get("index") == index), None)
        if not match:
            raise ValueError(f"Static route not found by index: {index}")
    else:
        want = str(ipaddress.ip_network(destination, strict=False))
        match = next((item for item in routes if item.get("destination") == want), None)
        if not match:
            raise ValueError(f"Static route not found: {destination}")
    async with _get_client() as client:
        resp = await client.rci([
            {"ip": {"route": {
                "network": match["network"],
                "mask": match["mask"],
                "no": True,
            }}},
            {"system": {"configuration": {"save": {}}}},
        ])
        _raise_on_rci_errors(resp)
    return {"deleted": True, **{k: match[k] for k in ("destination", "gateway", "interface", "index") if k in match}}


def register(mcp) -> None:
    mcp.tool()(list_static_routes)
    mcp.tool()(add_static_route)
    mcp.tool()(delete_static_route)
