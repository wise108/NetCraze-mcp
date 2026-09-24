"""Connection priority and policy-routing summary (read-only)."""

from __future__ import annotations

from typing import Any

from ..client import _get_client
from ..redact import redact_value
from .dns_routes import get_dns_routes
from .static_routes import list_static_routes


def _iface_priority_entry(iface: dict) -> dict | None:
    if not iface.get("global") and iface.get("priority") is None and not iface.get("defaultgw"):
        # still include Policy* and known WAN/VPN with address
        if iface.get("type") not in (
            "GigabitEthernet", "Wireguard", "PPPoE", "PPTP", "L2TP", "SSTP",
            "OpenVPN", "ZeroTier", "UsbQmi", "CdcEthernet", "WifiStation", "Policy",
        ):
            return None
    return {
        key: value
        for key, value in {
            "id": iface.get("id"),
            "name": iface.get("interface-name"),
            "description": iface.get("description") or None,
            "type": iface.get("type"),
            "priority": iface.get("priority"),
            "global": iface.get("global"),
            "defaultgw": iface.get("defaultgw"),
            "state": iface.get("state"),
            "link": iface.get("link"),
            "address": iface.get("address"),
            "connected": iface.get("connected"),
        }.items()
        if value is not None and value != ""
    }


async def get_connection_priorities() -> dict:
    """Order/metric of interfaces «для Интернета» (ip global priority) + Policy tables."""
    async with _get_client() as client:
        ifaces_raw = await client.rci_get("show/interface")
        policies = None
        policies_error = None
        try:
            policies = await client.rci_get("show/ip/policy")
        except Exception as exc:  # noqa: BLE001
            policies_error = str(exc).split("\n")[0][:200]

    if isinstance(ifaces_raw, dict):
        ifaces = [v for v in ifaces_raw.values() if isinstance(v, dict)]
    elif isinstance(ifaces_raw, list):
        ifaces = [item for item in ifaces_raw if isinstance(item, dict)]
    else:
        ifaces = []

    entries = []
    for iface in ifaces:
        entry = _iface_priority_entry(iface)
        if entry and (entry.get("global") or entry.get("priority") is not None or entry.get("defaultgw")):
            entries.append(entry)
    entries.sort(key=lambda item: int(item.get("priority") or 0), reverse=True)

    policy_summary = []
    if isinstance(policies, dict):
        for name, pol in policies.items():
            if not isinstance(pol, dict):
                continue
            routes = ((pol.get("route4") or {}).get("route") if isinstance(pol.get("route4"), dict) else None) or []
            if isinstance(routes, dict):
                routes = list(routes.values())
            policy_summary.append({
                "id": name,
                "description": pol.get("description"),
                "mark": pol.get("mark"),
                "table4": pol.get("table4"),
                "default_routes": [
                    {
                        key: value
                        for key, value in {
                            "destination": r.get("destination"),
                            "gateway": r.get("gateway"),
                            "interface": r.get("interface"),
                            "metric": r.get("metric"),
                        }.items()
                        if value is not None
                    }
                    for r in (routes if isinstance(routes, list) else [])
                    if isinstance(r, dict) and str(r.get("destination") or "").startswith("0.0.0.0")
                ],
            })

    return redact_value({
        "ok": True,
        "note": (
            "Higher priority = preferred for Internet (NDMS ip global). "
            "VPN with lower priority stays for policy/DNS-split."
        ),
        "internet_order": entries,
        "default_wan": next((e for e in entries if e.get("defaultgw")), None),
        "policies": policy_summary or None,
        "policies_error": policies_error,
    })


async def get_policy_routing_summary() -> dict:
    """DNS-routes + static routes + ip policy/rules summary (read-only)."""
    async with _get_client() as client:
        rules_raw = None
        rules_error = None
        try:
            rules_raw = await client.rci_get("show/ip/rule")
        except Exception as exc:  # noqa: BLE001
            rules_error = str(exc).split("\n")[0][:200]
        policies = None
        try:
            policies = await client.rci_get("show/ip/policy")
        except Exception:  # noqa: BLE001
            policies = None
        live_routes = await client.rci_get("show/ip/route")

    try:
        dns_routes = await get_dns_routes()
    except Exception as exc:  # noqa: BLE001
        dns_routes = {"error": str(exc)}
    try:
        static_routes = await list_static_routes()
    except Exception as exc:  # noqa: BLE001
        static_routes = {"error": str(exc)}

    rule_text = rules_raw if isinstance(rules_raw, str) else None
    rule_lines = [line for line in (rule_text or "").splitlines() if line.strip()] if rule_text else []

    defaults = []
    route_list = live_routes if isinstance(live_routes, list) else (
        live_routes.get("route") if isinstance(live_routes, dict) else []
    )
    if not isinstance(route_list, list):
        route_list = [route_list] if route_list else []
    for route in route_list:
        if not isinstance(route, dict):
            continue
        dest = str(route.get("destination") or "")
        if dest in ("0.0.0.0/0", "default") or dest.startswith("0.0.0.0"):
            defaults.append({
                key: value
                for key, value in {
                    "destination": route.get("destination"),
                    "gateway": route.get("gateway"),
                    "interface": route.get("interface"),
                    "metric": route.get("metric"),
                    "proto": route.get("proto"),
                }.items()
                if value is not None
            })

    return redact_value({
        "ok": True,
        "summary": (
            "Default Internet follows highest-priority global interface; "
            "DNS-routes steer selected domains to VPN; Policy tables use fwmark."
        ),
        "default_routes": defaults,
        "dns_routes": dns_routes,
        "static_routes": static_routes,
        "policies": policies if isinstance(policies, dict) else None,
        "ip_rules": rule_lines[:50] or None,
        "ip_rules_error": rules_error,
    })


def register(mcp) -> None:
    mcp.tool()(get_connection_priorities)
    mcp.tool()(get_policy_routing_summary)
