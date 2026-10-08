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


_FWMARK_TABLE_RE = __import__("re").compile(
    r"fwmark\s+(0x[0-9a-fA-F]+)(?:/\S+)?\s+lookup\s+(\d+)",
    __import__("re").I,
)


def _extract_parse_routes(resp: Any) -> list[dict]:
    """Pull route list from RCI parse response (show ip route table N)."""
    found: list[dict] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            routes = value.get("route")
            if isinstance(routes, list):
                found.extend(r for r in routes if isinstance(r, dict))
            elif isinstance(routes, dict):
                found.extend(r for r in routes.values() if isinstance(r, dict))
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(resp)
    return found


def _defaults_and_on_link(routes: list[dict]) -> tuple[list[dict], bool]:
    defaults = []
    on_link = False
    for r in routes:
        dest = str(r.get("destination") or "")
        if dest in ("0.0.0.0/0", "default") or dest.startswith("0.0.0.0"):
            gw = str(r.get("gateway") or "")
            iface = r.get("interface")
            defaults.append({
                "destination": dest,
                "gateway": gw or None,
                "interface": iface,
                "metric": r.get("metric"),
            })
            # ON_LINK_DEFAULT: default via 0.0.0.0 on iface (gateway ignored by NDMS)
            if gw in ("", "0.0.0.0", "None") and iface:
                on_link = True
    return defaults, on_link


async def get_policy_tables() -> dict:
    """Dump policy/auto tables (4097+), fwmark, linked dns-proxy routes, defaults.

    NDMS 5.1.6 often returns empty show/ip/policy. Source of truth:
    show/ip/rule (fwmark→lookup N) + ``show ip route table N`` via parse.
    """
    async with _get_client() as client:
        policies = None
        policies_error = None
        try:
            policies = await client.rci_get("show/ip/policy")
        except Exception as exc:  # noqa: BLE001
            policies_error = str(exc).split("\n")[0][:200]
        rules_raw = None
        try:
            rules_raw = await client.rci_get("show/ip/rule")
        except Exception as exc:  # noqa: BLE001
            rules_raw = str(exc)

        # tables from ip rule fwmark lookups (auto dns-proxy tables)
        rule_text = rules_raw if isinstance(rules_raw, str) else (
            "\n".join(str(x) for x in rules_raw) if isinstance(rules_raw, list) else ""
        )
        mark_tables: dict[int, str] = {}
        for match in _FWMARK_TABLE_RE.finditer(rule_text or ""):
            mark, table_s = match.group(1), match.group(2)
            table_n = int(table_s)
            if table_n >= 4096:
                mark_tables[table_n] = mark.lower()

        table_routes: dict[int, list[dict]] = {}
        for table_n in sorted(mark_tables):
            try:
                resp = await client.rci([
                    {"parse": "exit"},
                    {"parse": f"show ip route table {table_n}"},
                    {"parse": "exit"},
                ])
                table_routes[table_n] = _extract_parse_routes(resp)
            except Exception:  # noqa: BLE001
                table_routes[table_n] = []

    try:
        dns_routes = await get_dns_routes()
    except Exception as exc:  # noqa: BLE001
        dns_routes = []
        dns_error = str(exc).split("\n")[0][:160]
    else:
        dns_error = None

    tables: list[dict] = []
    seen_table_ids: set[int] = set()

    # 1) From ip rule + show ip route table N (primary on NDMS 5.1.6)
    for table_n, fwmark in mark_tables.items():
        routes = table_routes.get(table_n) or []
        defaults, on_link_default = _defaults_and_on_link(routes)
        tables.append({
            "id": f"table{table_n}",
            "description": None,
            "mark": fwmark,
            "fwmark": fwmark,
            "table4": table_n,
            "auto_table": table_n >= 4097,
            "materialized_default": defaults,
            "ON_LINK_DEFAULT": on_link_default,
            "linked_dns_proxy_routes": [],  # filled 1:1 below
            "route_count": len(routes),
            "source": "ip-rule+show-ip-route-table",
        })
        seen_table_ids.add(table_n)

    # 1:1 pair auto-tables ↔ dns-proxy routes on same egress iface (by table4 / index order)
    from collections import defaultdict
    by_iface_tables: dict[str, list[dict]] = defaultdict(list)
    for table in tables:
        for d in table.get("materialized_default") or []:
            iface = (d or {}).get("interface")
            if iface:
                by_iface_tables[str(iface)].append(table)
                break
    by_iface_routes: dict[str, list[dict]] = defaultdict(list)
    for dr in (dns_routes if isinstance(dns_routes, list) else []):
        if isinstance(dr, dict) and dr.get("interface") and not dr.get("disable", False):
            by_iface_routes[str(dr["interface"])].append(dr)
    for iface, tlist in by_iface_tables.items():
        t_sorted = sorted(tlist, key=lambda t: (t.get("table4") is None, t.get("table4") or 0))
        r_sorted = sorted(
            by_iface_routes.get(iface) or [],
            key=lambda r: str(r.get("index") or r.get("list_key") or r.get("group") or ""),
        )
        for table, route in zip(t_sorted, r_sorted):
            table["linked_dns_proxy_routes"] = [route]
        if len(r_sorted) > len(t_sorted) and t_sorted:
            t_sorted[-1]["linked_dns_proxy_routes"] = [
                *t_sorted[-1].get("linked_dns_proxy_routes", []),
                *r_sorted[len(t_sorted):],
            ]

    # 2) Merge any show/ip/policy entries (when firmware populates them)
    if isinstance(policies, dict):
        for name, pol in policies.items():
            if not isinstance(pol, dict):
                continue
            routes = ((pol.get("route4") or {}).get("route") if isinstance(pol.get("route4"), dict) else None) or []
            if isinstance(routes, dict):
                routes = list(routes.values())
            if not isinstance(routes, list):
                routes = [routes] if routes else []
            defaults, on_link_default = _defaults_and_on_link(routes)
            mark = pol.get("mark")
            table4 = pol.get("table4")
            if isinstance(table4, int) and table4 in seen_table_ids:
                # enrich existing entry
                for entry in tables:
                    if entry.get("table4") == table4:
                        entry["id"] = name
                        entry["description"] = pol.get("description")
                        if mark:
                            entry["mark"] = mark
                        break
                continue
            linked = [
                dr for dr in (dns_routes if isinstance(dns_routes, list) else [])
                if isinstance(dr, dict) and (
                    dr.get("interface") == name
                    or str(dr.get("interface") or "") == str(pol.get("description") or "")
                    or dr.get("interface") in {
                        str(d.get("interface")) for d in defaults if d.get("interface")
                    }
                )
            ]
            tables.append({
                "id": name,
                "description": pol.get("description"),
                "mark": mark,
                "fwmark": (
                    f"0x{mark}" if isinstance(mark, str) and mark and not str(mark).startswith("0x")
                    else mark
                ),
                "table4": table4,
                "auto_table": isinstance(table4, int) and table4 >= 4097,
                "materialized_default": defaults,
                "ON_LINK_DEFAULT": on_link_default,
                "linked_dns_proxy_routes": linked[:10],
                "route_count": len(routes),
                "source": "show/ip/policy",
            })

    rule_lines = [ln for ln in (rule_text or "").splitlines() if ln.strip()][:80]

    return redact_value({
        "ok": True,
        "tables": tables,
        "ip_rules": rule_lines or None,
        "dns_routes_error": dns_error,
        "policies_error": policies_error,
        "note": (
            "Tables from show/ip/rule fwmark lookups + show ip route table N "
            "(show/ip/policy is often empty on NDMS 5.1.6). "
            "ON_LINK_DEFAULT = 0.0.0.0/0 via 0.0.0.0 <iface> while dns-proxy has a gateway."
        ),
    })


def register(mcp) -> None:
    mcp.tool()(get_connection_priorities)
    mcp.tool()(get_policy_routing_summary)
    mcp.tool()(get_policy_tables)
