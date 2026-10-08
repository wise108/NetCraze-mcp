"""VPN/DNS datapath diagnostics (read-only).

NDMS 5.01 limitation (live-proven on websun NC-1812):
  tools.ping / tools.traceroute exist and honor ``interface=WireguardN``.
  There is NO tools.curl / tools.wget / tools.http / tools.tcp — L7/TCP probes
  return ``unsupported=true`` with honest fallbacks (ping + counters + capture).

Supported fully:
  explain_dns_route, explain_route, get_wireguard_runtime (via wireguard module),
  get_interface_counters (via network module), capability catalog.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from ..client import _get_client
from ..redact import redact_value
from .diagnostics import _check_host, router_nslookup, router_ping
from .dns_routes import get_dns_routes

_HOST_RE = re.compile(r"^[A-Za-z0-9._\-:%]+$")

_EXIT_IP_URLS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://1.1.1.1/cdn-cgi/trace",
)

_NDMS_L7_NOTE = (
    "NDMS 5.01 has no tools.curl/http/tcp via RCI. "
    "Use router_ping(interface=…), get_interface_counters deltas, "
    "get_wireguard_runtime, capture_flow_summary, or Entware curl on the router."
)


def _norm_iface(interface: str) -> str:
    return (interface or "").strip()


async def _load_iface(client, name: str) -> dict | None:
    raw = await client.rci_get("show/interface")
    if isinstance(raw, dict):
        if name in raw and isinstance(raw[name], dict):
            return raw[name]
        for key, val in raw.items():
            if isinstance(val, dict) and (
                val.get("id") == name or val.get("interface-name") == name
                or val.get("description") == name
            ):
                return val
    return None


async def _require_iface(client, interface: str) -> dict:
    name = _norm_iface(interface)
    if not name:
        raise ValueError("interface is required (e.g. Wireguard2, ZeroTier0, GigabitEthernet1)")
    iface = await _load_iface(client, name)
    if not iface:
        raise ValueError(f"interface not found: {name}")
    return iface


def _iface_meta(iface: dict, name: str) -> dict:
    return {
        "interface_used": iface.get("id") or name,
        "interface_description": iface.get("description"),
        "interface_state": iface.get("state"),
        "interface_link": iface.get("link"),
        "interface_address": iface.get("address"),
        "interface_type": iface.get("type"),
    }


def _domain_matches(pattern: str, domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if not pattern or not domain:
        return False
    if pattern.startswith("*."):
        root = pattern[2:]
        return domain == root or domain.endswith("." + root)
    return domain == pattern or domain.endswith("." + pattern)


def _best_route(dest_ip: str, routes: list[dict]) -> dict | None:
    try:
        addr = ipaddress.ip_address(dest_ip)
    except ValueError:
        return None
    best = None
    best_len = -1
    for route in routes:
        dest = str(route.get("destination") or "")
        if not dest:
            continue
        try:
            net = ipaddress.ip_network(dest if "/" in dest else f"{dest}/32", strict=False)
        except ValueError:
            continue
        if addr.version != net.version:
            continue
        if addr in net and net.prefixlen >= best_len:
            best = route
            best_len = net.prefixlen
    return best


async def list_datapath_capabilities() -> dict:
    """What VPN datapath probes this firmware/MCP can do (honest matrix)."""
    return {
        "ok": True,
        "ndms": "5.01-class",
        "capabilities": {
            "router_ping_via_interface": True,
            "router_traceroute_via_interface": True,
            "router_nslookup": "partial (ping-resolve)",
            "get_wireguard_runtime": True,
            "get_interface_counters": True,
            "explain_dns_route": True,
            "explain_route": True,
            "capture_flow_summary": True,
            "router_http_probe": False,
            "router_tcp_check": False,
            "router_exit_ip": False,
            "router_http_speed": False,
        },
        "note": _NDMS_L7_NOTE,
        "rci_catalog_tool": "list_rci_readonly_catalog",
    }


async def router_http_probe(
    url: str,
    interface: str = "",
    method: str = "GET",
    timeout: float = 10.0,
    follow_redirects: bool = True,
    max_bytes: int = 65536,
) -> dict:
    """HTTP/HTTPS probe via a router interface (Wireguard2…).

    NDMS 5.01: unsupported over RCI (no tools.curl/http). Returns explicit unsupported
    plus ICMP reachability of the resolved host via the same interface when possible.
    """
    raw_url = (url or "").strip()
    if not raw_url:
        raise ValueError("url is required")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    host = parsed.hostname or ""
    if not host:
        raise ValueError("url has no host")
    method = (method or "GET").upper()
    if method not in ("GET", "HEAD", "POST"):
        raise ValueError("method must be GET|HEAD|POST")
    max_bytes = max(256, min(int(max_bytes), 1_000_000))
    timeout = max(1.0, min(float(timeout), 30.0))

    async with _get_client() as client:
        iface_name = _norm_iface(interface)
        meta = {}
        if iface_name:
            iface = await _require_iface(client, iface_name)
            meta = _iface_meta(iface, iface_name)
            if iface.get("state") != "up":
                return redact_value({
                    "ok": False,
                    "unsupported": True,
                    "url": raw_url,
                    "method": method,
                    "error": f"interface down: {iface_name}",
                    **meta,
                    "note": _NDMS_L7_NOTE,
                })

    # Best-effort side channel: resolve + ping via interface
    ping_side = None
    resolved = None
    try:
        ns = await router_nslookup(host)
        resolved = (ns.get("addresses") or [None])[0]
        if iface_name and resolved:
            ping_side = await router_ping(resolved, count=1, interface=iface_name)
    except Exception as exc:  # noqa: BLE001
        ping_side = {"ok": False, "error": str(exc).split("\n")[0][:160]}

    return redact_value({
        "ok": False,
        "unsupported": True,
        "url": raw_url,
        "method": method,
        "follow_redirects": follow_redirects,
        "max_bytes": max_bytes,
        "timeout_sec": timeout,
        "resolved_target": resolved,
        "http_code": None,
        "time_connect_ms": None,
        "time_tls_ms": None,
        "time_total_ms": None,
        "size": None,
        "effective_url": None,
        "remote_ip": resolved,
        "error": "HTTP probe not available on this NDMS (no tools.curl/http)",
        "icmp_via_interface": ping_side,
        "fallbacks": [
            "router_ping(host, interface=…)",
            "router_tcp_check → also unsupported; use capture_flow_summary(port=443)",
            "get_wireguard_runtime + get_interface_counters(second_sample_after_ms=…)",
        ],
        "note": _NDMS_L7_NOTE,
        **meta,
        "interface_used": meta.get("interface_used") or iface_name or None,
    })


async def router_tcp_check(
    host: str,
    port: int = 443,
    interface: str = "",
    timeout: float = 5.0,
) -> dict:
    """TCP connect test via router interface. NDMS 5.01: unsupported (no tools.tcp).

    Still validates interface and returns ICMP reachability of host via that interface.
    """
    target = _check_host(host)
    port = int(port)
    if not (1 <= port <= 65535):
        raise ValueError("port must be 1..65535")
    timeout = max(1.0, min(float(timeout), 30.0))
    iface_name = _norm_iface(interface)

    async with _get_client() as client:
        meta = {}
        if iface_name:
            iface = await _require_iface(client, iface_name)
            meta = _iface_meta(iface, iface_name)
            if iface.get("state") != "up":
                return redact_value({
                    "ok": False,
                    "unsupported": True,
                    "host": target,
                    "port": port,
                    "resolved_target": target,
                    "error": f"interface down: {iface_name}",
                    **meta,
                    "note": _NDMS_L7_NOTE,
                })

    ping_side = None
    try:
        if iface_name:
            ping_side = await router_ping(target, count=1, interface=iface_name)
        else:
            ping_side = await router_ping(target, count=1)
    except Exception as exc:  # noqa: BLE001
        ping_side = {"ok": False, "error": str(exc).split("\n")[0][:160]}

    return redact_value({
        "ok": False,
        "unsupported": True,
        "host": target,
        "port": port,
        "timeout_sec": timeout,
        "resolved_target": target,
        "time_connect_ms": None,
        "error": "TCP connect not available on this NDMS (no tools.tcp/nc)",
        "icmp_via_interface": ping_side,
        "fallbacks": [
            "capture_flow_summary(interface=…, host=…, port=…)",
            "router_traceroute(host, interface=…)",
        ],
        "note": _NDMS_L7_NOTE,
        **meta,
        "interface_used": meta.get("interface_used") or iface_name or None,
    })


async def router_exit_ip(
    interface: str = "",
    urls: list[str] | None = None,
) -> dict:
    """Public exit-IP / whoami via interface. NDMS 5.01: unsupported without Entware curl.

    For default WAN only, returns show/ndns address as a weak hint (not a whoami fetch).
    """
    iface_name = _norm_iface(interface)
    url_list = [u.strip() for u in (urls or list(_EXIT_IP_URLS)) if u and u.strip()]

    async with _get_client() as client:
        meta = {}
        wan_hint = None
        if iface_name:
            iface = await _require_iface(client, iface_name)
            meta = _iface_meta(iface, iface_name)
            # weak WAN hint from ndns when interface looks like ISP/default
            try:
                ndns = await client.rci_get("show/ndns")
                internet = await client.rci_get("show/internet/status")
                gw_if = ((internet or {}).get("gateway") or {}).get("interface")
                if gw_if and gw_if == (iface.get("id") or iface_name):
                    wan_hint = {
                        "source": "show/ndns (WAN path only — not a whoami HTTP fetch)",
                        "public_ip": (ndns or {}).get("address") or None,
                        "ndns_interface": ((ndns or {}).get("ttp") or {}).get("interface"),
                    }
            except Exception:  # noqa: BLE001
                pass
        else:
            try:
                ndns = await client.rci_get("show/ndns")
                pub = (ndns or {}).get("address") or None
                wan_hint = {
                    "source": "show/ndns (default Internet path — not a whoami HTTP fetch)",
                    "public_ip": pub,
                    "behind_nat": bool(pub is None),
                }
            except Exception:  # noqa: BLE001
                pass

    return redact_value({
        "ok": False,
        "unsupported": True,
        "urls_tried": url_list,
        "public_ip": None,
        "provider_hint": None,
        "latency_ms": None,
        "error": "exit-IP HTTP whoami not available on this NDMS (no tools.curl)",
        "wan_ndns_hint": wan_hint,
        "fallbacks": [
            "From a LAN client whose DNS-route points to this WG: curl ifconfig.me",
            "capture_flow_summary while generating HTTPS to prove path",
            "compare get_wireguard_runtime transfer counters during a known download",
        ],
        "note": _NDMS_L7_NOTE,
        **meta,
        "interface_used": meta.get("interface_used") or iface_name or None,
    })


async def router_http_speed(
    url: str = "https://speed.cloudflare.com/__down?bytes=5000000",
    interface: str = "",
    bytes: int = 5_000_000,
    direction: str = "download",
) -> dict:
    """Limited HTTP download speed via interface. NDMS 5.01: unsupported (no tools.curl).

    Use get_interface_counters(second_sample_after_ms=…) while a LAN client downloads
    through the same DNS-route/WG for A/B comparison.
    """
    direction = (direction or "download").lower()
    if direction not in ("download", "upload"):
        raise ValueError("direction must be download|upload")
    bytes = max(100_000, min(int(bytes), 50_000_000))
    iface_name = _norm_iface(interface)

    async with _get_client() as client:
        meta = {}
        if iface_name:
            iface = await _require_iface(client, iface_name)
            meta = _iface_meta(iface, iface_name)

    return redact_value({
        "ok": False,
        "unsupported": True,
        "url": url,
        "bytes_requested": bytes,
        "direction": direction,
        "mbps": None,
        "duration_sec": None,
        "http_code": None,
        "bytes_transferred": None,
        "error": "HTTP speed test not available on this NDMS (no tools.curl)",
        "fallbacks": [
            "get_interface_counters(iface, second_sample_after_ms=5000) during client download",
            "get_wireguard_runtime before/after for peer rx/tx deltas",
        ],
        "note": _NDMS_L7_NOTE,
        **meta,
        "interface_used": meta.get("interface_used") or iface_name or None,
        "resolved_target": urlparse(url).hostname if url else None,
    })


async def explain_dns_route(domain: str) -> dict:
    """Explain which domain-list / dns-proxy route / interface a domain would use.

    Matches FQDN object-group includes (suffix / *. patterns) against configured
    dns-proxy routes. Does not change config.
    """
    name = (domain or "").strip().lower().rstrip(".")
    if not name or not _HOST_RE.match(name):
        raise ValueError("domain is required")

    from .dns_routes import _fetch_fqdn_groups

    async with _get_client() as client:
        groups = await _fetch_fqdn_groups(client)
        routes = await get_dns_routes()

    matched_lists: list[dict] = []
    for key, value in groups.items():
        if not isinstance(value, dict):
            continue
        list_name = value.get("description", key)
        raw = value.get("include", [])
        if not isinstance(raw, list):
            raw = [raw] if raw else []
        hits = []
        for entry in raw:
            addr = entry.get("address") if isinstance(entry, dict) else None
            if addr and _domain_matches(str(addr), name):
                hits.append(str(addr))
        if hits:
            matched_lists.append({
                "list_name": list_name,
                "list_key": key,
                "matched_patterns": hits[:20],
                "pattern_count": len(hits),
            })

    selected_routes = []
    for route in routes:
        if not route.get("enabled", True):
            continue
        for ml in matched_lists:
            if route.get("list_key") == ml["list_key"] or route.get("list_name") == ml["list_name"]:
                selected_routes.append({**route, "matched_list": ml["list_name"]})
                break

    # Prefer first enabled match (NDMS applies by config order — we expose all)
    primary = selected_routes[0] if selected_routes else None

    resolved = None
    try:
        ns = await router_nslookup(name)
        resolved = ns.get("addresses")
    except Exception as exc:  # noqa: BLE001
        resolved = {"error": str(exc).split("\n")[0][:160]}

    policy_hint = None
    try:
        from .policy import get_policy_tables
        tables = await get_policy_tables()
        iface = (primary or {}).get("interface")
        for table in tables.get("tables") or []:
            if iface and (
                table.get("id") == iface
                or any(
                    (lr or {}).get("interface") == iface
                    for lr in (table.get("linked_dns_proxy_routes") or [])
                )
            ):
                policy_hint = {
                    "table_id": table.get("id"),
                    "table4": table.get("table4"),
                    "fwmark": table.get("fwmark") or table.get("mark"),
                    "ON_LINK_DEFAULT": table.get("ON_LINK_DEFAULT"),
                    "materialized_default": table.get("materialized_default"),
                }
                break
    except Exception as exc:  # noqa: BLE001
        policy_hint = {"error": str(exc).split("\n")[0][:160]}

    via = (
        f"dns-proxy → {(primary or {}).get('interface')}"
        if primary else "no dns-proxy match (system/default DNS path)"
    )
    if policy_hint and policy_hint.get("fwmark"):
        via = f"{via}; fwmark={policy_hint.get('fwmark')} table4={policy_hint.get('table4')}"
        if policy_hint.get("ON_LINK_DEFAULT"):
            via = f"{via}; ON_LINK_DEFAULT"

    return redact_value({
        "ok": True,
        "domain": name,
        "matched_domain_lists": matched_lists,
        "dns_routes": selected_routes,
        "selected": {
            "list_name": (primary or {}).get("list_name") or (primary or {}).get("matched_list"),
            "interface": (primary or {}).get("interface"),
            "gateway": (primary or {}).get("gateway"),
            "auto": (primary or {}).get("auto"),
            "via": via,
        },
        "policy": policy_hint,
        "resolved_addresses": resolved,
        "note": (
            "Matching is suffix-based on object-group FQDN includes. "
            "policy includes fwmark/table when dns-proxy auto-table is present."
        ),
    })


async def diagnose_dns_proxy_route(list_name: str) -> dict:
    """Compare dns-proxy route config vs materialized policy table (ON_LINK_DEFAULT)."""
    from .dns_routes import _fetch_fqdn_groups, _read_list_entries, _resolve_list_key
    from .policy import get_policy_tables
    from .report import diag_report

    name = (list_name or "").strip()
    if not name:
        raise ValueError("list_name is required")

    routes = await get_dns_routes()
    matched_routes = [
        r for r in routes
        if r.get("list_name") == name or r.get("list_key") == name
    ]
    async with _get_client() as client:
        key = await _resolve_list_key(client, name)
        description, entries = await _read_list_entries(client, key)

    fqdn_entries = []
    cidr_entries = []
    for entry in entries:
        try:
            ipaddress.ip_network(entry, strict=False)
            cidr_entries.append(entry)
        except ValueError:
            fqdn_entries.append(entry)

    tables = await get_policy_tables()
    related = []
    on_link = False
    for table in tables.get("tables") or []:
        linked = table.get("linked_dns_proxy_routes") or []
        if any(
            (lr or {}).get("list_name") == description
            or (lr or {}).get("list_key") == key
            for lr in linked
        ):
            related.append(table)
            if table.get("ON_LINK_DEFAULT"):
                on_link = True
        else:
            # match by interface of dns route
            for mr in matched_routes:
                if mr.get("interface") and (
                    table.get("id") == mr.get("interface")
                    or any(
                        (d or {}).get("interface") == mr.get("interface")
                        for d in (table.get("materialized_default") or [])
                    )
                ):
                    related.append(table)
                    if table.get("ON_LINK_DEFAULT"):
                        on_link = True

    configured_gw = next((r.get("gateway") for r in matched_routes if r.get("gateway")), None)
    evidence = [
        {"dns_routes": matched_routes},
        {"list": {"name": description, "key": key, "fqdn": fqdn_entries[:50], "cidr": cidr_entries}},
        {"policy_tables": related},
        {"ON_LINK_DEFAULT": on_link},
        {"configured_gateway": configured_gw},
    ]
    if on_link and configured_gw and configured_gw not in ("0.0.0.0", ""):
        verdict = "ON_LINK_DEFAULT"
        note = (
            f"Configured gateway {configured_gw} but table has 0.0.0.0/0 via 0.0.0.0 "
            f"<iface> — NDMS 5.1.6 ignores gateway for FQDN→VPN (e.g. ZeroTier0). "
            f"Workaround: plan_fqdn_static_sync /32 routes."
        )
    elif not matched_routes:
        verdict = "no_route"
        note = "No dns-proxy route for this list"
    else:
        verdict = "ok"
        note = "Policy table matches configured dns-proxy route (no ON_LINK_DEFAULT detected)"

    return diag_report(
        verdict,
        evidence=evidence,
        changes=[],
        config_saved=False,
        ok=verdict == "ok",
        list_name=description,
        list_key=key,
        fqdn_only=bool(fqdn_entries) and not cidr_entries,
        has_cidr=bool(cidr_entries),
        ON_LINK_DEFAULT=on_link,
        note=note,
    )


async def explain_route(destination: str = "", source: str = "") -> dict:
    """Explain FIB LPM for a destination IP or hostname (main table).

    Limitation: bare IP from a dns-proxy CIDR object-group still shows WAN default
    (0.0.0.0/0) — that is FIB truth, not policy path. Use explain_policy_path /
    verify_flow_path for dns-proxy → WG/HAPP steering.
    """
    dest = (destination or "").strip()
    if not dest:
        raise ValueError("destination_ip or host is required")
    src = (source or "").strip() or None

    resolved_ip = None
    host = None
    try:
        ipaddress.ip_address(dest)
        resolved_ip = dest
    except ValueError:
        host = dest
        ns = await router_nslookup(dest)
        addrs = ns.get("addresses") or []
        if not addrs:
            return {
                "ok": False,
                "destination": dest,
                "error": "hostname did not resolve",
                "nslookup": ns,
            }
        resolved_ip = addrs[0]

    dns_hint = None
    if host:
        dns_hint = await explain_dns_route(host)

    async with _get_client() as client:
        raw = await client.rci_get("show/ip/route")
        routes_raw = raw if isinstance(raw, list) else (raw.get("route") if isinstance(raw, dict) else [])
        if not isinstance(routes_raw, list):
            routes_raw = [routes_raw] if routes_raw else []
        routes = [
            {
                key: value
                for key, value in {
                    "destination": r.get("destination"),
                    "gateway": r.get("gateway"),
                    "interface": r.get("interface"),
                    "metric": r.get("metric"),
                    "flags": r.get("flags"),
                    "proto": r.get("proto"),
                    "static": r.get("static"),
                    "rejecting": r.get("rejecting"),
                }.items()
                if value is not None
            }
            for r in routes_raw
            if isinstance(r, dict)
        ]
        best = _best_route(resolved_ip, routes)

    via = None
    if best:
        iface = best.get("interface") or ""
        via = f"via {iface}" + (
            f" gw {best.get('gateway')}"
            if best.get("gateway") and best.get("gateway") != "0.0.0.0"
            else ""
        )
    dns_if = ((dns_hint or {}).get("selected") or {}).get("interface") if dns_hint else None
    if dns_if:
        path_summary = (
            f"dns-proxy→{dns_if}; kernel LPM→{best.get('interface') if best else 'none'}"
        )
    elif host:
        path_summary = via or "no matching route"
    else:
        path_summary = (
            f"{via or 'no matching route'} "
            "(bare IP: pass hostname to include dns-proxy policy)"
        )

    return redact_value({
        "ok": True,
        "destination": dest,
        "resolved_target": resolved_ip,
        "source": src,
        "matched_route": best,
        "via": via,
        "dns_proxy_interface": dns_if,
        "path_summary": path_summary,
        "note": (
            "Kernel LPM from show/ip/route. DNS-proxy policy applies on hostname "
            "lookup (domain-list → interface); bare IP only shows FIB LPM."
        ),
        "dns_explain": {
            "matched_lists": (dns_hint or {}).get("matched_domain_lists"),
            "selected": (dns_hint or {}).get("selected"),
        } if dns_hint else None,
    })


def register(mcp) -> None:
    mcp.tool()(list_datapath_capabilities)
    mcp.tool()(router_http_probe)
    mcp.tool()(router_tcp_check)
    mcp.tool()(router_exit_ip)
    mcp.tool()(router_http_speed)
    mcp.tool()(explain_dns_route)
    mcp.tool()(explain_route)
    mcp.tool()(diagnose_dns_proxy_route)
