"""Raw RCI GET access with automatic secret redaction."""

from __future__ import annotations

from typing import Any

from ..client import _get_client
from ..redact import is_denied_safe_path, normalize_rci_path, redact_value


async def rci_get(path: str, params: dict | None = None) -> dict:
    """GET /rci/<path> using the MCP auth session. Secrets are redacted.

    path — without leading /rci (e.g. show/system, show/interface, show/ip/route).
    Only GET. For POST/write use a separate dangerous tool with confirm=true.
    """
    clean = normalize_rci_path(path)
    async with _get_client() as client:
        data = await client.rci_get(clean, params=params)
    return {
        "path": clean,
        "ok": True,
        "data": redact_value(data),
    }


async def rci_get_safe(path: str) -> dict:
    """Like rci_get, but refuses paths that typically hold secrets.

    Deny-list includes: password, private-key, psk, secret, token, ipsec.secrets, …
    """
    clean = normalize_rci_path(path)
    if is_denied_safe_path(clean):
        return {
            "path": clean,
            "ok": False,
            "denied": True,
            "error": (
                "path blocked by rci_get_safe deny-list "
                "(likely contains secrets). Use a typed read-only tool instead."
            ),
        }
    async with _get_client() as client:
        data = await client.rci_get(clean)
    return {
        "path": clean,
        "ok": True,
        "data": redact_value(data),
    }


def list_rci_readonly_catalog() -> dict:
    """Catalog of useful read-only RCI paths for VPN/DNS datapath diagnostics.

    Prefer typed tools (get_wireguard_runtime, explain_dns_route, …) when available.
    Use rci_get / rci_get_safe for exploration; secrets are redacted / denied.
    """
    return {
        "ok": True,
        "note": "Paths relative to /rci. Prefer typed MCP tools over raw GET when listed.",
        "endpoints": [
            {
                "path": "show/interface",
                "use": "All interfaces incl. WireguardN / ZeroTier0",
                "typed_tool": "get_interfaces / list_wireguard / get_wireguard_runtime",
            },
            {
                "path": "show/interface/stat? via POST show.interface.stat.name",
                "use": "rx/tx bytes packets errors drops speeds",
                "typed_tool": "get_interface_counters",
            },
            {
                "path": "show/sc/interface/WireguardN",
                "use": "WG config: allow-ips, keepalive, endpoint (no private key in show if redacted)",
                "typed_tool": "get_wireguard_runtime",
            },
            {
                "path": "show/ip/route",
                "use": "Kernel routes for LPM explain",
                "typed_tool": "explain_route / get_routes",
            },
            {
                "path": "show/sc/dns-proxy/route + show/sc/object-group/fqdn",
                "use": "DNS-route / domain-list mapping",
                "typed_tool": "get_dns_routes / explain_dns_route",
            },
            {
                "path": "show/dns-proxy",
                "use": "dns-proxy runtime / upstream servers",
                "typed_tool": "rci_get",
            },
            {
                "path": "show/ip/hotspot/host",
                "use": "LAN clients + rx/tx traffic",
                "typed_tool": "get_connected_clients / get_speed",
            },
            {
                "path": "show/internet/status",
                "use": "Default Internet path / captive / DNS accessibility",
                "typed_tool": "get_wan_status / health_check",
            },
            {
                "path": "show/ndns",
                "use": "KeeneticNDNS booked name / WAN address hint",
                "typed_tool": "get_public_ip / router_exit_ip (WAN hint only)",
            },
            {
                "path": "tools.ping / tools.traceroute (POST, continued)",
                "use": "ICMP / traceroute with interface=WireguardN",
                "typed_tool": "router_ping / router_traceroute",
            },
        ],
        "unsupported_on_ndms_5_01": [
            "tools.curl / tools.http / tools.tcp — no L7/TCP probe via RCI",
        ],
    }


def register(mcp) -> None:
    mcp.tool()(rci_get)
    mcp.tool()(rci_get_safe)
    mcp.tool()(list_rci_readonly_catalog)
