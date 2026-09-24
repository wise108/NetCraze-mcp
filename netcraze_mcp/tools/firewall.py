"""Firewall / NAT / port-forward read-only views."""

from __future__ import annotations

from typing import Any

from ..client import _get_client
from ..redact import redact_value


def _redact_comment(text: Any) -> Any:
    if not isinstance(text, str):
        return text
    lower = text.lower()
    if any(word in lower for word in ("password", "passwd", "secret", "token", "psk")):
        return "<REDACTED_COMMENT>"
    return text


async def list_firewall_rules() -> dict:
    """Access-lists / security summary (read-only). Never modifies config."""
    async with _get_client() as client:
        acls = None
        acl_error = None
        try:
            acls = await client.rci_get("show/sc/access-list")
        except Exception as exc:  # noqa: BLE001
            acl_error = str(exc).split("\n")[0][:200]

        ifaces_raw = await client.rci_get("show/interface")
        security = []
        if isinstance(ifaces_raw, dict):
            items = ifaces_raw.values()
        elif isinstance(ifaces_raw, list):
            items = ifaces_raw
        else:
            items = []
        for iface in items:
            if not isinstance(iface, dict):
                continue
            level = iface.get("security-level")
            if level is None and not iface.get("global"):
                continue
            security.append({
                key: value
                for key, value in {
                    "id": iface.get("id"),
                    "security_level": level,
                    "type": iface.get("type"),
                    "address": iface.get("address"),
                }.items()
                if value is not None
            })

    rules = []
    if isinstance(acls, list):
        for item in acls:
            if not isinstance(item, dict):
                continue
            rules.append(redact_value({
                key: _redact_comment(value) if key in ("description", "comment") else value
                for key, value in item.items()
            }))
    elif isinstance(acls, dict):
        rules = [redact_value(acls)]

    if not rules and acl_error:
        return {
            "ok": False,
            "supported": False,
            "unsupported": True,
            "reason": f"show/sc/access-list unavailable: {acl_error}",
            "security_levels": security,
        }

    return redact_value({
        "ok": True,
        "source": "show/sc/access-list",
        "count": len(rules),
        "rules": rules,
        "security_levels": security,
        "note": (
            "NDMS uses per-interface security-level + access-lists. "
            "This is not a classic iptables dump."
        ),
    })


async def list_nat_rules() -> dict:
    """Port forwards / UPnP / NAT summary (read-only). Conntrack table is summarized only."""
    async with _get_client() as client:
        static_nat = None
        try:
            static_nat = await client.rci_get("show/sc/ip/static")
        except Exception as exc:  # noqa: BLE001
            static_nat = {"error": str(exc).split("\n")[0][:200]}

        upnp = None
        try:
            upnp = await client.rci_get("show/upnp/redirect")
        except Exception as exc:  # noqa: BLE001
            upnp = {"error": str(exc).split("\n")[0][:200]}

        conntrack_count = None
        conntrack_error = None
        try:
            nat_live = await client.rci_get("show/ip/nat")
            if isinstance(nat_live, list):
                conntrack_count = len(nat_live)
            elif isinstance(nat_live, dict):
                conntrack_count = len(nat_live)
        except Exception as exc:  # noqa: BLE001
            conntrack_error = str(exc).split("\n")[0][:200]

    forwards = []
    raw_static = static_nat if isinstance(static_nat, list) else []
    if isinstance(static_nat, dict) and "error" not in static_nat:
        raw_static = [static_nat]
    for item in raw_static:
        if not isinstance(item, dict):
            continue
        forwards.append(redact_value({
            key: _redact_comment(value) if key in ("comment", "description") else value
            for key, value in {
                "interface": item.get("interface"),
                "protocol": item.get("protocol"),
                "port": item.get("port"),
                "to_port": item.get("to-port"),
                "to_host": item.get("to-host"),
                "comment": item.get("comment"),
                "index": item.get("index"),
            }.items()
            if value is not None
        }))

    upnp_entries = []
    if isinstance(upnp, dict) and "entry" in upnp:
        entries = upnp.get("entry") or []
        if isinstance(entries, dict):
            entries = list(entries.values())
        for item in entries if isinstance(entries, list) else []:
            if not isinstance(item, dict):
                continue
            upnp_entries.append(redact_value({
                key: _redact_comment(value) if key == "description" else value
                for key, value in {
                    "interface": item.get("interface"),
                    "protocol": item.get("protocol"),
                    "port": item.get("port"),
                    "to_address": item.get("to-address"),
                    "to_port": item.get("to-port"),
                    "description": item.get("description"),
                    "policy": item.get("policy"),
                }.items()
                if value is not None
            }))

    return redact_value({
        "ok": True,
        "port_forwards": forwards,
        "port_forwards_count": len(forwards),
        "upnp_redirects": upnp_entries,
        "upnp_count": len(upnp_entries),
        "conntrack_sessions": conntrack_count,
        "conntrack_error": conntrack_error,
        "note": (
            "Full show/ip/nat conntrack is not dumped (can be huge). "
            "Use port_forwards + upnp for audit; conntrack_sessions is a count only."
        ),
        "static_error": static_nat.get("error") if isinstance(static_nat, dict) else None,
        "upnp_error": upnp.get("error") if isinstance(upnp, dict) else None,
    })


def register(mcp) -> None:
    mcp.tool()(list_firewall_rules)
    mcp.tool()(list_nat_rules)
