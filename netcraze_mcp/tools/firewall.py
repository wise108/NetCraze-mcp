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
            "Use get_conntrack(host=…, port=…) for filtered sessions; "
            "conntrack_sessions is a count only."
        ),
        "static_error": static_nat.get("error") if isinstance(static_nat, dict) else None,
        "upnp_error": upnp.get("error") if isinstance(upnp, dict) else None,
    })


def _row_ports(row: dict) -> set[int]:
    ports: set[int] = set()
    for key in ("sport", "dport", "sport-out", "dport-out"):
        try:
            ports.add(int(row.get(key)))
        except (TypeError, ValueError):
            continue
    return ports


def _row_addrs(row: dict) -> set[str]:
    return {
        str(row.get(key) or "")
        for key in ("src", "dst", "src-out", "dst-out")
        if row.get(key)
    }


def _session_from_nat(row: dict) -> dict:
    packets = int(row.get("packets") or 0)
    packets_out = int(row.get("packets-out") or 0)
    flags_raw = row.get("flags") or []
    if isinstance(flags_raw, str):
        flags = [flags_raw]
    elif isinstance(flags_raw, list):
        flags = [str(f) for f in flags_raw]
    else:
        flags = []
    if packets > 0 and packets_out == 0 and "UNREPLIED" not in flags:
        flags = [*flags, "UNREPLIED"]
    return {
        key: value
        for key, value in {
            "protocol": row.get("protocol"),
            "src": row.get("src"),
            "dst": row.get("dst"),
            "sport": row.get("sport"),
            "dport": row.get("dport"),
            "src_out": row.get("src-out"),
            "dst_out": row.get("dst-out"),
            "sport_out": row.get("sport-out"),
            "dport_out": row.get("dport-out"),
            "packets": packets,
            "packets_reply": packets_out,
            "bytes": row.get("bytes"),
            "bytes_reply": row.get("bytes-out"),
            "flags": flags or None,
        }.items()
        if value is not None
    }


async def get_conntrack(
    host: str = "",
    port: int | None = None,
    protocol: str = "",
    limit: int = 50,
) -> dict:
    """Filtered live NAT/conntrack sessions from show/ip/nat (read-only).

    Refuses unfiltered dump — pass host and/or port (and optional protocol).
    Prefer this over show/ip/conntrack text dump. For IKE use get_ike_conntrack.
    """
    host_s = (host or "").strip()
    proto_s = (protocol or "").strip().upper()
    if proto_s in ("6", "TCP"):
        proto_s = "TCP"
    elif proto_s in ("17", "UDP"):
        proto_s = "UDP"
    elif proto_s in ("1", "ICMP"):
        proto_s = "ICMP"
    port_i = None if port is None else int(port)
    if port_i is not None and not (1 <= port_i <= 65535):
        raise ValueError("port must be 1..65535")
    if not host_s and port_i is None:
        raise ValueError("provide host and/or port (refusing full conntrack dump)")
    limit = max(1, min(int(limit), 200))

    async with _get_client() as client:
        nat = await client.rci_get("show/ip/nat")
    rows = nat if isinstance(nat, list) else []
    matched: list[dict] = []
    scanned = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        scanned += 1
        if proto_s:
            row_proto = str(row.get("protocol") or "").upper()
            aliases = {"TCP": {"TCP", "6"}, "UDP": {"UDP", "17"}, "ICMP": {"ICMP", "1"}}
            if row_proto not in aliases.get(proto_s, {proto_s}):
                continue
        if host_s and host_s not in _row_addrs(row):
            continue
        if port_i is not None and port_i not in _row_ports(row):
            continue
        matched.append(_session_from_nat(row))
        if len(matched) >= limit:
            break

    return redact_value({
        "ok": True,
        "source": "show/ip/nat",
        "filter": {
            "host": host_s or None,
            "port": port_i,
            "protocol": proto_s or None,
            "limit": limit,
        },
        "scanned": scanned,
        "count": len(matched),
        "truncated": len(matched) >= limit,
        "sessions": matched,
        "note": (
            "Structured filter of show/ip/nat (not the noisy show/ip/conntrack text). "
            "IKE UDP/500|4500: prefer get_ike_conntrack(peer=…)."
        ),
    })


def register(mcp) -> None:
    mcp.tool()(list_firewall_rules)
    mcp.tool()(list_nat_rules)
    mcp.tool()(get_conntrack)
