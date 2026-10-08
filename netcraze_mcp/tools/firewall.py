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


async def get_access_list(name: str) -> dict:
    """Return body of one ACL (e.g. _WEBADMIN_ZeroTier0), not just names."""
    needle = (name or "").strip()
    if not needle:
        raise ValueError("name is required")
    async with _get_client() as client:
        acls = await client.rci_get("show/sc/access-list")
        # try detailed show
        detailed = None
        try:
            detailed = await client.rci({"show": {"ip": {"access-list": needle}}})
        except Exception:  # noqa: BLE001
            detailed = None
    entries = []
    if isinstance(acls, list):
        for item in acls:
            if not isinstance(item, dict):
                continue
            acl_name = str(item.get("acl") or item.get("name") or "")
            if acl_name == needle or needle in acl_name:
                entries.append(redact_value(item))
    elif isinstance(acls, dict):
        if needle in acls:
            entries.append(redact_value(acls[needle]))
        else:
            for key, value in acls.items():
                if needle in str(key) and isinstance(value, (dict, list)):
                    entries.append(redact_value({"acl": key, "body": value}))
    return redact_value({
        "ok": True,
        "name": needle,
        "entries": entries,
        "count": len(entries),
        "detailed": redact_value(detailed) if detailed else None,
        "note": "Read-only ACL dump. Use add_acl_rule/remove_acl_rule to change.",
    })


async def add_acl_rule(
    acl: str,
    action: str = "permit",
    protocol: str = "udp",
    source: str = "any",
    destination: str = "any",
    port: int | None = None,
    confirm: bool = False,
    save: bool = False,
) -> dict:
    """Add one ACL rule via apply_cli_batch. save=False by default."""
    from ..config import assert_writable
    from .txn import apply_cli_batch

    assert_writable()
    if not confirm:
        raise PermissionError("confirm=true is required")
    acl_name = acl.strip()
    if not acl_name:
        raise ValueError("acl is required")
    action_s = action.strip().lower()
    if action_s not in ("permit", "deny"):
        raise ValueError("action must be permit|deny")
    proto = protocol.strip().lower()
    parts = [action_s, proto, source.strip() or "any", destination.strip() or "any"]
    if port is not None:
        parts.extend(["eq", str(int(port))])
    # NDMS access-list syntax varies; use parse form
    cmd = f"ip access-list {acl_name} {' '.join(parts)}"
    return await apply_cli_batch(
        commands=[cmd],
        confirm=True,
        verify=[f"show ip access-list {acl_name}"],
        rollback_on_fail=True,
        save=save,
    )


async def remove_acl_rule(
    acl: str,
    action: str = "permit",
    protocol: str = "udp",
    source: str = "any",
    destination: str = "any",
    port: int | None = None,
    confirm: bool = False,
    save: bool = False,
) -> dict:
    """Remove one ACL rule via ``no …`` parse. save=False by default."""
    from ..config import assert_writable
    from .txn import apply_cli_batch

    assert_writable()
    if not confirm:
        raise PermissionError("confirm=true is required")
    acl_name = acl.strip()
    action_s = action.strip().lower()
    proto = protocol.strip().lower()
    parts = [action_s, proto, source.strip() or "any", destination.strip() or "any"]
    if port is not None:
        parts.extend(["eq", str(int(port))])
    cmd = f"no ip access-list {acl_name} {' '.join(parts)}"
    return await apply_cli_batch(
        commands=[cmd],
        confirm=True,
        verify=[],
        rollback_on_fail=False,
        save=save,
    )


async def get_interface_security(interface: str) -> dict:
    """security-level + bound ACLs + whether inbound UDP/<hint> to router is plausible."""
    iface = (interface or "").strip()
    if not iface:
        raise ValueError("interface is required")
    async with _get_client() as client:
        data = await client.rci_get(f"show/interface/{iface}")
        acls = None
        try:
            acls = await client.rci_get("show/sc/access-list")
        except Exception:  # noqa: BLE001
            acls = None
    if not isinstance(data, dict) or not data:
        return {"ok": False, "error": f"interface not found: {iface}"}
    level = data.get("security-level")
    bound = []
    acl_list = acls if isinstance(acls, list) else []
    for item in acl_list if isinstance(acl_list, list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("acl") or item.get("name") or "")
        if name == f"_WEBADMIN_{iface}" or iface in name:
            bound.append(redact_value(item))
    return redact_value({
        "ok": True,
        "interface": iface,
        "security_level": level,
        "bound_acls": bound,
        "inbound_udp_hint": (
            "security-level public typically blocks unsolicited inbound to the router; "
            "permit rules needed on _WEBADMIN_<iface> for WG/IPsec listen ports"
            if str(level).lower() in ("public", "true") or level is True
            else "check bound ACL for explicit permit udp"
        ),
    })


async def check_udp_listen(port: int) -> dict:
    """Honest UDP listen probe: NDMS has no socket listing — return unsupported + indirect signs."""
    port_i = int(port)
    if not (1 <= port_i <= 65535):
        raise ValueError("port must be 1..65535")
    async with _get_client() as client:
        ifaces = await client.rci_get("show/interface")
        forwards = None
        try:
            forwards = await client.rci_get("show/sc/ip/static")
        except Exception:  # noqa: BLE001
            forwards = None
        acls = None
        try:
            acls = await client.rci_get("show/sc/access-list")
        except Exception:  # noqa: BLE001
            acls = None

    wg_ports = []
    items = ifaces.values() if isinstance(ifaces, dict) else (ifaces if isinstance(ifaces, list) else [])
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "Wireguard" and not str(item.get("id") or "").startswith("Wireguard"):
            continue
        lp = (item.get("wireguard") or {}).get("listen-port")
        if lp is not None and int(lp) == port_i:
            wg_ports.append(item.get("id"))

    pf = []
    raw_static = forwards if isinstance(forwards, list) else []
    for item in raw_static:
        if not isinstance(item, dict):
            continue
        if str(item.get("port") or "") == str(port_i) or str(item.get("to-port") or "") == str(port_i):
            pf.append(redact_value(item))

    return {
        "ok": False,
        "unsupported": True,
        "port": port_i,
        "reason": "NDMS RCI does not expose listening UDP sockets",
        "indirect": {
            "wireguard_listen_port_matches": wg_ports,
            "port_forwards": pf[:10],
            "acl_mentions": [
                redact_value(item)
                for item in (acls if isinstance(acls, list) else [])[:50]
                if isinstance(item, dict) and str(port_i) in str(item)
            ][:10],
        },
        "note": "Use wireguard_handshake_check / capture_flow_summary as path proof.",
    }


def register(mcp) -> None:
    mcp.tool()(list_firewall_rules)
    mcp.tool()(list_nat_rules)
    mcp.tool()(get_conntrack)
    mcp.tool()(get_access_list)
    mcp.tool()(add_acl_rule)
    mcp.tool()(remove_acl_rule)
    mcp.tool()(get_interface_security)
    mcp.tool()(check_udp_listen)
