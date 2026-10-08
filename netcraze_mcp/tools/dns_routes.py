"""DNS routing and domain list tools (rc/sc aware)."""

from __future__ import annotations

import ipaddress

from ..client import _get_client
from ..config import assert_writable, save_payload
from . import sc_rc


async def _resolve_list_key(client, name: str, groups: dict | None = None) -> str:
    if groups is None:
        groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
    if name in groups:
        return name
    for key, value in groups.items():
        if isinstance(value, dict) and value.get("description") == name:
            return key
    available = [value.get("description", key) for key, value in groups.items() if isinstance(value, dict)]
    raise ValueError(f"Domain list '{name}' not found. Available: {available}")


async def _read_list_entries(client, key: str, groups: dict | None = None) -> tuple[str, list[str]]:
    if groups is None:
        groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
    value = groups.get(key, {})
    description = value.get("description", key) if isinstance(value, dict) else key
    return description, sc_rc.include_addresses(value.get("include") if isinstance(value, dict) else [])


# Back-compat aliases used by other modules
async def _fetch_fqdn_groups(client) -> dict[str, dict]:
    groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
    return groups


async def _write_list_entries(
    client, key: str, description: str, entries: list[str], *, save: bool = False
) -> None:
    await client.rci([
        {"object-group": {"fqdn": {key: {"include": {"no": True}}}}},
        {"object-group": {"fqdn": {key: {
            "description": description,
            "include": [{"address": entry} for entry in entries],
        }}}},
        *save_payload(save),
    ])


def _route_view(route: dict, key_to_name: dict[str, str]) -> dict:
    return {key: value for key, value in {
        "index": route.get("index"),
        "list_name": key_to_name.get(route.get("group", ""), route.get("group")),
        "list_key": route.get("group"),
        "interface": route.get("interface"),
        "gateway": route.get("gateway") or None,
        "auto": route.get("auto"),
        "enabled": not route.get("disable", False),
        "comment": route.get("comment") or None,
    }.items() if value is not None}


async def get_domain_lists(saved: bool = False) -> list[dict]:
    """List domain-lists. Default source=rc (running); saved=true → sc."""
    prefer = "sc" if saved else "rc"
    async with _get_client() as client:
        groups, source = await sc_rc.fetch_fqdn_groups(client, prefer=prefer)
        other, _ = await sc_rc.fetch_fqdn_groups(client, prefer="sc" if prefer == "rc" else "rc")
        result = []
        for key, value in groups.items():
            if not isinstance(value, dict):
                continue
            entries = sc_rc.include_addresses(value.get("include"))
            other_entries = sc_rc.include_addresses((other.get(key) or {}).get("include") if isinstance(other.get(key), dict) else [])
            types = {sc_rc.entry_type(e) for e in entries}
            result.append({
                "name": value.get("description", key),
                "key": key,
                "count": len(entries),
                "has_cidr": "CIDR" in types,
                "has_fqdn": "FQDN" in types,
                "has_ip": "IP" in types,
                "source": source,
                "dirty": sc_rc.list_dirty(other_entries, entries) if prefer == "rc" else sc_rc.list_dirty(entries, other_entries),
            })
        return result


async def get_domain_list(name: str, saved: bool = False) -> dict:
    """Get one domain-list. Default = running-config (rc). Pass saved=true for sc.

    Limitation: after write without save, only rc has the change — sc lags until save_config.
    """
    prefer = "sc" if saved else "rc"
    async with _get_client() as client:
        groups, source = await sc_rc.fetch_fqdn_groups(client, prefer=prefer)
        key = await _resolve_list_key(client, name, groups)
        value = groups.get(key) or {}
        description = value.get("description", key) if isinstance(value, dict) else key
        entries_full = sc_rc.normalize_include(value.get("include") if isinstance(value, dict) else [])
        entries = [e["address"] for e in entries_full]
        other_root = "sc" if prefer == "rc" else "rc"
        other_groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer=other_root)
        other_entries = sc_rc.include_addresses(
            (other_groups.get(key) or {}).get("include") if isinstance(other_groups.get(key), dict) else []
        )
        dirty = sc_rc.list_dirty(other_entries if prefer == "rc" else entries,
                                 entries if prefer == "rc" else other_entries)
        # dirty true means sc≠rc regardless of which we read
        dirty = sorted(entries) != sorted(other_entries)
        return {
            "ok": True,
            "name": description,
            "key": key,
            "entries": entries,
            "entries_detail": entries_full,
            "count": len(entries),
            "source": source,
            "dirty": dirty,
            "note": (
                "source=rc is running (post-write without save). "
                "source=sc is saved/startup. dirty=true means sc≠rc."
            ),
        }


async def get_dns_routes(saved: bool = False) -> list[dict]:
    """DNS-proxy routes. Default source=rc; saved=true → sc."""
    prefer = "sc" if saved else "rc"
    async with _get_client() as client:
        routes, source = await sc_rc.fetch_dns_routes(client, prefer=prefer)
        other, _ = await sc_rc.fetch_dns_routes(client, prefer="sc" if prefer == "rc" else "rc")
        groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer=prefer)
        key_to_name = {
            key: value.get("description", key)
            for key, value in groups.items() if isinstance(value, dict)
        }
        dirty_all = sc_rc.routes_fingerprint(routes) != sc_rc.routes_fingerprint(other)
        return [
            {**_route_view(route, key_to_name), "source": source, "dirty": dirty_all}
            for route in routes
        ]


async def list_dns_route_metadata() -> dict:
    """One table: domain-list + linked dns-proxy route metadata (rc + dirty)."""
    async with _get_client() as client:
        rc_groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
        sc_groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="sc")
        rc_routes, _ = await sc_rc.fetch_dns_routes(client, prefer="rc")
        sc_routes, _ = await sc_rc.fetch_dns_routes(client, prefer="sc")
    key_to_name = {
        key: value.get("description", key)
        for key, value in rc_groups.items() if isinstance(value, dict)
    }
    routes_by_group: dict[str, dict] = {}
    for route in rc_routes:
        g = str(route.get("group") or "")
        if g:
            routes_by_group[g] = route
    rows = []
    for key, value in rc_groups.items():
        if not isinstance(value, dict):
            continue
        entries = sc_rc.include_addresses(value.get("include"))
        types = {sc_rc.entry_type(e) for e in entries}
        sc_entries = sc_rc.include_addresses(
            (sc_groups.get(key) or {}).get("include") if isinstance(sc_groups.get(key), dict) else []
        )
        route = routes_by_group.get(key)
        rows.append({
            "list_key": key,
            "name": value.get("description", key),
            "route_interface": (route or {}).get("interface"),
            "route_gateway": (route or {}).get("gateway") or None,
            "route_enabled": (not route.get("disable", False)) if route else None,
            "entry_count": len(entries),
            "has_cidr": "CIDR" in types,
            "has_fqdn": "FQDN" in types,
            "has_ip": "IP" in types,
            "sc_dirty": sorted(entries) != sorted(sc_entries),
            "source": "rc",
        })
    return {
        "ok": True,
        "count": len(rows),
        "routes_dirty": sc_rc.routes_fingerprint(rc_routes) != sc_rc.routes_fingerprint(sc_routes),
        "rows": rows,
        "note": "Running (rc) view. sc_dirty=true means list includes differ from saved config.",
    }


async def domain_list_covers_ip(list_name: str, ip: str, saved: bool = False) -> dict:
    """Whether list includes IP via exact IP or CIDR (and FQDN note). Default source=rc."""
    prefer = "sc" if saved else "rc"
    try:
        target = ipaddress.ip_address((ip or "").strip())
    except ValueError as exc:
        raise ValueError(f"invalid ip: {ip}") from exc
    async with _get_client() as client:
        groups, source = await sc_rc.fetch_fqdn_groups(client, prefer=prefer)
        key = await _resolve_list_key(client, list_name, groups)
        value = groups.get(key) or {}
        description = value.get("description", key) if isinstance(value, dict) else key
        entries = sc_rc.normalize_include(value.get("include") if isinstance(value, dict) else [])
        routes, _ = await sc_rc.fetch_dns_routes(client, prefer=prefer)
        linked = next((r for r in routes if r.get("group") == key), None)
    matched = []
    for entry in entries:
        et = entry["type"]
        addr = entry["address"]
        if et in ("IP", "CIDR"):
            try:
                if target in ipaddress.ip_network(addr, strict=False):
                    matched.append(entry)
            except ValueError:
                continue
    return {
        "ok": True,
        "list_name": description,
        "list_key": key,
        "ip": str(target),
        "covered": bool(matched),
        "matched": matched,
        "matched_entry": matched[0] if matched else None,
        "type": (matched[0]["type"] if matched else None),
        "linked_dns_route_interface": (linked or {}).get("interface"),
        "linked_dns_route_gateway": (linked or {}).get("gateway") or None,
        "source": source,
        "note": (
            "FQDN entries cannot cover a bare IP without DNS resolution; "
            "CIDR/IP matches are authoritative for object-group includes."
        ),
    }


async def diff_sc_rc(paths: list[str] | None = None) -> dict:
    """Diff saved (sc) vs running (rc) for domain-lists, dns-proxy routes, WG AllowedIPs."""
    wanted = {p.strip().lower() for p in (paths or [
        "domain-lists", "dns-routes", "wireguard-allowed-ips"
    ]) if p and p.strip()}
    result: dict = {"ok": True, "diffs": {}}
    async with _get_client() as client:
        if "domain-lists" in wanted or "domain_lists" in wanted:
            rc_g, _ = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
            sc_g, _ = await sc_rc.fetch_fqdn_groups(client, prefer="sc")
            lists = []
            for key in sorted(set(rc_g) | set(sc_g)):
                rc_e = sc_rc.include_addresses((rc_g.get(key) or {}).get("include") if isinstance(rc_g.get(key), dict) else [])
                sc_e = sc_rc.include_addresses((sc_g.get(key) or {}).get("include") if isinstance(sc_g.get(key), dict) else [])
                if sorted(rc_e) == sorted(sc_e):
                    continue
                lists.append({
                    "key": key,
                    "name": ((rc_g.get(key) or sc_g.get(key) or {}).get("description") if isinstance(rc_g.get(key) or sc_g.get(key), dict) else key),
                    "only_in_rc": sorted(set(rc_e) - set(sc_e)),
                    "only_in_sc": sorted(set(sc_e) - set(rc_e)),
                })
            result["diffs"]["domain_lists"] = {"dirty": bool(lists), "lists": lists}

        if "dns-routes" in wanted or "dns_routes" in wanted:
            rc_r, _ = await sc_rc.fetch_dns_routes(client, prefer="rc")
            sc_r, _ = await sc_rc.fetch_dns_routes(client, prefer="sc")
            result["diffs"]["dns_routes"] = {
                "dirty": sc_rc.routes_fingerprint(rc_r) != sc_rc.routes_fingerprint(sc_r),
                "rc_count": len(rc_r),
                "sc_count": len(sc_r),
                "rc": rc_r,
                "sc": sc_r,
            }

        if "wireguard-allowed-ips" in wanted or "wireguard_allowed_ips" in wanted or "wg" in wanted:
            wg_diffs = []
            for root in ("rc", "sc"):
                pass
            try:
                rc_if = await client.rci_get("show/rc/interface")
                sc_if = await client.rci_get("show/sc/interface")
            except Exception as exc:  # noqa: BLE001
                result["diffs"]["wireguard_allowed_ips"] = {"error": str(exc).split("\n")[0][:160]}
            else:
                def peers_map(blob: dict) -> dict[str, dict[str, list[str]]]:
                    out: dict[str, dict[str, list[str]]] = {}
                    if not isinstance(blob, dict):
                        return out
                    for name, iface in blob.items():
                        if not isinstance(iface, dict):
                            continue
                        if not (str(name).startswith("Wireguard") or iface.get("wireguard")):
                            continue
                        peers = (iface.get("wireguard") or {}).get("peer") or []
                        if isinstance(peers, dict):
                            peers = list(peers.values())
                        out[name] = {}
                        for peer in peers if isinstance(peers, list) else []:
                            if not isinstance(peer, dict):
                                continue
                            pk = str(peer.get("key") or peer.get("public-key") or "")
                            if pk:
                                out[name][pk] = sc_rc.allow_ips_from_peer(peer)
                    return out

                rc_map = peers_map(rc_if if isinstance(rc_if, dict) else {})
                sc_map = peers_map(sc_if if isinstance(sc_if, dict) else {})
                for iface in sorted(set(rc_map) | set(sc_map)):
                    for pk in sorted(set(rc_map.get(iface, {})) | set(sc_map.get(iface, {}))):
                        rc_a = rc_map.get(iface, {}).get(pk, [])
                        sc_a = sc_map.get(iface, {}).get(pk, [])
                        if sorted(rc_a) != sorted(sc_a):
                            wg_diffs.append({
                                "interface": iface,
                                "public_key": pk,
                                "only_in_rc": sorted(set(rc_a) - set(sc_a)),
                                "only_in_sc": sorted(set(sc_a) - set(rc_a)),
                            })
                result["diffs"]["wireguard_allowed_ips"] = {
                    "dirty": bool(wg_diffs),
                    "peers": wg_diffs,
                }
    return result


async def add_dns_route(
    list_name: str,
    interface: str,
    gateway: str = "",
    auto: bool = True,
    enabled: bool = True,
    save: bool = False,
) -> dict:
    """Add dns-proxy route into running-config. Verify against rc before claiming created."""
    assert_writable()
    async with _get_client() as client:
        key = await _resolve_list_key(client, list_name)
        before, _ = await sc_rc.fetch_dns_routes(client, prefer="rc")
        before_fp = sc_rc.routes_fingerprint(before)
        await client.rci([
            {"dns-proxy": {"route": {
                "group": key,
                "interface": interface,
                "gateway": gateway,
                "auto": auto,
                "disable": not enabled,
            }}},
            *save_payload(save),
        ])
        after, _ = await sc_rc.fetch_dns_routes(client, prefer="rc")
        sc_after, _ = await sc_rc.fetch_dns_routes(client, prefer="sc")
    match = None
    for route in reversed(after):
        if route.get("group") == key and route.get("interface") == interface:
            match = route
            break
    created = match is not None and sc_rc.routes_fingerprint(after) != before_fp
    return {
        "created": created,
        "index": (match or {}).get("index"),
        "list_name": list_name,
        "interface": interface,
        "applied_to": "rc",
        "persisted": bool(save),
        "dirty": sc_rc.routes_fingerprint(after) != sc_rc.routes_fingerprint(sc_after),
        "config_saved": save,
        "note": "created=true only if running-config routes changed.",
    }


async def delete_dns_route(index: str, save: bool = False) -> dict:
    assert_writable()
    async with _get_client() as client:
        before, _ = await sc_rc.fetch_dns_routes(client, prefer="rc")
        await client.rci([
            {"dns-proxy": {"route": {"index": index, "no": True}}},
            *save_payload(save),
        ])
        after, _ = await sc_rc.fetch_dns_routes(client, prefer="rc")
        sc_after, _ = await sc_rc.fetch_dns_routes(client, prefer="sc")
    deleted = sc_rc.routes_fingerprint(before) != sc_rc.routes_fingerprint(after)
    return {
        "deleted": deleted,
        "index": index,
        "applied_to": "rc",
        "persisted": bool(save),
        "dirty": sc_rc.routes_fingerprint(after) != sc_rc.routes_fingerprint(sc_after),
        "config_saved": save,
    }


async def set_domain_list(name: str, entries: list[str], save: bool = False) -> dict:
    assert_writable()
    async with _get_client() as client:
        groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
        key = await _resolve_list_key(client, name, groups)
        description, before = await _read_list_entries(client, key, groups)
        await _write_list_entries(client, key, description, entries, save=save)
        after_groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
        _, after = await _read_list_entries(client, key, after_groups)
        sc_groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="sc")
        sc_entries = sc_rc.include_addresses(
            (sc_groups.get(key) or {}).get("include") if isinstance(sc_groups.get(key), dict) else []
        )
    return {
        "updated": description,
        "key": key,
        "count": len(after),
        "changed": sorted(before) != sorted(after),
        "applied_to": "rc",
        "persisted": bool(save),
        "dirty": sorted(after) != sorted(sc_entries),
        "config_saved": save,
    }


async def add_domains(name: str, domains: list[str], save: bool = False) -> dict:
    assert_writable()
    async with _get_client() as client:
        groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
        key = await _resolve_list_key(client, name, groups)
        description, existing = await _read_list_entries(client, key, groups)
        to_add = [d for d in domains if d not in existing]
        merged = list(dict.fromkeys(existing + to_add))
        if to_add:
            await _write_list_entries(client, key, description, merged, save=save)
        after_groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
        _, after = await _read_list_entries(client, key, after_groups)
        sc_groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="sc")
        sc_entries = sc_rc.include_addresses(
            (sc_groups.get(key) or {}).get("include") if isinstance(sc_groups.get(key), dict) else []
        )
    actually_added = [d for d in to_add if d in after]
    return {
        "updated": description,
        "key": key,
        "added": len(actually_added),
        "added_entries": actually_added,
        "total": len(after),
        "applied_to": "rc",
        "persisted": bool(save),
        "dirty": sorted(after) != sorted(sc_entries),
        "config_saved": save,
        "note": "added counts only entries present in running-config after write.",
    }


async def remove_domains(name: str, domains: list[str], save: bool = False) -> dict:
    assert_writable()
    async with _get_client() as client:
        groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
        key = await _resolve_list_key(client, name, groups)
        description, existing = await _read_list_entries(client, key, groups)
        filtered = [entry for entry in existing if entry not in set(domains)]
        removed_expect = len(existing) - len(filtered)
        if removed_expect:
            await _write_list_entries(client, key, description, filtered, save=save)
        after_groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
        _, after = await _read_list_entries(client, key, after_groups)
        sc_groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="sc")
        sc_entries = sc_rc.include_addresses(
            (sc_groups.get(key) or {}).get("include") if isinstance(sc_groups.get(key), dict) else []
        )
    return {
        "updated": description,
        "key": key,
        "removed": len(existing) - len(after),
        "total": len(after),
        "applied_to": "rc",
        "persisted": bool(save),
        "dirty": sorted(after) != sorted(sc_entries),
        "config_saved": save,
    }


async def create_domain_list(name: str, entries: list[str] | None = None, save: bool = False) -> dict:
    assert_writable()
    async with _get_client() as client:
        groups, _ = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
        used = {key for key in groups if key.startswith("domain-list")}
        index = 0
        while f"domain-list{index}" in used:
            index += 1
        key = f"domain-list{index}"
        await client.rci([
            {"object-group": {"fqdn": {key: {
                "description": name,
                "include": [{"address": entry} for entry in (entries or [])],
            }}}},
            *save_payload(save),
        ])
        after, _ = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
        created = key in after
        sc_after, _ = await sc_rc.fetch_fqdn_groups(client, prefer="sc")
    return {
        "created": created,
        "name": name,
        "key": key,
        "count": len(entries or []),
        "applied_to": "rc",
        "persisted": bool(save),
        "dirty": key not in sc_after or sorted(sc_rc.include_addresses((sc_after.get(key) or {}).get("include") if isinstance(sc_after.get(key), dict) else [])) != sorted(entries or []),
        "config_saved": save,
    }


async def delete_domain_list(name: str, save: bool = False) -> dict:
    assert_writable()
    async with _get_client() as client:
        key = await _resolve_list_key(client, name)
        await client.rci([
            {"object-group": {"fqdn": {key: {"no": True}}}},
            *save_payload(save),
        ])
        after, _ = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
        deleted = key not in after
        sc_after, _ = await sc_rc.fetch_fqdn_groups(client, prefer="sc")
    return {
        "deleted": deleted,
        "name": name,
        "key": key,
        "applied_to": "rc",
        "persisted": bool(save),
        "dirty": (key not in after) != (key not in sc_after),
        "config_saved": save,
    }


def register(mcp) -> None:
    mcp.tool()(get_domain_lists)
    mcp.tool()(get_domain_list)
    mcp.tool()(get_dns_routes)
    mcp.tool()(list_dns_route_metadata)
    mcp.tool()(domain_list_covers_ip)
    mcp.tool()(diff_sc_rc)
    mcp.tool()(add_dns_route)
    mcp.tool()(delete_dns_route)
    mcp.tool()(set_domain_list)
    mcp.tool()(add_domains)
    mcp.tool()(remove_domains)
    mcp.tool()(create_domain_list)
    mcp.tool()(delete_domain_list)
