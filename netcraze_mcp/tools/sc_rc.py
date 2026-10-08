"""sc (saved) vs rc (running) helpers for honest agent-facing reads."""

from __future__ import annotations

import ipaddress
from typing import Any


def entry_type(address: str) -> str:
    text = (address or "").strip()
    if not text:
        return "empty"
    try:
        net = ipaddress.ip_network(text, strict=False)
        return "CIDR" if "/" in text or net.prefixlen not in (32, 128) else "IP"
    except ValueError:
        return "FQDN"


def normalize_include(raw: Any) -> list[dict]:
    if not isinstance(raw, list):
        raw = [raw] if raw else []
    out = []
    for item in raw:
        if isinstance(item, dict):
            addr = item.get("address")
            if addr is None:
                continue
            out.append({
                "address": str(addr),
                "type": entry_type(str(addr)),
                "ipv4": item.get("ipv4") if item.get("ipv4") not in (None, []) else None,
            })
        elif item:
            out.append({"address": str(item), "type": entry_type(str(item)), "ipv4": None})
    return out


def include_addresses(raw: Any) -> list[str]:
    return [e["address"] for e in normalize_include(raw)]


def fqdn_groups_from_show(data: Any, root: str) -> dict[str, dict]:
    """Extract object-group fqdn map from show/{sc|rc}/… or nested show response."""
    if not isinstance(data, dict):
        return {}
    if root in data and isinstance(data[root], dict):
        node = data[root]
        fq = ((node.get("object-group") or {}).get("fqdn") if isinstance(node.get("object-group"), dict) else None)
        if isinstance(fq, dict):
            return fq
    # direct GET show/sc/object-group/fqdn already returns the map
    if any(isinstance(v, dict) and ("include" in v or "description" in v) for v in data.values()):
        return {k: v for k, v in data.items() if isinstance(v, dict)}
    show = data.get("show")
    if isinstance(show, dict):
        return fqdn_groups_from_show(show, root)
    return {}


def dns_routes_from_show(data: Any, root: str) -> list[dict]:
    if not isinstance(data, dict):
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        return []
    if root in data and isinstance(data[root], dict):
        routes = (data[root].get("dns-proxy") or {}).get("route")
        if isinstance(routes, list):
            return [r for r in routes if isinstance(r, dict)]
        if isinstance(routes, dict):
            return [routes]
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    # direct list-like GET
    if all(isinstance(v, dict) and ("group" in v or "interface" in v) for v in data.values() if isinstance(v, dict)):
        return list(data.values())  # type: ignore[arg-type]
    show = data.get("show")
    if isinstance(show, dict):
        return dns_routes_from_show(show, root)
    # GET show/*/dns-proxy/route returns a list
    return []


async def fetch_fqdn_groups(client, *, prefer: str = "rc") -> tuple[dict[str, dict], str]:
    prefer = prefer if prefer in ("rc", "sc") else "rc"
    order = [prefer, "sc" if prefer == "rc" else "rc"]
    last_err = None
    for root in order:
        groups: dict[str, dict] = {}
        try:
            raw = await client.rci_get(f"show/{root}/object-group/fqdn")
            groups = fqdn_groups_from_show(raw, root)
        except Exception as exc:  # noqa: BLE001
            last_err = exc
        if not groups:
            try:
                nested = await client.rci({"show": {root: {"object-group": {"fqdn": {}}}}})
                groups = fqdn_groups_from_show(nested, root)
                if not groups:
                    # fixtures / some NDMS embeds often only show.sc
                    alt = "sc" if root == "rc" else "rc"
                    groups = fqdn_groups_from_show(nested, alt)
                    if groups:
                        return groups, alt
            except Exception as exc2:  # noqa: BLE001
                last_err = exc2
        if groups:
            return groups, root
    if last_err:
        raise last_err
    return {}, prefer


async def fetch_dns_routes(client, *, prefer: str = "rc") -> tuple[list[dict], str]:
    prefer = prefer if prefer in ("rc", "sc") else "rc"
    for root in [prefer, "sc" if prefer == "rc" else "rc"]:
        routes: list[dict] = []
        try:
            raw = await client.rci_get(f"show/{root}/dns-proxy/route")
            parsed = raw if isinstance(raw, list) else dns_routes_from_show(raw, root)
            if isinstance(parsed, list):
                routes = [r for r in parsed if isinstance(r, dict)]
        except Exception:  # noqa: BLE001
            routes = []
        if not routes:
            try:
                nested = await client.rci({"show": {root: {"dns-proxy": {"route": {}}}}})
                routes = dns_routes_from_show(nested, root)
                if not routes:
                    alt = "sc" if root == "rc" else "rc"
                    routes = dns_routes_from_show(nested, alt)
                    if routes:
                        return routes, alt
            except Exception:  # noqa: BLE001
                routes = []
        if routes:
            return routes, root
    return [], prefer


def list_dirty(sc_entries: list[str], rc_entries: list[str]) -> bool:
    return sorted(sc_entries) != sorted(rc_entries)


def routes_fingerprint(routes: list[dict]) -> list[tuple]:
    out = []
    for r in routes:
        out.append((
            str(r.get("group") or r.get("list_key") or ""),
            str(r.get("interface") or ""),
            str(r.get("gateway") or ""),
            bool(r.get("disable", False)),
            str(r.get("index") or ""),
        ))
    return sorted(out)


def allow_ips_from_peer(peer: dict) -> list[str]:
    raw = peer.get("allow-ips") or peer.get("allowed-ips") or []
    if isinstance(raw, dict):
        raw = list(raw.values())
    out = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        addr = item.get("address")
        mask = item.get("mask") or "255.255.255.255"
        if not addr:
            continue
        try:
            out.append(str(ipaddress.ip_network(f"{addr}/{mask}", strict=False)))
        except ValueError:
            out.append(f"{addr}/{mask}")
    return out


def cidr_covers(cidr: str, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def path_class_from_dst_out(dst_out: str | None, wg_addrs: set[str] | None = None) -> str:
    if not dst_out:
        return "OTHER"
    try:
        ip = ipaddress.ip_address(dst_out)
    except ValueError:
        return "OTHER"
    if wg_addrs and dst_out in wg_addrs:
        return "WG0"
    # common WG tunnel nets used in this fleet
    for net in ("10.255.0.0/16", "10.13.0.0/16"):
        try:
            if ip in ipaddress.ip_network(net):
                return "WG0"
        except ValueError:
            continue
    if ip.is_private:
        return "OTHER"
    return "WAN"
