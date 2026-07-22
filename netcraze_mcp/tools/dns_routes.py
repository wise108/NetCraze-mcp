"""DNS routing and domain list tools."""

from ..client import _get_client
from ..config import assert_writable


async def _fetch_fqdn_groups(client) -> dict[str, dict]:
    data = await client.rci({"show": {"sc": {"object-group": {"fqdn": {}}}}})
    return data.get("show", {}).get("sc", {}).get("object-group", {}).get("fqdn", {})


async def _resolve_list_key(client, name: str, groups: dict | None = None) -> str:
    if groups is None:
        groups = await _fetch_fqdn_groups(client)
    if name in groups:
        return name
    for key, value in groups.items():
        if isinstance(value, dict) and value.get("description") == name:
            return key
    available = [value.get("description", key) for key, value in groups.items() if isinstance(value, dict)]
    raise ValueError(f"Domain list '{name}' not found. Available: {available}")


async def _read_list_entries(client, key: str, groups: dict | None = None) -> tuple[str, list[str]]:
    if groups is None:
        groups = await _fetch_fqdn_groups(client)
    value = groups.get(key, {})
    description = value.get("description", key) if isinstance(value, dict) else key
    raw = value.get("include", []) if isinstance(value, dict) else []
    if not isinstance(raw, list):
        raw = [raw] if raw else []
    return description, [entry["address"] for entry in raw if isinstance(entry, dict) and entry.get("address")]


async def _write_list_entries(client, key: str, description: str, entries: list[str]) -> None:
    await client.rci([
        {"object-group": {"fqdn": {key: {"include": {"no": True}}}}},
        {"object-group": {"fqdn": {key: {
            "description": description,
            "include": [{"address": entry} for entry in entries],
        }}}},
        {"system": {"configuration": {"save": {}}}},
    ])


async def get_domain_lists() -> list[dict]:
    async with _get_client() as client:
        groups = await _fetch_fqdn_groups(client)
        result = []
        for key, value in groups.items():
            if not isinstance(value, dict):
                continue
            raw = value.get("include", [])
            if not isinstance(raw, list):
                raw = [raw] if raw else []
            result.append({
                "name": value.get("description", key),
                "key": key,
                "count": len(raw),
            })
        return result


async def get_domain_list(name: str) -> dict:
    async with _get_client() as client:
        key = await _resolve_list_key(client, name)
        description, entries = await _read_list_entries(client, key)
        return {"name": description, "key": key, "entries": entries}


async def get_dns_routes() -> list[dict]:
    async with _get_client() as client:
        data = await client.rci({"show": {"sc": {"dns-proxy": {"route": {}}, "object-group": {"fqdn": {}}}}})
    sc = data.get("show", {}).get("sc", {})
    routes = sc.get("dns-proxy", {}).get("route", [])
    if not isinstance(routes, list):
        routes = [routes] if routes else []
    fqdn = sc.get("object-group", {}).get("fqdn", {})
    key_to_name = {key: value.get("description", key) for key, value in fqdn.items() if isinstance(value, dict)}
    return [{key: value for key, value in {
        "index": route.get("index"),
        "list_name": key_to_name.get(route.get("group", ""), route.get("group")),
        "list_key": route.get("group"),
        "interface": route.get("interface"),
        "gateway": route.get("gateway") or None,
        "auto": route.get("auto"),
        "enabled": not route.get("disable", False),
        "comment": route.get("comment") or None,
    }.items() if value is not None} for route in routes]


async def add_dns_route(
    list_name: str,
    interface: str,
    gateway: str = "",
    auto: bool = True,
    enabled: bool = True,
) -> dict:
    assert_writable()
    async with _get_client() as client:
        key = await _resolve_list_key(client, list_name)
        await client.rci([
            {"dns-proxy": {"route": {
                "group": key,
                "interface": interface,
                "gateway": gateway,
                "auto": auto,
                "disable": not enabled,
            }}},
            {"system": {"configuration": {"save": {}}}},
        ])
        routes_data = await client.rci({"show": {"sc": {"dns-proxy": {"route": {}}}}})
    routes = routes_data.get("show", {}).get("sc", {}).get("dns-proxy", {}).get("route", [])
    if not isinstance(routes, list):
        routes = [routes] if routes else []
    for route in reversed(routes):
        if route.get("group") == key and route.get("interface") == interface:
            return {"created": True, "index": route.get("index"), "list_name": list_name, "interface": interface}
    return {"created": True, "list_name": list_name, "interface": interface}


async def delete_dns_route(index: str) -> dict:
    assert_writable()
    async with _get_client() as client:
        await client.rci([
            {"dns-proxy": {"route": {"index": index, "no": True}}},
            {"system": {"configuration": {"save": {}}}},
        ])
        return {"deleted": True, "index": index}


async def set_domain_list(name: str, entries: list[str]) -> dict:
    assert_writable()
    async with _get_client() as client:
        groups = await _fetch_fqdn_groups(client)
        key = await _resolve_list_key(client, name, groups)
        description, _ = await _read_list_entries(client, key, groups)
        await _write_list_entries(client, key, description, entries)
        return {"updated": description, "key": key, "count": len(entries)}


async def add_domains(name: str, domains: list[str]) -> dict:
    assert_writable()
    async with _get_client() as client:
        groups = await _fetch_fqdn_groups(client)
        key = await _resolve_list_key(client, name, groups)
        description, existing = await _read_list_entries(client, key, groups)
        merged = list(dict.fromkeys(existing + [domain for domain in domains if domain not in existing]))
        await _write_list_entries(client, key, description, merged)
        return {"updated": description, "key": key, "added": len(merged) - len(existing), "total": len(merged)}


async def remove_domains(name: str, domains: list[str]) -> dict:
    assert_writable()
    async with _get_client() as client:
        groups = await _fetch_fqdn_groups(client)
        key = await _resolve_list_key(client, name, groups)
        description, existing = await _read_list_entries(client, key, groups)
        filtered = [entry for entry in existing if entry not in set(domains)]
        await _write_list_entries(client, key, description, filtered)
        return {"updated": description, "key": key, "removed": len(existing) - len(filtered), "total": len(filtered)}


async def create_domain_list(name: str, entries: list[str] | None = None) -> dict:
    assert_writable()
    async with _get_client() as client:
        groups = await _fetch_fqdn_groups(client)
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
            {"system": {"configuration": {"save": {}}}},
        ])
        return {"created": name, "key": key, "count": len(entries or [])}


async def delete_domain_list(name: str) -> dict:
    assert_writable()
    async with _get_client() as client:
        key = await _resolve_list_key(client, name)
        await client.rci([
            {"object-group": {"fqdn": {key: {"no": True}}}},
            {"system": {"configuration": {"save": {}}}},
        ])
        return {"deleted": name, "key": key}


def register(mcp) -> None:
    mcp.tool()(get_domain_lists)
    mcp.tool()(get_domain_list)
    mcp.tool()(get_dns_routes)
    mcp.tool()(add_dns_route)
    mcp.tool()(delete_dns_route)
    mcp.tool()(set_domain_list)
    mcp.tool()(add_domains)
    mcp.tool()(remove_domains)
    mcp.tool()(create_domain_list)
    mcp.tool()(delete_domain_list)
