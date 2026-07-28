"""USB storage, SMB shares and printer tools."""

from ..client import _get_client


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def _partitions(raw) -> list[dict]:
    if isinstance(raw, dict):
        items = list(raw.values())
    elif isinstance(raw, list):
        items = raw
    else:
        items = [raw] if raw else []
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        result.append({
            key: value
            for key, value in {
                "id": item.get("id"),
                "uuid": item.get("uuid"),
                "label": item.get("label"),
                "fstype": item.get("fstype"),
                "state": item.get("state"),
                "total_bytes": _as_int(item.get("total")),
                "free_bytes": _as_int(item.get("free")),
                "used_by": item.get("used-by") or None,
            }.items()
            if value is not None and value != []
        })
    return result


async def list_usb_storage() -> list[dict]:
    """List media/USB storage devices and partitions from show media."""
    async with _get_client() as client:
        data = await client.rci_get("show/media")
    if not isinstance(data, dict):
        return []
    result = []
    for device_id, item in data.items():
        if not isinstance(item, dict):
            continue
        entry = {
            key: value
            for key, value in {
                "id": device_id,
                "bus": item.get("bus"),
                "state": item.get("state"),
                "manufacturer": item.get("manufacturer"),
                "product": item.get("product"),
                "serial": item.get("serial"),
                "size_bytes": _as_int(item.get("size")),
                "removable": item.get("removable"),
                "ejectable": item.get("ejectable"),
                "partitions": _partitions(item.get("partition")),
            }.items()
            if value is not None and value != []
        }
        result.append(entry)
    result.sort(key=lambda item: item.get("id", ""))
    return result


async def list_shares() -> list[dict]:
    """List SMB/CIFS shares and server flags from show cifs."""
    async with _get_client() as client:
        data = await client.rci_get("show/cifs")
    if not isinstance(data, dict):
        return []
    shares = data.get("share") or []
    if not isinstance(shares, list):
        shares = [shares] if shares else []
    server = {
        key: value
        for key, value in {
            "enabled": data.get("enabled"),
            "automount": data.get("automount"),
            "permissive": data.get("permissive"),
            "map_hidden": data.get("map-hidden"),
        }.items()
        if value is not None
    }
    result = []
    for item in shares:
        if not isinstance(item, dict):
            continue
        entry = {
            key: value
            for key, value in {
                "label": item.get("label"),
                "mount": item.get("mount"),
                "description": item.get("description") or None,
                "active": item.get("active"),
                **server,
            }.items()
            if value is not None and value != ""
        }
        result.append(entry)
    result.sort(key=lambda item: item.get("label") or item.get("mount") or "")
    return result


async def list_printers() -> list[dict]:
    """List USB/network printers from show printers."""
    async with _get_client() as client:
        data = await client.rci_get("show/printers")
    if data in (None, {}, []):
        return []
    if isinstance(data, dict):
        # either {"printer": [...]} or id -> printer map
        if "printer" in data:
            items = data.get("printer") or []
            if not isinstance(items, list):
                items = [items] if items else []
        else:
            items = [
                {**value, "id": key} if isinstance(value, dict) else value
                for key, value in data.items()
            ]
    elif isinstance(data, list):
        items = data
    else:
        items = [data]

    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        result.append({
            key: value
            for key, value in {
                "id": item.get("id") or item.get("name"),
                "name": item.get("name") or item.get("product"),
                "manufacturer": item.get("manufacturer"),
                "product": item.get("product"),
                "state": item.get("state") or item.get("status"),
                "interface": item.get("interface"),
                "share": item.get("share"),
            }.items()
            if value is not None
        })
    return result


def register(mcp) -> None:
    mcp.tool()(list_usb_storage)
    mcp.tool()(list_shares)
    mcp.tool()(list_printers)
