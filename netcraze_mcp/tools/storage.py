"""USB storage, SMB shares and printer tools."""

from ..client import _get_client, _raise_on_rci_errors
from ..config import assert_writable


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


def _media_items(data) -> list[tuple[str, dict]]:
    """Normalize show media payload: dict map, list, or wrapped {show:{media}} / {media}."""
    if isinstance(data, dict):
        if "show" in data and isinstance(data.get("show"), dict) and "media" in data["show"]:
            data = data["show"]["media"]
        elif list(data.keys()) == ["media"]:
            data = data["media"]
    if data in (None, {}, []):
        return []
    if isinstance(data, list):
        items = []
        for index, item in enumerate(data):
            if not isinstance(item, dict):
                continue
            device_id = str(item.get("name") or item.get("id") or f"media{index}")
            items.append((device_id, item))
        return items
    if isinstance(data, dict):
        return [(str(device_id), item) for device_id, item in data.items() if isinstance(item, dict)]
    return []


def _device_entry(device_id: str, item: dict) -> dict:
    return {
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


def _device_from_ls_storage(ls_payload) -> dict | None:
    """Built-in flash from RCI ls entry storage: (same source as UI «Встроенное хранилище»).

    On some firmwares (e.g. 5.0.x) show media is empty while ls storage: still has UBIFS.
    """
    if not isinstance(ls_payload, dict):
        return None
    root = ls_payload.get("ls") if isinstance(ls_payload.get("ls"), dict) else ls_payload
    raw = (root.get("entry") or {}).get("storage:")
    if not isinstance(raw, dict):
        return None
    if raw.get("fstype") is None and raw.get("total") is None:
        return None
    mounted = str(raw.get("mounted") or "").lower() in ("yes", "y", "true", "1")
    total = _as_int(raw.get("total"))
    free = _as_int(raw.get("free"))
    bus = raw.get("storage")
    if bus in (None, "", "none"):
        bus = "mtd"
    partition = {
        key: value
        for key, value in {
            "id": "Partition1",
            "label": raw.get("label") or "Storage",
            "fstype": raw.get("fstype"),
            "state": "MOUNTED" if mounted else "UNMOUNTED",
            "total_bytes": total,
            "free_bytes": free,
        }.items()
        if value is not None and value != ""
    }
    return {
        key: value
        for key, value in {
            "id": "FlashStorage",
            "bus": bus,
            "state": "ACTIVE" if mounted else "INACTIVE",
            "size_bytes": total,
            "removable": False,
            "ejectable": False,
            "partitions": [partition] if partition else [],
        }.items()
        if value is not None and value != []
    }


def _has_internal_storage(devices: list[dict]) -> bool:
    return any(
        item.get("id") == "FlashStorage" or item.get("bus") == "mtd"
        for item in devices
    )


async def list_usb_storage() -> list[dict]:
    """List media/USB storage and built-in flash.

    Primary source: show media. If internal flash is missing there (common on
    some 5.0.x builds), fall back to ls entry storage: — same as the web UI.
    """
    async with _get_client() as client:
        data = await client.rci_get("show/media")
        items = _media_items(data)
        if not items:
            posted = await client.rci({"show": {"media": {}}})
            items = _media_items(posted)
        result = [_device_entry(device_id, item) for device_id, item in items]
        if not _has_internal_storage(result):
            internal = _device_from_ls_storage(await client.rci({"ls": {}}))
            if internal:
                result.append(internal)
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
        if "printer" in data:
            raw = data.get("printer") or {}
            if isinstance(raw, dict):
                items = [
                    {**value, "id": key} if isinstance(value, dict) else value
                    for key, value in raw.items()
                ]
            elif isinstance(raw, list):
                items = raw
            else:
                items = [raw] if raw else []
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
                "type": item.get("type"),
                "attached": item.get("attached"),
                "interface": item.get("interface"),
                "share": item.get("share"),
            }.items()
            if value is not None
        })
    return result


async def set_share(label: str, mount: str, description: str = "") -> dict:
    """Create or update SMB/CIFS share and save configuration."""
    assert_writable()
    if not label.strip() or not mount.strip():
        raise ValueError("label and mount are required")
    share = {"label": label.strip(), "mount": mount.strip()}
    if description.strip():
        share["description"] = description.strip()
    async with _get_client() as client:
        resp = await client.rci([
            {"cifs": {"share": share}},
            {"system": {"configuration": {"save": {}}}},
        ])
        _raise_on_rci_errors(resp)
    return {"added": True, **share}


async def delete_share(label: str) -> dict:
    """Delete SMB/CIFS share by label and save configuration."""
    assert_writable()
    if not label.strip():
        raise ValueError("label is required")
    shares = await list_shares()
    match = next((item for item in shares if item.get("label") == label.strip()), None)
    if not match:
        raise ValueError(f"Share not found: {label}")
    async with _get_client() as client:
        resp = await client.rci([
            {"cifs": {"share": {
                "label": match["label"],
                "mount": match["mount"],
                "no": True,
            }}},
            {"system": {"configuration": {"save": {}}}},
        ])
        _raise_on_rci_errors(resp)
    return {"deleted": True, "label": match["label"], "mount": match["mount"]}


async def unmount_usb(device: str) -> dict:
    """Safely eject USB/media device (system eject). Refuses non-ejectable drives."""
    assert_writable()
    if not device.strip():
        raise ValueError("device id is required (from list_usb_storage)")
    devices = await list_usb_storage()
    match = next((item for item in devices if item.get("id") == device.strip()), None)
    if not match:
        raise ValueError(f"Media device not found: {device}")
    if match.get("ejectable") is False:
        raise ValueError(f"Device is not ejectable: {device}")
    async with _get_client() as client:
        resp = await client.rci({"system": {"eject": {"name": device.strip()}}})
        _raise_on_rci_errors(resp)
    return {"ejected": True, "device": device.strip()}


def register(mcp) -> None:
    mcp.tool()(list_usb_storage)
    mcp.tool()(list_shares)
    mcp.tool()(list_printers)
    mcp.tool()(set_share)
    mcp.tool()(delete_share)
    mcp.tool()(unmount_usb)
