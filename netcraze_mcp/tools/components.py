"""Firmware and NDMS component tools."""

from ..client import _get_client, _raise_on_rci_errors
from ..config import assert_writable


def _component_description(meta: dict) -> str:
    desc = meta.get("description")
    if isinstance(desc, dict):
        return str(desc.get("RU") or desc.get("EN") or "")
    return str(desc or "")


def _group_matches(needle: str, component_group: str, name: str) -> bool:
    """Substring match on group or component name (usb → USB modems, usb, usblte…)."""
    if not needle:
        return True
    q = needle.lower()
    return q in component_group.lower() or q in name.lower()


async def list_components(installed_only: bool = False, group: str = "") -> list[dict]:
    """List NDMS components (installed and available), optionally filtered by group.

    group — substring match (case-insensitive) on group name or component name.
    Examples: Storage, USB, Base system, usb (matches USB modems + usb*).
    """
    async with _get_client() as client:
        version = await client.rci_get("show/version")
        catalog = await client.rci({"components": {"list": {}}})
    installed = {
        name.strip()
        for name in str((version.get("ndw") or {}).get("components") or "").split(",")
        if name.strip()
    }
    components = ((catalog.get("components") or {}).get("list") or {}).get("component") or {}
    if not isinstance(components, dict):
        return []

    result: list[dict] = []
    for name, meta in components.items():
        if not isinstance(meta, dict):
            continue
        is_installed = name in installed
        if installed_only and not is_installed:
            continue
        component_group = str(meta.get("group") or "")
        if not _group_matches(group, component_group, name):
            continue
        # RCI "queued" means "selected in current set", not pending op.
        # It equals installed in steady state — only expose real pending changes.
        selected = meta.get("queued")
        pending = None
        if isinstance(selected, bool) and selected != is_installed:
            pending = "install" if selected else "remove"
        entry = {
            key: value
            for key, value in {
                "name": name,
                "installed": is_installed,
                "group": component_group or None,
                "description": _component_description(meta) or None,
                "version": meta.get("version"),
                "size": int(meta["size"]) if str(meta.get("size") or "").isdigit() else meta.get("size"),
                "queued": True if pending else None,
                "pending": pending,
            }.items()
            if value is not None
        }
        result.append(entry)
    result.sort(key=lambda item: (not item.get("installed", False), item.get("name", "")))
    return result


async def get_component(name: str) -> dict:
    """One NDMS component: installed, version, description, dependencies if known."""
    if not name.strip():
        raise ValueError("name is required")
    needle = name.strip()
    async with _get_client() as client:
        version = await client.rci_get("show/version")
        catalog = await client.rci({"components": {"list": {}}})
    installed = {
        item.strip()
        for item in str((version.get("ndw") or {}).get("components") or "").split(",")
        if item.strip()
    }
    components = ((catalog.get("components") or {}).get("list") or {}).get("component") or {}
    if not isinstance(components, dict) or needle not in components:
        # case-insensitive fallback
        match = next((k for k in components if isinstance(components, dict) and k.lower() == needle.lower()), None)
        if match is None:
            raise ValueError(f"Component not found: {needle}")
        needle = match
    meta = components[needle] if isinstance(components, dict) else {}
    if not isinstance(meta, dict):
        raise ValueError(f"Component not found: {needle}")
    deps = meta.get("depends") or meta.get("dependencies") or meta.get("require")
    if isinstance(deps, str):
        deps = [part.strip() for part in deps.split(",") if part.strip()]
    features = (version.get("ndw") or {}).get("features") if isinstance(version, dict) else None
    return {
        key: value
        for key, value in {
            "name": needle,
            "installed": needle in installed,
            "group": meta.get("group"),
            "description": _component_description(meta) or None,
            "version": meta.get("version"),
            "size": int(meta["size"]) if str(meta.get("size") or "").isdigit() else meta.get("size"),
            "dependencies": deps or None,
            "ndw_features": features,
            "note": (
                "related CLI/RCI feature flags come from show/version ndw.features when present; "
                "component packaging does not always expose a dedicated flag map."
            ),
        }.items()
        if value is not None
    }


async def get_firmware_info() -> dict:
    """Firmware version, update channel/sandbox and component summary."""
    async with _get_client() as client:
        version = await client.rci_get("show/version")
        components_cfg = await client.rci_get("components")
    installed = [
        name.strip()
        for name in str((version.get("ndw") or {}).get("components") or "").split(",")
        if name.strip()
    ]
    auto_update = (components_cfg or {}).get("auto-update") or {}
    return {
        key: value
        for key, value in {
            "model": version.get("model") or version.get("title"),
            "manufacturer": version.get("manufacturer") or version.get("vendor"),
            "firmware": version.get("release"),
            "title": version.get("title"),
            "arch": version.get("arch"),
            "sandbox": version.get("sandbox"),
            "update_channel": auto_update.get("channel"),
            "auto_update": (not auto_update.get("disable")) if "disable" in auto_update else None,
            "components_installed": len(installed),
            "components": installed,
        }.items()
        if value is not None
    }


async def install_component(name: str, commit: bool = True) -> dict:
    """Queue NDMS component for install; optionally run components commit."""
    assert_writable()
    if not name.strip():
        raise ValueError("Component name is required")
    async with _get_client() as client:
        resp = await client.rci({"parse": f"components install {name.strip()}"})
        _raise_on_rci_errors(resp)
        committed = False
        if commit:
            commit_resp = await client.rci({"parse": "components commit"})
            _raise_on_rci_errors(commit_resp)
            committed = True
    return {"queued": True, "name": name.strip(), "action": "install", "committed": committed}


async def remove_component(name: str, commit: bool = True) -> dict:
    """Queue NDMS component for removal; optionally run components commit."""
    assert_writable()
    if not name.strip():
        raise ValueError("Component name is required")
    async with _get_client() as client:
        resp = await client.rci({"parse": f"components remove {name.strip()}"})
        _raise_on_rci_errors(resp)
        committed = False
        if commit:
            commit_resp = await client.rci({"parse": "components commit"})
            _raise_on_rci_errors(commit_resp)
            committed = True
    return {"queued": True, "name": name.strip(), "action": "remove", "committed": committed}


def register(mcp) -> None:
    mcp.tool()(list_components)
    mcp.tool()(get_component)
    mcp.tool()(get_firmware_info)
    mcp.tool()(install_component)
    mcp.tool()(remove_component)
