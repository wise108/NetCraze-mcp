"""Firmware and NDMS component tools."""

from ..client import _get_client, _raise_on_rci_errors
from ..config import assert_writable


def _component_description(meta: dict) -> str:
    desc = meta.get("description")
    if isinstance(desc, dict):
        return str(desc.get("RU") or desc.get("EN") or "")
    return str(desc or "")


async def list_components(installed_only: bool = False, group: str = "") -> list[dict]:
    """List NDMS components (installed and available), optionally filtered by group."""
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
        if group and component_group.lower() != group.lower():
            continue
        entry = {
            key: value
            for key, value in {
                "name": name,
                "installed": is_installed,
                "group": component_group or None,
                "description": _component_description(meta) or None,
                "version": meta.get("version"),
                "size": int(meta["size"]) if str(meta.get("size") or "").isdigit() else meta.get("size"),
                "queued": meta.get("queued"),
            }.items()
            if value is not None
        }
        result.append(entry)
    result.sort(key=lambda item: (not item.get("installed", False), item.get("name", "")))
    return result


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
    mcp.tool()(get_firmware_info)
    mcp.tool()(install_component)
    mcp.tool()(remove_component)
