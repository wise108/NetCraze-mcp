"""System tools."""

from ..client import _get_client
from ..config import assert_writable


async def get_system_info() -> dict:
    """Get router model, firmware version, uptime and system summary."""
    async with _get_client() as client:
        data = await client.rci({"show": {"version": {}, "system": {}}})
        version = data.get("show", {}).get("version", {})
        system = data.get("show", {}).get("system", {})
        return {
            key: value
            for key, value in {
                "model": version.get("model"),
                "firmware": version.get("release"),
                "arch": version.get("arch"),
                "uptime": system.get("uptime"),
                "memory_total": system.get("memory"),
                "memory_free": system.get("memory-free"),
                "cpu_load": system.get("load"),
            }.items()
            if value is not None
        }


async def reboot() -> dict:
    """Reboot the router. The router will be unreachable for ~30–60 seconds."""
    assert_writable()
    async with _get_client() as client:
        await client.rci({"system": {"reboot": {}}})
        return {"status": "reboot initiated"}


def register(mcp) -> None:
    mcp.tool()(get_system_info)
    mcp.tool()(reboot)
