"""Tool registration."""

from . import backup, components, dns_routes, network, static_hosts, static_routes, storage, system, wireguard


def register_tools(mcp) -> None:
    system.register(mcp)
    backup.register(mcp)
    components.register(mcp)
    network.register(mcp)
    dns_routes.register(mcp)
    static_hosts.register(mcp)
    static_routes.register(mcp)
    storage.register(mcp)
    wireguard.register(mcp)
