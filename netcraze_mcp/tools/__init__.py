"""Tool registration."""

from . import components, dns_routes, network, static_hosts, static_routes, storage, system


def register_tools(mcp) -> None:
    system.register(mcp)
    components.register(mcp)
    network.register(mcp)
    dns_routes.register(mcp)
    static_hosts.register(mcp)
    static_routes.register(mcp)
    storage.register(mcp)
