"""Tool registration."""

from . import dns_routes, network, static_hosts, system


def register_tools(mcp) -> None:
    system.register(mcp)
    network.register(mcp)
    dns_routes.register(mcp)
    static_hosts.register(mcp)
