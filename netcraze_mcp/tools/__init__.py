"""Tool registration."""

from . import (
    backup,
    components,
    diagnostics,
    dns_routes,
    firewall,
    health,
    ipsec,
    network,
    policy,
    rci_access,
    static_hosts,
    static_routes,
    storage,
    system,
    vpn,
    wan,
    wireguard,
    zerotier,
)


def register_tools(mcp) -> None:
    system.register(mcp)
    health.register(mcp)
    backup.register(mcp)
    components.register(mcp)
    network.register(mcp)
    wan.register(mcp)
    dns_routes.register(mcp)
    static_hosts.register(mcp)
    static_routes.register(mcp)
    storage.register(mcp)
    wireguard.register(mcp)
    ipsec.register(mcp)
    zerotier.register(mcp)
    vpn.register(mcp)
    policy.register(mcp)
    firewall.register(mcp)
    diagnostics.register(mcp)
    rci_access.register(mcp)
