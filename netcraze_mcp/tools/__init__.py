"""Tool registration."""

from ..router_ctx import with_router_param
from . import (
    backup,
    capture,
    cli,
    components,
    cross,
    datapath,
    diagnostics,
    dns_routes,
    firewall,
    flow,
    fqdn_sync,
    health,
    ipsec,
    network,
    policy,
    rci_access,
    static_hosts,
    static_routes,
    storage,
    system,
    txn,
    vpn,
    wan,
    wireguard,
    zerotier,
)


def _wrap_register(module) -> None:
    """Patch module.register so every mcp.tool() gets optional router=."""
    original = module.register

    def register(mcp) -> None:
        real_tool = mcp.tool

        def tool_factory(*args, **kwargs):
            if args and callable(args[0]) and not kwargs:
                return real_tool()(with_router_param(args[0]))
            inner = real_tool(*args, **kwargs)

            def decorator(fn):
                return inner(with_router_param(fn))

            return decorator

        mcp.tool = tool_factory  # type: ignore[method-assign]
        try:
            original(mcp)
        finally:
            mcp.tool = real_tool  # type: ignore[method-assign]

    module.register = register  # type: ignore[method-assign]


for _mod in (
    system, health, backup, components, network, wan, dns_routes,
    static_hosts, static_routes, storage, wireguard, ipsec, capture,
    datapath, zerotier, vpn, policy, firewall, flow, diagnostics, rci_access,
    txn, cli, fqdn_sync, cross,
):
    _wrap_register(_mod)


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
    capture.register(mcp)
    datapath.register(mcp)
    zerotier.register(mcp)
    vpn.register(mcp)
    policy.register(mcp)
    firewall.register(mcp)
    flow.register(mcp)
    diagnostics.register(mcp)
    rci_access.register(mcp)
    txn.register(mcp)
    cli.register(mcp)
    fqdn_sync.register(mcp)
    cross.register(mcp)

