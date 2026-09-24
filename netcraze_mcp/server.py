"""NetCraze Router MCP Server — entry point and tool re-exports."""

from mcp.server.fastmcp import FastMCP

from .client import _sanitize_error
from .config import configure
from .tools import register_tools
from .tools.backup import download_system_file, export_backup
from .tools.components import (
    get_firmware_info,
    install_component,
    list_components,
    remove_component,
)
from .tools.dns_routes import (
    add_dns_route,
    add_domains,
    create_domain_list,
    delete_dns_route,
    delete_domain_list,
    get_dns_routes,
    get_domain_list,
    get_domain_lists,
    remove_domains,
    set_domain_list,
)
from .tools.network import (
    get_connected_clients,
    get_interface,
    get_interfaces,
    get_routes,
    get_speed,
    get_wan_speed,
    get_wan_status,
    get_wifi_associations,
    set_interface_state,
)
from .tools.static_hosts import add_static_host, delete_static_host, list_static_hosts
from .tools.static_routes import add_static_route, delete_static_route, list_static_routes
from .tools.storage import (
    delete_share,
    list_printers,
    list_shares,
    list_usb_storage,
    set_share,
    unmount_usb,
)
from .tools.system import get_system_info, reboot
from .tools.wireguard import (
    add_wireguard_from_conf,
    delete_wireguard,
    get_wireguard,
    list_wireguard,
    set_wireguard_state,
)
from .tools.ipsec import (
    get_ipsec,
    list_ipsec,
    list_ipsec_connections,
    list_ipsec_proposals,
    show_crypto,
    show_ipsec,
    show_ipsec_sa,
)

mcp = FastMCP("netcraze")
register_tools(mcp)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="NetCraze Router MCP Server")
    parser.add_argument(
        "--safe-mode",
        action="store_true",
        default=False,
        help="Disable all write operations",
    )
    args = parser.parse_args()
    if args.safe_mode:
        configure(safe_mode=True)
    mcp.run()


if __name__ == "__main__":
    main()
