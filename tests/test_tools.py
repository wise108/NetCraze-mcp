"""Tests for netcraze-mcp tools."""

import asyncio
import pytest
from netcraze_mcp.client import _sanitize_error
from netcraze_mcp.config import configure
from netcraze_mcp.tools.dns_routes import (
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
from netcraze_mcp.tools.network import (
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
from netcraze_mcp.tools.static_hosts import (
    add_static_host,
    delete_static_host,
    list_static_hosts,
)
from netcraze_mcp.tools.static_routes import (
    add_static_route,
    delete_static_route,
    list_static_routes,
)
from netcraze_mcp.tools.system import get_system_info, reboot


# ─── get_system_info ──────────────────────────────────────────────────────────

async def test_get_system_info_returns_parsed_fields(mock_client):
    mock_client.rci.return_value = {
        "show": {
            "version": {"model": "NetCraze Giga", "release": "4.1.7", "arch": "mips"},
            "system": {"uptime": 123456, "memory": 262144, "memory-free": 98304, "load": 12},
        }
    }
    result = await get_system_info()
    assert result["model"] == "NetCraze Giga"
    assert result["firmware"] == "4.1.7"
    assert result["uptime"] == 123456
    assert result["memory_free"] == 98304


async def test_get_system_info_omits_none_fields(mock_client):
    mock_client.rci.return_value = {
        "show": {"version": {"model": "KN-1010"}, "system": {}}
    }
    result = await get_system_info()
    assert "firmware" not in result
    assert "uptime" not in result
    assert result["model"] == "KN-1010"


# ─── get_interfaces ───────────────────────────────────────────────────────────

async def test_get_interfaces_returns_list(mock_client):
    mock_client.rci_get.return_value = {
        "GigabitEthernet0": {"id": "GigabitEthernet0", "state": "up", "address": "192.168.1.1", "mask": "255.255.255.0"},
        "Wireguard0": {"id": "Wireguard0", "state": "up"},
    }
    result = await get_interfaces()
    assert len(result) == 2
    ids = {r["id"] for r in result}
    assert "GigabitEthernet0" in ids
    assert result[0]["address"] == "192.168.1.1" or result[1].get("address") == "192.168.1.1"


async def test_get_interfaces_wraps_list(mock_client):
    mock_client.rci_get.return_value = [{"id": "GigabitEthernet0", "state": "up"}]
    result = await get_interfaces()
    assert isinstance(result, list)
    assert len(result) == 1


async def test_get_interface_single(mock_client):
    mock_client.rci_get.return_value = {
        "id": "Wireguard0", "state": "up", "rxbytes": 1024, "txbytes": 2048
    }
    result = await get_interface("Wireguard0")
    assert result["id"] == "Wireguard0"
    assert result["rx_bytes"] == 1024
    mock_client.rci_get.assert_called_once_with("show/interface/Wireguard0")


# ─── get_connected_clients ────────────────────────────────────────────────────

async def test_get_connected_clients_returns_hosts(mock_client):
    mock_client.rci_get.return_value = [
        {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.10", "hostname": "laptop",
         "active": True, "rxbytes": 1_000_000, "txbytes": 500_000},
        {"mac": "11:22:33:44:55:66", "ip": "192.168.1.11", "active": False},
    ]
    result = await get_connected_clients()
    assert len(result) == 2
    assert result[0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert result[0]["rx_bytes"] == 1_000_000


async def test_get_connected_clients_empty(mock_client):
    mock_client.rci_get.return_value = []
    result = await get_connected_clients()
    assert result == []


# ─── get_speed ────────────────────────────────────────────────────────────────

async def test_get_speed_calculates_mbps(mock_client, monkeypatch):
    async def fake_sleep(_): pass
    monkeypatch.setattr("netcraze_mcp.tools.network.asyncio.sleep", fake_sleep)

    snap1 = [{"mac": "aa:bb:cc:00:00:01", "active": True, "rxbytes": 0,         "txbytes": 0},
             {"mac": "aa:bb:cc:00:00:02", "active": True, "rxbytes": 0,         "txbytes": 0}]
    snap2 = [{"mac": "aa:bb:cc:00:00:01", "active": True, "rxbytes": 5_000_000, "txbytes": 500_000},
             {"mac": "aa:bb:cc:00:00:02", "active": True, "rxbytes": 5_000_000, "txbytes": 500_000}]
    mock_client.rci_get.side_effect = [snap1, snap2]

    _times = [0.0, 3.0]
    _idx = [0]
    def fake_monotonic():
        v = _times[_idx[0] % len(_times)]
        _idx[0] += 1
        return v
    monkeypatch.setattr("netcraze_mcp.tools.network.time.monotonic", fake_monotonic)

    result = await get_speed(interval=3.0)
    assert result["download_mbps"] > 0
    assert result["upload_mbps"] > 0
    assert "top_clients" in result


async def test_get_speed_clamps_interval(mock_client, monkeypatch):
    async def fake_sleep(_): pass
    monkeypatch.setattr("netcraze_mcp.tools.network.asyncio.sleep", fake_sleep)

    snap = [{"mac": "aa:bb:cc:00:00:01", "active": True, "rxbytes": 0, "txbytes": 0}]
    mock_client.rci_get.side_effect = [snap, snap]

    _times = [0.0, 1.0]
    _idx = [0]
    def fake_monotonic():
        v = _times[_idx[0] % len(_times)]
        _idx[0] += 1
        return v
    monkeypatch.setattr("netcraze_mcp.tools.network.time.monotonic", fake_monotonic)

    result = await get_speed(interval=999)  # clamped to 10
    assert result["interval_sec"] == 1.0


# ─── get_wan_speed ────────────────────────────────────────────────────────────

# Shared ifaces dict for get_wan_speed tests
_IFACES = {
    "UsbQmi0":          {"id": "UsbQmi0",          "type": "UsbQmi",          "link": "up", "description": "Beeline-big"},
    "GigabitEthernet1": {"id": "GigabitEthernet1", "type": "GigabitEthernet", "link": "up", "address": "192.168.8.133"},
    "Wireguard1":       {"id": "Wireguard1",        "type": "Wireguard",       "link": "up", "description": "awg"},
    "Bridge0":          {"id": "Bridge0",           "type": "Bridge",          "link": "up"},
}
_STATS = [
    {"rxspeed": 1_000_000, "txspeed": 500_000},   # UsbQmi0
    {"rxspeed":     1_000, "txspeed":     500},   # GigabitEthernet1
    {"rxspeed":    50_000, "txspeed":  25_000},   # Wireguard1
    # Bridge0 is excluded by _is_wan_interface, so no stat for it
]
_RCI_STAT_RESPONSE = {"show": {"interface": {"stat": _STATS}}}


async def test_get_wan_speed_returns_wan_interfaces_only(mock_client):
    mock_client.rci_get.return_value = _IFACES
    mock_client.rci.return_value = _RCI_STAT_RESPONSE

    result = await get_wan_speed()
    ids = {r["interface"] for r in result}
    assert "UsbQmi0" in ids
    assert "GigabitEthernet1" in ids
    assert "Wireguard1" in ids
    assert "Bridge0" not in ids  # LAN bridge must be excluded


async def test_get_wan_speed_calculates_mbps(mock_client):
    mock_client.rci_get.return_value = _IFACES
    mock_client.rci.return_value = _RCI_STAT_RESPONSE

    result = await get_wan_speed()
    usb = next(r for r in result if r["interface"] == "UsbQmi0")
    # rxspeed=1_000_000 bytes/s → 8.0 Mbit/s
    assert usb["dl_mbps"] == 8.0
    assert usb["ul_mbps"] == 4.0


async def test_get_wan_speed_sorted_by_total(mock_client):
    mock_client.rci_get.return_value = _IFACES
    mock_client.rci.return_value = _RCI_STAT_RESPONSE

    result = await get_wan_speed()
    totals = [r["dl_mbps"] + r["ul_mbps"] for r in result]
    assert totals == sorted(totals, reverse=True)


async def test_get_wan_speed_gigabit_without_ip_excluded(mock_client):
    mock_client.rci_get.return_value = {
        "GigabitEthernet0": {"id": "GigabitEthernet0", "type": "GigabitEthernet", "link": "up"},
        # no address → LAN port, excluded
    }
    mock_client.rci.return_value = {"show": {"interface": {"stat": []}}}

    result = await get_wan_speed()
    assert result == []


async def test_get_wan_speed_interface_down_excluded(mock_client):
    mock_client.rci_get.return_value = {
        "PPTP0": {"id": "PPTP0", "type": "PPTP", "link": "down"},
    }
    mock_client.rci.return_value = {"show": {"interface": {"stat": []}}}

    result = await get_wan_speed()
    assert result == []


async def test_get_wan_speed_no_wan_interfaces(mock_client):
    mock_client.rci_get.return_value = {}
    result = await get_wan_speed()
    assert result == []


async def test_get_wan_speed_description_included(mock_client):
    mock_client.rci_get.return_value = _IFACES
    mock_client.rci.return_value = _RCI_STAT_RESPONSE

    result = await get_wan_speed()
    usb = next(r for r in result if r["interface"] == "UsbQmi0")
    assert usb.get("description") == "Beeline-big"
    ge = next(r for r in result if r["interface"] == "GigabitEthernet1")
    assert "description" not in ge  # no description field in iface dict


# ─── get_wifi_associations ────────────────────────────────────────────────────

async def test_get_wifi_associations(mock_client):
    mock_client.rci_get.return_value = [
        {"mac": "de:ad:be:ef:00:01", "ssid": "HomeNet", "rssi": -65, "snr": 30},
    ]
    result = await get_wifi_associations()
    assert result[0]["mac"] == "de:ad:be:ef:00:01"
    assert result[0]["rssi"] == -65


async def test_get_wifi_associations_dict_with_station_key(mock_client):
    mock_client.rci_get.return_value = {
        "station": [{"mac": "aa:00:00:00:00:01", "rssi": -70}]
    }
    result = await get_wifi_associations()
    assert len(result) == 1
    assert result[0]["rssi"] == -70


# ─── get_routes ───────────────────────────────────────────────────────────────

async def test_get_routes(mock_client):
    mock_client.rci_get.return_value = [
        {"destination": "0.0.0.0/0", "gateway": "10.0.0.1", "interface": "PPPoE0", "metric": 1, "proto": "boot"},
        {"destination": "192.168.1.0/24", "interface": "GigabitEthernet0/0", "proto": "kernel"},
    ]
    result = await get_routes()
    assert len(result) == 2
    assert result[0]["destination"] == "0.0.0.0/0"
    assert result[0]["gateway"] == "10.0.0.1"


# ─── get_wan_status ───────────────────────────────────────────────────────────

async def test_get_wan_status_returns_dict(mock_client):
    mock_client.rci_get.return_value = {"internet": True, "provider": "PPPoE0"}
    result = await get_wan_status()
    assert result["internet"] is True


# ─── domain lists ────────────────────────────────────────────────────────────

FQDN_GROUPS = {
    "show": {"sc": {"object-group": {"fqdn": {
        "domain-list0": {"description": "XEGARE", "include": [{"address": "xegare.com"}]},
        "domain-list1": {"description": "steam",  "include": [{"address": "steampowered.com"}, {"address": "steamcommunity.com"}]},
    }}}}
}

async def test_get_domain_lists(mock_client):
    mock_client.rci.return_value = FQDN_GROUPS
    result = await get_domain_lists()
    assert len(result) == 2
    names = {r["name"] for r in result}
    assert "steam" in names
    assert "XEGARE" in names
    steam = next(r for r in result if r["name"] == "steam")
    assert steam["count"] == 2
    assert steam["key"] == "domain-list1"


async def test_get_domain_list(mock_client):
    mock_client.rci.return_value = FQDN_GROUPS
    result = await get_domain_list("steam")
    assert result["name"] == "steam"
    assert "steampowered.com" in result["entries"]


async def test_get_domain_list_by_key(mock_client):
    mock_client.rci.return_value = FQDN_GROUPS
    result = await get_domain_list("domain-list1")
    assert result["name"] == "steam"


async def test_get_domain_list_not_found(mock_client):
    mock_client.rci.return_value = FQDN_GROUPS
    with pytest.raises(ValueError, match="not found"):
        await get_domain_list("nonexistent")


async def test_set_domain_list(mock_client):
    mock_client.rci.side_effect = [FQDN_GROUPS, {}]
    result = await set_domain_list("steam", ["steampowered.com", "newdomain.com"])
    assert result["count"] == 2
    assert result["key"] == "domain-list1"


async def test_set_domain_list_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError):
        await set_domain_list("steam", ["example.com"])


async def test_add_domains(mock_client):
    mock_client.rci.side_effect = [FQDN_GROUPS, {}]
    result = await add_domains("steam", ["newdomain.com"])
    assert result["added"] == 1
    assert result["total"] == 3


async def test_add_domains_deduplicates(mock_client):
    mock_client.rci.side_effect = [FQDN_GROUPS, {}]
    result = await add_domains("steam", ["steampowered.com"])  # already exists
    assert result["added"] == 0
    assert result["total"] == 2


async def test_remove_domains(mock_client):
    mock_client.rci.side_effect = [FQDN_GROUPS, {}]
    result = await remove_domains("steam", ["steampowered.com"])
    assert result["removed"] == 1
    assert result["total"] == 1


async def test_remove_domains_nonexistent_is_noop(mock_client):
    mock_client.rci.side_effect = [FQDN_GROUPS, {}]
    result = await remove_domains("steam", ["notinlist.com"])
    assert result["removed"] == 0


async def test_create_domain_list(mock_client):
    mock_client.rci.side_effect = [FQDN_GROUPS, {}, {}]
    result = await create_domain_list("mylist", ["example.com"])
    assert result["created"] == "mylist"
    assert result["key"] == "domain-list2"  # next unused after list0, list1
    assert result["count"] == 1


async def test_delete_domain_list(mock_client):
    mock_client.rci.side_effect = [FQDN_GROUPS, {}, {}]
    result = await delete_domain_list("steam")
    assert result["deleted"] == "steam"
    assert result["key"] == "domain-list1"


async def test_delete_domain_list_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError):
        await delete_domain_list("steam")


# ─── static hosts ─────────────────────────────────────────────────────────────

async def test_list_static_hosts_filters_private_and_unique(mock_client):
    mock_client.rci_get.return_value = {
        "static_a": [
            {"name": "router.home", "address": "192.168.0.1"},
            {"name": "router.home", "address": "192.168.0.1"},
            {"name": "loopback.local", "address": "127.0.0.1"},
            {"name": "public.host", "address": "8.8.8.8"},
        ]
    }
    result = await list_static_hosts()
    assert result == [{"host": "router.home", "ip": "192.168.0.1"}]


async def test_list_static_hosts_sort_ip_desc(mock_client):
    mock_client.rci_get.return_value = {
        "static_a": [
            {"name": "h1", "address": "192.168.0.2"},
            {"name": "h2", "address": "192.168.0.10"},
        ]
    }
    result = await list_static_hosts(sort_by="ip", order="desc")
    assert result[0]["ip"] == "192.168.0.10"


async def test_add_static_host_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError):
        await add_static_host("router.home", "192.168.0.1")


async def test_add_static_host_sends_batch(mock_client):
    result = await add_static_host("router.home", "192.168.0.1")
    assert result["added"] is True
    mock_client.rci.assert_called_once_with([
        {"ip": {"host": {"domain": "router.home", "address": "192.168.0.1"}}},
        {"system": {"configuration": {"save": {}}}},
    ])


async def test_add_static_host_raises_on_rci_error(mock_client):
    mock_client.rci.return_value = [{
        "ip": {"host": {"status": [{"status": "error", "message": "no input [http/rci]."}]}}
    }]
    with pytest.raises(RuntimeError, match="no input"):
        await add_static_host("router.home", "192.168.0.1")


async def test_delete_static_host_by_name(mock_client):
    mock_client.rci_get.return_value = {"static_a": [{"name": "router.home", "address": "192.168.0.1"}]}
    result = await delete_static_host("router.home")
    assert result["deleted"] is True
    mock_client.rci.assert_called_once_with([
        {"ip": {"host": {"domain": "router.home", "address": "192.168.0.1", "no": True}}},
        {"system": {"configuration": {"save": {}}}},
    ])


# ─── static routes ────────────────────────────────────────────────────────────

async def test_list_static_routes(mock_client):
    mock_client.rci_get.return_value = [
        {
            "network": "192.168.10.0",
            "mask": "255.255.255.0",
            "gateway": "10.211.114.1",
            "interface": "ZeroTier0",
            "index": "abc",
            "comment": "",
        }
    ]
    result = await list_static_routes()
    assert result == [{
        "destination": "192.168.10.0/24",
        "network": "192.168.10.0",
        "mask": "255.255.255.0",
        "gateway": "10.211.114.1",
        "interface": "ZeroTier0",
        "index": "abc",
    }]


async def test_add_static_route_sends_batch(mock_client):
    result = await add_static_route(
        "192.168.10.0/24",
        "10.211.114.1",
        "ZeroTier0",
        metric=1000,
    )
    assert result["added"] is True
    assert result["destination"] == "192.168.10.0/24"
    mock_client.rci.assert_called_once_with([
        {"ip": {"route": {
            "network": "192.168.10.0",
            "mask": "255.255.255.0",
            "gateway": "10.211.114.1",
            "interface": "ZeroTier0",
            "metric": 1000,
        }}},
        {"system": {"configuration": {"save": {}}}},
    ])


async def test_add_static_route_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError):
        await add_static_route("192.168.10.0/24", "10.211.114.1", "ZeroTier0")


async def test_add_static_route_raises_on_rci_error(mock_client):
    mock_client.rci.return_value = [{
        "ip": {"route": {"status": [{"status": "error", "message": "no input [http/rci]."}]}}
    }]
    with pytest.raises(RuntimeError, match="no input"):
        await add_static_route("192.168.10.0/24", "10.211.114.1", "ZeroTier0")


async def test_delete_static_route_by_destination(mock_client):
    mock_client.rci_get.return_value = [{
        "network": "192.168.10.0",
        "mask": "255.255.255.0",
        "gateway": "10.211.114.1",
        "interface": "ZeroTier0",
        "index": "abc",
    }]
    result = await delete_static_route(destination="192.168.10.0/24")
    assert result["deleted"] is True
    mock_client.rci.assert_called_once_with([
        {"ip": {"route": {
            "network": "192.168.10.0",
            "mask": "255.255.255.0",
            "no": True,
        }}},
        {"system": {"configuration": {"save": {}}}},
    ])


# ─── DNS routes ───────────────────────────────────────────────────────────────

DNS_ROUTES_DATA = {
    "show": {"sc": {
        "dns-proxy": {"route": [
            {"index": "abc123", "group": "domain-list1", "interface": "Wireguard0", "auto": True},
            {"index": "def456", "group": "domain-list0", "interface": "GigabitEthernet1", "auto": False, "disable": True},
        ]},
        "object-group": {"fqdn": {
            "domain-list0": {"description": "XEGARE"},
            "domain-list1": {"description": "steam"},
        }},
    }}
}


async def test_get_dns_routes(mock_client):
    mock_client.rci.return_value = DNS_ROUTES_DATA
    result = await get_dns_routes()
    assert len(result) == 2
    assert result[0]["list_name"] == "steam"
    assert result[0]["interface"] == "Wireguard0"
    assert result[0]["enabled"] is True
    assert result[1]["enabled"] is False


async def test_add_dns_route(mock_client):
    mock_client.rci.side_effect = [
        FQDN_GROUPS,  # _resolve_list_key
        {},           # rci batch (add + save)
        {"show": {"sc": {"dns-proxy": {"route": [
            {"index": "new999", "group": "domain-list1", "interface": "Wireguard0"}
        ]}}}},  # read back
    ]
    result = await add_dns_route("steam", "Wireguard0")
    assert result["created"] is True
    assert result["index"] == "new999"


async def test_add_dns_route_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError):
        await add_dns_route("steam", "Wireguard0")


async def test_delete_dns_route(mock_client):
    mock_client.rci.return_value = {}
    result = await delete_dns_route("abc123")
    assert result["deleted"] is True
    assert result["index"] == "abc123"


async def test_delete_dns_route_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError):
        await delete_dns_route("abc123")


# ─── set_interface_state ──────────────────────────────────────────────────────

async def test_set_interface_up(mock_client):
    mock_client.rci.return_value = {}
    result = await set_interface_state("GigabitEthernet0/1", up=True)
    assert result["state"] == "up"
    mock_client.rci.assert_called_once_with(
        {"interface": {"GigabitEthernet0/1": {"up": True}}}
    )


async def test_set_interface_down(mock_client):
    result = await set_interface_state("GigabitEthernet0/1", up=False)
    assert result["state"] == "down"
    mock_client.rci.assert_called_once_with(
        {"interface": {"GigabitEthernet0/1": {"down": True}}}
    )


async def test_set_interface_blocked_in_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError, match="safe mode"):
        await set_interface_state("GigabitEthernet0/1", up=False)


# ─── reboot ───────────────────────────────────────────────────────────────────

async def test_reboot_sends_command(mock_client):
    result = await reboot()
    assert "reboot" in result["status"]
    mock_client.rci.assert_called_once_with({"system": {"reboot": {}}})


async def test_reboot_blocked_in_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError, match="safe mode"):
        await reboot()


# ─── safe mode via env var ────────────────────────────────────────────────────

async def test_safe_mode_via_env_var(mock_client, monkeypatch):
    monkeypatch.setenv("NETCRAZE_SAFE_MODE", "true")
    with pytest.raises(PermissionError):
        await reboot()


async def test_safe_mode_env_var_false_allows_write(mock_client, monkeypatch):
    monkeypatch.setenv("NETCRAZE_SAFE_MODE", "false")
    result = await reboot()
    assert result is not None


# ─── credentials validation ───────────────────────────────────────────────────

async def test_missing_host_raises(monkeypatch):
    monkeypatch.delenv("NETCRAZE_HOST", raising=False)
    monkeypatch.setenv("NETCRAZE_PASS", "pass")
    with pytest.raises(RuntimeError, match="NETCRAZE_HOST"):
        await get_system_info()


async def test_missing_pass_raises(monkeypatch):
    monkeypatch.setenv("NETCRAZE_HOST", "192.168.1.1")
    monkeypatch.delenv("NETCRAZE_PASS", raising=False)
    with pytest.raises(RuntimeError, match="NETCRAZE_PASS"):
        await get_system_info()


# ─── error sanitization ───────────────────────────────────────────────────────

def test_sanitize_error_redacts_password():
    err = Exception("Auth failed: password=my_secret_pass status=401")
    result = _sanitize_error(err)
    assert "my_secret_pass" not in result
    assert "password=<redacted>" in result


def test_sanitize_error_redacts_token():
    err = Exception("Request failed token=abc123xyz status=403")
    result = _sanitize_error(err)
    assert "abc123xyz" not in result


def test_sanitize_error_preserves_other_info():
    err = Exception("Connection refused to 192.168.1.1:80")
    result = _sanitize_error(err)
    assert "192.168.1.1" in result
    assert "Connection refused" in result


# ─── _sanitize_error in configure priority ───────────────────────────────────

async def test_configure_overrides_env_safe_mode(mock_client, monkeypatch):
    monkeypatch.setenv("NETCRAZE_SAFE_MODE", "true")
    configure(safe_mode=False)  # explicit False wins over env
    result = await reboot()
    assert result is not None


async def test_configure_none_defers_to_env(mock_client, monkeypatch):
    monkeypatch.setenv("NETCRAZE_SAFE_MODE", "1")
    configure(safe_mode=None)
    with pytest.raises(PermissionError):
        await reboot()
