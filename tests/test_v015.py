"""Tests for NetCraze-mcp 0.15.0 sc/rc honesty + policy path tools."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from netcraze_mcp.tools import sc_rc
from netcraze_mcp.tools.dns_routes import (
    add_domains,
    domain_list_covers_ip,
    get_domain_list,
)
from netcraze_mcp.tools.firewall import get_conntrack
from netcraze_mcp.tools.flow import explain_policy_path, verify_flow_path
from netcraze_mcp.tools.wireguard import add_wireguard_allowed_ips, get_wireguard


def test_cidr_covers_and_entry_type():
    assert sc_rc.entry_type("95.161.64.0/20") == "CIDR"
    assert sc_rc.entry_type("1.2.3.4") == "IP"
    assert sc_rc.entry_type("ya.ru") == "FQDN"
    assert sc_rc.cidr_covers("95.161.64.0/20", "95.161.64.100")
    assert not sc_rc.cidr_covers("95.161.64.0/20", "149.154.167.1")
    assert sc_rc.path_class_from_dst_out("10.255.12.2") == "WG0"
    assert sc_rc.path_class_from_dst_out("8.8.8.8") == "WAN"


@pytest.mark.asyncio
async def test_get_domain_list_defaults_to_rc_and_dirty(mock_client):
    async def _get(path):
        if "show/rc/object-group/fqdn" in path:
            return {
                "DomainList6": {
                    "description": "list6",
                    "include": [
                        {"address": "telegram.org"},
                        {"address": "95.161.64.0/20"},
                    ],
                }
            }
        if "show/sc/object-group/fqdn" in path:
            return {
                "DomainList6": {
                    "description": "list6",
                    "include": [{"address": "telegram.org"}],
                }
            }
        return {}

    mock_client.rci_get.side_effect = _get
    result = await get_domain_list("list6")
    assert result["source"] == "rc"
    assert result["dirty"] is True
    assert "95.161.64.0/20" in result["entries"]
    saved = await get_domain_list("list6", saved=True)
    assert saved["source"] == "sc"
    assert "95.161.64.0/20" not in saved["entries"]


@pytest.mark.asyncio
async def test_add_domains_honest_rc_counts(mock_client):
    rc_state = {
        "DomainList6": {
            "description": "list6",
            "include": [{"address": "telegram.org"}],
        }
    }
    sc_state = {
        "DomainList6": {
            "description": "list6",
            "include": [{"address": "telegram.org"}],
        }
    }

    async def _get(path):
        if "show/rc/object-group/fqdn" in path:
            return rc_state
        if "show/sc/object-group/fqdn" in path:
            return sc_state
        return {}

    async def _rci(payload):
        # simulate write into rc only
        if isinstance(payload, list):
            for item in payload:
                if "object-group" in item:
                    fq = item["object-group"]["fqdn"]["DomainList6"]
                    if "include" in fq and isinstance(fq["include"], list):
                        rc_state["DomainList6"]["include"] = fq["include"]
        return {}

    mock_client.rci_get.side_effect = _get
    mock_client.rci.side_effect = _rci
    out = await add_domains("list6", ["95.161.64.0/20"], save=False)
    assert out["added"] == 1
    assert out["applied_to"] == "rc"
    assert out["persisted"] is False
    assert out["dirty"] is True
    assert out["total"] == 2


@pytest.mark.asyncio
async def test_domain_list_covers_ip(mock_client):
    async def _get(path):
        if "object-group/fqdn" in path:
            return {
                "DomainList6": {
                    "description": "list6",
                    "include": [{"address": "95.161.64.0/20"}],
                }
            }
        if "dns-proxy/route" in path:
            return [{"group": "DomainList6", "interface": "Wireguard0", "gateway": "10.255.12.2"}]
        return {}

    mock_client.rci_get.side_effect = _get
    hit = await domain_list_covers_ip("list6", "95.161.64.100")
    assert hit["covered"] is True
    assert hit["type"] == "CIDR"
    assert hit["linked_dns_route_interface"] == "Wireguard0"


@pytest.mark.asyncio
async def test_explain_policy_path_wg_not_wan(mock_client):
    async def _get(path):
        if "object-group/fqdn" in path:
            return {
                "DomainList6": {
                    "description": "list6",
                    "include": [{"address": "95.161.64.0/20"}],
                }
            }
        if "dns-proxy/route" in path:
            # gateway ≠ iface addr (ON_LINK_DEFAULT: live SNAT uses iface)
            return [{"group": "DomainList6", "interface": "Wireguard0", "gateway": "10.255.30.1", "auto": True, "index": "1"}]
        if path == "show/ip/route":
            return [{"destination": "0.0.0.0/0", "gateway": "192.168.0.1", "interface": "GigabitEthernet1", "metric": 0}]
        if path == "show/interface":
            return {"Wireguard0": {"id": "Wireguard0", "address": "10.255.12.2", "type": "Wireguard"}}
        if path == "show/ip/nat":
            return [{
                "protocol": "TCP", "src": "192.168.10.53", "dst": "95.161.64.100",
                "sport": 40000, "dport": 443, "dst-out": "10.255.12.2",
                "packets": 10, "packets-out": 8,
            }]
        if path == "show/ip/policy":
            return {}
        if path == "show/ip/rule":
            return "102: from all fwmark 0xffffaaa0 lookup 4097\n"
        return {}

    mock_client.rci_get.side_effect = _get
    with patch("netcraze_mcp.tools.flow.get_policy_tables", new=AsyncMock(return_value={
        "tables": [
            {
                "table4": 4097,
                "fwmark": "0xffffaaa0",
                "ON_LINK_DEFAULT": True,
                "materialized_default": [{"interface": "Wireguard0", "gateway": "0.0.0.0"}],
                "linked_dns_proxy_routes": [{"list_key": "other", "interface": "Wireguard0"}],
            },
            {
                "table4": 4098,
                "fwmark": "0xffffaaa1",
                "ON_LINK_DEFAULT": True,
                "materialized_default": [{"interface": "Wireguard0", "gateway": "0.0.0.0"}],
                "linked_dns_proxy_routes": [{"list_key": "DomainList6", "interface": "Wireguard0"}],
            },
        ]
    })):
        result = await explain_policy_path("95.161.64.100")
    assert result["ok"] is True
    assert result["verdict"] in ("HAPP/WG", "WG")
    assert result["expected_interface"] == "Wireguard0"
    assert result["expected_dst_out"] == "10.255.12.2"  # iface addr, not gateway
    assert result["gateway_configured"] == "10.255.30.1"
    assert result["expected_path_class"] == "WG0"
    assert len(result["policy"]) == 1
    assert result["policy"][0]["table4"] == 4098
    assert result["fib_lpm"]["interface"] == "GigabitEthernet1"  # FIB still WAN — expected


@pytest.mark.asyncio
async def test_batch_wan_expect_is_pass(mock_client):
    from netcraze_mcp.tools.flow import verify_flow_path_batch

    async def _get(path):
        if "object-group/fqdn" in path:
            return {"DomainList6": {"description": "list6", "include": [{"address": "claude.ai"}]}}
        if "dns-proxy/route" in path:
            return [{"group": "DomainList6", "interface": "Wireguard0"}]
        if path == "show/ip/route":
            return [{"destination": "0.0.0.0/0", "gateway": "1.1.1.1", "interface": "GigabitEthernet1"}]
        if path == "show/interface":
            return {}
        if path == "show/ip/nat":
            return []
        return {}

    mock_client.rci_get.side_effect = _get
    with patch("netcraze_mcp.tools.flow.get_policy_tables", new=AsyncMock(return_value={"tables": []})):
        with patch("netcraze_mcp.tools.flow.verify_flow_path", new=AsyncMock(side_effect=[
            {
                "verdict": "FAIL", "ok": False, "failure_point": "A",
                "domain_list_hit": False, "expected_interface": None, "dst": "77.88.8.8",
            },
            {
                "verdict": "PASS", "ok": True, "failure_point": "G",
                "domain_list_hit": True, "expected_interface": "Wireguard0", "dst": "1.2.3.4",
            },
        ])):
            out = await verify_flow_path_batch([
                {"name": "ya.ru", "src": "192.168.10.53", "dst": "ya.ru", "expect": "WAN"},
                {"name": "Claude", "src": "192.168.10.53", "dst": "claude.ai", "expect": "WG0"},
            ])
    assert out["ok"] is True
    assert out["results"][0]["name"] == "ya.ru"
    assert out["results"][0]["verdict"] == "PASS"
    assert out["results"][0]["path"] == "WAN"
    assert out["results"][0]["expect_ok"] is True
    assert out["results"][1]["name"] == "Claude"
    assert out["results"][1]["expect_ok"] is True


@pytest.mark.asyncio
async def test_add_wireguard_allowed_ips_merge(mock_client):
    rc = {
        "wireguard": {
            "peer": [{
                "key": "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd=",
                "allow-ips": [
                    {"address": "149.154.160.0", "mask": "255.255.240.0"},
                ],
                "endpoint": {"address": "1.2.3.4:51820"},
                "keepalive-interval": {"interval": 25},
            }]
        }
    }
    sc = {
        "wireguard": {
            "peer": [{
                "key": "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd=",
                "allow-ips": [
                    {"address": "149.154.160.0", "mask": "255.255.240.0"},
                ],
            }]
        }
    }

    async def _get(path):
        if path.startswith("show/rc/"):
            return rc
        if path.startswith("show/sc/"):
            return sc
        return {}

    async def _rci(payload):
        if isinstance(payload, list):
            for item in payload:
                iface = (item.get("interface") or {}).get("Wireguard0") or {}
                peers = ((iface.get("wireguard") or {}).get("peer") or [])
                if peers and isinstance(peers[0], dict) and peers[0].get("allow-ips"):
                    rc["wireguard"]["peer"] = peers
        return {}

    mock_client.rci_get.side_effect = _get
    mock_client.rci.side_effect = _rci
    out = await add_wireguard_allowed_ips(
        "Wireguard0",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd=",
        ["95.161.64.0/20"],
        confirm=True,
        save=False,
    )
    assert out["added"] == ["95.161.64.0/20"]
    assert out["count"] == 2
    assert out["sc_dirty"] is True
    assert out["applied_to"] == "rc"


@pytest.mark.asyncio
async def test_get_wireguard_includes_allowed_ips(mock_client):
    live = {
        "id": "Wireguard0",
        "type": "Wireguard",
        "state": "up",
        "address": "10.255.12.1",
        "wireguard": {
            "public-key": "pub=",
            "peer": [{
                "public-key": "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd=",
                "online": True,
                "rxbytes": 1,
                "txbytes": 2,
            }],
        },
    }
    rc = {
        "wireguard": {
            "peer": [{
                "key": "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd=",
                "allow-ips": [{"address": "95.161.64.0", "mask": "255.255.240.0"}],
            }]
        }
    }

    async def _get(path):
        if path == "show/interface/Wireguard0":
            return live
        if "show/rc/interface" in path:
            return rc
        if "show/sc/interface" in path:
            return rc
        return {}

    mock_client.rci_get.side_effect = _get
    data = await get_wireguard("Wireguard0")
    assert data["source"] == "rc"
    assert data["peers"][0]["allowed_ips"] == ["95.161.64.0/20"]


@pytest.mark.asyncio
async def test_get_conntrack_src_dst_path_class(mock_client):
    mock_client.rci_get.return_value = [
        {
            "protocol": "TCP", "src": "192.168.10.53", "dst": "95.161.64.100",
            "sport": 1, "dport": 443, "dst-out": "10.255.12.2",
            "packets": 5, "packets-out": 0,
        },
        {
            "protocol": "TCP", "src": "192.168.10.53", "dst": "8.8.8.8",
            "sport": 2, "dport": 443, "dst-out": "1.1.1.1",
            "packets": 3, "packets-out": 3,
        },
    ]
    out = await get_conntrack(src="192.168.10.53", dst="95.161.64.100", port=443, protocol="tcp")
    assert out["count"] == 1
    assert out["sessions"][0]["path_class"] == "WG0"
    assert out["sessions"][0]["unreplied"] is True
    grouped = await get_conntrack(host="192.168.10.53", group_by="dst", only_unreplied=True)
    assert "95.161.64.100" in grouped["grouped"]


@pytest.mark.asyncio
async def test_verify_flow_path_card(mock_client):
    async def _get(path):
        if "object-group/fqdn" in path:
            return {
                "DomainList6": {
                    "description": "list6",
                    "include": [{"address": "95.161.64.0/20"}],
                }
            }
        if "dns-proxy/route" in path:
            return [{"group": "DomainList6", "interface": "Wireguard0", "gateway": "10.255.12.2"}]
        if path == "show/ip/route":
            return [{"destination": "0.0.0.0/0", "gateway": "192.168.0.1", "interface": "GigabitEthernet1"}]
        wg_live = {
            "id": "Wireguard0",
            "type": "Wireguard",
            "address": "10.255.12.1",
            "wireguard": {"peer": [{
                "public-key": "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd=",
                "online": True, "last-handshake": 10, "rxbytes": 1, "txbytes": 1,
            }]},
        }
        if path == "show/interface":
            return {"Wireguard0": wg_live}
        if path == "show/ip/nat":
            return [{
                "protocol": "TCP", "src": "192.168.10.53", "dst": "95.161.64.100",
                "sport": 40000, "dport": 443, "dst-out": "10.255.12.2",
                "packets": 10, "packets-out": 8,
            }]
        if path == "show/interface/Wireguard0":
            return wg_live
        if "interface/Wireguard0" in path:
            return {
                "wireguard": {"peer": [{
                    "key": "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd=",
                    "allow-ips": [
                        {"address": "95.161.64.0", "mask": "255.255.240.0"},
                    ],
                    "keepalive-interval": {"interval": 25},
                }]}
            }
        return {}

    mock_client.rci_get.side_effect = _get
    with patch("netcraze_mcp.tools.flow.get_policy_tables", new=AsyncMock(return_value={
        "tables": [{
            "table4": 4097,
            "materialized_default": [{"interface": "Wireguard0"}],
            "ON_LINK_DEFAULT": True,
        }]
    })):
        card = await verify_flow_path("192.168.10.53", "95.161.64.100", port=443, proto="tcp")
    assert card["verdict"] == "PASS"
    assert card["failure_point"] == "G"
    assert card["domain_list_hit"] is True
    assert card["allowed_ips_covers"] is True
