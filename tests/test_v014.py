"""Tests for NetCraze-mcp 0.14.0 features."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from netcraze_mcp.client import (
    RCI_FORBIDDEN_BY_SECURITY_LEVEL,
    NetCrazeClient,
    NetCrazeError,
)
from netcraze_mcp.config import configure, get_router, load_routers
from netcraze_mcp.router_ctx import reset_current_router, set_current_router
from netcraze_mcp.tools.datapath import diagnose_dns_proxy_route
from netcraze_mcp.tools.fqdn_sync import apply_fqdn_static_sync, plan_fqdn_static_sync
from netcraze_mcp.tools.static_routes import add_static_route
from netcraze_mcp.tools.txn import apply_cli_batch, snapshot_config
from netcraze_mcp.tools.wireguard import add_wireguard_peer


@pytest.mark.asyncio
async def test_save_false_default_no_save_in_batch(mock_client):
    mock_client.rci.return_value = {}
    await add_static_route("1.2.3.4/32", "10.0.0.1", "ZeroTier0", save=False)
    batch = mock_client.rci.call_args[0][0]
    assert isinstance(batch, list)
    assert not any("configuration" in str(item) and "save" in str(item) for item in batch)


@pytest.mark.asyncio
async def test_snapshot_redacts_secrets(mock_client):
    mock_client.rci_get.return_value = {
        "message": [
            "interface Wireguard0",
            "  wireguard private-key SUPERSECRETKEYMATERIAL============",
            "  password hunter2",
            "!",
        ]
    }
    snap = await snapshot_config(label="t")
    assert snap["ok"] is True
    # stored config must not contain raw secret material
    stored = __import__("netcraze_mcp.tools.txn", fromlist=["_SNAPSHOTS"])._SNAPSHOTS[snap["id"]]["config"]
    assert "hunter2" not in stored
    assert "SUPERSECRETKEYMATERIAL" not in stored or "<REDACTED>" in stored


@pytest.mark.asyncio
async def test_auth_403_without_challenge_is_security_level():
    client = NetCrazeClient(host="10.0.0.1", user="admin", password="x")
    resp = MagicMock()
    resp.status_code = 403
    resp.headers = {}
    resp.text = "Forbidden"

    async def fake_get(path):
        return resp

    client._http = MagicMock()
    client._http.get = fake_get
    with pytest.raises(NetCrazeError) as ei:
        await client._auth()
    assert ei.value.code == RCI_FORBIDDEN_BY_SECURITY_LEVEL
    assert "SECURITY_LEVEL" in str(ei.value)


@pytest.mark.asyncio
async def test_on_link_default_detector(mock_client):
    """ON_LINK_DEFAULT from ip-rule table N + show ip route table (policy JSON often empty)."""
    async def _get(path):
        if path == "show/ip/policy":
            return {}
        if path == "show/ip/rule":
            return (
                "102  : from all to all fwmark 0xffffaaa0/0xffffffff lookup 4097 unicast\n"
                "32766: from all to all lookup main (254) unicast\n"
            )
        return {}

    async def _rci(payload):
        text = str(payload)
        if "show ip route table 4097" in text:
            return {
                "parse": {
                    "route": [
                        {
                            "destination": "0.0.0.0/0",
                            "gateway": "0.0.0.0",
                            "interface": "Wireguard0",
                            "metric": 1000,
                        }
                    ]
                }
            }
        # dns-proxy / fqdn object-group
        return {
            "show": {
                "sc": {
                    "object-group": {
                        "fqdn": {
                            "domain-list0": {
                                "description": "Claude",
                                "include": [{"address": "claude.ai"}],
                            }
                        }
                    },
                    "dns-proxy": {
                        "route": [
                            {
                                "index": "1",
                                "group": "domain-list0",
                                "interface": "Wireguard0",
                                "gateway": "10.255.30.1",
                                "auto": True,
                            }
                        ]
                    },
                }
            }
        }

    mock_client.rci_get.side_effect = _get
    mock_client.rci.side_effect = _rci
    result = await diagnose_dns_proxy_route("Claude")
    assert result["ON_LINK_DEFAULT"] is True
    assert result["verdict"] == "ON_LINK_DEFAULT"
    assert any(
        (t or {}).get("table4") == 4097
        for ev in result.get("evidence") or []
        for t in ((ev or {}).get("policy_tables") or [])
    )


@pytest.mark.asyncio
async def test_fqdn_sync_only_own_tags(mock_client, monkeypatch):
    mock_client.rci.return_value = {
        "show": {
            "sc": {
                "object-group": {
                    "fqdn": {
                        "domain-list0": {
                            "description": "Stable",
                            "include": [{"address": "1.1.1.1"}],
                        }
                    }
                }
            }
        }
    }

    async def fake_nslookup(name):
        return {"addresses": ["1.1.1.1"]}

    monkeypatch.setattr(
        "netcraze_mcp.tools.fqdn_sync.router_nslookup",
        fake_nslookup,
    )
    mock_client.rci_get.return_value = [
        {
            "network": "8.8.8.8",
            "mask": "255.255.255.255",
            "gateway": "10.0.0.1",
            "interface": "ZeroTier0",
            "comment": "manual-keep",
            "index": "9",
        },
        {
            "network": "9.9.9.9",
            "mask": "255.255.255.255",
            "gateway": "10.0.0.1",
            "interface": "ZeroTier0",
            "comment": "fqdnsync:Stable",
            "index": "10",
        },
    ]
    plan = await plan_fqdn_static_sync("Stable", "10.211.114.2", "ZeroTier0")
    assert plan["ok"] is True
    # foreign 8.8.8.8 not in remove
    remove_dests = [r.get("destination") for r in plan["plan"]["remove"]]
    assert not any(d and d.startswith("8.8.8.8") for d in remove_dests)

    dry = await apply_fqdn_static_sync(plan["plan_id"], confirm=False)
    assert dry["verdict"] == "dry_run"
    assert dry["changes"] == []


@pytest.mark.asyncio
async def test_add_wireguard_peer_connect_via_shape_and_required_allow(mock_client):
    from netcraze_mcp.tools.wireguard import add_wireguard_peer, update_wireguard_peer

    mock_client.rci_get.side_effect = [
        {"id": "Wireguard0", "type": "Wireguard"},  # show/interface
        {"wireguard": {"peer": []}},  # show/rc
    ]
    mock_client.rci.return_value = {}
    with pytest.raises(ValueError, match="allowed_ips is required"):
        await add_wireguard_peer(
            "Wireguard0",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            allowed_ips=[],
            confirm=True,
        )

    mock_client.rci_get.side_effect = [
        {"id": "Wireguard0", "type": "Wireguard"},
        {"wireguard": {"peer": []}},
    ]
    result = await add_wireguard_peer(
        "Wireguard0",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        allowed_ips=["10.255.30.1/32"],
        connect_via="ZeroTier0",
        confirm=True,
    )
    assert result["ok"] is True
    batch = mock_client.rci.call_args[0][0]
    peer = batch[0]["interface"]["Wireguard0"]["wireguard"]["peer"][0]
    assert peer["connect"] == {"via": "ZeroTier0"}
    assert "connect-via" not in peer

    # update: remove then add same key
    mock_client.rci_get.side_effect = None
    mock_client.rci_get.return_value = {
        "wireguard": {
            "peer": [{
                "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "endpoint": {"address": "192.168.1.110:42821"},
                "allow-ips": [{"address": "10.255.30.1", "mask": "255.255.255.255"}],
                "connect": {"via": "ZeroTier0"},
                "keepalive-interval": {"interval": 25},
            }]
        }
    }
    mock_client.rci.reset_mock()
    upd = await update_wireguard_peer(
        "Wireguard0",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        allowed_ips=["10.255.30.1/32"],
        connect_via="ZeroTier0",
        keepalive=25,
        confirm=True,
    )
    assert upd["updated"] is True
    calls = mock_client.rci.call_args[0][0]
    assert calls[0]["interface"]["Wireguard0"]["wireguard"]["peer"][0].get("no") is True
    assert calls[1]["interface"]["Wireguard0"]["wireguard"]["peer"][0]["connect"] == {
        "via": "ZeroTier0"
    }


def test_add_wireguard_from_conf_ip_global_default_false():
    import inspect
    from netcraze_mcp.tools.wireguard import add_wireguard_from_conf
    sig = inspect.signature(add_wireguard_from_conf)
    assert sig.parameters["ip_global"].default is False


@pytest.mark.asyncio
async def test_apply_cli_batch_rollback_on_verify_fail(mock_client):
    mock_client.rci_get.return_value = {"message": ["interface Bridge0", "!"]}
    calls = {"n": 0}

    async def fake_rci(payload):
        calls["n"] += 1
        # verify command fails
        text = str(payload)
        if "show running-config" in text or "show bogus" in text:
            return {"status": [{"status": "error", "message": "no such command"}]}
        return {}

    mock_client.rci.side_effect = fake_rci
    result = await apply_cli_batch(
        commands=["ip route 1.2.3.4 255.255.255.255 10.0.0.1 ZeroTier0"],
        confirm=True,
        verify=["show bogus"],
        rollback_on_fail=True,
        save=False,
    )
    assert result["rolled_back"] is True or result["verdict"] in ("rolled_back", "failed")
    assert result["config_saved"] is False


def test_multi_router_context(monkeypatch):
    monkeypatch.setenv(
        "NETCRAZE_ROUTERS",
        '{"router.home":{"host":"192.168.10.1","user":"admin","password":"a"},'
        '"router.websun":{"host":"192.168.1.1","user":"admin","password":"b"}}',
    )
    configure(safe_mode=False)
    load_routers(force=True)
    token = set_current_router("router.websun")
    try:
        from netcraze_mcp.client import _get_client
        client = _get_client()
        assert client._host == "192.168.1.1"
        assert get_router("router.home").host == "192.168.10.1"
    finally:
        reset_current_router(token)
        configure(safe_mode=None)
        load_routers(force=True)
