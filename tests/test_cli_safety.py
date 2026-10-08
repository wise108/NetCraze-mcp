"""Safety tests: apply_cli_batch must never delete interfaces on rollback."""

from __future__ import annotations

import pytest

from netcraze_mcp.tools.txn import (
    _inverse_cli,
    _is_context_enter,
    _normalize_blocks,
    apply_cli_batch,
)


def test_inverse_cli_bare_interface_is_none():
    assert _inverse_cli("interface Wireguard0") is None
    assert _inverse_cli("interface Bridge0") is None
    assert _is_context_enter("interface Wireguard0")


def test_inverse_cli_never_returns_no_interface():
    assert _inverse_cli("interface Wireguard0") is None
    # even if someone passes already-destructive
    assert _inverse_cli("no interface Wireguard0") is None


def test_inverse_cli_safe_route_and_dns():
    assert _inverse_cli("ip route 1.2.3.4 255.255.255.255 10.0.0.1 ZeroTier0") == (
        "no ip route 1.2.3.4 255.255.255.255 10.0.0.1 ZeroTier0"
    )
    assert _inverse_cli("dns-proxy route DomainList0 Wireguard0") == (
        "no dns-proxy route DomainList0 Wireguard0"
    )


def test_normalize_blocks_groups_interface_context():
    blocks = _normalize_blocks([
        "interface Wireguard0",
        "ip tcp adjust-mss pmtu",
        "ip route 1.2.3.4 255.255.255.255 10.0.0.1 ZeroTier0",
    ])
    assert blocks[0] == {
        "context": "interface Wireguard0",
        "lines": ["ip tcp adjust-mss pmtu"],
    }
    assert blocks[1] == {
        "context": None,
        "lines": ["ip route 1.2.3.4 255.255.255.255 10.0.0.1 ZeroTier0"],
    }


def test_normalize_blocks_dict_form():
    blocks = _normalize_blocks([
        {"context": "interface Wireguard0", "lines": ["ip tcp adjust-mss pmtu"]},
    ])
    assert len(blocks) == 1
    assert blocks[0]["context"] == "interface Wireguard0"
    assert blocks[0]["lines"] == ["ip tcp adjust-mss pmtu"]


@pytest.mark.asyncio
async def test_apply_cli_batch_mss_fail_does_not_delete_interface(mock_client):
    """Incident regression: failed MSS subcommand must NOT run 'no interface Wireguard0'."""
    mock_client.rci_get.return_value = {"message": ["interface Wireguard0", "!"]}
    parse_calls: list[list] = []

    async def fake_rci(payload):
        parse_calls.append(payload if isinstance(payload, list) else [payload])
        text = str(payload).lower()
        if "adjust-mss" in text or "tcp" in text:
            return {"status": [{"status": "error", "message": "no such command: tcp."}]}
        return {}

    mock_client.rci.side_effect = fake_rci
    result = await apply_cli_batch(
        commands=["interface Wireguard0", "ip tcp adjust-mss pmtu"],
        confirm=True,
        rollback_on_fail=True,
        save=False,
    )
    flat = " ".join(str(c) for c in parse_calls).lower()
    assert "no interface wireguard0" not in flat
    assert "no interface" not in flat
    # context enter alone is not a successful mutation
    assert result.get("applied") == [] or all(
        "interface Wireguard0" != a for a in (result.get("applied") or [])
    )
    assert result["verdict"] in (
        "failed",
        "failed_needs_manual_restore",
        "partial_rollback_needs_manual_restore",
    )
    assert result["baseline_id"]
    assert result.get("rolled_back") is False or "no interface" not in str(
        result.get("rollback_commands") or []
    ).lower()


@pytest.mark.asyncio
async def test_apply_cli_batch_context_block_atomic(mock_client):
    mock_client.rci_get.return_value = {"message": ["!"]}
    parse_calls: list = []

    async def fake_rci(payload):
        parse_calls.append(payload)
        text = str(payload).lower()
        if "adjust-mss" in text:
            return {"status": [{"status": "error", "message": "no such command: tcp."}]}
        return {}

    mock_client.rci.side_effect = fake_rci
    result = await apply_cli_batch(
        commands=[{
            "context": "interface Wireguard0",
            "lines": ["ip tcp adjust-mss pmtu"],
        }],
        confirm=True,
        rollback_on_fail=True,
        allow_destructive_rollback=False,
        save=False,
    )
    # One session: interface + subcommand + exit together
    session = next(
        (p for p in parse_calls if isinstance(p, list) and any(
            isinstance(x, dict) and x.get("parse") == "interface Wireguard0" for x in p
        )),
        None,
    )
    assert session is not None
    parses = [x.get("parse") for x in session if isinstance(x, dict)]
    assert parses[0] == "interface Wireguard0"
    assert "ip tcp adjust-mss pmtu" in parses
    assert parses[-1] == "exit"
    # no per-line exit between interface and subcommand
    assert parses != ["interface Wireguard0", "exit", "ip tcp adjust-mss pmtu", "exit"]
    assert result["ok"] is False
    assert result["baseline_id"]


@pytest.mark.asyncio
async def test_apply_cli_batch_safe_route_inverse_still_works(mock_client):
    mock_client.rci_get.return_value = {"message": ["ip route 1.2.3.4 …", "!"]}
    calls: list[str] = []

    async def fake_rci(payload):
        text = str(payload)
        calls.append(text)
        if "show bogus" in text:
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
    assert any("no ip route" in c.lower() for c in calls)
    assert result["config_saved"] is False


@pytest.mark.asyncio
async def test_set_interface_tcp_adjust_mss_structured(mock_client):
    from netcraze_mcp.tools.network import set_interface_tcp_adjust_mss

    mock_client.rci.return_value = {}
    mock_client.rci_get.return_value = {
        "ip": {"tcp": {"adjust-mss": {"pmtu": True}}},
    }
    out = await set_interface_tcp_adjust_mss("Wireguard0", mode="pmtu", confirm=True, save=False)
    assert out["ok"] is True
    assert out["mode"] == "pmtu"
    assert out["applied_to"] == "rc"
    batch = mock_client.rci.call_args[0][0]
    assert batch[0] == {
        "interface": {"Wireguard0": {"ip": {"tcp": {"adjust-mss": {"pmtu": True}}}}}
    }
