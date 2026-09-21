"""Shared test fixtures for netcraze-mcp."""

import pytest
from unittest.mock import AsyncMock

import netcraze_mcp.config as config
import netcraze_mcp.tools.backup as backup_tools
import netcraze_mcp.tools.components as components_tools
import netcraze_mcp.tools.dns_routes as dns_routes_tools
import netcraze_mcp.tools.network as network_tools
import netcraze_mcp.tools.static_hosts as static_hosts_tools
import netcraze_mcp.tools.static_routes as static_routes_tools
import netcraze_mcp.tools.storage as storage_tools
import netcraze_mcp.tools.system as system_tools
import netcraze_mcp.tools.wireguard as wireguard_tools


@pytest.fixture(autouse=True)
def reset_config(monkeypatch):
    """Reset server config between tests."""
    monkeypatch.setenv("NETCRAZE_SAFE_MODE", "false")
    monkeypatch.setenv("NETCRAZE_HOST", "192.168.1.1")
    monkeypatch.setenv("NETCRAZE_PASS", "s3cret")
    config.configure(safe_mode=None)
    yield
    config.configure(safe_mode=None)


class MockNetCrazeClient:
    """Fake NetCrazeClient that never touches the network."""

    def __init__(self) -> None:
        self.rci = AsyncMock(return_value={})
        self.rci_get = AsyncMock(return_value={})
        self.ci_get_bytes = AsyncMock(return_value=b"")
        self.rci_post = AsyncMock(return_value={})

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass


def _patch_get_client(monkeypatch, client: MockNetCrazeClient) -> None:
    getter = lambda: client
    for module in (
        system_tools,
        backup_tools,
        components_tools,
        network_tools,
        dns_routes_tools,
        static_hosts_tools,
        static_routes_tools,
        storage_tools,
        wireguard_tools,
    ):
        monkeypatch.setattr(module, "_get_client", getter)


@pytest.fixture
def mock_client(monkeypatch):
    """Patch _get_client() in all tool modules."""
    client = MockNetCrazeClient()
    _patch_get_client(monkeypatch, client)
    return client


@pytest.fixture
def safe_env(monkeypatch):
    """Set required env vars so _get_client() doesn't raise."""
    monkeypatch.setenv("NETCRAZE_HOST", "192.168.1.1")
    monkeypatch.setenv("NETCRAZE_USER", "admin")
    monkeypatch.setenv("NETCRAZE_PASS", "s3cret")
