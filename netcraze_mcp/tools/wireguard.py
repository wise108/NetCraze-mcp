"""WireGuard interface tools (list / import from .conf / up-down / delete)."""

from __future__ import annotations

import base64
import ipaddress
import re
from pathlib import Path
from typing import Any

from ..client import _get_client, _raise_on_rci_errors
from ..config import assert_writable

_KEY_RE = re.compile(r"[A-Za-z0-9+/]{42,44}=")
_SECRET_FIELD_RE = re.compile(
    r"(?i)(private[_-]?key|preshared[_-]?key|psk)\s*[:=]\s*\S+"
)


def _mask_secrets(text: str) -> str:
    text = _SECRET_FIELD_RE.sub(r"\1=<redacted>", text)
    return _KEY_RE.sub("***", text)


def _cidr_to_allow_ip(cidr: str) -> dict:
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    if net.version != 4:
        raise ValueError(f"Only IPv4 AllowedIPs are supported: {cidr}")
    return {"address": str(net.network_address), "mask": str(net.netmask)}


def _parse_wg_conf(text: str) -> dict:
    """Parse standard WireGuard .conf into structured fields (secrets stay in memory only)."""
    if not text or not text.strip():
        raise ValueError("conf is empty")
    section: str | None = None
    interface: dict[str, str] = {}
    peer: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if "=" not in line or section is None:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if section == "interface":
            interface[key] = value
        elif section == "peer":
            peer[key] = value
    if "privatekey" not in interface:
        raise ValueError("conf [Interface] PrivateKey is required")
    if "address" not in interface:
        raise ValueError("conf [Interface] Address is required")
    if "publickey" not in peer:
        raise ValueError("conf [Peer] PublicKey is required")
    if "endpoint" not in peer:
        raise ValueError("conf [Peer] Endpoint is required")
    address = interface["address"].split(",")[0].strip()
    if "/" not in address:
        address = f"{address}/32"
    ip_iface = ipaddress.ip_interface(address)
    if ip_iface.version != 4:
        raise ValueError("Only IPv4 Address is supported")
    allowed = [item.strip() for item in (peer.get("allowedips") or "0.0.0.0/0").split(",") if item.strip()]
    keepalive = int(peer.get("persistentkeepalive") or 25)
    return {
        "address": str(ip_iface.ip),
        "mask": str(ip_iface.network.netmask),
        "private_key": interface["privatekey"],
        "listen_port": int(interface["listenport"]) if interface.get("listenport") else None,
        "dns": interface.get("dns"),
        "peer_public_key": peer["publickey"],
        "preshared_key": peer.get("presharedkey") or None,
        "endpoint": peer["endpoint"],
        "allowed_ips": allowed,
        "keepalive": keepalive,
    }


def _load_conf_text(conf: str = "", path: str = "") -> str:
    if conf.strip() and path.strip():
        raise ValueError("Pass either conf or path, not both")
    if conf.strip():
        return conf
    if not path.strip():
        raise ValueError("conf or path is required")
    file_path = Path(path.strip()).expanduser()
    if file_path.suffix.lower() != ".conf":
        raise ValueError("path must point to a .conf file")
    # Only the requested .conf — never follow into ssh/key material elsewhere.
    return file_path.read_text(encoding="utf-8")


def _peer_endpoint(iface: dict) -> str | None:
    wg = iface.get("wireguard") or {}
    peers = wg.get("peer") or []
    if isinstance(peers, dict):
        peers = list(peers.values())
    if not isinstance(peers, list) or not peers:
        return None
    peer = peers[0]
    if not isinstance(peer, dict):
        return None
    remote = peer.get("remote-endpoint-address")
    port = peer.get("remote-port")
    if remote and port:
        return f"{remote}:{port}"
    if remote:
        return str(remote)
    return None


def _wg_summary(iface: dict) -> dict:
    return {
        key: value
        for key, value in {
            "id": iface.get("id") or iface.get("interface-name"),
            "description": iface.get("description"),
            "state": iface.get("state"),
            "link": iface.get("link"),
            "connected": iface.get("connected"),
            "address": iface.get("address"),
            "mask": iface.get("mask"),
            "mtu": iface.get("mtu"),
            "endpoint": _peer_endpoint(iface),
            "listen_port": (iface.get("wireguard") or {}).get("listen-port"),
            "enabled": iface.get("state") == "up",
        }.items()
        if value is not None and value != ""
    }


def _wg_details(iface: dict) -> dict:
    summary = _wg_summary(iface)
    wg = iface.get("wireguard") or {}
    peers_raw = wg.get("peer") or []
    if isinstance(peers_raw, dict):
        peers_raw = list(peers_raw.values())
    peers = []
    for peer in peers_raw if isinstance(peers_raw, list) else []:
        if not isinstance(peer, dict):
            continue
        peers.append({
            key: value
            for key, value in {
                "public_key": peer.get("public-key") or peer.get("key"),
                "endpoint": (
                    f"{peer.get('remote-endpoint-address')}:{peer.get('remote-port')}"
                    if peer.get("remote-endpoint-address") and peer.get("remote-port")
                    else peer.get("remote-endpoint-address")
                ),
                "online": peer.get("online"),
                "enabled": peer.get("enabled"),
                "last_handshake": peer.get("last-handshake"),
                "rx_bytes": peer.get("rxbytes"),
                "tx_bytes": peer.get("txbytes"),
            }.items()
            if value is not None
        })
    if peers:
        summary["peers"] = peers
    summary["public_key"] = wg.get("public-key")
    return {k: v for k, v in summary.items() if v is not None}


async def _fetch_wg_ifaces(client) -> list[dict]:
    data = await client.rci_get("show/interface")
    if isinstance(data, dict):
        items = [value for value in data.values() if isinstance(value, dict)]
    elif isinstance(data, list):
        items = [item for item in data if isinstance(item, dict)]
    else:
        items = []
    return [
        item for item in items
        if item.get("type") == "Wireguard" or str(item.get("id") or "").startswith("Wireguard")
    ]


async def list_wireguard() -> list[dict]:
    """List WireGuard interfaces (id, description, state, link, address, endpoint)."""
    async with _get_client() as client:
        result = [_wg_summary(item) for item in await _fetch_wg_ifaces(client)]
    result.sort(key=lambda item: item.get("id") or "")
    return result


async def get_wireguard(interface_id: str) -> dict:
    """Get one WireGuard interface; private/preshared keys are never returned."""
    if not interface_id.strip():
        raise ValueError("interface_id is required")
    async with _get_client() as client:
        data = await client.rci_get(f"show/interface/{interface_id.strip()}")
    if not isinstance(data, dict) or not data:
        raise ValueError(f"Interface not found: {interface_id}")
    if data.get("type") and data.get("type") != "Wireguard":
        raise ValueError(f"Interface is not WireGuard: {interface_id}")
    return _wg_details(data)


async def _import_conf(client, conf_text: str, filename: str) -> str:
    payload = {
        "import": base64.b64encode(conf_text.encode("utf-8")).decode("ascii"),
        "name": "",
        "filename": filename or "import.conf",
    }
    resp = await client.rci_post("interface/wireguard/import", payload)
    _raise_on_rci_errors(resp)
    created = resp.get("created") if isinstance(resp, dict) else None
    if not created:
        raise RuntimeError(_mask_secrets(f"WireGuard import failed: {resp}"))
    return str(created)


async def _apply_conf_to_interface(client, interface_id: str, parsed: dict, description: str) -> None:
    """Create/update a specific WireguardN from parsed conf (when interface_id is forced)."""
    peer: dict[str, Any] = {
        "key": parsed["peer_public_key"],
        "endpoint": {"address": parsed["endpoint"]},
        "keepalive-interval": {"interval": parsed["keepalive"]},
        "allow-ips": [_cidr_to_allow_ip(cidr) for cidr in parsed["allowed_ips"]],
    }
    if parsed.get("preshared_key"):
        peer["preshared-key"] = parsed["preshared_key"]
    wireguard: dict[str, Any] = {"peer": [peer]}
    if parsed.get("listen_port"):
        wireguard["listen-port"] = {"port": parsed["listen_port"]}
    wireguard["private-key"] = parsed["private_key"]
    body: dict[str, Any] = {
        "description": description or interface_id,
        "security-level": {"public": True},
        "ip": {
            "address": {"address": parsed["address"], "mask": parsed["mask"]},
        },
        "wireguard": wireguard,
    }
    if parsed.get("dns"):
        body["ip"]["name-server"] = [{"name-server": parsed["dns"].split(",")[0].strip()}]
    resp = await client.rci({"interface": {interface_id: body}})
    _raise_on_rci_errors(resp)


async def add_wireguard_from_conf(
    conf: str = "",
    path: str = "",
    description: str = "",
    enabled: bool = True,
    interface_id: str = "",
    ip_global: bool = True,
) -> dict:
    """Create WireGuard connection from standard .conf text (or local .conf path).

    Uses NDMS /rci/interface/wireguard/import (same as UI «из файла»).
    If interface_id is set, creates/updates that WireguardN via structured RCI instead.
    PrivateKey/PresharedKey are never returned.
    """
    assert_writable()
    conf_text = _load_conf_text(conf=conf, path=path)
    parsed = _parse_wg_conf(conf_text)
    desc = description.strip() or (Path(path).stem if path.strip() else "WireGuard")
    filename = Path(path).name if path.strip() else f"{desc.replace(' ', '_')}.conf"

    async with _get_client() as client:
        if interface_id.strip():
            iface_id = interface_id.strip()
            if not re.fullmatch(r"Wireguard\d+", iface_id):
                raise ValueError("interface_id must look like WireguardN")
            existing = await client.rci_get(f"show/interface/{iface_id}")
            if not isinstance(existing, dict) or not existing.get("id"):
                create_resp = await client.rci({"interface": {iface_id: {}}})
                _raise_on_rci_errors(create_resp)
            await _apply_conf_to_interface(client, iface_id, parsed, desc)
        else:
            iface_id = await _import_conf(client, conf_text, filename)
            if description.strip():
                resp = await client.rci({"interface": {iface_id: {"description": desc}}})
                _raise_on_rci_errors(resp)

        batch: list[dict] = []
        if ip_global:
            batch.append({"parse": f"interface {iface_id} ip global auto"})
        if enabled:
            batch.append({"interface": {iface_id: {"up": True}}})
        else:
            batch.append({"interface": {iface_id: {"down": True}}})
        batch.append({"system": {"configuration": {"save": {}}}})
        resp = await client.rci(batch)
        _raise_on_rci_errors(resp)

        data = await client.rci_get(f"show/interface/{iface_id}")
    summary = _wg_summary(data if isinstance(data, dict) else {"id": iface_id})
    summary["enabled"] = enabled
    if "address" not in summary:
        summary["address"] = parsed["address"]
    if "endpoint" not in summary:
        summary["endpoint"] = parsed["endpoint"]
    if "description" not in summary:
        summary["description"] = desc
    return summary


async def set_wireguard_state(interface_id: str, enabled: bool) -> dict:
    """Enable or disable WireGuard interface without deleting it; saves config."""
    assert_writable()
    if not interface_id.strip():
        raise ValueError("interface_id is required")
    iface_id = interface_id.strip()
    action = "up" if enabled else "down"
    async with _get_client() as client:
        data = await client.rci_get(f"show/interface/{iface_id}")
        if not isinstance(data, dict) or not data:
            raise ValueError(f"WireGuard interface not found: {iface_id}")
        if data.get("type") not in (None, "Wireguard") and not str(data.get("id") or iface_id).startswith("Wireguard"):
            raise ValueError(f"Interface is not WireGuard: {iface_id}")
        resp = await client.rci([
            {"interface": {iface_id: {action: True}}},
            {"system": {"configuration": {"save": {}}}},
        ])
        _raise_on_rci_errors(resp)
        refreshed = await client.rci_get(f"show/interface/{iface_id}")
    result = _wg_summary(refreshed if isinstance(refreshed, dict) else {"id": iface_id})
    result["enabled"] = enabled
    return result


async def delete_wireguard(interface_id: str) -> dict:
    """Delete WireGuard interface and save configuration."""
    assert_writable()
    if not interface_id.strip():
        raise ValueError("interface_id is required")
    iface_id = interface_id.strip()
    async with _get_client() as client:
        data = await client.rci_get(f"show/interface/{iface_id}")
        if not isinstance(data, dict) or not data:
            raise ValueError(f"Interface not found: {iface_id}")
        resp = await client.rci([
            {"interface": {iface_id: {"no": True}}},
            {"system": {"configuration": {"save": {}}}},
        ])
        _raise_on_rci_errors(resp)
    return {"deleted": True, "id": iface_id}


def register(mcp) -> None:
    mcp.tool()(list_wireguard)
    mcp.tool()(get_wireguard)
    mcp.tool()(add_wireguard_from_conf)
    mcp.tool()(set_wireguard_state)
    mcp.tool()(delete_wireguard)
