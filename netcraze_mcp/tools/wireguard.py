"""WireGuard interface tools (list / import from .conf / up-down / delete)."""

from __future__ import annotations

import base64
import ipaddress
import re
from pathlib import Path
from typing import Any

from ..client import _get_client, _raise_on_rci_errors
from ..config import assert_writable, save_payload

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
    needle = interface_id.strip()
    async with _get_client() as client:
        try:
            data = await client.rci_get(f"show/interface/{needle}")
        except Exception:  # noqa: BLE001
            data = None
        if isinstance(data, dict) and data and (not data.get("type") or data.get("type") == "Wireguard"):
            if data.get("type") == "Wireguard" or "wireguard" in data:
                return _wg_details(data)
        for item in await _fetch_wg_ifaces(client):
            if (item.get("id") or item.get("interface-name")) == needle:
                return _wg_details(item)
    raise ValueError(f"Interface not found: {interface_id}")


def _handshake_age(value: Any) -> int | None:
    if value is None:
        return None
    try:
        age = int(value)
    except (TypeError, ValueError):
        return None
    if age >= 2147483647:
        return None  # never
    return age


async def get_wireguard_runtime(interface_id: str = "") -> dict:
    """WireGuard runtime like ``wg show``: handshake age, transfer, endpoint, keepalive.

    Reads show/interface + show/sc|rc interface for allow-ips / persistent keepalive.
    Private keys are never returned. peer_online from NDMS peer.online.
    """
    needle = interface_id.strip()
    async with _get_client() as client:
        items = await _fetch_wg_ifaces(client)
        if needle:
            items = [
                item for item in items
                if (item.get("id") or item.get("interface-name")) == needle
                or item.get("description") == needle
            ]
            if not items:
                available = sorted(
                    (i.get("id") or i.get("interface-name") or "")
                    for i in await _fetch_wg_ifaces(client)
                )
                return {"ok": False, "error": "not found", "id": needle, "available_ids": available}

        result = []
        for iface in items:
            name = iface.get("id") or iface.get("interface-name")
            wg = iface.get("wireguard") or {}
            peers_raw = wg.get("peer") or []
            if isinstance(peers_raw, dict):
                peers_raw = list(peers_raw.values())
            # config for allow-ips / keepalive
            cfg = {}
            for path in (f"show/rc/interface/{name}", f"show/sc/interface/{name}"):
                try:
                    cfg = await client.rci_get(path)
                    if isinstance(cfg, dict) and cfg:
                        break
                except Exception:  # noqa: BLE001
                    continue
            cfg_peers = ((cfg.get("wireguard") or {}).get("peer") if isinstance(cfg, dict) else None) or []
            if isinstance(cfg_peers, dict):
                cfg_peers = list(cfg_peers.values())
            cfg_peer0 = cfg_peers[0] if cfg_peers and isinstance(cfg_peers[0], dict) else {}
            allow = cfg_peer0.get("allow-ips") or []
            if isinstance(allow, dict):
                allow = list(allow.values())
            allowed_ips = []
            for item in allow if isinstance(allow, list) else []:
                if isinstance(item, dict) and item.get("address") is not None:
                    mask = item.get("mask") or "255.255.255.255"
                    try:
                        net = ipaddress.IPv4Network(f"{item['address']}/{mask}", strict=False)
                        allowed_ips.append(str(net))
                    except Exception:  # noqa: BLE001
                        allowed_ips.append(f"{item.get('address')}/{mask}")

            peers_out = []
            for peer in peers_raw if isinstance(peers_raw, list) else []:
                if not isinstance(peer, dict):
                    continue
                age = _handshake_age(peer.get("last-handshake"))
                online = bool(peer.get("online")) if peer.get("online") is not None else (age is not None and age < 180)
                endpoint = None
                if peer.get("remote-endpoint-address"):
                    endpoint = (
                        f"{peer.get('remote-endpoint-address')}:{peer.get('remote-port')}"
                        if peer.get("remote-port") is not None
                        else str(peer.get("remote-endpoint-address"))
                    )
                ka = None
                if isinstance(cfg_peer0.get("keepalive-interval"), dict):
                    ka = cfg_peer0["keepalive-interval"].get("interval")
                peers_out.append({
                    key: value
                    for key, value in {
                        "public_key": peer.get("public-key") or peer.get("key"),
                        "endpoint_actual": endpoint,
                        "via": peer.get("via") or None,
                        "latest_handshake_age_sec": age,
                        "handshake_never": peer.get("last-handshake") in (None, 2147483647, "2147483647"),
                        "transfer_rx_bytes": int(peer.get("rxbytes") or 0),
                        "transfer_tx_bytes": int(peer.get("txbytes") or 0),
                        "peer_online": online,
                        "enabled": peer.get("enabled"),
                        "persistent_keepalive": int(ka) if ka is not None else None,
                        "allowed_ips": allowed_ips or None,
                        "local_endpoint": (
                            f"{peer.get('local-endpoint-address')}:{peer.get('local-port')}"
                            if peer.get("local-endpoint-address") and peer.get("local-port") is not None
                            else None
                        ),
                    }.items()
                    if value is not None
                })
            result.append({
                key: value
                for key, value in {
                    "id": name,
                    "description": iface.get("description"),
                    "state": iface.get("state"),
                    "link": iface.get("link"),
                    "connected": iface.get("connected"),
                    "address": iface.get("address"),
                    "listen_port": wg.get("listen-port") or (
                        (peers_raw[0].get("local-port") if peers_raw and isinstance(peers_raw[0], dict) else None)
                    ),
                    "peers": peers_out,
                    "peer_online": any(p.get("peer_online") for p in peers_out),
                    "latest_handshake_age_sec": (
                        min(
                            (p["latest_handshake_age_sec"] for p in peers_out
                             if p.get("latest_handshake_age_sec") is not None),
                            default=None,
                        )
                    ),
                    "transfer_rx_bytes": sum(int(p.get("transfer_rx_bytes") or 0) for p in peers_out),
                    "transfer_tx_bytes": sum(int(p.get("transfer_tx_bytes") or 0) for p in peers_out),
                }.items()
                if value is not None
            })

    result.sort(key=lambda item: item.get("id") or "")
    if needle:
        return {"ok": True, **result[0]} if result else {"ok": False, "error": "not found", "id": needle}
    return {"ok": True, "interfaces": result, "count": len(result)}


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
    ip_global: bool = False,
    save: bool = False,
) -> dict:
    """Create WireGuard connection from standard .conf text (or local .conf path).

    Uses NDMS /rci/interface/wireguard/import (same as UI «из файла»).
    If interface_id is set, creates/updates that WireguardN via structured RCI instead.
    PrivateKey/PresharedKey are never returned.
    ip_global defaults False (tunnel-only / site-to-site); pass True for WAN-style WG.
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
        batch.extend(save_payload(save))
        resp = await client.rci(batch)
        _raise_on_rci_errors(resp)

        data = await client.rci_get(f"show/interface/{iface_id}")
    summary = _wg_summary(data if isinstance(data, dict) else {"id": iface_id})
    summary["enabled"] = enabled
    summary["config_saved"] = save
    if "address" not in summary:
        summary["address"] = parsed["address"]
    if "endpoint" not in summary:
        summary["endpoint"] = parsed["endpoint"]
    if "description" not in summary:
        summary["description"] = desc
    return summary


async def set_wireguard_state(interface_id: str, enabled: bool, save: bool = False) -> dict:
    """Enable or disable WireGuard interface without deleting it."""
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
            *save_payload(save),
        ])
        _raise_on_rci_errors(resp)
        refreshed = await client.rci_get(f"show/interface/{iface_id}")
    result = _wg_summary(refreshed if isinstance(refreshed, dict) else {"id": iface_id})
    result["enabled"] = enabled
    result["config_saved"] = save
    return result


async def delete_wireguard(interface_id: str, save: bool = False) -> dict:
    """Delete WireGuard interface. save=False by default."""
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
            *save_payload(save),
        ])
        _raise_on_rci_errors(resp)
    return {"deleted": True, "id": iface_id, "config_saved": save}


async def _next_wg_id(client) -> str:
    existing = await _fetch_wg_ifaces(client)
    used = set()
    for item in existing:
        mid = str(item.get("id") or "")
        m = re.fullmatch(r"Wireguard(\d+)", mid)
        if m:
            used.add(int(m.group(1)))
    idx = 0
    while idx in used:
        idx += 1
    return f"Wireguard{idx}"


async def create_wireguard(
    interface_id: str = "",
    address: str = "",
    listen_port: int | None = None,
    description: str = "",
    confirm: bool = False,
    save: bool = False,
) -> dict:
    """Create empty WireGuard interface; keys generated on router. Returns public key only."""
    assert_writable()
    if not confirm:
        raise PermissionError("confirm=true is required")
    if not address.strip():
        raise ValueError("address is required (CIDR or host IP)")
    ip_iface = ipaddress.ip_interface(address.strip() if "/" in address else f"{address.strip()}/32")
    if ip_iface.version != 4:
        raise ValueError("Only IPv4 address is supported")
    async with _get_client() as client:
        iface_id = interface_id.strip() or await _next_wg_id(client)
        if not re.fullmatch(r"Wireguard\d+", iface_id):
            raise ValueError("interface_id must look like WireguardN")
        body: dict[str, Any] = {
            "description": description.strip() or iface_id,
            "security-level": {"public": True},
            "ip": {"address": {"address": str(ip_iface.ip), "mask": str(ip_iface.network.netmask)}},
            "wireguard": {},
        }
        if listen_port is not None:
            body["wireguard"]["listen-port"] = {"port": int(listen_port)}
        resp = await client.rci([
            {"interface": {iface_id: {}}},
            {"interface": {iface_id: body}},
            *save_payload(save),
        ])
        _raise_on_rci_errors(resp)
        data = await client.rci_get(f"show/interface/{iface_id}")
        pub = ((data or {}).get("wireguard") or {}).get("public-key") if isinstance(data, dict) else None
        # try show rc for public-key
        if not pub:
            try:
                rc = await client.rci_get(f"show/rc/interface/{iface_id}")
                pub = ((rc or {}).get("wireguard") or {}).get("public-key") if isinstance(rc, dict) else None
            except Exception:  # noqa: BLE001
                pub = None
    return {
        "ok": True,
        "id": iface_id,
        "address": str(ip_iface.ip),
        "public_key": pub,
        "config_saved": save,
        "note": "Private key stays on router and is never returned.",
    }


def _build_wg_peer_payload(
    *,
    public_key: str,
    allowed_ips: list[str],
    endpoint: str = "",
    keepalive: int | None = 25,
    connect_via: str = "",
    existing: dict | None = None,
) -> dict[str, Any]:
    """Build NDMS peer body. connect_via → connect.via (live RC shape on NDMS 5.1.6)."""
    base = dict(existing or {})
    # drop fields we rewrite / never send back
    for drop in ("online", "rxbytes", "txbytes", "last-handshake", "via",
                 "remote-endpoint-address", "remote-port", "local-endpoint-address", "local-port"):
        base.pop(drop, None)
    peer: dict[str, Any] = {
        "key": public_key,
        "allow-ips": [_cidr_to_allow_ip(cidr) for cidr in allowed_ips],
    }
    if endpoint.strip():
        peer["endpoint"] = {"address": endpoint.strip()}
    elif isinstance(base.get("endpoint"), dict) and base["endpoint"].get("address"):
        peer["endpoint"] = {"address": str(base["endpoint"]["address"])}
    if keepalive is not None:
        peer["keepalive-interval"] = {"interval": int(keepalive)}
    elif isinstance(base.get("keepalive-interval"), dict):
        peer["keepalive-interval"] = base["keepalive-interval"]
    connect_via_s = connect_via.strip()
    if connect_via_s:
        # Live-proven SC: wireguard.peer[].connect.via (not connect-via)
        peer["connect"] = {"via": connect_via_s}
    elif isinstance(base.get("connect"), dict) and base["connect"].get("via"):
        peer["connect"] = {"via": str(base["connect"]["via"])}
    if base.get("comment") is not None:
        peer["comment"] = base.get("comment")
    if base.get("preshared-key"):
        peer["preshared-key"] = base["preshared-key"]
    return peer


def _peers_from_rc(rc: dict) -> list[dict]:
    wg = rc.get("wireguard") if isinstance(rc, dict) else {}
    peers = (wg or {}).get("peer") or []
    if isinstance(peers, dict):
        peers = list(peers.values())
    return [p for p in peers if isinstance(p, dict)] if isinstance(peers, list) else []


async def add_wireguard_peer(
    interface_id: str,
    public_key: str,
    allowed_ips: list[str],
    endpoint: str = "",
    keepalive: int | None = 25,
    connect_via: str = "",
    confirm: bool = False,
    save: bool = False,
) -> dict:
    """Add a peer to an existing WireGuard interface (no .conf import).

    allowed_ips is required (no silent 0.0.0.0/0). connect_via maps to connect.via in RCI.
    """
    assert_writable()
    if not confirm:
        raise PermissionError("confirm=true is required")
    iface_id = interface_id.strip()
    pub = public_key.strip()
    if not iface_id or not pub:
        raise ValueError("interface_id and public_key are required")
    allow = [str(x).strip() for x in (allowed_ips or []) if str(x).strip()]
    if not allow:
        raise ValueError(
            "allowed_ips is required (explicit CIDR list). "
            "Refusing default 0.0.0.0/0 for tunnel-only safety."
        )
    peer = _build_wg_peer_payload(
        public_key=pub,
        allowed_ips=allow,
        endpoint=endpoint,
        keepalive=keepalive,
        connect_via=connect_via,
    )

    async with _get_client() as client:
        data = await client.rci_get(f"show/interface/{iface_id}")
        if not isinstance(data, dict) or not data:
            raise ValueError(f"WireGuard interface not found: {iface_id}")
        # refuse duplicate public key (use update_wireguard_peer instead)
        try:
            rc = await client.rci_get(f"show/rc/interface/{iface_id}")
        except Exception:  # noqa: BLE001
            rc = {}
        for existing in _peers_from_rc(rc if isinstance(rc, dict) else {}):
            if str(existing.get("key") or existing.get("public-key") or "") == pub:
                raise ValueError(
                    f"peer {pub[:8]}… already exists on {iface_id}; "
                    f"use update_wireguard_peer to change it"
                )
        resp = await client.rci([
            {"interface": {iface_id: {"wireguard": {"peer": [peer]}}}},
            *save_payload(save),
        ])
        _raise_on_rci_errors(resp)
    return {
        "ok": True,
        "id": iface_id,
        "peer_public_key": pub,
        "allowed_ips": allow,
        "endpoint": endpoint.strip() or None,
        "connect_via": connect_via.strip() or None,
        "config_saved": save,
    }


async def update_wireguard_peer(
    interface_id: str,
    public_key: str,
    allowed_ips: list[str] | None = None,
    endpoint: str = "",
    keepalive: int | None = None,
    connect_via: str = "",
    confirm: bool = False,
    save: bool = False,
) -> dict:
    """Update existing peer by public key (remove+add same key — no duplicate peers)."""
    assert_writable()
    if not confirm:
        raise PermissionError("confirm=true is required")
    iface_id = interface_id.strip()
    pub = public_key.strip()
    if not iface_id or not pub:
        raise ValueError("interface_id and public_key are required")

    async with _get_client() as client:
        rc = await client.rci_get(f"show/rc/interface/{iface_id}")
        if not isinstance(rc, dict) or not rc:
            raise ValueError(f"WireGuard interface not found: {iface_id}")
        existing_peer = None
        for item in _peers_from_rc(rc):
            if str(item.get("key") or item.get("public-key") or "") == pub:
                existing_peer = item
                break
        if existing_peer is None:
            raise ValueError(f"peer not found on {iface_id}: {pub[:12]}…")

        if allowed_ips is None:
            # keep existing allow-ips
            raw_allow = existing_peer.get("allow-ips") or []
            if isinstance(raw_allow, dict):
                raw_allow = list(raw_allow.values())
            allow = []
            for item in raw_allow if isinstance(raw_allow, list) else []:
                if not isinstance(item, dict):
                    continue
                addr = item.get("address")
                mask = item.get("mask") or "255.255.255.255"
                if addr:
                    try:
                        allow.append(str(ipaddress.ip_network(f"{addr}/{mask}", strict=False)))
                    except ValueError:
                        allow.append(f"{addr}/{mask}")
            if not allow:
                raise ValueError("existing peer has no allow-ips; pass allowed_ips explicitly")
        else:
            allow = [str(x).strip() for x in allowed_ips if str(x).strip()]
            if not allow:
                raise ValueError("allowed_ips must contain at least one CIDR")

        peer = _build_wg_peer_payload(
            public_key=pub,
            allowed_ips=allow,
            endpoint=endpoint,
            keepalive=keepalive,
            connect_via=connect_via,
            existing=existing_peer,
        )
        # explicit remove then add — NDMS append-on-write can otherwise duplicate
        resp = await client.rci([
            {"interface": {iface_id: {"wireguard": {"peer": [{"key": pub, "no": True}]}}}},
            {"interface": {iface_id: {"wireguard": {"peer": [peer]}}}},
            *save_payload(save),
        ])
        _raise_on_rci_errors(resp)
    return {
        "ok": True,
        "updated": True,
        "id": iface_id,
        "peer_public_key": pub,
        "allowed_ips": allow,
        "endpoint": endpoint.strip() or (peer.get("endpoint") or {}).get("address"),
        "connect_via": (peer.get("connect") or {}).get("via"),
        "config_saved": save,
    }


async def remove_wireguard_peer(
    interface_id: str,
    public_key: str,
    confirm: bool = False,
    save: bool = False,
) -> dict:
    """Remove peer by public key."""
    assert_writable()
    if not confirm:
        raise PermissionError("confirm=true is required")
    iface_id = interface_id.strip()
    pub = public_key.strip()
    if not iface_id or not pub:
        raise ValueError("interface_id and public_key are required")
    async with _get_client() as client:
        resp = await client.rci([
            {"interface": {iface_id: {"wireguard": {"peer": [{"key": pub, "no": True}]}}}},
            *save_payload(save),
        ])
        _raise_on_rci_errors(resp)
    return {"ok": True, "deleted_peer": pub, "id": iface_id, "config_saved": save}


async def find_leftover_interfaces() -> dict:
    """Report empty/orphaned Wireguard* and related _WEBADMIN_Wireguard* ACLs."""
    async with _get_client() as client:
        ifaces = await _fetch_wg_ifaces(client)
        acls = None
        try:
            acls = await client.rci_get("show/sc/access-list")
        except Exception:  # noqa: BLE001
            acls = None
    leftovers = []
    for item in ifaces:
        iface_id = str(item.get("id") or "")
        wg = item.get("wireguard") or {}
        peers = wg.get("peer") or []
        if isinstance(peers, dict):
            peers = list(peers.values())
        peer_count = len(peers) if isinstance(peers, list) else 0
        empty = not item.get("address") and peer_count == 0
        if empty:
            leftovers.append({
                "id": iface_id,
                "description": item.get("description"),
                "reason": "no address and no peers",
                "state": item.get("state"),
            })
    acl_hits = []
    acl_list = acls if isinstance(acls, list) else []
    if isinstance(acls, dict):
        acl_list = list(acls.values()) if not any(isinstance(v, list) for v in acls.values()) else acls
        # flatten common shapes
        flat = []
        for item in acl_list if isinstance(acl_list, list) else []:
            if isinstance(item, dict):
                flat.append(item)
        acl_list = flat
    for item in acl_list if isinstance(acl_list, list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("acl") or item.get("name") or item.get("id") or "")
        if name.startswith("_WEBADMIN_Wireguard"):
            iface = name.replace("_WEBADMIN_", "")
            still = any(str(i.get("id")) == iface for i in ifaces)
            if not still:
                acl_hits.append({"acl": name, "reason": "ACL without matching WireGuard iface"})
    return {
        "ok": True,
        "leftover_interfaces": leftovers,
        "orphan_acls": acl_hits,
        "count": len(leftovers) + len(acl_hits),
    }


async def wireguard_handshake_check(
    router_a: str,
    iface_a: str,
    router_b: str,
    iface_b: str,
) -> dict:
    """Compare WG runtime on two routers and ping across the tunnel."""
    from ..router_ctx import reset_current_router, set_current_router
    from .diagnostics import router_ping
    from .report import diag_report

    async def _runtime(alias: str, iface: str) -> dict:
        token = set_current_router(alias)
        try:
            return await get_wireguard_runtime(iface)
        finally:
            reset_current_router(token)

    async def _addr(alias: str, iface: str) -> str | None:
        token = set_current_router(alias)
        try:
            data = await get_wireguard(iface)
            return data.get("address")
        finally:
            reset_current_router(token)

    rt_a = await _runtime(router_a, iface_a)
    rt_b = await _runtime(router_b, iface_b)
    addr_a = await _addr(router_a, iface_a)
    addr_b = await _addr(router_b, iface_b)

    ping_ab = None
    ping_ba = None
    if addr_b:
        token = set_current_router(router_a)
        try:
            ping_ab = await router_ping(addr_b, count=2, interface=iface_a)
        except Exception as exc:  # noqa: BLE001
            ping_ab = {"ok": False, "error": str(exc).split("\n")[0][:160]}
        finally:
            reset_current_router(token)
    if addr_a:
        token = set_current_router(router_b)
        try:
            ping_ba = await router_ping(addr_a, count=2, interface=iface_b)
        except Exception as exc:  # noqa: BLE001
            ping_ba = {"ok": False, "error": str(exc).split("\n")[0][:160]}
        finally:
            reset_current_router(token)

    tx_a = int(rt_a.get("transfer_tx_bytes") or 0)
    rx_a = int(rt_a.get("transfer_rx_bytes") or 0)
    tx_b = int(rt_b.get("transfer_tx_bytes") or 0)
    rx_b = int(rt_b.get("transfer_rx_bytes") or 0)
    reasons = []
    if tx_a > 0 and rx_a == 0:
        reasons.append(f"{router_a}/{iface_a}: tx>0 rx=0 — UDP likely not reaching peer")
    if tx_b > 0 and rx_b == 0:
        reasons.append(f"{router_b}/{iface_b}: tx>0 rx=0 — UDP likely not reaching peer")
    if not rt_a.get("peer_online") and not rt_b.get("peer_online"):
        reasons.append("both peers offline / no recent handshake")
    ping_ok = bool((ping_ab or {}).get("ok")) or bool((ping_ba or {}).get("ok"))
    if ping_ok and (rt_a.get("peer_online") or rt_b.get("peer_online")):
        verdict = "ok"
    elif reasons:
        verdict = "udp_path_problem" if any("tx>0 rx=0" in r for r in reasons) else "degraded"
    else:
        verdict = "unknown"

    return diag_report(
        verdict,
        evidence=[
            {"router_a": rt_a, "router_b": rt_b},
            {"ping_ab": ping_ab, "ping_ba": ping_ba},
            {"reasons": reasons},
        ],
        changes=[],
        config_saved=False,
        ok=verdict == "ok",
        reasons=reasons,
        router_a=router_a,
        router_b=router_b,
    )


def register(mcp) -> None:
    mcp.tool()(list_wireguard)
    mcp.tool()(get_wireguard)
    mcp.tool()(get_wireguard_runtime)
    mcp.tool()(add_wireguard_from_conf)
    mcp.tool()(set_wireguard_state)
    mcp.tool()(delete_wireguard)
    mcp.tool()(create_wireguard)
    mcp.tool()(add_wireguard_peer)
    mcp.tool()(update_wireguard_peer)
    mcp.tool()(remove_wireguard_peer)
    mcp.tool()(find_leftover_interfaces)
    mcp.tool()(wireguard_handshake_check)
