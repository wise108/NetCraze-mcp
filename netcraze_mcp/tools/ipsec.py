"""IPsec site-to-site read-only tools (NDMS crypto map / site-to-site)."""

from __future__ import annotations

import re
from typing import Any

from ..client import _get_client

# NDMS UI hardcodes these proposal IDs (no live RCI catalog on 5.01).
_IKE_ENCRYPTION = [
    "des", "3des",
    "aes-cbc-128", "aes-cbc-192", "aes-cbc-256",
    "aes-ctr-128", "aes-ctr-192", "aes-ctr-256",
]
_IKE_ENCRYPTION_AEAD = [
    "aes-128-ccm-8", "aes-192-ccm-8", "aes-256-ccm-8",
    "aes-128-ccm-12", "aes-192-ccm-12", "aes-256-ccm-12",
    "aes-128-ccm-16", "aes-192-ccm-16", "aes-256-ccm-16",
    "aes-128-gcm-8", "aes-192-gcm-8", "aes-256-gcm-8",
    "aes-128-gcm-12", "aes-192-gcm-12", "aes-256-gcm-12",
    "aes-128-gcm-16", "aes-192-gcm-16", "aes-256-gcm-16",
]
_IKE_INTEGRITY = ["md5", "sha1", "sha256", "sha384", "sha512"]
_IKE_PRF = ["md5", "sha1", "sha256", "sha384", "sha512", "aes-xcbc", "aes-cmac"]
_DH_GROUPS = ["1", "2", "5", "14", "15", "16", "17", "18", "19", "20", "21", "25", "26", "31", "32"]
_ESP_ENCRYPTION = [
    "esp-des", "esp-3des",
    "esp-aes-128", "esp-aes-192", "esp-aes-256",
    "esp-aes-128-ctr", "esp-aes-192-ctr", "esp-aes-256-ctr",
    "esp-null",
]
_ESP_ENCRYPTION_AEAD = [
    "esp-aes-128-ccm-8", "esp-aes-192-ccm-8", "esp-aes-256-ccm-8",
    "esp-aes-128-ccm-12", "esp-aes-192-ccm-12", "esp-aes-256-ccm-12",
    "esp-aes-128-ccm-16", "esp-aes-192-ccm-16", "esp-aes-256-ccm-16",
    "esp-aes-128-gcm-8", "esp-aes-192-gcm-8", "esp-aes-256-gcm-8",
    "esp-aes-128-gcm-12", "esp-aes-192-gcm-12", "esp-aes-256-gcm-12",
    "esp-aes-128-gcm-16", "esp-aes-192-gcm-16", "esp-aes-256-gcm-16",
]
_ESP_INTEGRITY = ["esp-md5-hmac", "esp-sha1-hmac", "esp-sha256-hmac", "esp-sha512-hmac"]

_SECRET_KEY_RE = re.compile(
    r"(?i)(^|[_-])(psk|password|secret|private[_-]?key|pre[_-]?shared|ike[_-]?psk|xauth[_-]?password)($|[_-])"
)
_RCI_PATHS = {
    "connections": "show/sc/crypto/ipsec/site-to-site",
    "status_map": "show/crypto/map",
    "crypto": "show/crypto",
    "ipsec": "show/ipsec",
    "crypto_engine": "show/sc/crypto",
    "sa_legacy": "show/crypto/ipsec/sa",
}


def _is_secret_key(key: str) -> bool:
    return bool(_SECRET_KEY_RE.search(key.replace("-", "_")))


def _redact(value: Any) -> Any:
    """Recursively redact secret fields; never echo PSK/passwords."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if _is_secret_key(str(key)):
                if item in (None, "", False):
                    out[key] = item
                elif item is True:
                    out[key] = True
                else:
                    out[key] = "<REDACTED>"
            else:
                out[key] = _redact(item)
        return out
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _split_csv(value) -> list[str]:
    if value in (None, "", False):
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    return [part for part in str(value).split(",") if part]


def _split_subnets(value) -> list[str]:
    """NDM stores subnets as comma-separated addr/mask or CIDR-ish strings."""
    return _split_csv(value)


def _as_bool(value) -> bool | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("yes", "true", "1", "on", "enabled"):
        return True
    if text in ("no", "false", "0", "off", "disabled"):
        return False
    return None


def _normalize_connections(raw) -> dict[str, dict]:
    """Normalize show/sc/crypto/ipsec/site-to-site to {name: config}."""
    if raw in (None, {}, []):
        return {}
    if isinstance(raw, dict):
        # unwrap accidental wrappers
        if "crypto" in raw or "ipsec" in raw or "site-to-site" in raw:
            node = raw
            for key in ("show", "sc", "crypto", "ipsec", "site-to-site"):
                if isinstance(node, dict) and key in node:
                    node = node[key]
            return _normalize_connections(node)
        result = {}
        for key, value in raw.items():
            if isinstance(value, dict):
                result[str(value.get("name") or key)] = value
        return result
    if isinstance(raw, list):
        result = {}
        for index, item in enumerate(raw):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or f"map{index}")
            result[name] = item
        return result
    return {}


def _normalize_status_map(raw) -> dict[str, dict]:
    """Normalize show/crypto/map (possibly wrapped as crypto_map)."""
    if raw in (None, {}, []):
        return {}
    if isinstance(raw, dict):
        if "crypto_map" in raw and isinstance(raw["crypto_map"], dict):
            return {str(k): v for k, v in raw["crypto_map"].items() if isinstance(v, dict)}
        if "show" in raw or "crypto" in raw or "map" in raw:
            node = raw
            for key in ("show", "crypto", "map"):
                if isinstance(node, dict) and key in node:
                    node = node[key]
            return _normalize_status_map(node)
        return {str(k): v for k, v in raw.items() if isinstance(v, dict)}
    return {}


def _connection_state(status_entry: dict | None) -> dict:
    if not status_entry:
        return {"connected": False, "state": "unknown", "enabled": None}
    config = status_entry.get("config") if isinstance(status_entry.get("config"), dict) else {}
    status = status_entry.get("status") if isinstance(status_entry.get("status"), dict) else {}
    enabled = _as_bool(config.get("enabled"))
    phase_state = status.get("state")
    ike_state = status.get("ike_state")
    if enabled is False:
        state = "down"
        connected = False
    elif phase_state == "PHASE2_ESTABLISHED":
        state = "connected"
        connected = True
    elif ike_state == "UNDEFINED":
        state = "no_link"
        connected = False
    elif enabled is True:
        state = "standing_by"
        connected = False
    else:
        state = str(phase_state or ike_state or "unknown").lower()
        connected = phase_state == "PHASE2_ESTABLISHED"
    return {
        "connected": connected,
        "state": state,
        "enabled": enabled,
        "phase_state": phase_state,
        "ike_state": ike_state,
    }


def _summary(name: str, config: dict, status_entry: dict | None) -> dict:
    runtime = _connection_state(status_entry)
    enabled = runtime["enabled"]
    if enabled is None:
        enabled = _as_bool(config.get("enable"))
        if enabled is None and "passive" in config:
            # configured entries are present even if status map empty
            enabled = True
    return {
        key: value
        for key, value in {
            "id": name,
            "name": name,
            "enabled": enabled,
            "connected": runtime["connected"],
            "state": runtime["state"],
            "remote_gateway": config.get("peer") if config.get("peer") != "any" else None,
            "role": (
                "responder" if _as_bool(config.get("passive"))
                else "initiator" if config.get("passive") is not None
                else None
            ),
            "ike_version": config.get("ike-protocol"),
            "ipsec_mode": config.get("ipsec-mode"),
        }.items()
        if value is not None and value != ""
    }


def _details(name: str, config: dict, status_entry: dict | None) -> dict:
    summary = _summary(name, config, status_entry)
    psk = config.get("ike-psk")
    has_psk = bool(psk) and str(psk) not in ("", "<REDACTED>")
    local_id_type = config.get("ike-local-id-type")
    remote_id_type = config.get("ike-remote-id-type")
    details = {
        **summary,
        "has_psk": has_psk,
        "local_id_type": local_id_type,
        "local_id": config.get("ike-local-id"),
        "remote_id_type": remote_id_type,
        "remote_id": config.get("ike-remote-id"),
        "local_subnets": _split_subnets(config.get("ipsec-local-networks")),
        "remote_subnets": _split_subnets(config.get("ipsec-remote-networks")),
        "ike_proposal": {
            key: value
            for key, value in {
                "aead": _as_bool(config.get("ike-aead")),
                "encryption": _split_csv(config.get("ike-encryption")),
                "integrity": _split_csv(config.get("ike-integrity")),
                "prf": _split_csv(config.get("ike-prf")),
                "dh": _split_csv(config.get("ike-dh")),
                "lifetime": config.get("ike-lifetime"),
                "mode": config.get("ike-mode"),
            }.items()
            if value not in (None, [], "")
        },
        "esp_proposal": {
            key: value
            for key, value in {
                "aead": _as_bool(config.get("ipsec-aead")),
                "encryption": _split_csv(config.get("ipsec-encryption")),
                "integrity": _split_csv(config.get("ipsec-integrity")),
                "pfs_dh": _split_csv(config.get("ipsec-dh")),
                "lifetime": config.get("ipsec-lifetime"),
                "mode": config.get("ipsec-mode"),
            }.items()
            if value not in (None, [], "")
        },
        "dpd": _as_bool(config.get("dpd")),
        "dpd_interval": config.get("dpd-interval"),
        "nailed_up": _as_bool(config.get("nail-up")),
        "autoconnect": _as_bool(config.get("autoconnect")),
        "passive": _as_bool(config.get("passive")),
        "force_encaps": _as_bool(config.get("force-encaps")),
        "nat_t": _as_bool(config.get("force-encaps") or config.get("nat-t")),
    }
    if status_entry:
        status = status_entry.get("status") if isinstance(status_entry.get("status"), dict) else {}
        phase1 = status.get("phase1") if isinstance(status.get("phase1"), dict) else {}
        phase2_list = []
        phase2_sa_list = status.get("phase2_sa_list")
        if isinstance(phase2_sa_list, dict):
            raw_sa = phase2_sa_list.get("phase2_sa") or []
            if isinstance(raw_sa, list):
                phase2_list = raw_sa
            elif isinstance(raw_sa, dict):
                phase2_list = [raw_sa]
        details["phase1"] = _redact({
            key: value
            for key, value in {
                "rekey_time": phase1.get("rekey_time"),
                **{k: v for k, v in phase1.items() if k != "rekey_time"},
            }.items()
            if value is not None
        }) or None
        details["phase2_sa"] = _redact(phase2_list) or None
        details["runtime"] = _redact({
            "peer_fallback": status_entry.get("remote_peer_fallback") or (status_entry.get("config") or {}).get("remote_peer_fallback"),
            "status": status,
        })
    return {
        key: value
        for key, value in details.items()
        if value is not None and value != [] and value != {}
    }


async def _load_connections(client) -> tuple[dict[str, dict], dict[str, dict]]:
    config_raw = await client.rci_get(_RCI_PATHS["connections"])
    status_raw = await client.rci_get(_RCI_PATHS["status_map"])
    return _normalize_connections(config_raw), _normalize_status_map(status_raw)


async def list_ipsec() -> list[dict]:
    """List IPsec site-to-site connections (crypto map).

    RCI: GET show/sc/crypto/ipsec/site-to-site + GET show/crypto/map
    """
    async with _get_client() as client:
        configs, statuses = await _load_connections(client)
    result = [
        _summary(name, config, statuses.get(name))
        for name, config in configs.items()
    ]
    # include status-only entries if any
    for name, status_entry in statuses.items():
        if name not in configs:
            result.append(_summary(name, {}, status_entry))
    result.sort(key=lambda item: item.get("id") or "")
    return result


async def list_ipsec_connections() -> list[dict]:
    """Alias for list_ipsec."""
    return await list_ipsec()


async def get_ipsec(connection_id: str) -> dict:
    """Get one IPsec S2S connection details. PSK is never returned (has_psk only).

    RCI: GET show/sc/crypto/ipsec/site-to-site + GET show/crypto/map
    """
    if not connection_id.strip():
        raise ValueError("connection_id is required")
    name = connection_id.strip()
    async with _get_client() as client:
        configs, statuses = await _load_connections(client)
    if name not in configs and name not in statuses:
        raise ValueError(f"IPsec connection not found: {name}")
    return _details(name, configs.get(name) or {}, statuses.get(name))


async def list_ipsec_proposals() -> dict:
    """Return IKE/ESP/DH algorithm IDs known to NDMS 5.x UI.

    Note: NDMS 5.01 has no live RCI proposal catalog; values are taken from the
    web UI option lists (same IDs used when writing crypto.ipsec.site-to-site).
    aes256 ≈ aes-cbc-256 / esp-aes-256; modp2048 ≈ DH group 14.
    """
    return {
        "source": "ndms-ui-static",
        "rci_path": None,
        "note": "No GET proposal endpoint on NDMS 5.01; lists mirror UI editors.",
        "ike": {
            "encryption": _IKE_ENCRYPTION,
            "encryption_aead": _IKE_ENCRYPTION_AEAD,
            "integrity": _IKE_INTEGRITY,
            "prf": _IKE_PRF,
            "dh_groups": _DH_GROUPS,
            "aliases": {"aes256": "aes-cbc-256", "modp2048": "14", "dh14": "14"},
        },
        "esp": {
            "encryption": _ESP_ENCRYPTION,
            "encryption_aead": _ESP_ENCRYPTION_AEAD,
            "integrity": _ESP_INTEGRITY,
            "dh_groups_pfs": _DH_GROUPS,
            "aliases": {"aes256": "esp-aes-256", "sha256": "esp-sha256-hmac", "modp2048": "14"},
        },
        "contains": {
            "aes256": True,
            "sha256": True,
            "modp2048_dh14": True,
        },
    }


async def show_ipsec_sa() -> dict:
    """Show IPsec SAs.

    Preferred legacy path GET show/crypto/ipsec/sa (404 on NDMS 5.01).
    Fallback: SA/runtime from GET show/crypto/map (phase1 / phase2_sa_list).
    """
    async with _get_client() as client:
        legacy = None
        legacy_error = None
        try:
            legacy = await client.rci_get(_RCI_PATHS["sa_legacy"])
        except Exception as exc:  # noqa: BLE001 — surface path availability
            legacy_error = str(exc).split("\n")[0][:200]
        statuses = _normalize_status_map(await client.rci_get(_RCI_PATHS["status_map"]))
    associations = []
    for name, entry in statuses.items():
        status = entry.get("status") if isinstance(entry.get("status"), dict) else {}
        phase2 = []
        phase2_sa_list = status.get("phase2_sa_list")
        if isinstance(phase2_sa_list, dict):
            raw = phase2_sa_list.get("phase2_sa") or []
            if isinstance(raw, list):
                phase2 = raw
            elif isinstance(raw, dict):
                phase2 = [raw]
        associations.append(_redact({
            "id": name,
            "state": status.get("state"),
            "ike_state": status.get("ike_state"),
            "phase1": status.get("phase1"),
            "phase2_sa": phase2,
            "enabled": (entry.get("config") or {}).get("enabled") if isinstance(entry.get("config"), dict) else None,
        }))
    return {
        "rci_paths": {
            "legacy_sa": _RCI_PATHS["sa_legacy"],
            "status_map": _RCI_PATHS["status_map"],
        },
        "legacy_sa_available": legacy is not None,
        "legacy_sa_error": legacy_error,
        "legacy_sa": _redact(legacy) if legacy not in (None, {}) else None,
        "established": sum(1 for item in associations if item.get("state") == "PHASE2_ESTABLISHED"),
        "count": len(associations),
        "sa": associations,
    }


async def show_ipsec() -> dict:
    """Safe dump of show/ipsec + site-to-site config/status (secrets redacted).

    RCI: show/ipsec, show/sc/crypto/ipsec/site-to-site, show/crypto/map
    """
    async with _get_client() as client:
        ipsec = await client.rci_get(_RCI_PATHS["ipsec"])
        configs, statuses = await _load_connections(client)
    return _redact({
        "rci_paths": {
            "ipsec": _RCI_PATHS["ipsec"],
            "connections": _RCI_PATHS["connections"],
            "status_map": _RCI_PATHS["status_map"],
        },
        "ipsec": ipsec,
        "site_to_site": configs,
        "crypto_map": statuses,
    })


async def show_crypto() -> dict:
    """Safe dump of show/crypto and show/sc/crypto (engine, maps; secrets redacted).

    RCI: show/crypto, show/sc/crypto, show/crypto/map
    """
    async with _get_client() as client:
        crypto = await client.rci_get(_RCI_PATHS["crypto"])
        sc_crypto = await client.rci_get(_RCI_PATHS["crypto_engine"])
        status_map = await client.rci_get(_RCI_PATHS["status_map"])
        ike = None
        ike_key = None
        try:
            ike = await client.rci_get("show/crypto/ike")
        except Exception:  # noqa: BLE001
            ike = None
        try:
            ike_key = await client.rci_get("show/crypto/ike/key")
        except Exception:  # noqa: BLE001
            ike_key = None
    return _redact({
        "rci_paths": {
            "crypto": _RCI_PATHS["crypto"],
            "sc_crypto": _RCI_PATHS["crypto_engine"],
            "status_map": _RCI_PATHS["status_map"],
            "ike": "show/crypto/ike",
            "ike_key": "show/crypto/ike/key",
        },
        "crypto": crypto,
        "sc_crypto": sc_crypto,
        "crypto_map": status_map,
        "ike": ike,
        "ike_key": ike_key,
    })


def register(mcp) -> None:
    mcp.tool()(list_ipsec)
    mcp.tool()(list_ipsec_connections)
    mcp.tool()(get_ipsec)
    mcp.tool()(list_ipsec_proposals)
    mcp.tool()(show_ipsec_sa)
    mcp.tool()(show_ipsec)
    mcp.tool()(show_crypto)
