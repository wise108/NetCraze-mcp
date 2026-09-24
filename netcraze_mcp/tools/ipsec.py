"""IPsec site-to-site tools (NDMS crypto map / site-to-site).

Read-only: list/get/proposals/show.
Write: create_ipsec_s2s / update_ipsec_s2s / set_ipsec_state / delete_ipsec.

NDMS 5.01 live rules (websun NC-1812):
- Write FLAT object with required \"name\" field — NEVER nested site-to-site.{name}.
- Do NOT enable via site-to-site.enable JSON (resets peer/autoconnect/…); use
  parse \"crypto map {name} enable\" / \"no crypto map {name} enable\".
- Verify with show/rc before save; show/sc is stale until save.
- ike-prf may stay empty in RC; force-encaps may be omitted from RC after set.
- Delete: flat {\"name\": …, \"no\": true} → \"removed crypto map.\"
"""

from __future__ import annotations

import re
from typing import Any

from ..client import _get_client, _raise_on_rci_errors, _sanitize_error
from ..config import assert_writable

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
    "connections_rc": "show/rc/crypto/ipsec/site-to-site",
    "status_map": "show/crypto/map",
    "crypto": "show/crypto",
    "ipsec": "show/ipsec",
    "crypto_engine": "show/sc/crypto",
    "sa_legacy": "show/crypto/ipsec/sa",
}

_ID_TYPES = frozenset({"dn", "address", "fqdn", "email"})
_IKE_PROTOCOLS = frozenset({"ikev1", "ikev2"})
# Fields NDMS may ignore — mismatch is warning, not fatal.
_SOFT_VERIFY_KEYS = frozenset({"ike-prf", "force-encaps"})
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


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


async def _load_rc_connections(client) -> dict[str, dict]:
    return _normalize_connections(await client.rci_get(_RCI_PATHS["connections_rc"]))


def _require_confirm(confirm: bool) -> None:
    if not confirm:
        raise ValueError("pass confirm=true to execute this IPsec write operation")


def _networks_csv(value: str | list[str]) -> str:
    if isinstance(value, list):
        parts = [str(item).strip() for item in value if str(item).strip()]
    else:
        parts = [part.strip() for part in str(value).split(",") if part.strip()]
    if not parts:
        raise ValueError("networks must be non-empty (CIDR or list of CIDRs)")
    return ",".join(parts)


def _validate_proposal(kind: str, value: str, allowed: list[str]) -> None:
    if value not in allowed:
        raise ValueError(
            f"Unsupported {kind}={value!r}. "
            f"See list_ipsec_proposals(); known: {', '.join(allowed[:8])}…"
        )


def _s2s_flat_payload(
    *,
    name: str,
    peer: str,
    ike_psk: str,
    local_id: str,
    remote_id: str,
    local_networks: str | list[str],
    remote_networks: str | list[str],
    ike_protocol: str = "ikev2",
    local_id_type: str = "dn",
    remote_id_type: str = "dn",
    ike_aead: bool = False,
    ike_encryption: str = "aes-cbc-256",
    ike_integrity: str = "sha256",
    ike_prf: str = "sha256",
    ike_dh: str = "14",
    ike_lifetime: str = "86400",
    ipsec_aead: bool = False,
    ipsec_encryption: str = "esp-aes-256",
    ipsec_integrity: str = "esp-sha256-hmac",
    ipsec_dh: str = "14",
    ipsec_lifetime: str = "28800",
    ike_mode: str = "main",
    ipsec_mode: str = "tunnel",
    dpd: bool = True,
    dpd_interval: str = "30",
    nail_up: bool = True,
    autoconnect: bool = True,
    passive: bool = False,
    force_encaps: bool | None = True,
) -> dict[str, Any]:
    """Build flat crypto.ipsec.site-to-site object (name field required; never nested)."""
    if not name or not _NAME_RE.match(name):
        raise ValueError("name must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
    if ike_protocol not in _IKE_PROTOCOLS:
        raise ValueError("ike_protocol must be ikev1 or ikev2")
    if local_id_type not in _ID_TYPES or remote_id_type not in _ID_TYPES:
        raise ValueError("id types must be one of dn|address|fqdn|email")
    if not str(ike_psk):
        raise ValueError("ike_psk is required")
    if not str(local_id).strip() or not str(remote_id).strip():
        raise ValueError("local_id and remote_id are required")
    if not str(ike_lifetime).strip() or not str(ipsec_lifetime).strip():
        raise ValueError("ike_lifetime and ipsec_lifetime are required (empty lifetime breaks NDMS)")

    peer_clean = (peer or "").strip()
    if not peer_clean:
        if passive:
            peer_clean = "any"
        else:
            raise ValueError("peer is required unless passive=True (then peer may be empty → any)")

    enc_list = _IKE_ENCRYPTION_AEAD if ike_aead else _IKE_ENCRYPTION
    esp_list = _ESP_ENCRYPTION_AEAD if ipsec_aead else _ESP_ENCRYPTION
    _validate_proposal("ike_encryption", ike_encryption, enc_list)
    if not ike_aead:
        _validate_proposal("ike_integrity", ike_integrity, _IKE_INTEGRITY)
    _validate_proposal("ike_prf", ike_prf, _IKE_PRF)
    _validate_proposal("ike_dh", str(ike_dh), _DH_GROUPS)
    _validate_proposal("ipsec_encryption", ipsec_encryption, esp_list)
    if not ipsec_aead:
        _validate_proposal("ipsec_integrity", ipsec_integrity, _ESP_INTEGRITY)
    _validate_proposal("ipsec_dh", str(ipsec_dh), _DH_GROUPS)

    payload: dict[str, Any] = {
        "name": name,
        "peer": peer_clean,
        "ike-protocol": ike_protocol,
        "ike-psk": ike_psk,
        "ike-local-id-type": local_id_type,
        "ike-local-id": local_id.strip(),
        "ike-remote-id-type": remote_id_type,
        "ike-remote-id": remote_id.strip(),
        "ipsec-local-networks": _networks_csv(local_networks),
        "ipsec-remote-networks": _networks_csv(remote_networks),
        "ike-aead": bool(ike_aead),
        "ike-encryption": ike_encryption,
        "ike-integrity": ike_integrity,
        "ike-prf": ike_prf,
        "ike-dh": str(ike_dh),
        "ike-lifetime": str(ike_lifetime).strip(),
        "ipsec-aead": bool(ipsec_aead),
        "ipsec-encryption": ipsec_encryption,
        "ipsec-integrity": ipsec_integrity,
        "ipsec-dh": str(ipsec_dh),
        "ipsec-lifetime": str(ipsec_lifetime).strip(),
        "dpd": bool(dpd),
        "dpd-interval": str(dpd_interval).strip(),
        "nail-up": bool(nail_up),
        "autoconnect": bool(autoconnect),
        "passive": bool(passive),
        "ike-mode": ike_mode,
        "ipsec-mode": ipsec_mode,
    }
    if force_encaps is not None:
        payload["force-encaps"] = bool(force_encaps)
    return payload


async def _apply_s2s(client, payload: dict[str, Any]) -> Any:
    """POST flat site-to-site (full field set). Never nested by name."""
    resp = await client.rci([{"crypto": {"ipsec": {"site-to-site": payload}}}])
    _raise_on_rci_errors(resp)
    return resp


async def _set_map_enabled(client, name: str, enabled: bool) -> Any:
    """Enable/disable crypto map via CLI parse — NOT via site-to-site.enable JSON."""
    if enabled:
        cmd = f"crypto map {name} enable"
    else:
        # Live NDMS 5.01: "crypto map X disable" → no such command;
        # working forms: "no crypto map X enable" / "crypto map X no enable"
        cmd = f"no crypto map {name} enable"
    resp = await client.rci({"parse": cmd})
    _raise_on_rci_errors(resp)
    return resp


async def _save_config(client) -> Any:
    resp = await client.rci({"system": {"configuration": {"save": {}}}})
    _raise_on_rci_errors(resp)
    return resp


def _verify_rc_against_payload(rc_cfg: dict, payload: dict[str, Any]) -> list[str]:
    """Compare RC config to sent payload; soft-ignore ike-prf / force-encaps."""
    warnings: list[str] = []
    check_keys = [
        "peer", "ike-protocol", "ike-local-id-type", "ike-local-id",
        "ike-remote-id-type", "ike-remote-id", "ipsec-local-networks",
        "ipsec-remote-networks", "ike-encryption", "ike-integrity", "ike-dh",
        "ike-lifetime", "ipsec-encryption", "ipsec-integrity", "ipsec-dh",
        "ipsec-lifetime", "ike-mode", "ipsec-mode", "dpd", "dpd-interval",
        "nail-up", "autoconnect", "passive", "ike-aead", "ipsec-aead",
        "ike-prf", "force-encaps",
    ]
    for key in check_keys:
        if key not in payload:
            continue
        expected = payload[key]
        actual = rc_cfg.get(key)
        if key in ("dpd", "nail-up", "autoconnect", "passive", "ike-aead", "ipsec-aead", "force-encaps"):
            expected_b = _as_bool(expected)
            actual_b = _as_bool(actual)
            if actual is None and key in _SOFT_VERIFY_KEYS:
                warnings.append(f"{key}: sent {expected!r}, absent in RC (known NDMS quirk)")
                continue
            if expected_b is not None and actual_b is not None and expected_b != actual_b:
                msg = f"{key}: sent {expected!r}, RC has {actual!r}"
                if key in _SOFT_VERIFY_KEYS:
                    warnings.append(msg)
                else:
                    raise RuntimeError(f"IPsec verify failed: {msg}")
            continue
        exp_s = str(expected)
        act_s = "" if actual is None else str(actual)
        if key in ("ipsec-local-networks", "ipsec-remote-networks"):
            if sorted(_split_subnets(exp_s)) != sorted(_split_subnets(act_s)):
                raise RuntimeError(
                    f"IPsec verify failed: {key}: sent {exp_s!r}, RC has {act_s!r}"
                )
            continue
        if exp_s != act_s:
            msg = f"{key}: sent {exp_s!r}, RC has {act_s!r}"
            if key in _SOFT_VERIFY_KEYS:
                warnings.append(msg + " (known NDMS quirk)")
            else:
                raise RuntimeError(f"IPsec verify failed: {msg}")
    if not rc_cfg.get("ike-psk"):
        warnings.append("ike-psk empty in RC after write")
    return warnings


async def _raw_psk_from_rc(client, name: str) -> str | None:
    """Read ike-psk from running-config for keep_psk rewrite. Never return to caller."""
    cfg = (await _load_rc_connections(client)).get(name) or {}
    psk = cfg.get("ike-psk")
    if psk in (None, "", False):
        return None
    return str(psk)


def _connection_summary_safe(name: str, config: dict, status: dict | None) -> dict:
    return _redact(_details(name, config, status))


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


async def create_ipsec_s2s(
    name: str,
    peer: str,
    ike_psk: str,
    local_id: str,
    remote_id: str,
    local_networks: str | list[str],
    remote_networks: str | list[str],
    ike_protocol: str = "ikev2",
    local_id_type: str = "dn",
    remote_id_type: str = "dn",
    ike_aead: bool = False,
    ike_encryption: str = "aes-cbc-256",
    ike_integrity: str = "sha256",
    ike_prf: str = "sha256",
    ike_dh: str = "14",
    ike_lifetime: str = "86400",
    ipsec_aead: bool = False,
    ipsec_encryption: str = "esp-aes-256",
    ipsec_integrity: str = "esp-sha256-hmac",
    ipsec_dh: str = "14",
    ipsec_lifetime: str = "28800",
    ike_mode: str = "main",
    ipsec_mode: str = "tunnel",
    dpd: bool = True,
    dpd_interval: str = "30",
    nail_up: bool = True,
    autoconnect: bool = True,
    passive: bool = False,
    force_encaps: bool | None = True,
    enable: bool = True,
    save: bool = True,
    confirm: bool = False,
) -> dict:
    """Create or update one IPsec S2S profile (idempotent by name). Requires confirm=true.

    NDMS 5.01: POST flat crypto.ipsec.site-to-site with \"name\" field (NOT nested
    site-to-site.{name}). Always sends full field set including lifetimes.
    Enable via parse \"crypto map {name} enable\" — never site-to-site.enable JSON.
    Verify show/rc before save; show/sc is stale until save.
    Known quirks: ike-prf may stay empty in RC; force-encaps may be omitted (NAT-T
    limitation — verify path with show/crypto/map if behind double-NAT).
    PSK is input-only and never returned (has_psk only).
    Does not touch WireGuard/ZeroTier/DNS/routes/firewall.
    """
    assert_writable()
    _require_confirm(confirm)
    try:
        payload = _s2s_flat_payload(
            name=name.strip(),
            peer=peer,
            ike_psk=ike_psk,
            local_id=local_id,
            remote_id=remote_id,
            local_networks=local_networks,
            remote_networks=remote_networks,
            ike_protocol=ike_protocol,
            local_id_type=local_id_type,
            remote_id_type=remote_id_type,
            ike_aead=ike_aead,
            ike_encryption=ike_encryption,
            ike_integrity=ike_integrity,
            ike_prf=ike_prf,
            ike_dh=ike_dh,
            ike_lifetime=ike_lifetime,
            ipsec_aead=ipsec_aead,
            ipsec_encryption=ipsec_encryption,
            ipsec_integrity=ipsec_integrity,
            ipsec_dh=ipsec_dh,
            ipsec_lifetime=ipsec_lifetime,
            ike_mode=ike_mode,
            ipsec_mode=ipsec_mode,
            dpd=dpd,
            dpd_interval=dpd_interval,
            nail_up=nail_up,
            autoconnect=autoconnect,
            passive=passive,
            force_encaps=force_encaps,
        )
        conn_name = payload["name"]
        async with _get_client() as client:
            before = await _load_rc_connections(client)
            existed = conn_name in before
            await _apply_s2s(client, payload)
            rc_after = await _load_rc_connections(client)
            if conn_name not in rc_after:
                raise RuntimeError(f"IPsec profile missing in show/rc after write: {conn_name}")
            warnings = _verify_rc_against_payload(rc_after[conn_name], payload)
            await _set_map_enabled(client, conn_name, enable)
            saved = False
            if save:
                await _save_config(client)
                saved = True
            sc, statuses = await _load_connections(client)
            if saved and conn_name not in sc:
                warnings.append("saved but profile missing from show/sc")
            status_entry = statuses.get(conn_name)
            summary = _connection_summary_safe(
                conn_name,
                sc.get(conn_name) or rc_after[conn_name],
                status_entry,
            )
        return _redact({
            **summary,
            "action": "updated" if existed else "created",
            "saved": saved,
            "enabled": enable,
            "warnings": warnings,
            "rci_notes": {
                "write": "flat crypto.ipsec.site-to-site with name field",
                "enable": "parse crypto map {name} enable|no … enable",
                "verify": "show/rc before save; show/sc after save",
            },
        })
    except Exception as exc:  # noqa: BLE001
        raise type(exc)(_sanitize_error(exc)) from None


async def update_ipsec_s2s(
    name: str,
    peer: str = "",
    ike_psk: str = "",
    local_id: str = "",
    remote_id: str = "",
    local_networks: str | list[str] = "",
    remote_networks: str | list[str] = "",
    keep_psk: bool = True,
    ike_protocol: str | None = None,
    local_id_type: str | None = None,
    remote_id_type: str | None = None,
    ike_aead: bool | None = None,
    ike_encryption: str | None = None,
    ike_integrity: str | None = None,
    ike_prf: str | None = None,
    ike_dh: str | None = None,
    ike_lifetime: str | None = None,
    ipsec_aead: bool | None = None,
    ipsec_encryption: str | None = None,
    ipsec_integrity: str | None = None,
    ipsec_dh: str | None = None,
    ipsec_lifetime: str | None = None,
    ike_mode: str | None = None,
    ipsec_mode: str | None = None,
    dpd: bool | None = None,
    dpd_interval: str | None = None,
    nail_up: bool | None = None,
    autoconnect: bool | None = None,
    passive: bool | None = None,
    force_encaps: bool | None = None,
    enable: bool | None = None,
    save: bool = True,
    confirm: bool = False,
) -> dict:
    """Full-replace update of an existing S2S profile (read-modify-write). Requires confirm=true.

    Always writes the complete flat field set (never partial enable JSON).
    keep_psk=True (default): reuse ike-psk from show/rc in memory only — never returned.
    Pass ike_psk to rotate the secret.
    """
    assert_writable()
    _require_confirm(confirm)
    if not name.strip():
        raise ValueError("name is required")
    conn_name = name.strip()
    try:
        async with _get_client() as client:
            rc = await _load_rc_connections(client)
            if conn_name not in rc:
                raise ValueError(f"IPsec connection not found in show/rc: {conn_name}")
            cur = rc[conn_name]
            psk = ike_psk
            if not psk:
                if keep_psk:
                    psk = await _raw_psk_from_rc(client, conn_name)
                if not psk:
                    raise ValueError("ike_psk required (RC has no PSK or keep_psk=False)")

            kwargs = {
                "name": conn_name,
                "peer": peer if peer != "" else (cur.get("peer") or ""),
                "ike_psk": psk,
                "local_id": local_id if local_id else str(cur.get("ike-local-id") or ""),
                "remote_id": remote_id if remote_id else str(cur.get("ike-remote-id") or ""),
                "local_networks": local_networks if local_networks not in ("", [], None) else str(cur.get("ipsec-local-networks") or ""),
                "remote_networks": remote_networks if remote_networks not in ("", [], None) else str(cur.get("ipsec-remote-networks") or ""),
                "ike_protocol": ike_protocol if ike_protocol is not None else str(cur.get("ike-protocol") or "ikev2"),
                "local_id_type": local_id_type if local_id_type is not None else str(cur.get("ike-local-id-type") or "dn"),
                "remote_id_type": remote_id_type if remote_id_type is not None else str(cur.get("ike-remote-id-type") or "dn"),
                "ike_aead": ike_aead if ike_aead is not None else bool(_as_bool(cur.get("ike-aead")) or False),
                "ike_encryption": ike_encryption if ike_encryption is not None else str(cur.get("ike-encryption") or "aes-cbc-256"),
                "ike_integrity": ike_integrity if ike_integrity is not None else str(cur.get("ike-integrity") or "sha256"),
                "ike_prf": ike_prf if ike_prf is not None else (str(cur.get("ike-prf") or "sha256") or "sha256"),
                "ike_dh": ike_dh if ike_dh is not None else str(cur.get("ike-dh") or "14"),
                "ike_lifetime": ike_lifetime if ike_lifetime is not None else str(cur.get("ike-lifetime") or "86400"),
                "ipsec_aead": ipsec_aead if ipsec_aead is not None else bool(_as_bool(cur.get("ipsec-aead")) or False),
                "ipsec_encryption": ipsec_encryption if ipsec_encryption is not None else str(cur.get("ipsec-encryption") or "esp-aes-256"),
                "ipsec_integrity": ipsec_integrity if ipsec_integrity is not None else str(cur.get("ipsec-integrity") or "esp-sha256-hmac"),
                "ipsec_dh": ipsec_dh if ipsec_dh is not None else str(cur.get("ipsec-dh") or "14"),
                "ipsec_lifetime": ipsec_lifetime if ipsec_lifetime is not None else str(cur.get("ipsec-lifetime") or "28800"),
                "ike_mode": ike_mode if ike_mode is not None else str(cur.get("ike-mode") or "main"),
                "ipsec_mode": ipsec_mode if ipsec_mode is not None else str(cur.get("ipsec-mode") or "tunnel"),
                "dpd": dpd if dpd is not None else bool(_as_bool(cur.get("dpd")) if cur.get("dpd") is not None else True),
                "dpd_interval": dpd_interval if dpd_interval is not None else str(cur.get("dpd-interval") or "30"),
                "nail_up": nail_up if nail_up is not None else bool(_as_bool(cur.get("nail-up")) if cur.get("nail-up") is not None else True),
                "autoconnect": autoconnect if autoconnect is not None else bool(_as_bool(cur.get("autoconnect")) if cur.get("autoconnect") is not None else True),
                "passive": passive if passive is not None else bool(_as_bool(cur.get("passive")) or False),
                "force_encaps": force_encaps if force_encaps is not None else (
                    _as_bool(cur.get("force-encaps")) if cur.get("force-encaps") is not None else True
                ),
            }
            payload = _s2s_flat_payload(**kwargs)
            await _apply_s2s(client, payload)
            rc_after = await _load_rc_connections(client)
            warnings = _verify_rc_against_payload(rc_after.get(conn_name) or {}, payload)
            if enable is not None:
                await _set_map_enabled(client, conn_name, enable)
            saved = False
            if save:
                await _save_config(client)
                saved = True
            sc, statuses = await _load_connections(client)
            summary = _connection_summary_safe(
                conn_name,
                sc.get(conn_name) or rc_after.get(conn_name) or {},
                statuses.get(conn_name),
            )
        return _redact({
            **summary,
            "action": "updated",
            "saved": saved,
            "enabled": enable,
            "warnings": warnings,
            "psk_rotated": bool(ike_psk),
        })
    except Exception as exc:  # noqa: BLE001
        raise type(exc)(_sanitize_error(exc)) from None


async def set_ipsec_state(
    name: str,
    enabled: bool,
    save: bool = True,
    confirm: bool = False,
) -> dict:
    """Enable/disable IPsec crypto map via parse only. Requires confirm=true.

    Uses \"crypto map {name} enable\" or \"no crypto map {name} enable\".
    Does NOT write site-to-site JSON with enable (that resets peer and other fields).
    """
    assert_writable()
    _require_confirm(confirm)
    if not name.strip():
        raise ValueError("name is required")
    conn_name = name.strip()
    try:
        async with _get_client() as client:
            rc = await _load_rc_connections(client)
            if conn_name not in rc:
                # also allow status-only maps
                statuses_pre = _normalize_status_map(await client.rci_get(_RCI_PATHS["status_map"]))
                if conn_name not in statuses_pre:
                    raise ValueError(f"IPsec connection not found: {conn_name}")
            await _set_map_enabled(client, conn_name, enabled)
            saved = False
            if save:
                await _save_config(client)
                saved = True
            sc, statuses = await _load_connections(client)
            summary = _connection_summary_safe(
                conn_name,
                sc.get(conn_name) or rc.get(conn_name) or {},
                statuses.get(conn_name),
            )
        return _redact({
            **summary,
            "action": "enabled" if enabled else "disabled",
            "saved": saved,
            "enabled": enabled,
        })
    except Exception as exc:  # noqa: BLE001
        raise type(exc)(_sanitize_error(exc)) from None


async def delete_ipsec(
    name: str,
    save: bool = True,
    confirm: bool = False,
) -> dict:
    """Delete IPsec S2S profile. Requires confirm=true.

    NDMS 5.01 confirmed: POST flat
    {\"crypto\":{\"ipsec\":{\"site-to-site\":{\"name\": name, \"no\": true}}}}
    → \"removed crypto map.\"
    Does not touch other VPN/DNS/routes.
    """
    assert_writable()
    _require_confirm(confirm)
    if not name.strip():
        raise ValueError("name is required")
    conn_name = name.strip()
    try:
        async with _get_client() as client:
            rc = await _load_rc_connections(client)
            if conn_name not in rc:
                raise ValueError(f"IPsec connection not found: {conn_name}")
            resp = await client.rci([{
                "crypto": {"ipsec": {"site-to-site": {"name": conn_name, "no": True}}},
            }])
            _raise_on_rci_errors(resp)
            rc_after = await _load_rc_connections(client)
            if conn_name in rc_after:
                raise RuntimeError(f"IPsec profile still in show/rc after delete: {conn_name}")
            saved = False
            if save:
                await _save_config(client)
                saved = True
            sc, statuses = await _load_connections(client)
            if conn_name in sc or conn_name in statuses:
                # map entry may linger briefly; warn if still in saved config after save
                if saved and conn_name in sc:
                    raise RuntimeError(f"IPsec profile still in show/sc after save: {conn_name}")
        return _redact({
            "deleted": True,
            "id": conn_name,
            "saved": saved,
        })
    except Exception as exc:  # noqa: BLE001
        raise type(exc)(_sanitize_error(exc)) from None


def register(mcp) -> None:
    mcp.tool()(list_ipsec)
    mcp.tool()(list_ipsec_connections)
    mcp.tool()(get_ipsec)
    mcp.tool()(list_ipsec_proposals)
    mcp.tool()(show_ipsec_sa)
    mcp.tool()(show_ipsec)
    mcp.tool()(show_crypto)
    mcp.tool()(create_ipsec_s2s)
    mcp.tool()(update_ipsec_s2s)
    mcp.tool()(set_ipsec_state)
    mcp.tool()(delete_ipsec)
