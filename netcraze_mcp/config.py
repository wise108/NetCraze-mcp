"""Runtime configuration helpers and multi-router registry."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_config: dict[str, bool | None] = {"safe_mode": None}
_routers_cache: dict[str, "RouterSpec"] | None = None


@dataclass
class RouterSpec:
    """One named router endpoint (alias → connection params)."""

    alias: str
    host: str
    user: str = "admin"
    password: str = ""
    scheme: str = "http"
    port: int | None = None
    verify_tls: bool = True
    fallback_hosts: list[str] = field(default_factory=list)
    timeout: float = 15.0
    connect_timeout: float = 8.0

    def base_url_for(self, host: str) -> str:
        host_s = (host or "").strip()
        if "://" in host_s:
            return host_s.rstrip("/")
        port = self.port
        # host may already include :port
        if ":" in host_s and not host_s.count(":") > 1:
            netloc = host_s
        elif port:
            netloc = f"{host_s}:{port}"
        else:
            netloc = host_s
        return f"{self.scheme}://{netloc}"

    def host_candidates(self) -> list[str]:
        seen: list[str] = []
        for item in [self.host, *self.fallback_hosts]:
            h = (item or "").strip()
            if h and h not in seen:
                seen.append(h)
        return seen


def configure(*, safe_mode: bool | None = None) -> None:
    """Configure the MCP server programmatically."""
    global _routers_cache
    _config["safe_mode"] = safe_mode
    _routers_cache = None


def is_safe_mode() -> bool:
    """Resolve effective safe mode flag."""
    if _config["safe_mode"] is not None:
        return bool(_config["safe_mode"])
    return os.environ.get("NETCRAZE_SAFE_MODE", "true").lower() in ("1", "true", "yes")


def assert_writable() -> None:
    """Raise PermissionError when running in safe mode."""
    if is_safe_mode():
        raise PermissionError(
            "The server is running in safe mode. Write operations are not allowed."
        )


def _parse_host_field(raw: str, *, default_scheme: str = "http") -> tuple[str, str, int | None]:
    """Return (scheme, host_or_netloc_without_scheme, port)."""
    text = (raw or "").strip()
    if not text:
        return default_scheme, "", None
    if "://" not in text:
        # host or host:port
        if text.count(":") == 1:
            host, port_s = text.rsplit(":", 1)
            try:
                return default_scheme, host, int(port_s)
            except ValueError:
                return default_scheme, text, None
        return default_scheme, text, None
    parsed = urlparse(text)
    scheme = parsed.scheme or default_scheme
    host = parsed.hostname or ""
    port = parsed.port
    return scheme, host, port


def _spec_from_mapping(alias: str, data: dict[str, Any]) -> RouterSpec:
    host_raw = str(data.get("host") or data.get("url") or "").strip()
    scheme_default = str(data.get("scheme") or "http")
    scheme, host, port_from_host = _parse_host_field(host_raw, default_scheme=scheme_default)
    port = data.get("port", port_from_host)
    if port is not None:
        port = int(port)
    fallback = data.get("fallback_hosts") or data.get("fallbacks") or []
    if isinstance(fallback, str):
        fallback = [x.strip() for x in fallback.split(",") if x.strip()]
    verify = data.get("verify_tls", data.get("verify", True))
    if isinstance(verify, str):
        verify = verify.lower() in ("1", "true", "yes")
    return RouterSpec(
        alias=alias,
        host=host or host_raw,
        user=str(data.get("user") or data.get("username") or "admin"),
        password=str(data.get("password") or data.get("pass") or ""),
        scheme=str(data.get("scheme") or scheme or "http"),
        port=port,
        verify_tls=bool(verify),
        fallback_hosts=[str(x) for x in fallback],
        timeout=float(data.get("timeout") or 15.0),
        connect_timeout=float(data.get("connect_timeout") or 8.0),
    )


def _load_creds_file(path: str | Path) -> dict[str, Any]:
    text = Path(path).expanduser().read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"creds file must be a JSON object: {path}")
    return data


def _legacy_default_spec() -> RouterSpec | None:
    host_raw = os.environ.get("NETCRAZE_HOST", "").strip()
    password = os.environ.get("NETCRAZE_PASS", "")
    if not host_raw:
        # also try NETCRAZE_CREDS_FILE
        creds = os.environ.get("NETCRAZE_CREDS_FILE", "").strip()
        if creds and Path(creds).expanduser().is_file():
            data = _load_creds_file(creds)
            return _spec_from_mapping("default", data)
        return None
    scheme_env = os.environ.get("NETCRAZE_SCHEME", "http")
    scheme, host, port = _parse_host_field(host_raw, default_scheme=scheme_env)
    verify_raw = os.environ.get("NETCRAZE_VERIFY_TLS", "true")
    fallback_raw = os.environ.get("NETCRAZE_FALLBACK_HOSTS", "")
    fallbacks = [x.strip() for x in fallback_raw.split(",") if x.strip()]
    return RouterSpec(
        alias="default",
        host=host or host_raw,
        user=os.environ.get("NETCRAZE_USER", "admin"),
        password=password,
        scheme=scheme,
        port=port or (int(os.environ["NETCRAZE_PORT"]) if os.environ.get("NETCRAZE_PORT") else None),
        verify_tls=verify_raw.lower() in ("1", "true", "yes"),
        fallback_hosts=fallbacks,
    )


def load_routers(*, force: bool = False) -> dict[str, RouterSpec]:
    """Load router registry from NETCRAZE_ROUTERS and/or legacy single-host env."""
    global _routers_cache
    if _routers_cache is not None and not force:
        return _routers_cache

    routers: dict[str, RouterSpec] = {}
    raw = os.environ.get("NETCRAZE_ROUTERS", "").strip()
    if raw:
        if raw.startswith("{") or raw.startswith("["):
            parsed = json.loads(raw)
        else:
            # comma/newline separated creds file paths
            paths = [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]
            parsed = {}
            for path in paths:
                data = _load_creds_file(path)
                alias = str(data.get("alias") or Path(path).stem)
                parsed[alias] = data
        if isinstance(parsed, dict):
            for alias, value in parsed.items():
                if isinstance(value, str):
                    # path to creds file
                    data = _load_creds_file(value)
                    routers[alias] = _spec_from_mapping(alias, data)
                elif isinstance(value, dict):
                    routers[alias] = _spec_from_mapping(alias, value)
        elif isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, str):
                    data = _load_creds_file(item)
                    alias = str(data.get("alias") or Path(item).stem)
                    routers[alias] = _spec_from_mapping(alias, data)
                elif isinstance(item, dict):
                    alias = str(item.get("alias") or item.get("name") or f"router{len(routers)}")
                    routers[alias] = _spec_from_mapping(alias, item)

    legacy = _legacy_default_spec()
    if legacy and (legacy.password or legacy.host):
        routers.setdefault("default", legacy)

    _routers_cache = routers
    return routers


def list_routers() -> list[dict[str, Any]]:
    """Public summary of configured routers (no passwords)."""
    out = []
    for alias, spec in load_routers().items():
        out.append({
            "alias": alias,
            "host": spec.host,
            "scheme": spec.scheme,
            "port": spec.port,
            "verify_tls": spec.verify_tls,
            "fallback_hosts": list(spec.fallback_hosts),
            "user": spec.user,
        })
    return out


def get_router(alias: str | None = None) -> RouterSpec:
    """Resolve router by alias; empty alias → default / sole entry."""
    routers = load_routers()
    if not routers:
        raise RuntimeError(
            "No routers configured. Set NETCRAZE_HOST/NETCRAZE_PASS or NETCRAZE_ROUTERS."
        )
    name = (alias or "").strip()
    if not name:
        if "default" in routers:
            return routers["default"]
        if len(routers) == 1:
            return next(iter(routers.values()))
        raise RuntimeError(
            "Multiple routers configured; pass router=<alias>. "
            f"Available: {sorted(routers)}"
        )
    if name not in routers:
        raise RuntimeError(f"Unknown router alias '{name}'. Available: {sorted(routers)}")
    spec = routers[name]
    if not spec.password:
        raise RuntimeError(f"Router '{name}' has empty password")
    return spec


def save_payload(save: bool) -> list[dict]:
    """Return RCI save batch fragment when save is True."""
    if not save:
        return []
    return [{"system": {"configuration": {"save": {}}}}]
