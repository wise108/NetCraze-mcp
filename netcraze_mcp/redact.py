"""Shared secret redaction for RCI JSON and running-config text."""

from __future__ import annotations

import re
from typing import Any

# Keys that must never leave the MCP (JSON responses).
_SECRET_KEY_RE = re.compile(
    r"(?i)(^|[_-])("
    r"password|passwd|passphrase|secret|token|api[_-]?key|"
    r"psk|pre[_-]?shared|ike[_-]?psk|xauth[_-]?password|"
    r"private[_-]?key|preshared[_-]?key|wireguard[_-]?private|"
    r"zerotier[_-]?(token|secret)|backup[_-]?key|encryption[_-]?key"
    r")($|[_-])"
)

# Paths blocked by rci_get_safe (substring match).
_SAFE_DENY_PATH_RE = re.compile(
    r"(?i)("
    r"password|passphrase|passwd|"
    r"private([-_/]?key)?|"
    r"\bpsk\b|pre[-_]?shared|ike[-_]?psk|"
    r"secret|token|"
    r"ipsec\.secrets|"
    r"wireguard/.+private|"
    r"zerotier/.+(token|secret)|"
    r"backup/.+key|"
    r"/auth\b"
    r")"
)

_CLI_SECRET_LINE_RE = re.compile(
    r"(?i)^(\s*(?:.*\s)?(?:"
    r"password|passphrase|private-key|preshared-key|pre-shared-key|"
    r"psk|secret|token|encryption-key|ike-psk"
    r")\s+)(\S+)(.*)$"
)
_WG_KEY_RE = re.compile(r"[A-Za-z0-9+/]{42,44}=")


def is_secret_key(key: str) -> bool:
    return bool(_SECRET_KEY_RE.search(str(key).replace("-", "_")))


def is_denied_safe_path(path: str) -> bool:
    """True if path must not be fetched via rci_get_safe."""
    normalized = path.strip().lstrip("/")
    if normalized.lower().startswith("rci/"):
        normalized = normalized[4:]
    return bool(_SAFE_DENY_PATH_RE.search(normalized))


def redact_value(value: Any) -> Any:
    """Recursively redact secret fields in JSON-like structures."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if is_secret_key(str(key)):
                if item in (None, "", False):
                    out[key] = item
                elif item is True:
                    out[key] = True
                else:
                    out[key] = "<REDACTED>"
            else:
                out[key] = redact_value(item)
        return out
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return _WG_KEY_RE.sub("<REDACTED>", value)
    return value


def redact_cli_text(text: str) -> str:
    """Strip secrets from running-config / CLI dump lines."""
    lines: list[str] = []
    for line in text.splitlines():
        match = _CLI_SECRET_LINE_RE.match(line)
        if match:
            lines.append(f"{match.group(1)}<REDACTED>{match.group(3)}")
            continue
        lines.append(_WG_KEY_RE.sub("<REDACTED>", line))
    return "\n".join(lines)


def normalize_rci_path(path: str) -> str:
    """Normalize to path under /rci/ without leading slash or rci/ prefix."""
    cleaned = (path or "").strip().lstrip("/")
    if cleaned.lower().startswith("rci/"):
        cleaned = cleaned[4:]
    if not cleaned:
        raise ValueError("path is required (e.g. show/system)")
    if ".." in cleaned.split("/"):
        raise ValueError("path must not contain '..'")
    return cleaned
