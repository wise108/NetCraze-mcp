"""Runtime configuration helpers."""

import os

_config: dict[str, bool | None] = {"safe_mode": None}


def configure(*, safe_mode: bool | None = None) -> None:
    """Configure the MCP server programmatically."""
    _config["safe_mode"] = safe_mode


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
