"""System file download and backup export tools."""

import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import httpx

from ..client import _get_client, _raise_on_rci_errors

SYSTEM_FILES = {
    "startup-config": {"ci_path": "startup-config.txt", "is_text": True},
    "running-config": {"ci_path": "running-config.txt", "is_text": True},
    "default-config": {"ci_path": "default-config.txt", "is_text": True},
    "log": {"ci_path": "log.txt", "is_text": True},
    "self-test": {"ci_path": "self-test.txt", "is_text": True},
    "firmware": {"ci_path": "firmware", "is_text": False},
}


def _parse_config_header(text: str) -> dict | None:
    metadata: dict[str, str] = {}
    for line in text.splitlines():
        if not line.startswith("! $$$ "):
            if not line.strip() and metadata:
                break
            continue
        body = line[6:].strip()
        if ": " not in body:
            continue
        key, value = body.split(": ", 1)
        metadata[key.lower().replace(" ", "_")] = value
    return metadata or None


def _normalize_file_name(file_name: str) -> str:
    value = file_name.strip().lower()
    if value.endswith(".txt"):
        value = value[:-4]
    if value not in SYSTEM_FILES:
        raise ValueError(f"Unsupported system file: {file_name}")
    return value


def _save_bytes(data: bytes, save_path: str) -> str:
    path = Path(save_path.strip()).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return str(path)


async def _read_startup_config_via_parse(client) -> str:
    data = await client.rci({"parse": "more startup-config"})
    _raise_on_rci_errors(data)
    messages = (data.get("parse") or {}).get("message") or []
    if isinstance(messages, list):
        return "\n".join(str(line) for line in messages)
    return str(messages)


async def _download_system_file_from_client(
    client,
    *,
    file_name: str,
    save_path: str = "",
    include_base64: bool = False,
    include_text: bool = False,
) -> dict:
    normalized = _normalize_file_name(file_name)
    file_info = SYSTEM_FILES[normalized]
    ci_path = file_info["ci_path"]
    is_text = file_info["is_text"]
    try:
        data = await client.ci_get_bytes(ci_path)
    except httpx.HTTPStatusError:
        if normalized != "startup-config":
            raise
        text = await _read_startup_config_via_parse(client)
        data = text.encode("utf-8")
        used_fallback = True
    else:
        text = data.decode("utf-8", errors="replace") if is_text else ""
        used_fallback = False

    result = {
        key: value
        for key, value in {
            "name": normalized,
            "filename": ci_path,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "is_text": is_text,
            "metadata": _parse_config_header(text) if normalized in ("startup-config", "running-config") else None,
            "used_parse_fallback": True if used_fallback else None,
        }.items()
        if value is not None
    }
    if include_text and is_text:
        result["text"] = text
    if save_path.strip():
        result["saved_to"] = _save_bytes(data, save_path)
    if include_base64:
        result["content_base64"] = base64.b64encode(data).decode("ascii")
    if normalized == "firmware":
        version = await client.rci_get("show/version")
        result.update({
            key: value
            for key, value in {
                "model": version.get("model"),
                "firmware": version.get("release"),
                "title": version.get("title"),
                "source": "installed",
            }.items()
            if value is not None
        })
    return result


async def _update_channel_info(client, sandbox: str) -> dict | None:
    payload: dict = {"download": True}
    if sandbox.strip():
        payload["sandbox"] = sandbox.strip()
    data = await client.rci({"components": {"check-update": payload}})
    info = (data.get("components") or {}).get("check-update") or {}
    if not info:
        return None
    return {
        key: value
        for key, value in {
            "sandbox": info.get("sandbox"),
            "release": info.get("release"),
            "title": info.get("title"),
            "timestamp": info.get("timestamp"),
            "update_available": info.get("update-available"),
            "sandboxes": info.get("sandboxes"),
        }.items()
        if value is not None
    }


async def download_system_file(
    file_name: str,
    save_path: str = "",
    include_base64: bool = False,
    include_text: bool = False,
    sandbox: str = "",
) -> dict:
    """Download one system file (firmware/startup-config/running-config/default-config/log/self-test)."""
    async with _get_client() as client:
        result = await _download_system_file_from_client(
            client,
            file_name=file_name,
            save_path=save_path,
            include_base64=include_base64,
            include_text=include_text,
        )
        if sandbox.strip() and _normalize_file_name(file_name) == "firmware":
            channel = await _update_channel_info(client, sandbox)
            if channel:
                result["update_channel"] = channel
    return result


async def export_backup(
    files: list[str] | None = None,
    save_dir: str = "",
    include_base64: bool = False,
    include_text: bool = False,
    sandbox: str = "",
) -> dict:
    """Export selected system files plus router metadata."""
    async with _get_client() as client:
        version = await client.rci_get("show/version")
        selected_files = files or ["startup-config", "firmware"]
        exported_files = []
        for file_name in selected_files:
            normalized = _normalize_file_name(file_name)
            filename = SYSTEM_FILES[normalized]["ci_path"]
            file_save_path = ""
            if save_dir.strip():
                file_save_path = str(Path(save_dir.strip()).expanduser() / filename)
            exported_files.append(
                await _download_system_file_from_client(
                    client,
                    file_name=normalized,
                    save_path=file_save_path,
                    include_base64=include_base64,
                    include_text=include_text,
                )
            )
        result = {
            key: value
            for key, value in {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "model": version.get("model"),
                "firmware": version.get("release"),
                "title": version.get("title"),
                "arch": version.get("arch"),
                "files": exported_files,
            }.items()
            if value is not None
        }
        if sandbox.strip():
            channel = await _update_channel_info(client, sandbox)
            if channel:
                result["update_channel"] = channel
    return result


async def export_startup_config() -> dict:
    """Compatibility wrapper. Prefer download_system_file(file_name='startup-config')."""
    return await download_system_file(file_name="startup-config", include_text=True)


async def download_firmware(save_path: str = "", include_base64: bool = False, sandbox: str = "") -> dict:
    """Compatibility wrapper. Prefer download_system_file(file_name='firmware')."""
    return await download_system_file(
        file_name="firmware",
        save_path=save_path,
        include_base64=include_base64,
        sandbox=sandbox,
    )


def register(mcp) -> None:
    mcp.tool()(download_system_file)
    mcp.tool()(export_backup)
