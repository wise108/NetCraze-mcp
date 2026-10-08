"""Raw RCI parse helpers (read-only whitelist + write via apply_cli_batch)."""

from __future__ import annotations

import re
from typing import Any

from ..client import _get_client, _raise_on_rci_errors
from ..config import assert_writable
from ..redact import redact_cli_text, redact_value
from .txn import apply_cli_batch

_READONLY_PREFIXES = (
    "show ",
    "show\t",
    "tools ping",
    "tools traceroute",
    "help ",
    "help\t",
)

_MUTATING_HINTS = re.compile(
    r"(?i)\b(no\s+|interface\s+\S+\s+(up|down)|ip\s+route|dns-proxy\s+route|"
    r"crypto\s+|object-group|system\s+configuration\s+save|access-list)\b"
)


def _is_readonly_command(command: str) -> bool:
    cmd = " ".join(command.strip().split())
    lower = cmd.lower()
    if lower in ("help", "show", "exit", "end"):
        return True
    return any(lower.startswith(p.strip()) for p in (
        "show", "tools ping", "tools traceroute", "help",
    ))


def _collect_messages(data: Any) -> list[str]:
    found: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            msg = value.get("message")
            if isinstance(msg, list):
                found.extend(str(x) for x in msg)
            elif isinstance(msg, str):
                found.append(msg)
            status = value.get("status")
            if isinstance(status, list):
                for item in status:
                    if isinstance(item, dict) and item.get("message"):
                        found.append(str(item.get("message")))
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(data)
    return found


async def rci_parse_readonly(command: str) -> dict:
    """POST {\"parse\": cmd} for whitelisted read-only prefixes only.

    Always issues ``exit`` after the command. Responses are redacted.
    """
    cmd = (command or "").strip()
    if not cmd:
        raise ValueError("command is required")
    if not _is_readonly_command(cmd):
        raise PermissionError(
            "rci_parse_readonly only allows show / tools ping|traceroute / help. "
            "Use rci_parse_write(confirm=true) for mutating commands."
        )
    if _MUTATING_HINTS.search(cmd) and not cmd.lower().startswith(("show", "help", "tools")):
        raise PermissionError("command looks mutating; refused by readonly parse")

    async with _get_client() as client:
        # leave any config context first
        await client.rci([{"parse": "exit"}])
        resp = await client.rci([{"parse": cmd}, {"parse": "exit"}])
    messages = [redact_cli_text(m) for m in _collect_messages(resp)]
    return redact_value({
        "ok": True,
        "command": cmd,
        "messages": messages,
        "raw": redact_value(resp),
        "note": "read-only parse; secrets redacted",
    })


async def cli_help(command_prefix: str) -> dict:
    """Probe NDMS help without executing mutating forms.

    NDMS has no ``?`` completion. Tries ``help <cmd>`` and an incomplete
    command, classifying supported / not_supported / unknown from errors.
    """
    prefix = (command_prefix or "").strip()
    if not prefix:
        raise ValueError("command_prefix is required")
    # Never send "?" — NDMS: no such command
    probes = [
        f"help {prefix}",
        prefix,  # incomplete often yields argument parse error with usage hints
    ]
    results = []
    classification = "unknown"
    async with _get_client() as client:
        await client.rci([{"parse": "exit"}])
        for probe in probes:
            try:
                resp = await client.rci([{"parse": probe}, {"parse": "exit"}])
                msgs = [redact_cli_text(m) for m in _collect_messages(resp)]
                err = None
                try:
                    _raise_on_rci_errors(resp)
                except Exception as exc:  # noqa: BLE001
                    err = str(exc).split("\n")[0][:240]
                blob = " ".join(msgs + ([err] if err else [])).lower()
                entry = {
                    "probe": probe,
                    "messages": msgs[:30],
                    "error": err,
                }
                results.append(entry)
                if "no such command" in blob and "?" in probe:
                    continue
                if any(x in blob for x in (
                    "invalid", "argument parse error", "expected", "usage", "incomplete",
                )):
                    classification = "supported"
                elif err is None and msgs:
                    classification = "supported"
                elif "no such command" in blob:
                    classification = "not_supported"
            except Exception as exc:  # noqa: BLE001
                results.append({
                    "probe": probe,
                    "messages": [],
                    "error": redact_cli_text(str(exc).split("\n")[0][:240]),
                })

    return {
        "ok": True,
        "command_prefix": prefix,
        "classification": classification,
        "supported": classification == "supported",
        "not_supported": classification == "not_supported",
        "unknown": classification == "unknown",
        "probes": results,
        "note": (
            "NDMS does not support '?'; mutating forms are never sent for probing. "
            "Treat 'unknown' as inconclusive — do not invent syntax."
        ),
    }


async def rci_parse_write(
    commands: list[str] | None = None,
    confirm: bool = False,
    save: bool = False,
    verify: list[str] | None = None,
    rollback_on_fail: bool = True,
) -> dict:
    """Mutating parse commands via apply_cli_batch. Requires confirm=true."""
    assert_writable()
    return await apply_cli_batch(
        commands=commands,
        confirm=confirm,
        verify=verify,
        rollback_on_fail=rollback_on_fail,
        save=save,
    )


def register(mcp) -> None:
    mcp.tool()(rci_parse_readonly)
    mcp.tool()(cli_help)
    mcp.tool()(rci_parse_write)
