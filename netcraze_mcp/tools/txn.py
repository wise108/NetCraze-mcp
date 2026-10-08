"""Config snapshot / diff / rollback hints / save / apply_cli_batch.

Safety: rollback never deletes interfaces. Bare ``interface X`` is context-only
(not a mutation). Inverse ``no interface X`` is deny-listed and never executed
without confirm_destructive=true (and even then prefer manual restore from
baseline snapshot / reboot from sc).
"""

from __future__ import annotations

import difflib
import re
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from ..client import _get_client, _raise_on_rci_errors
from ..config import assert_writable, save_payload
from ..redact import redact_cli_text
from .report import diag_report

_SNAPSHOTS: dict[str, dict[str, Any]] = {}
_SNAPSHOT_DIR = Path(tempfile.gettempdir()) / "netcraze-mcp-snapshots"

# Commands that only enter a config submode (not a mutation by themselves).
_CONTEXT_ENTER_RE = re.compile(
    r"^(interface|crypto\s+map|ip\s+access-list)\s+\S+\s*$",
    re.I,
)

# Top-level commands that must NOT be swallowed into an interface submode session.
_GLOBAL_CLI_RE = re.compile(
    r"^(?:"
    r"ip\s+route\b|"
    r"dns-proxy\b|"
    r"system\b|"
    r"crypto\b|"
    r"no\s+interface\b|"
    r"ip\s+access-list\b|"
    r"access-list\b|"
    r"object-group\b|"
    r"user\b|"
    r"service\b|"
    r"component\b|"
    r"schedule\b"
    r")",
    re.I,
)


def _is_global_command(command: str) -> bool:
    return bool(_GLOBAL_CLI_RE.match((command or "").strip()))

# Top-level CLI that must NOT be absorbed into an interface submode session.
_GLOBAL_CLI_RE = re.compile(
    r"^(?:"
    r"ip\s+route\b|no\s+ip\s+route\b|"
    r"dns-proxy\b|no\s+dns-proxy\b|"
    r"system\b|object-group\b|crypto\b|"
    r"access-list\b|ip\s+access-list\b|no\s+access-list\b|"
    r"user\b|component\b|service\b"
    r")",
    re.I,
)

# Inverse / rollback lines that must NEVER run unless confirm_destructive=true.
_DESTRUCTIVE_CLI_RE = re.compile(
    r"^(?:"
    r"no\s+interface\b|"
    r"interface\s+\S+\s*$|"  # bare enter — not an inverse, but never auto-run as rollback
    r"no\s+crypto\b|"
    r"no\s+ipsec\b|"
    r"no\s+wireguard\b|"
    r"crypto\s+ipsec\s+.*\bno\b|"
    r"system\s+configuration\s+save\b|"
    r"system\s+reboot\b|"
    r"system\s+(?:factory|reset)\b|"
    r"no\s+ip\s+global\b"
    r")",
    re.I,
)

# Source commands whose generic ``no <cmd>`` would be catastrophic — never invent inverse.
_NO_INVERSE_SOURCE_RE = re.compile(
    r"^(?:"
    r"interface\s+\S+\s*$|"  # bare context enter
    r"no\s+interface\b|"
    r"interface\s+\S+\s+(?:no\s+)?|"  # any interface-scoped line without known-safe pattern
    r"crypto\b|"
    r"ipsec\b|"
    r"wireguard\b|"
    r"system\s+(?:configuration|reboot|factory|reset)\b"
    r")",
    re.I,
)


def _require_confirm(confirm: bool) -> None:
    if not confirm:
        raise PermissionError("confirm=true is required for this write operation")


def _is_context_enter(command: str) -> bool:
    return bool(_CONTEXT_ENTER_RE.match((command or "").strip()))


def _is_destructive_cli(command: str) -> bool:
    cmd = (command or "").strip()
    if not cmd:
        return False
    if re.match(r"^no\s+interface\b", cmd, re.I):
        return True
    if _is_context_enter(cmd):
        return True  # never execute bare interface enter as a "rollback" alone
    return bool(_DESTRUCTIVE_CLI_RE.match(cmd))


def _inverse_cli(command: str) -> str | None:
    """Safe inverse of a single CLI line, or None if unknown/denied.

    NEVER returns ``no interface …`` (that deletes the whole interface).
    Bare ``interface X`` (context enter) → None.
    No generic ``no <cmd>`` fallback.
    """
    cmd = (command or "").strip()
    if not cmd:
        return None
    # Already a "no …" — only invert known safe patterns (rare).
    if cmd.lower().startswith("no "):
        rest = cmd[3:].strip()
        if re.match(r"^interface\b", rest, re.I):
            return None  # never invent "interface X" recreate from delete
        if re.match(r"^ip\s+route\b", rest, re.I):
            return rest
        if re.match(r"^dns-proxy\s+route\b", rest, re.I):
            return rest
        if re.match(r"^(access-list|ip\s+access-list)\b", rest, re.I):
            return rest
        return None

    if _is_context_enter(cmd):
        return None

    # Known-safe explicit inverses only
    if re.match(r"^interface\s+\S+\s+up\b", cmd, re.I):
        return re.sub(r"\bup\b", "down", cmd, count=1, flags=re.I)
    if re.match(r"^interface\s+\S+\s+down\b", cmd, re.I):
        return re.sub(r"\bdown\b", "up", cmd, count=1, flags=re.I)
    if re.match(r"^ip\s+route\b", cmd, re.I):
        return f"no {cmd}"
    if re.match(r"^dns-proxy\s+route\b", cmd, re.I):
        return f"no {cmd}"
    if re.match(r"^(access-list|ip\s+access-list)\b", cmd, re.I):
        return f"no {cmd}"
    # WG peer add in one line (rare) — still not interface delete
    if re.match(r"^interface\s+Wireguard\d+", cmd, re.I) and "peer" in cmd.lower():
        return f"no {cmd}"
    # ip tcp adjust-mss (usually inside interface context)
    if re.match(r"^ip\s+tcp\s+adjust-mss\b", cmd, re.I):
        return "no ip tcp adjust-mss"

    # Deny everything else — including bare interface / crypto / system
    if _NO_INVERSE_SOURCE_RE.match(cmd):
        return None
    return None


async def _fetch_running_config_text(client) -> str:
    raw = await client.rci_get("show/running-config")
    messages = []
    if isinstance(raw, dict):
        messages = raw.get("message") or []
        if isinstance(messages, str):
            messages = [messages]
    elif isinstance(raw, list):
        messages = [str(item) for item in raw]
    else:
        messages = [str(raw)]
    return redact_cli_text("\n".join(str(line) for line in messages))


def _parse_messages(data: Any) -> list[str]:
    found: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            msg = value.get("message")
            if isinstance(msg, list):
                found.extend(str(x) for x in msg)
            elif isinstance(msg, str):
                found.append(msg)
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(data)
    return found


def _normalize_blocks(commands: list[Any] | None) -> list[dict[str, Any]]:
    """Normalize flat strings and/or {context, lines} into session blocks.

    Flat ``interface X`` followed by non-context lines is grouped into one
    submode session (no exit between them).
    """
    raw = list(commands or [])
    blocks: list[dict[str, Any]] = []
    i = 0
    while i < len(raw):
        item = raw[i]
        if isinstance(item, dict):
            ctx = str(item.get("context") or "").strip() or None
            lines = [str(x).strip() for x in (item.get("lines") or []) if str(x).strip()]
            if ctx or lines:
                blocks.append({"context": ctx, "lines": lines})
            i += 1
            continue
        cmd = str(item).strip()
        if not cmd:
            i += 1
            continue
        if _is_context_enter(cmd):
            body: list[str] = []
            i += 1
            while i < len(raw):
                nxt = raw[i]
                if isinstance(nxt, dict):
                    break
                nxt_s = str(nxt).strip()
                if not nxt_s or nxt_s.lower() == "exit" or _is_context_enter(nxt_s):
                    if nxt_s.lower() == "exit":
                        i += 1
                    break
                if _is_global_command(nxt_s):
                    break
                body.append(nxt_s)
                i += 1
            blocks.append({"context": cmd, "lines": body})
            continue
        blocks.append({"context": None, "lines": [cmd]})
        i += 1
    return blocks


async def snapshot_config(label: str = "") -> dict:
    """Save redacted running-config to process memory + temp file; return snapshot id."""
    label_s = (label or "").strip() or "unnamed"
    async with _get_client() as client:
        text = await _fetch_running_config_text(client)
        path_used = getattr(client, "path_used", None)
    snap_id = f"snap-{uuid.uuid4().hex[:12]}"
    _SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    file_path = _SNAPSHOT_DIR / f"{snap_id}.txt"
    file_path.write_text(text, encoding="utf-8")
    entry = {
        "id": snap_id,
        "label": label_s,
        "created_at": time.time(),
        "lines": len(text.splitlines()),
        "config": text,
        "file": str(file_path),
        "path_used": path_used,
    }
    _SNAPSHOTS[snap_id] = entry
    return {
        "ok": True,
        "id": snap_id,
        "label": label_s,
        "lines": entry["lines"],
        "file": str(file_path),
        "path_used": path_used,
        "note": "Config stored redacted (secrets stripped).",
    }


def _load_snapshot(snapshot_id: str) -> dict[str, Any]:
    snap_id = (snapshot_id or "").strip()
    if snap_id in _SNAPSHOTS:
        return _SNAPSHOTS[snap_id]
    file_path = _SNAPSHOT_DIR / f"{snap_id}.txt"
    if file_path.is_file():
        text = file_path.read_text(encoding="utf-8")
        entry = {
            "id": snap_id,
            "label": "from-file",
            "created_at": file_path.stat().st_mtime,
            "lines": len(text.splitlines()),
            "config": text,
            "file": str(file_path),
        }
        _SNAPSHOTS[snap_id] = entry
        return entry
    raise ValueError(f"snapshot not found: {snap_id}")


async def diff_config(snapshot_id: str) -> dict:
    """Diff current running-config against a snapshot (both redacted)."""
    snap = _load_snapshot(snapshot_id)
    async with _get_client() as client:
        current = await _fetch_running_config_text(client)
    before = snap["config"].splitlines()
    after = current.splitlines()
    diff = list(difflib.unified_diff(
        before, after,
        fromfile=f"snapshot:{snap['id']}",
        tofile="running-config",
        lineterm="",
    ))
    return {
        "ok": True,
        "snapshot_id": snap["id"],
        "label": snap.get("label"),
        "changed": bool(diff),
        "diff_lines": len(diff),
        "diff": "\n".join(diff),
    }


async def rollback_hint(snapshot_id: str) -> dict:
    """Generate reverse CLI hints from diff vs snapshot. Does NOT execute.

    Filters out destructive inverses (``no interface …``, etc.).
    """
    snap = _load_snapshot(snapshot_id)
    async with _get_client() as client:
        current = await _fetch_running_config_text(client)
    before_set = set(line.strip() for line in snap["config"].splitlines() if line.strip() and not line.strip().startswith("!"))
    after_set = set(line.strip() for line in current.splitlines() if line.strip() and not line.strip().startswith("!"))
    added = sorted(after_set - before_set)
    removed = sorted(before_set - after_set)
    commands: list[str] = []
    skipped: list[str] = []
    for line in added:
        inv = _inverse_cli(line)
        if inv and not _is_destructive_cli(inv):
            commands.append(inv)
        elif inv and _is_destructive_cli(inv):
            skipped.append(inv)
        elif _is_context_enter(line) or re.match(r"^interface\s+\S+", line, re.I):
            skipped.append(f"(no safe inverse for: {line})")
    for line in removed:
        if _is_destructive_cli(line) or _is_context_enter(line):
            skipped.append(f"(skip re-add destructive/context: {line})")
            continue
        commands.append(line)
    return {
        "ok": True,
        "snapshot_id": snap["id"],
        "commands": commands,
        "skipped_destructive": skipped[:50],
        "added_since_snapshot": added[:100],
        "removed_since_snapshot": removed[:100],
        "note": (
            "Hints only — review before apply_cli_batch. "
            "Destructive inverses (no interface …) are omitted; "
            "use baseline_id + manual restore / reboot from sc."
        ),
    }


async def save_config(
    confirm: bool = False,
    check_paths: list[str] | None = None,
) -> dict:
    """Explicit system.configuration.save + post-check sc==rc for key paths.

    check_paths defaults to domain-lists, dns-routes, wireguard-allowed-ips.
    Verdict FAILED if dirty remains after save.
    """
    assert_writable()
    _require_confirm(confirm)
    paths = check_paths or ["domain-lists", "dns-routes", "wireguard-allowed-ips"]
    async with _get_client() as client:
        resp = await client.rci({"system": {"configuration": {"save": {}}}})
        _raise_on_rci_errors(resp)
    import asyncio
    await asyncio.sleep(0.3)
    from .dns_routes import diff_sc_rc
    diff = await diff_sc_rc(paths)
    dirty_parts = []
    for key, value in (diff.get("diffs") or {}).items():
        if isinstance(value, dict) and value.get("dirty"):
            dirty_parts.append(key)
        if isinstance(value, dict) and value.get("error"):
            dirty_parts.append(f"{key}:error")
    if dirty_parts:
        return diag_report(
            "FAILED",
            evidence=["system.configuration.save", {"diff_sc_rc": diff}],
            changes=["configuration save issued"],
            config_saved=True,
            ok=False,
            dirty_parts=dirty_parts,
            dirty_paths=dirty_parts,
            note="save returned but sc≠rc on checked paths — retry or inspect diff_sc_rc",
        )
    return diag_report(
        "saved",
        evidence=["system.configuration.save", {"diff_sc_rc": diff}],
        changes=["configuration saved"],
        config_saved=True,
        ok=True,
        dirty_paths=[],
    )


def _applied_record(context: str | None, command: str) -> dict[str, str]:
    return {"context": context or "", "command": command}


def _filter_rollback_commands(
    candidates: list[str],
    *,
    allow_destructive: bool,
    confirm_destructive: bool,
) -> tuple[list[str], list[str]]:
    """Split into executable vs denied rollback lines."""
    allowed: list[str] = []
    denied: list[str] = []
    for cmd in candidates:
        text = (cmd or "").strip()
        if not text:
            continue
        if _is_destructive_cli(text):
            if allow_destructive and confirm_destructive and re.match(r"^no\s+interface\b", text, re.I):
                allowed.append(text)
            else:
                denied.append(text)
            continue
        allowed.append(text)
    return allowed, denied


async def apply_cli_batch(
    commands: list[Any] | None = None,
    confirm: bool = False,
    verify: list[str] | None = None,
    rollback_on_fail: bool = False,
    allow_destructive_rollback: bool = False,
    confirm_destructive: bool = False,
    save: bool = False,
) -> dict:
    """Baseline snapshot → apply parse commands (with interface submode sessions) → verify.

    Safety:
    - rollback_on_fail defaults **false**. When true, only safe inverses run.
    - ``no interface …`` / bare ``interface X`` never executed as rollback unless
      allow_destructive_rollback=true AND confirm_destructive=true
      (``no interface`` only — still refuses treating context-enter as rollback).
    - Bare ``interface X`` is context-only: grouped with following subcommands;
      not recorded as a mutation; failed subcommand does not invent interface delete.
    - Prefer typed tools (e.g. set_interface_tcp_adjust_mss) over CLI for MSS.

    On unsafe/incomplete rollback: verdict=failed_needs_manual_restore + baseline_id.
    """
    assert_writable()
    _require_confirm(confirm)
    blocks = _normalize_blocks(commands)
    if not blocks:
        raise ValueError(
            "commands list is required "
            "(strings and/or {context, lines} blocks)"
        )
    verify_cmds = [str(c).strip() for c in (verify or []) if str(c).strip()]

    if rollback_on_fail and allow_destructive_rollback and not confirm_destructive:
        # allow flag alone is not enough for destructive lines — documented gate
        pass

    baseline = await snapshot_config(label="apply_cli_batch-baseline")
    applied: list[dict[str, str]] = []
    applied_flat: list[str] = []
    verify_results: list[dict] = []
    rolled_back = False
    rollback_cmds: list[str] = []
    rollback_denied: list[str] = []
    error: str | None = None
    needs_manual = False

    async with _get_client() as client:
        try:
            for block in blocks:
                context = block.get("context")
                lines = list(block.get("lines") or [])
                if context and not lines:
                    # Context-only with no body — do not apply (not a mutation)
                    continue
                if context:
                    payload: list[dict] = (
                        [{"parse": context}]
                        + [{"parse": line} for line in lines]
                        + [{"parse": "exit"}]
                    )
                else:
                    payload = []
                    for line in lines:
                        payload.extend([{"parse": line}, {"parse": "exit"}])
                resp = await client.rci(payload)
                try:
                    _raise_on_rci_errors(resp)
                except Exception as exc:  # noqa: BLE001
                    error = str(exc).split("\n")[0][:240]
                    # Do NOT record context enter as applied mutation
                    break
                for line in lines:
                    applied.append(_applied_record(context, line))
                    applied_flat.append(
                        f"{context} › {line}" if context else line
                    )

            if error is None:
                for vcmd in verify_cmds:
                    resp = await client.rci([{"parse": vcmd}, {"parse": "exit"}])
                    msgs = _parse_messages(resp)
                    ok = True
                    try:
                        _raise_on_rci_errors(resp)
                    except Exception as exc:  # noqa: BLE001
                        ok = False
                        error = str(exc).split("\n")[0][:200]
                    verify_results.append({"command": vcmd, "ok": ok, "messages": msgs[:20]})
                    if not ok:
                        break

            should_rollback = bool(
                rollback_on_fail
                and (error or any(not item["ok"] for item in verify_results))
            )
            if should_rollback:
                candidates: list[str] = []
                # Prefer inverse of applied mutations (with context awareness at exec time)
                for rec in reversed(applied):
                    inv = _inverse_cli(rec["command"])
                    if inv:
                        candidates.append(inv)
                # Optional non-destructive hints from snapshot diff
                try:
                    hint = await rollback_hint(baseline["id"])
                    for cmd in hint.get("commands") or []:
                        if cmd not in candidates:
                            candidates.append(cmd)
                except Exception:  # noqa: BLE001
                    pass

                allowed, denied = _filter_rollback_commands(
                    candidates,
                    allow_destructive=allow_destructive_rollback,
                    confirm_destructive=confirm_destructive,
                )
                rollback_denied = denied
                if denied and not allowed and applied:
                    needs_manual = True
                # Execute safe inverses only; wrap with original context when present
                for rcmd in allowed[:50]:
                    # find matching applied context for this inverse
                    ctx = None
                    for rec in applied:
                        inv = _inverse_cli(rec["command"])
                        if inv == rcmd and rec.get("context"):
                            ctx = rec["context"]
                            break
                    try:
                        if ctx:
                            resp = await client.rci([
                                {"parse": ctx},
                                {"parse": rcmd},
                                {"parse": "exit"},
                            ])
                        else:
                            resp = await client.rci([{"parse": rcmd}, {"parse": "exit"}])
                        _raise_on_rci_errors(resp)
                        rollback_cmds.append(
                            f"{ctx} › {rcmd}" if ctx else rcmd
                        )
                    except Exception:  # noqa: BLE001
                        continue
                rolled_back = bool(rollback_cmds)
                if denied:
                    needs_manual = True

            if save and not error and not any(not item["ok"] for item in verify_results):
                resp = await client.rci(save_payload(True))
                _raise_on_rci_errors(resp)
        except Exception as exc:  # noqa: BLE001
            error = str(exc).split("\n")[0][:240]
            if rollback_on_fail and applied:
                for rec in reversed(applied):
                    inv = _inverse_cli(rec["command"])
                    if not inv:
                        needs_manual = True
                        rollback_denied.append(rec["command"])
                        continue
                    if _is_destructive_cli(inv):
                        if not (allow_destructive_rollback and confirm_destructive):
                            needs_manual = True
                            rollback_denied.append(inv)
                            continue
                    try:
                        ctx = rec.get("context") or None
                        if ctx:
                            await client.rci([
                                {"parse": ctx},
                                {"parse": inv},
                                {"parse": "exit"},
                            ])
                        else:
                            await client.rci([{"parse": inv}, {"parse": "exit"}])
                        rollback_cmds.append(f"{ctx} › {inv}" if ctx else inv)
                        rolled_back = True
                    except Exception:  # noqa: BLE001
                        continue

    failed = bool(error or any(not item["ok"] for item in verify_results))
    if not failed:
        verdict = "ok"
    elif needs_manual and not rolled_back:
        verdict = "failed_needs_manual_restore"
    elif needs_manual and rolled_back:
        verdict = "partial_rollback_needs_manual_restore"
    elif rolled_back:
        verdict = "rolled_back"
    else:
        verdict = "failed"

    return diag_report(
        verdict,
        evidence=[
            {"baseline": baseline["id"]},
            {"verify": verify_results},
            {"error": error} if error else None,
            {"rollback_denied": rollback_denied} if rollback_denied else None,
        ],
        changes=[
            {"applied": applied_flat},
            {"rollback": rollback_cmds},
        ],
        config_saved=bool(save and verdict == "ok"),
        ok=verdict == "ok",
        baseline_id=baseline["id"],
        applied=applied_flat,
        applied_records=applied,
        verify=verify_results,
        rolled_back=rolled_back,
        rollback_commands=rollback_cmds,
        rollback_denied=rollback_denied,
        error=error,
        save=save,
        rollback_on_fail=rollback_on_fail,
        note=(
            "Rollback never deletes interfaces. Failed interface subcommands leave "
            "baseline_id for manual restore / reboot from sc. "
            "Prefer set_interface_tcp_adjust_mss over CLI for MSS clamp."
        ),
    )


def register(mcp) -> None:
    mcp.tool()(snapshot_config)
    mcp.tool()(diff_config)
    mcp.tool()(rollback_hint)
    mcp.tool()(save_config)
    mcp.tool()(apply_cli_batch)
