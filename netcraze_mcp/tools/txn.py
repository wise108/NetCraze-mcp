"""Config snapshot / diff / rollback hints / save / apply_cli_batch."""

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


def _require_confirm(confirm: bool) -> None:
    if not confirm:
        raise PermissionError("confirm=true is required for this write operation")


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


def _inverse_cli(command: str) -> str | None:
    """Best-effort inverse of a single CLI line (hint only, not executed blindly)."""
    cmd = command.strip()
    if not cmd:
        return None
    if cmd.startswith("no "):
        return cmd[3:].strip()
    # common NDMS patterns
    if re.match(r"^interface\s+\S+\s+up\b", cmd, re.I):
        return re.sub(r"\bup\b", "down", cmd, count=1, flags=re.I)
    if re.match(r"^interface\s+\S+\s+down\b", cmd, re.I):
        return re.sub(r"\bdown\b", "up", cmd, count=1, flags=re.I)
    if re.match(r"^ip\s+route\b", cmd, re.I):
        return f"no {cmd}"
    if re.match(r"^dns-proxy\s+route\b", cmd, re.I):
        return f"no {cmd}"
    if re.match(r"^interface\s+Wireguard\d+", cmd, re.I) and "peer" in cmd.lower():
        return f"no {cmd}"
    if re.match(r"^(access-list|ip\s+access-list)\b", cmd, re.I):
        return f"no {cmd}"
    # generic: prefix with no
    if not cmd.lower().startswith("no "):
        return f"no {cmd}"
    return None


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
    """Generate reverse CLI hints from diff vs snapshot. Does NOT execute."""
    snap = _load_snapshot(snapshot_id)
    async with _get_client() as client:
        current = await _fetch_running_config_text(client)
    before_set = set(line.strip() for line in snap["config"].splitlines() if line.strip() and not line.strip().startswith("!"))
    after_set = set(line.strip() for line in current.splitlines() if line.strip() and not line.strip().startswith("!"))
    added = sorted(after_set - before_set)
    removed = sorted(before_set - after_set)
    commands: list[str] = []
    for line in added:
        inv = _inverse_cli(line)
        if inv:
            commands.append(inv)
    for line in removed:
        # re-add removed lines
        commands.append(line)
    return {
        "ok": True,
        "snapshot_id": snap["id"],
        "commands": commands,
        "added_since_snapshot": added[:100],
        "removed_since_snapshot": removed[:100],
        "note": "Hints only — review before apply_cli_batch. Heuristic inverses may be incomplete.",
    }


async def save_config(confirm: bool = False) -> dict:
    """Explicit system.configuration.save. Requires confirm=true."""
    assert_writable()
    _require_confirm(confirm)
    async with _get_client() as client:
        resp = await client.rci({"system": {"configuration": {"save": {}}}})
        _raise_on_rci_errors(resp)
    return diag_report(
        "saved",
        evidence=["system.configuration.save"],
        changes=["configuration saved"],
        config_saved=True,
        ok=True,
    )


async def apply_cli_batch(
    commands: list[str] | None = None,
    confirm: bool = False,
    verify: list[str] | None = None,
    rollback_on_fail: bool = True,
    save: bool = False,
) -> dict:
    """Baseline snapshot → apply parse commands → verify → optional rollback.

    Requires confirm=true. save defaults False.
    """
    assert_writable()
    _require_confirm(confirm)
    cmds = [str(c).strip() for c in (commands or []) if str(c).strip()]
    if not cmds:
        raise ValueError("commands list is required")
    verify_cmds = [str(c).strip() for c in (verify or []) if str(c).strip()]

    baseline = await snapshot_config(label="apply_cli_batch-baseline")
    applied: list[str] = []
    verify_results: list[dict] = []
    rolled_back = False
    rollback_cmds: list[str] = []
    error: str | None = None

    async with _get_client() as client:
        try:
            for cmd in cmds:
                # leave config contexts between commands
                payload = [{"parse": cmd}, {"parse": "exit"}]
                resp = await client.rci(payload)
                _raise_on_rci_errors(resp)
                applied.append(cmd)
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
            if any(not item["ok"] for item in verify_results) and rollback_on_fail:
                hint = await rollback_hint(baseline["id"])
                rollback_cmds = list(hint.get("commands") or [])
                # Prefer inverse of applied commands first
                for cmd in reversed(applied):
                    inv = _inverse_cli(cmd)
                    if inv and inv not in rollback_cmds:
                        rollback_cmds.insert(0, inv)
                for rcmd in rollback_cmds[:50]:
                    try:
                        resp = await client.rci([{"parse": rcmd}, {"parse": "exit"}])
                        _raise_on_rci_errors(resp)
                    except Exception:  # noqa: BLE001
                        continue
                rolled_back = True
            if save and not rolled_back and not error:
                resp = await client.rci(save_payload(True))
                _raise_on_rci_errors(resp)
        except Exception as exc:  # noqa: BLE001
            error = str(exc).split("\n")[0][:240]
            if rollback_on_fail and applied:
                for cmd in reversed(applied):
                    inv = _inverse_cli(cmd)
                    if not inv:
                        continue
                    rollback_cmds.append(inv)
                    try:
                        await client.rci([{"parse": inv}, {"parse": "exit"}])
                    except Exception:  # noqa: BLE001
                        continue
                rolled_back = True

    verdict = "ok"
    if error or any(not item["ok"] for item in verify_results):
        verdict = "rolled_back" if rolled_back else "failed"
    return diag_report(
        verdict,
        evidence=[
            {"baseline": baseline["id"]},
            {"verify": verify_results},
            {"error": error} if error else None,
        ],
        changes=[{"applied": applied}, {"rollback": rollback_cmds if rolled_back else []}],
        config_saved=bool(save and verdict == "ok"),
        ok=verdict == "ok",
        baseline_id=baseline["id"],
        applied=applied,
        verify=verify_results,
        rolled_back=rolled_back,
        rollback_commands=rollback_cmds,
        error=error,
        save=save,
    )


def register(mcp) -> None:
    mcp.tool()(snapshot_config)
    mcp.tool()(diff_config)
    mcp.tool()(rollback_hint)
    mcp.tool()(save_config)
    mcp.tool()(apply_cli_batch)
