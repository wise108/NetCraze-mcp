"""Unified diagnostic report format for NetCraze tools."""

from __future__ import annotations

from typing import Any


def diag_report(
    verdict: str,
    *,
    evidence: list[Any] | None = None,
    changes: list[Any] | None = None,
    config_saved: bool = False,
    **extra: Any,
) -> dict:
    """Standard shape: {verdict, evidence[], changes[], config_saved, …}."""
    out: dict[str, Any] = {
        "verdict": verdict,
        "evidence": list(evidence or []),
        "changes": list(changes or []),
        "config_saved": bool(config_saved),
    }
    out.update(extra)
    return out
