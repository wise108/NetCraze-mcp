"""Per-call router alias context for multi-router MCP tools."""

from __future__ import annotations

import functools
import inspect
from contextvars import ContextVar
from typing import Any, Callable

_current_router: ContextVar[str] = ContextVar("netcraze_router", default="")


def get_current_router() -> str:
    return _current_router.get() or ""


def set_current_router(alias: str):
    return _current_router.set((alias or "").strip())


def reset_current_router(token) -> None:
    _current_router.reset(token)


def with_router_param(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Inject optional ``router: str = ""`` into a tool without changing its body.

    Sets contextvar for the duration of the call so ``_get_client()`` picks the alias.
    """
    if getattr(fn, "_netcraze_router_wrapped", False):
        return fn

    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def async_wrapper(*args: Any, router: str = "", **kwargs: Any) -> Any:
            token = set_current_router(router)
            try:
                return await fn(*args, **kwargs)
            finally:
                reset_current_router(token)

        async_wrapper._netcraze_router_wrapped = True  # type: ignore[attr-defined]
        # Rebuild signature so FastMCP advertises router=
        try:
            sig = inspect.signature(fn)
            params = list(sig.parameters.values())
            if "router" not in sig.parameters:
                params.append(
                    inspect.Parameter(
                        "router",
                        inspect.Parameter.KEYWORD_ONLY,
                        default="",
                        annotation=str,
                    )
                )
            async_wrapper.__signature__ = sig.replace(parameters=params)  # type: ignore[attr-defined]
        except (TypeError, ValueError):
            pass
        return async_wrapper

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, router: str = "", **kwargs: Any) -> Any:
        token = set_current_router(router)
        try:
            return fn(*args, **kwargs)
        finally:
            reset_current_router(token)

    sync_wrapper._netcraze_router_wrapped = True  # type: ignore[attr-defined]
    try:
        sig = inspect.signature(fn)
        params = list(sig.parameters.values())
        if "router" not in sig.parameters:
            params.append(
                inspect.Parameter(
                    "router",
                    inspect.Parameter.KEYWORD_ONLY,
                    default="",
                    annotation=str,
                )
            )
        sync_wrapper.__signature__ = sig.replace(parameters=params)  # type: ignore[attr-defined]
    except (TypeError, ValueError):
        pass
    return sync_wrapper
