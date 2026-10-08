"""Cross-router reachability helpers."""

from __future__ import annotations

from ..router_ctx import reset_current_router, set_current_router
from .diagnostics import router_ping
from .report import diag_report


async def cross_router_reachability(
    src_router: str,
    dst_ip: str,
    port: int | None = None,
    proto: str = "icmp",
    dst_router: str = "",
    capture_interface: str = "",
    capture_seconds: float = 3.0,
    confirm: bool = False,
) -> dict:
    """Ping from src_router to dst_ip; optional short capture on dst_router (confirm=true)."""
    src = (src_router or "").strip()
    dst = (dst_ip or "").strip()
    if not src or not dst:
        raise ValueError("src_router and dst_ip are required")
    proto_s = (proto or "icmp").strip().lower()
    evidence = []
    changes = []

    token = set_current_router(src)
    try:
        if proto_s in ("icmp", "ping", ""):
            ping = await router_ping(dst, count=3)
            evidence.append({"ping": ping})
            ping_ok = bool(ping.get("ok"))
        else:
            ping = {
                "ok": False,
                "unsupported": True,
                "note": f"proto={proto_s} not executable from router RCI; ICMP used as fallback",
            }
            evidence.append({"ping_fallback": ping, "requested_proto": proto_s, "port": port})
            ping2 = await router_ping(dst, count=3)
            evidence.append({"ping": ping2})
            ping_ok = bool(ping2.get("ok"))
    finally:
        reset_current_router(token)

    capture_summary = None
    dst_alias = (dst_router or "").strip()
    iface = (capture_interface or "").strip()
    if dst_alias and iface and confirm:
        from .capture import capture_flow_summary
        src_ip = await _src_hint(src)
        token = set_current_router(dst_alias)
        try:
            capture_summary = await capture_flow_summary(
                interface=iface,
                host=src_ip or "",
                filter="" if src_ip else f"host {dst}",
                duration_sec=max(2, min(int(capture_seconds), 15)),
                confirm=True,
            )
            evidence.append({"capture": capture_summary})
            changes.append("temporary packet capture started/stopped/deleted")
        except Exception as exc:  # noqa: BLE001
            evidence.append({"capture_error": str(exc).split("\n")[0][:200]})
        finally:
            reset_current_router(token)
    elif dst_alias and iface and not confirm:
        evidence.append({
            "capture_skipped": "pass confirm=true to run capture_flow_summary on dst_router",
        })

    verdict = "ok" if ping_ok else "unreachable"
    return diag_report(
        verdict,
        evidence=evidence,
        changes=changes,
        config_saved=False,
        ok=ping_ok,
        src_router=src,
        dst_ip=dst,
        port=port,
        proto=proto_s,
    )


async def _src_hint(src_router: str) -> str | None:
    """Best-effort source IP for capture filter (ZeroTier/LAN)."""
    try:
        from .network import get_interfaces
        token = set_current_router(src_router)
        try:
            ifaces = await get_interfaces()
        finally:
            reset_current_router(token)
        for item in ifaces:
            if item.get("type") == "ZeroTier" and item.get("address"):
                return str(item["address"])
        for item in ifaces:
            if item.get("address") and item.get("type") in ("Bridge", "GigabitEthernet"):
                return str(item["address"])
    except Exception:  # noqa: BLE001
        return None
    return None


def register(mcp) -> None:
    mcp.tool()(cross_router_reachability)
