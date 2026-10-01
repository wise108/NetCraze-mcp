"""NDMS packet capture (component ``monitor``) lifecycle tools.

Research (websun NC-1812, NDMS 5.01) — live-proven:

rci_paths / CLI:
  create:  parse ``monitor capture interface {iface}``
  config:  buffer-size / capture-size / direction / filter \"{bpf}\"
  start:   parse ``monitor capture interface {iface} enable``
  stop:    parse ``no monitor capture interface {iface} enable``
  delete:  parse ``no monitor capture interface {iface}``
  status:  show monitor capture interface name={iface} status
  config:  show rc monitor
  download: GET /ci/{capture-file}  (e.g. temp:/run/monitor/….pcap, often gzip)

ndms_quirks:
  - Component id is ``monitor`` (UI: Packet capture).
  - start/stop are NOT ``start``/``stop`` CLI words — use enable / no enable.
  - BPF filter must be quoted in parse.
  - After stop, status.capture-file points at temp pcap; file may be gzip.
  - Nested JSON write for filter/buffer often fails («no input»); prefer parse.
  - Install may report «unavailable» on some channels while component already present.

unsupported:
  - Live packet preview without download (no show packet list API).
  - Autostart from diagnose_ipsec_bringup (intentionally not wired).
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import struct
from pathlib import Path
from typing import Any

from ..client import _get_client, _raise_on_rci_errors, _sanitize_error
from ..config import assert_writable

_IKE_BPF = "udp port 500 or udp port 4500"
_RESEARCH = {
    "rci_paths": {
        "status": "show monitor capture interface name={iface} status",
        "config": "show rc monitor",
        "start": "parse: monitor capture interface {iface} enable",
        "stop": "parse: no monitor capture interface {iface} enable",
        "delete": "parse: no monitor capture interface {iface}",
        "download": "GET /ci/{capture-file} (temp:/run/monitor/….pcap, often gzip)",
    },
    "ndms_quirks": [
        "enable/no enable = start/stop (no start/stop verbs)",
        "BPF filter must be quoted in parse",
        "pcap via /ci/temp:… often gzip-compressed",
    ],
    "unsupported": [
        "inline packet list without downloading pcap",
        "auto-install/start from diagnose_ipsec_bringup",
    ],
}


def _require_confirm(confirm: bool) -> None:
    if not confirm:
        raise PermissionError("confirm=true is required for this write operation")


def _as_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("yes", "true", "1", "on", "up"):
        return True
    if text in ("no", "false", "0", "off", "down"):
        return False
    return None


async def _installed_components(client) -> set[str]:
    version = await client.rci_get("show/version")
    return {
        part.strip()
        for part in str((version.get("ndw") or {}).get("components") or "").split(",")
        if part.strip()
    }


async def _parse(client, cmd: str) -> Any:
    resp = await client.rci({"parse": cmd})
    _raise_on_rci_errors(resp)
    return resp


def _build_bpf(filter: str = "", filter_preset: str = "", host: str = "") -> str:
    parts: list[str] = []
    preset = filter_preset.strip().lower()
    if preset in ("ike", "ipsec", "udp500"):
        parts.append(_IKE_BPF)
    if filter.strip():
        parts.append(filter.strip())
    if host.strip():
        parts.append(f"host {host.strip()}")
    if not parts:
        raise ValueError(
            "filter or filter_preset required "
            "(default capture of entire WAN is refused; use filter_preset='ike' or BPF)"
        )
    if len(parts) == 1:
        return parts[0]
    return " and ".join(f"({p})" for p in parts)


def _unwrap_status_payload(data: Any) -> dict[str, Any]:
    """Normalize show monitor capture interface … status to {iface: entry}."""
    cur = data
    if isinstance(cur, dict) and "show" in cur:
        cur = cur.get("show")
    # walk monitor.capture.interface.status.monitor.capture.interface
    for key in ("monitor", "capture", "interface", "status"):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
    if isinstance(cur, dict) and "monitor" in cur:
        cur = ((cur.get("monitor") or {}).get("capture") or {}).get("interface") or cur
    if not isinstance(cur, dict):
        return {}
    # error form
    if "status" in cur and isinstance(cur.get("status"), list):
        return {}
    if "id" in cur and "statistics" in cur:
        return {str(cur.get("id")): cur}
    return {k: v for k, v in cur.items() if isinstance(v, dict) and "statistics" in v}


def _entry_summary(iface: str, entry: dict, cfg: dict | None = None) -> dict:
    stats = entry.get("statistics") if isinstance(entry.get("statistics"), dict) else {}
    cfg = cfg if isinstance(cfg, dict) else {}
    filt = cfg.get("filter")
    if isinstance(filt, dict):
        filt = filt.get("bpf-program")
    buf = cfg.get("buffer-size")
    if isinstance(buf, dict):
        buf = buf.get("size-kb")
    cap = cfg.get("capture-size")
    if isinstance(cap, dict):
        cap = cap.get("size-kb")
    return {
        key: value
        for key, value in {
            "id": iface,
            "interface": iface,
            "running": bool(stats.get("started")),
            "packets": int(stats.get("frames-captured") or 0),
            "bytes": int(stats.get("bytes-captured") or 0),
            "frames_lost": int(stats.get("frames-lost") or 0),
            "frames_dropped": int(stats.get("frames-dropped") or 0),
            "started_at": stats.get("started-at"),
            "duration": stats.get("capture-duration"),
            "capture_file": entry.get("capture-file") or None,
            "stats_file": (stats.get("file") or None),
            "filter": filt or None,
            "direction": cfg.get("direction"),
            "buffer_size_kb": int(buf) if str(buf or "").isdigit() else buf,
            "capture_size_kb": int(cap) if str(cap or "").isdigit() else cap,
        }.items()
        if value is not None
    }


async def _load_rc_captures(client) -> dict[str, dict]:
    data = await client.rci({"show": {"rc": {"monitor": {}}}})
    mon = ((data.get("show") or {}).get("rc") or {}).get("monitor") or {}
    ifaces = ((mon.get("capture") or {}).get("interface") or {})
    return ifaces if isinstance(ifaces, dict) else {}


async def _status_one(client, iface: str) -> dict | None:
    data = await client.rci({
        "show": {"monitor": {"capture": {"interface": {"name": iface, "status": {}}}}},
    })
    mapped = _unwrap_status_payload(data)
    return mapped.get(iface)


async def _status_all(client) -> dict[str, dict]:
    rc = await _load_rc_captures(client)
    out: dict[str, dict] = {}
    for iface in rc:
        entry = await _status_one(client, iface)
        if entry:
            out[iface] = entry
    if out:
        return out
    # fallback: status without name
    data = await client.rci({"show": {"monitor": {"capture": {"interface": {"status": {}}}}}})
    return _unwrap_status_payload(data)


async def _iface_candidates(client) -> list[str]:
    raw = await client.rci_get("show/interface")
    if not isinstance(raw, dict):
        return []
    names = []
    for name, meta in raw.items():
        if not isinstance(name, str) or name.startswith("_"):
            continue
        if "/" in name and not name.startswith("GigabitEthernet0/"):
            # keep VLANs optional; prefer physical / WAN-like
            pass
        names.append(name)
    preferred = [n for n in names if n in ("GigabitEthernet1", "ISP", "Wan0") or n.startswith("GigabitEthernet")]
    rest = [n for n in names if n not in preferred]
    return (preferred + rest)[:40]


def _ensure_monitor(installed: set[str]) -> None:
    if "monitor" not in installed:
        raise RuntimeError(
            "install monitor first "
            "(ensure_packet_capture(confirm=true) or install_component(name='monitor', confirm=true))"
        )


async def get_packet_capture_status() -> dict:
    """Read-only: monitor component + capture availability / running state.

    Does not install components. Research paths in ``rci_paths``.
    """
    async with _get_client() as client:
        installed = await _installed_components(client)
        monitor_installed = "monitor" in installed
        supported: list[str] | None = None
        running = False
        captures: list[dict] = []
        probe_ok = False
        try:
            # existence probe — works even before instances
            await client.rci({"show": {"monitor": {"capture": {"interface": {"status": {}}}}}})
            probe_ok = True
        except Exception:  # noqa: BLE001
            probe_ok = False
        if monitor_installed or probe_ok:
            try:
                supported = await _iface_candidates(client)
            except Exception:  # noqa: BLE001
                supported = None
            try:
                statuses = await _status_all(client)
                rc = await _load_rc_captures(client)
                for iface, entry in statuses.items():
                    summary = _entry_summary(iface, entry, rc.get(iface))
                    captures.append(summary)
                    if summary.get("running"):
                        running = True
            except Exception:  # noqa: BLE001
                pass
        available = monitor_installed and probe_ok
        message = (
            "Packet capture available"
            if available
            else "Packet capture недоступен без установки компонента monitor"
        )
    return {
        "monitor_installed": monitor_installed,
        "capture_available": available,
        "capture_running": running,
        "captures": captures or None,
        "supported_interfaces": supported,
        "rci_paths": _RESEARCH["rci_paths"],
        "message": message,
    }


async def list_packet_captures() -> dict:
    """List configured capture instances (RC + live status)."""
    async with _get_client() as client:
        installed = await _installed_components(client)
        if "monitor" not in installed:
            return {
                "ok": False,
                "unsupported": False,
                "error": "monitor not installed",
                "items": [],
                "tried": ["show/version ndw.components", "show rc monitor"],
            }
        rc = await _load_rc_captures(client)
        statuses = await _status_all(client)
        items = [
            _entry_summary(iface, statuses.get(iface) or {}, rc.get(iface))
            for iface in sorted(set(rc) | set(statuses))
        ]
    return {"ok": True, "items": items, "count": len(items), "research": _RESEARCH}


async def get_packet_capture(id: str = "", name: str = "") -> dict:
    """Status of one capture instance (id/name = interface id, e.g. GigabitEthernet1)."""
    iface = (id or name or "").strip()
    if not iface:
        raise ValueError("id or name (interface) is required")
    async with _get_client() as client:
        installed = await _installed_components(client)
        if "monitor" not in installed:
            return {"ok": False, "error": "monitor not installed", "id": iface}
        rc = await _load_rc_captures(client)
        entry = await _status_one(client, iface)
        if entry is None and iface not in rc:
            return {
                "ok": False,
                "error": "not found",
                "id": iface,
                "available_ids": sorted(rc.keys()),
            }
        return {
            "ok": True,
            **_entry_summary(iface, entry or {}, rc.get(iface)),
        }


async def ensure_packet_capture(
    confirm: bool = False,
    install_if_missing: bool = True,
) -> dict:
    """Ensure monitor component is installed. Does not start capture. Requires confirm=true to install."""
    async with _get_client() as client:
        installed = await _installed_components(client)
        if "monitor" in installed:
            status = await get_packet_capture_status()
            return {
                "monitor_installed": True,
                "capture_available": bool(status.get("capture_available")),
                "installed_now": False,
                "message": "monitor already installed",
            }
        if not install_if_missing:
            return {
                "monitor_installed": False,
                "capture_available": False,
                "installed_now": False,
                "message": "monitor not installed; pass install_if_missing=true and confirm=true",
            }
        assert_writable()
        _require_confirm(confirm)
        from .components import install_component
        result = await install_component(name="monitor", commit=True, confirm=True)
        # re-check
        installed2 = await _installed_components(client)
        ok = "monitor" in installed2
        return {
            "monitor_installed": ok,
            "capture_available": ok,
            "installed_now": ok,
            "install_result": result,
            "message": (
                "monitor installed"
                if ok
                else "install attempted but monitor not in show/version components yet "
                "(channel may mark component unavailable — check UI Component options)"
            ),
        }


async def start_packet_capture(
    interface: str,
    filter: str = "",
    filter_preset: str = "",
    host: str = "",
    direction: str = "out",
    buffer_size_kb: int = 2048,
    capture_size_kb: int = 2048,
    max_packets: int | None = None,
    max_seconds: int | None = None,
    confirm: bool = False,
) -> dict:
    """Create/configure capture rule and start (enable). Requires confirm=true.

    NDMS: ``monitor capture interface {iface} enable`` starts capture.
    Default refuses empty filter — use filter_preset='ike' for UDP/500|4500.
    Optional max_seconds/max_packets auto-stop after start (still leaves instance configured).
    """
    assert_writable()
    _require_confirm(confirm)
    iface = interface.strip()
    if not iface:
        raise ValueError("interface is required")
    if direction not in ("in", "out", "in-out"):
        raise ValueError("direction must be in|out|in-out")
    bpf = _build_bpf(filter=filter, filter_preset=filter_preset, host=host)
    # escape for parse quotes
    bpf_q = bpf.replace('"', '\\"')
    try:
        async with _get_client() as client:
            installed = await _installed_components(client)
            _ensure_monitor(installed)
            rc = await _load_rc_captures(client)
            if iface not in rc:
                await _parse(client, f"monitor capture interface {iface}")
            await _parse(client, f"monitor capture interface {iface} buffer-size {int(buffer_size_kb)}")
            await _parse(client, f"monitor capture interface {iface} capture-size {int(capture_size_kb)}")
            await _parse(client, f"monitor capture interface {iface} direction {direction}")
            await _parse(client, f'monitor capture interface {iface} filter "{bpf_q}"')
            await _parse(client, f"monitor capture interface {iface} enable")

            if max_seconds or max_packets:
                deadline = asyncio.get_event_loop().time() + float(max_seconds or 30)
                while True:
                    entry = await _status_one(client, iface) or {}
                    stats = entry.get("statistics") or {}
                    frames = int(stats.get("frames-captured") or 0)
                    if max_packets is not None and frames >= int(max_packets):
                        break
                    if max_seconds is not None and asyncio.get_event_loop().time() >= deadline:
                        break
                    if not stats.get("started"):
                        break
                    await asyncio.sleep(1)
                await _parse(client, f"no monitor capture interface {iface} enable")

            entry = await _status_one(client, iface) or {}
            rc2 = await _load_rc_captures(client)
            summary = _entry_summary(iface, entry, rc2.get(iface))
        return {
            "ok": True,
            **summary,
            "filter": bpf,
            "running": bool(summary.get("running")),
            "auto_stopped": bool(max_seconds or max_packets),
            "rci_notes": _RESEARCH["rci_paths"],
        }
    except Exception as exc:  # noqa: BLE001
        raise type(exc)(_sanitize_error(exc)) from None


async def stop_packet_capture(id: str = "", name: str = "", confirm: bool = False) -> dict:
    """Stop capture via ``no monitor capture interface {iface} enable``. Requires confirm=true."""
    assert_writable()
    _require_confirm(confirm)
    iface = (id or name or "").strip()
    if not iface:
        raise ValueError("id or name (interface) is required")
    try:
        async with _get_client() as client:
            installed = await _installed_components(client)
            _ensure_monitor(installed)
            await _parse(client, f"no monitor capture interface {iface} enable")
            entry = await _status_one(client, iface) or {}
            rc = await _load_rc_captures(client)
            summary = _entry_summary(iface, entry, rc.get(iface))
        return {"ok": True, "stopped": True, **summary}
    except Exception as exc:  # noqa: BLE001
        raise type(exc)(_sanitize_error(exc)) from None


async def delete_packet_capture(id: str = "", name: str = "", confirm: bool = False) -> dict:
    """Remove capture instance (``no monitor capture interface {iface}``). Requires confirm=true."""
    assert_writable()
    _require_confirm(confirm)
    iface = (id or name or "").strip()
    if not iface:
        raise ValueError("id or name (interface) is required")
    try:
        async with _get_client() as client:
            installed = await _installed_components(client)
            _ensure_monitor(installed)
            await _parse(client, f"no monitor capture interface {iface}")
            rc = await _load_rc_captures(client)
            if iface in rc:
                raise RuntimeError(f"capture instance still in show/rc after delete: {iface}")
        return {"ok": True, "deleted": True, "id": iface}
    except Exception as exc:  # noqa: BLE001
        raise type(exc)(_sanitize_error(exc)) from None


def _decompress_maybe(data: bytes) -> bytes:
    if len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B:
        return gzip.decompress(data)
    return data


def _parse_pcap_preview(raw: bytes, max_packets: int = 50) -> dict:
    if len(raw) < 24:
        return {"packets_total": 0, "preview": [], "ike_summary": {}, "error": "pcap too short"}
    magic = struct.unpack("<I", raw[:4])[0]
    if magic in (0xA1B2C3D4, 0xA1B2CD34):
        endian = "<"
    elif magic in (0xD4C3B2A1, 0x34CDB2A1):
        endian = ">"
    else:
        return {
            "packets_total": 0,
            "preview": [],
            "ike_summary": {},
            "error": f"unsupported pcap magic {magic:#x} (pcapng not parsed)",
        }
    off = 24
    preview: list[dict] = []
    total = 0
    udp500_tx = udp500_rx = udp4500_tx = udp4500_rx = 0
    while off + 16 <= len(raw):
        _ts, _tu, incl, _orig = struct.unpack(endian + "IIII", raw[off : off + 16])
        pkt = raw[off + 16 : off + 16 + incl]
        off += 16 + incl
        if incl <= 0 or len(pkt) < incl:
            break
        total += 1
        ethertype = struct.unpack("!H", pkt[12:14])[0] if len(pkt) >= 14 else 0
        ip_off = 14
        if ethertype == 0x8100 and len(pkt) >= 18:
            ethertype = struct.unpack("!H", pkt[16:18])[0]
            ip_off = 18
        row: dict[str, Any] = {"len": incl}
        if ethertype == 0x0800 and len(pkt) >= ip_off + 20:
            ihl = (pkt[ip_off] & 0xF) * 4
            proto = pkt[ip_off + 9]
            src = ".".join(str(b) for b in pkt[ip_off + 12 : ip_off + 16])
            dst = ".".join(str(b) for b in pkt[ip_off + 16 : ip_off + 20])
            row.update({"src": src, "dst": dst, "proto": {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))})
            if proto == 17 and len(pkt) >= ip_off + ihl + 4:
                sport, dport = struct.unpack("!HH", pkt[ip_off + ihl : ip_off + ihl + 4])
                row["sport"] = sport
                row["dport"] = dport
                if sport == 500 or dport == 500:
                    # heuristic TX = sport 500 from local ephemerals often; count both ends
                    if dport == 500:
                        udp500_tx += 1
                    if sport == 500 and dport != 500:
                        udp500_rx += 1
                    if sport == 500 and dport == 500:
                        pass  # counted as tx above
                if sport == 4500 or dport == 4500:
                    if dport == 4500:
                        udp4500_tx += 1
                    if sport == 4500 and dport != 4500:
                        udp4500_rx += 1
        if len(preview) < max_packets:
            preview.append(row)
    return {
        "packets_total": total,
        "preview": preview,
        "ike_summary": {
            "udp500_tx": udp500_tx,
            "udp500_rx": udp500_rx,
            "udp4500_tx": udp4500_tx,
            "udp4500_rx": udp4500_rx,
        },
    }


async def download_packet_capture(
    id: str = "",
    name: str = "",
    format: str = "summary",
    max_packets_preview: int = 50,
    save_path: str = "",
    confirm: bool = False,
) -> dict:
    """Fetch capture pcap after stop. format=summary|pcap. Binary pcap requires confirm=true.

    Download path: GET /ci/{status.capture-file} (NDMS often returns gzip).
    """
    iface = (id or name or "").strip()
    if not iface:
        raise ValueError("id or name (interface) is required")
    fmt = format.strip().lower()
    if fmt not in ("summary", "pcap"):
        raise ValueError("format must be summary or pcap")
    if fmt == "pcap":
        assert_writable()  # treating binary export as sensitive op
        _require_confirm(confirm)
    try:
        async with _get_client() as client:
            installed = await _installed_components(client)
            _ensure_monitor(installed)
            entry = await _status_one(client, iface)
            if not entry:
                return {"ok": False, "error": "capture instance not found", "id": iface}
            if _as_bool((entry.get("statistics") or {}).get("started")):
                return {
                    "ok": False,
                    "error": "capture still running — stop_packet_capture first",
                    "id": iface,
                }
            cap_file = str(entry.get("capture-file") or "").strip()
            if not cap_file:
                return {
                    "ok": False,
                    "error": "no capture-file in status (start+stop a session first)",
                    "id": iface,
                    "packets": int((entry.get("statistics") or {}).get("frames-captured") or 0),
                }
            blob = await client.ci_get_bytes(cap_file)
            raw = _decompress_maybe(blob)
            result: dict[str, Any] = {
                "ok": True,
                "id": iface,
                "capture_file": cap_file,
                "size_bytes": len(blob),
                "uncompressed_bytes": len(raw),
                "gzip": blob is not raw or (len(blob) >= 2 and blob[0] == 0x1F),
                "sha256": hashlib.sha256(blob).hexdigest(),
            }
            if fmt == "summary":
                result.update(_parse_pcap_preview(raw, max_packets=max(1, int(max_packets_preview))))
            else:
                if save_path.strip():
                    path = Path(save_path.strip()).expanduser()
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw if raw[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4") else blob)
                    result["saved_to"] = str(path)
                    result["saved_bytes"] = path.stat().st_size
                else:
                    result["message"] = (
                        "pcap downloaded in memory; pass save_path to write file "
                        "(base64 omitted by default)"
                    )
                    result["pcap_sha256"] = hashlib.sha256(raw).hexdigest()
            return result
    except Exception as exc:  # noqa: BLE001
        raise type(exc)(_sanitize_error(exc)) from None


async def capture_flow_summary(
    interface: str,
    host: str = "",
    port: int | None = None,
    filter: str = "",
    filter_preset: str = "",
    duration_sec: int = 8,
    direction: str = "out",
    confirm: bool = False,
) -> dict:
    """High-level: start capture → wait → stop → summary parse → delete instance.

    Requires confirm=true (starts/stops monitor capture). Default returns summary only
    (no raw pcap in chat). Uses existing monitor lifecycle tools.
    """
    assert_writable()
    _require_confirm(confirm)
    iface = interface.strip()
    if not iface:
        raise ValueError("interface is required")
    duration_sec = max(2, min(int(duration_sec), 60))
    host_s = host.strip()
    port_i = int(port) if port is not None else None
    if not (filter.strip() or filter_preset.strip() or host_s or port_i):
        raise ValueError("provide filter, filter_preset, host, and/or port (refusing full-iface capture)")
    bpf_parts = []
    if filter.strip():
        bpf_parts.append(filter.strip())
    if host_s and port_i:
        bpf_parts.append(f"host {host_s} and port {port_i}")
    elif host_s:
        bpf_parts.append(f"host {host_s}")
    elif port_i:
        bpf_parts.append(f"port {port_i}")
    extra_filter = " and ".join(f"({p})" for p in bpf_parts) if bpf_parts else ""
    preset = filter_preset.strip()
    try:
        started = await start_packet_capture(
            interface=iface,
            filter=extra_filter,
            filter_preset=preset if not extra_filter else "",
            host="",
            direction=direction,
            max_seconds=duration_sec,
            confirm=True,
        )
        # auto_stopped already when max_seconds set; ensure stopped
        if started.get("running"):
            await stop_packet_capture(id=iface, confirm=True)
        summary = await download_packet_capture(
            id=iface,
            format="summary",
            max_packets_preview=40,
        )
        preview = summary.get("preview") or []
        talkers: dict[str, int] = {}
        syn = ack = 0
        for pkt in preview:
            src = pkt.get("src")
            dst = pkt.get("dst")
            if src:
                talkers[src] = talkers.get(src, 0) + 1
            if dst:
                talkers[dst] = talkers.get(dst, 0) + 1
            # TCP flags not in lightweight parser — leave 0
        top = sorted(talkers.items(), key=lambda item: item[1], reverse=True)[:10]
        deleted = await delete_packet_capture(id=iface, confirm=True)
        return {
            "ok": True,
            "interface": iface,
            "filter": started.get("filter"),
            "duration_sec": duration_sec,
            "packets": summary.get("packets_total") or started.get("packets") or 0,
            "ike_summary": summary.get("ike_summary"),
            "top_talkers": [{"ip": ip, "packets": n} for ip, n in top],
            "syn_count": syn,
            "ack_count": ack,
            "preview": preview[:20],
            "capture_file": summary.get("capture_file"),
            "cleaned_up": bool(deleted.get("deleted")),
            "note": "Raw pcap not inlined; use download_packet_capture(format=pcap) if needed before delete.",
        }
    except Exception as exc:  # noqa: BLE001
        # best-effort cleanup
        try:
            await stop_packet_capture(id=iface, confirm=True)
        except Exception:  # noqa: BLE001
            pass
        try:
            await delete_packet_capture(id=iface, confirm=True)
        except Exception:  # noqa: BLE001
            pass
        raise type(exc)(_sanitize_error(exc)) from None


def register(mcp) -> None:
    mcp.tool()(get_packet_capture_status)
    mcp.tool()(list_packet_captures)
    mcp.tool()(get_packet_capture)
    mcp.tool()(ensure_packet_capture)
    mcp.tool()(start_packet_capture)
    mcp.tool()(stop_packet_capture)
    mcp.tool()(download_packet_capture)
    mcp.tool()(delete_packet_capture)
    mcp.tool()(capture_flow_summary)
