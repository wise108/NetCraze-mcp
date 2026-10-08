"""Policy path / flow verification tools for dns-proxy → WG diagnostics."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any
from urllib.request import urlopen

from ..client import _get_client
from ..redact import redact_value
from . import sc_rc
from .datapath import _best_route, _domain_matches
from .diagnostics import router_ping
from .firewall import get_conntrack
from .policy import get_policy_tables
from .report import diag_report
from .wireguard import get_wireguard, get_wireguard_runtime


def _iface_address(ifaces: Any, iface_id: str | None) -> str | None:
    if not iface_id or not isinstance(ifaces, dict):
        return None
    node = ifaces.get(iface_id)
    if isinstance(node, dict) and node.get("address"):
        return str(node["address"])
    for value in ifaces.values():
        if isinstance(value, dict) and (value.get("id") or value.get("interface-name")) == iface_id:
            if value.get("address"):
                return str(value["address"])
    return None


def _match_policy_for_links(
    tables: list[dict],
    linked_routes: list[dict],
    all_dns_routes: list[dict],
) -> list[dict]:
    """Return at most one policy table per linked dns-route (not every WG0 table).

    Prefer unique list_key hit in linked_dns_proxy_routes; if many tables share the
    same iface (common on NDMS), zip sorted table4 ↔ dns-route index for that iface.
    """
    out: list[dict] = []
    seen_table: set[Any] = set()

    def _tables_for_iface(iface: str) -> list[dict]:
        return sorted(
            [
                t for t in tables
                if any((d or {}).get("interface") == iface for d in (t.get("materialized_default") or []))
            ],
            key=lambda t: (t.get("table4") is None, t.get("table4") or 0),
        )

    def _routes_for_iface(iface: str) -> list[dict]:
        return sorted(
            [
                r for r in all_dns_routes
                if isinstance(r, dict)
                and r.get("interface") == iface
                and not r.get("disable", False)
            ],
            key=lambda r: str(r.get("index") or r.get("group") or ""),
        )

    for link in linked_routes:
        list_key = link.get("list_key")
        iface = link.get("interface")
        exact = []
        for table in tables:
            for lr in table.get("linked_dns_proxy_routes") or []:
                if not isinstance(lr, dict):
                    continue
                if (lr.get("list_key") == list_key or lr.get("group") == list_key) and (
                    not iface or lr.get("interface") == iface
                ):
                    # unique ownership: table links ONLY this route (or sole link)
                    owned = [
                        x for x in (table.get("linked_dns_proxy_routes") or [])
                        if isinstance(x, dict)
                    ]
                    if len(owned) == 1 or all(
                        (x.get("list_key") or x.get("group")) == list_key for x in owned
                    ):
                        exact.append(table)
                    break
        chosen = None
        matched_via = "list_key"
        if len(exact) == 1:
            chosen = exact[0]
        elif iface:
            same_tables = _tables_for_iface(str(iface))
            same_routes = _routes_for_iface(str(iface))
            idx = next(
                (i for i, r in enumerate(same_routes) if r.get("group") == list_key),
                None,
            )
            if idx is not None and idx < len(same_tables):
                chosen = same_tables[idx]
                matched_via = "iface_order"
            elif len(same_tables) == 1:
                chosen = same_tables[0]
                matched_via = "iface_single"
            elif len(exact) > 1:
                chosen = sorted(exact, key=lambda t: (t.get("table4") is None, t.get("table4") or 0))[0]
                matched_via = "list_key_first"
        if chosen is None:
            continue
        tid = chosen.get("table4") or chosen.get("id")
        if tid in seen_table:
            continue
        seen_table.add(tid)
        out.append({
            "table4": chosen.get("table4"),
            "fwmark": chosen.get("fwmark") or chosen.get("mark"),
            "ON_LINK_DEFAULT": chosen.get("ON_LINK_DEFAULT"),
            "interface": iface,
            "list_key": list_key,
            "list_name": link.get("list_name"),
            "gateway_configured": link.get("gateway") or None,
            "matched_via": matched_via,
        })
    return out


async def explain_policy_path(
    destination: str,
    source_ip: str = "",
) -> dict:
    """Explain dns-proxy policy path for IP or hostname (not bare FIB LPM alone).

    Limitation: bare IP on explain_route only sees main table — use this tool instead
    when traffic is steered by object-group / dns-proxy / fwmark.

    expected_dst_out = egress iface address (live SNAT under ON_LINK_DEFAULT), not
    dns-proxy gateway. gateway_configured is reported separately.
    """
    dest = (destination or "").strip()
    if not dest:
        raise ValueError("destination ip or hostname is required")
    src = (source_ip or "").strip() or None

    resolved_ip = None
    host = None
    try:
        resolved_ip = str(ipaddress.ip_address(dest))
    except ValueError:
        host = dest.lower().rstrip(".")
        from .diagnostics import router_nslookup
        ns = await router_nslookup(host)
        addrs = ns.get("addresses") or []
        if not addrs or isinstance(addrs, dict):
            return {"ok": False, "error": "hostname did not resolve", "nslookup": ns}
        resolved_ip = str(addrs[0])

    async with _get_client() as client:
        groups, src_lists = await sc_rc.fetch_fqdn_groups(client, prefer="rc")
        routes, _ = await sc_rc.fetch_dns_routes(client, prefer="rc")
        fib = await client.rci_get("show/ip/route")
        ifaces = await client.rci_get("show/interface")

    fib_routes = fib if isinstance(fib, list) else (fib.get("route") if isinstance(fib, dict) else [])
    if not isinstance(fib_routes, list):
        fib_routes = [fib_routes] if fib_routes else []
    best = _best_route(resolved_ip, [
        {k: r.get(k) for k in ("destination", "gateway", "interface", "metric", "flags", "proto") if r.get(k) is not None}
        for r in fib_routes if isinstance(r, dict)
    ])

    list_hits = []
    for key, value in groups.items():
        if not isinstance(value, dict):
            continue
        name = value.get("description", key)
        for entry in sc_rc.normalize_include(value.get("include")):
            hit = False
            if entry["type"] in ("IP", "CIDR"):
                hit = sc_rc.cidr_covers(entry["address"], resolved_ip)
            elif host and entry["type"] == "FQDN":
                hit = _domain_matches(entry["address"], host)
            if hit:
                list_hits.append({
                    "list_key": key,
                    "list_name": name,
                    "entry": entry["address"],
                    "type": entry["type"],
                })

    linked_routes = []
    for hit in list_hits:
        for route in routes:
            if route.get("group") == hit["list_key"] and not route.get("disable", False):
                linked_routes.append({
                    **hit,
                    "interface": route.get("interface"),
                    "gateway": route.get("gateway") or None,
                    "auto": route.get("auto"),
                    "index": route.get("index"),
                })

    tables = await get_policy_tables()
    policy_match = _match_policy_for_links(
        tables.get("tables") or [],
        linked_routes,
        routes if isinstance(routes, list) else [],
    )

    expect_iface = (linked_routes[0].get("interface") if linked_routes else None)
    expect_gw = (linked_routes[0].get("gateway") if linked_routes else None)
    # Under ON_LINK_DEFAULT live SNAT dst_out is the WG iface address, not dns-proxy gateway
    expected_dst_out = _iface_address(ifaces, expect_iface)
    expected_path_class = sc_rc.path_class_from_dst_out(expected_dst_out) if expected_dst_out else (
        "WG0" if expect_iface and str(expect_iface).startswith("Wireguard") else ("WAN" if not expect_iface else "OTHER")
    )

    live_nat = None
    try:
        ct = await get_conntrack(host=resolved_ip, port=None, protocol="", limit=20)
        live_nat = ct.get("sessions") or []
    except Exception as exc:  # noqa: BLE001
        live_nat = {"error": str(exc).split("\n")[0][:160]}

    # classify
    if linked_routes:
        iface = linked_routes[0].get("interface") or ""
        if str(iface).startswith("Wireguard"):
            if iface in ("Wireguard0", "Wireguard1"):
                verdict = "HAPP/WG"
            else:
                verdict = "WG"
            confidence = "high" if list_hits else "medium"
        elif iface:
            verdict = "OTHER"
            confidence = "medium"
        else:
            verdict = "WAN"
            confidence = "low"
    else:
        verdict = "WAN"
        confidence = "medium" if best else "low"

    # refine with live NAT
    if isinstance(live_nat, list) and live_nat:
        dst_outs = {str(s.get("dst_out")) for s in live_nat if s.get("dst_out")}
        path_classes = {sc_rc.path_class_from_dst_out(x) for x in dst_outs}
        if "WG0" in path_classes and verdict.startswith("WAN"):
            verdict = "HAPP/WG"
            confidence = "high"
        elif path_classes == {"WAN"} and verdict.startswith("HAPP"):
            confidence = "conflict"

    return redact_value({
        "ok": True,
        "destination": dest,
        "resolved_ip": resolved_ip,
        "source_ip": src,
        "fib_lpm": best,
        "domain_list_hits": list_hits,
        "dns_proxy_routes": linked_routes,
        "policy": policy_match,
        "expected_dst_out": expected_dst_out,
        "expected_path_class": expected_path_class,
        "expected_interface": expect_iface,
        "gateway_configured": expect_gw,
        "live_nat_sessions": live_nat if isinstance(live_nat, list) else [],
        "live_nat_error": live_nat.get("error") if isinstance(live_nat, dict) else None,
        "verdict": verdict,
        "confidence": confidence,
        "lists_source": src_lists,
        "note": (
            "Bare IP must be covered by CIDR/IP object-group entry to hit dns-proxy policy. "
            "Main FIB LPM often still shows WAN default — that is expected. "
            "expected_dst_out is iface address (SNAT under ON_LINK_DEFAULT); "
            "gateway_configured is dns-proxy gateway (may differ)."
        ),
    })


async def verify_flow_path(
    src: str,
    dst: str,
    port: int = 443,
    proto: str = "tcp",
    watch_seconds: float = 0,
) -> dict:
    """One-card flow check: domain-list → policy → NAT → WG AllowedIPs → handshake.

    Failure points: A list miss, B no dns-route, C policy table, D NAT WAN/UNREPLIED,
    E AllowedIPs miss, F handshake stale, G ok.
    """
    src_s = (src or "").strip()
    dst_s = (dst or "").strip()
    if not src_s or not dst_s:
        raise ValueError("src and dst are required")
    port_i = int(port)
    proto_s = (proto or "tcp").upper()
    if proto_s in ("6",):
        proto_s = "TCP"
    if proto_s in ("17",):
        proto_s = "UDP"

    try:
        dst_ip = str(ipaddress.ip_address(dst_s))
        host = None
    except ValueError:
        host = dst_s
        path = await explain_policy_path(dst_s, source_ip=src_s)
        dst_ip = path.get("resolved_ip")
        if not dst_ip:
            return diag_report("FAIL", evidence=[path], changes=[], config_saved=False,
                               ok=False, failure_point="A", error="dst did not resolve")
    else:
        path = await explain_policy_path(dst_ip, source_ip=src_s)

    evidence: list[Any] = [{"explain_policy_path": path}]
    failure = None

    list_hit = bool(path.get("domain_list_hits"))
    if not list_hit:
        failure = failure or "A"

    dns_routes = path.get("dns_proxy_routes") or []
    expect_iface = path.get("expected_interface")
    if list_hit and not dns_routes:
        failure = failure or "B"

    policy = path.get("policy") or []
    if dns_routes and not policy:
        # not always fatal — mark C soft
        evidence.append({"policy_warning": "no auto table linked"})
        failure = failure or "C"

    # live NAT (optional watch)
    sessions = []
    deadline = time.monotonic() + max(0.0, float(watch_seconds))
    while True:
        try:
            ct = await get_conntrack(
                host=dst_ip,
                dst=dst_ip,
                src=src_s,
                port=port_i,
                protocol=proto_s,
                limit=50,
            )
            sessions = ct.get("sessions") or []
            evidence.append({"conntrack": {"count": ct.get("count"), "sessions": sessions[:10]}})
        except Exception as exc:  # noqa: BLE001
            evidence.append({"conntrack_error": str(exc).split("\n")[0][:160]})
            sessions = []
        if sessions or time.monotonic() >= deadline:
            break
        await asyncio.sleep(0.5)

    path_classes = []
    unreplied = False
    for s in sessions:
        pc = s.get("path_class") or sc_rc.path_class_from_dst_out(s.get("dst_out"))
        path_classes.append(pc)
        if (s.get("packets_reply") or 0) == 0 and (s.get("packets") or 0) > 0:
            unreplied = True
    if sessions and all(pc == "WAN" for pc in path_classes):
        failure = failure or "D"
    if unreplied and not failure:
        failure = failure or "D"

    # WG AllowedIPs
    allow_ok = None
    handshake_age = None
    if expect_iface and str(expect_iface).startswith("Wireguard"):
        try:
            wg = await get_wireguard(expect_iface)
            peers = wg.get("peers") or []
            covered = False
            for peer in peers:
                for cidr in peer.get("allowed_ips") or peer.get("allow_ips") or []:
                    if sc_rc.cidr_covers(str(cidr), dst_ip):
                        covered = True
                        break
            allow_ok = covered
            evidence.append({"wireguard_allowed_ips": {"interface": expect_iface, "covers_dst": covered, "peers": peers}})
            if not covered:
                failure = failure or "E"
            rt = await get_wireguard_runtime(expect_iface)
            handshake_age = rt.get("latest_handshake_age_sec")
            evidence.append({"wireguard_runtime": {
                "peer_online": rt.get("peer_online"),
                "latest_handshake_age_sec": handshake_age,
            }})
            # F only when peer clearly offline / never handshaked — age Alone is soft
            if not rt.get("peer_online") and (
                handshake_age is None or (isinstance(handshake_age, int) and handshake_age > 180)
            ):
                failure = failure or "F"

        except Exception as exc:  # noqa: BLE001
            evidence.append({"wireguard_error": str(exc).split("\n")[0][:160]})
            failure = failure or "E"

    if failure is None:
        failure = "G"
        verdict = "PASS"
    else:
        verdict = "FAIL"

    labels = {
        "A": "domain-list miss",
        "B": "no dns-proxy route",
        "C": "policy table miss/unclear",
        "D": "NAT path WAN or UNREPLIED",
        "E": "WG AllowedIPs miss",
        "F": "WG handshake stale/offline",
        "G": "ok",
    }
    return diag_report(
        verdict,
        evidence=evidence,
        changes=[],
        config_saved=False,
        ok=verdict == "PASS",
        failure_point=failure,
        failure_label=labels.get(failure),
        src=src_s,
        dst=dst_ip,
        port=port_i,
        proto=proto_s,
        domain_list_hit=list_hit,
        expected_interface=expect_iface,
        expected_dst_out=path.get("expected_dst_out"),
        expected_path_class=path.get("expected_path_class"),
        gateway_configured=path.get("gateway_configured"),
        nat_path_classes=path_classes,
        allowed_ips_covers=allow_ok,
        handshake_age_sec=handshake_age,
        path=path.get("verdict"),
    )


async def verify_flow_path_batch(checks: list[dict] | None = None) -> dict:
    """Batch verify_flow_path. Example: Claude/YouTube/OpenAI→WG0, ya.ru→WAN."""
    items = checks or []
    if not items:
        raise ValueError("checks list required: [{name?,src,dst,port?,proto?,expect_verdict?}, …]")
    results = []
    for item in items:
        if not isinstance(item, dict):
            continue
        r = await verify_flow_path(
            src=str(item.get("src") or ""),
            dst=str(item.get("dst") or ""),
            port=int(item.get("port") or 443),
            proto=str(item.get("proto") or "tcp"),
            watch_seconds=float(item.get("watch_seconds") or 0),
        )
        # preserve caller identity fields
        for key in ("name", "label", "id", "check"):
            if item.get(key) is not None:
                r[key] = item[key]
        expect = (item.get("expect_verdict") or item.get("expect") or "").upper()
        if expect:
            iface = str(r.get("expected_interface") or "")
            if expect in ("WG", "WG0", "HAPP/WG", "HAPP"):
                ok_expect = bool(r.get("domain_list_hit")) and iface.startswith("Wireguard")
                if ok_expect:
                    r["verdict"] = "PASS"
                    r["ok"] = True
                    r["path"] = "HAPP/WG" if expect in ("HAPP/WG", "HAPP", "WG0") else "WG"
                    r["failure_point"] = "G"
                    r["failure_label"] = "ok"
            elif expect == "WAN":
                # No list hit → expected WAN path is success for this check
                ok_expect = (not r.get("domain_list_hit")) and not iface.startswith("Wireguard")
                if ok_expect:
                    r["verdict"] = "PASS"
                    r["ok"] = True
                    r["path"] = "WAN"
                    r["failure_point"] = "G"
                    r["failure_label"] = "ok (expected WAN)"
            elif expect in ("PASS", "FAIL"):
                ok_expect = (r.get("verdict") or "").upper() == expect
            else:
                ok_expect = True
            r["expect"] = expect
            r["expect_ok"] = ok_expect
        results.append(r)
    return {
        "ok": all(x.get("expect_ok", x.get("ok")) for x in results),
        "count": len(results),
        "results": results,
    }


async def probe_tcp(
    dst: str,
    port: int = 443,
    via_expect: str = "Wireguard0",
) -> dict:
    """Best-effort path probe: ICMP via iface + conntrack class. TCP connect unsupported on NDMS.

    SSH/tcpdump on HAPP (.254) is out of MCP scope (no SSH key reads). Use verify_flow_path.
    """
    dst_s = (dst or "").strip()
    iface = (via_expect or "").strip()
    port_i = int(port)
    if not dst_s:
        raise ValueError("dst is required")
    explain = await explain_policy_path(dst_s)
    ping = None
    try:
        if iface:
            ping = await router_ping(explain.get("resolved_ip") or dst_s, count=2, interface=iface)
        else:
            ping = await router_ping(explain.get("resolved_ip") or dst_s, count=2)
    except Exception as exc:  # noqa: BLE001
        ping = {"ok": False, "error": str(exc).split("\n")[0][:160]}
    ct = None
    try:
        ct = await get_conntrack(host=str(explain.get("resolved_ip") or dst_s), port=port_i, protocol="tcp", limit=10)
    except Exception as exc:  # noqa: BLE001
        ct = {"error": str(exc).split("\n")[0][:160]}
    return diag_report(
        "partial",
        evidence=[
            {"explain_policy_path": explain},
            {"icmp_via_interface": ping},
            {"conntrack": ct},
        ],
        changes=[],
        config_saved=False,
        ok=False,
        unsupported_tcp=True,
        via_expect=iface or None,
        note=(
            "NDMS has no tools.tcp. ICMP+conntrack only. "
            "For packet capture on HAPP/tun use host SSH outside MCP."
        ),
    )


async def suggest_telegram_cidrs() -> dict:
    """Suggest Telegram DC CIDRs from core.telegram.org (suggest only, no apply)."""
    official: list[str] = []
    fetch_error = None
    try:
        with urlopen("https://core.telegram.org/resources/cidr.txt", timeout=8) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                official.append(str(ipaddress.ip_network(line, strict=False)))
            except ValueError:
                continue
    except Exception as exc:  # noqa: BLE001
        fetch_error = str(exc).split("\n")[0][:160]

    backup = ["95.161.64.0/20", "149.154.160.0/20", "149.154.164.0/22", "91.108.4.0/22"]
    return {
        "ok": True,
        "official_cidrs": official,
        "official_count": len(official),
        "backup_known": backup,
        "fetch_error": fetch_error,
        "note": (
            "Suggest only — do not auto-apply. Add via add_domains(list, cidrs) + "
            "add_wireguard_allowed_ips. Desktop DC 95.161.64.0/20 is a common miss."
        ),
    }


def register(mcp) -> None:
    mcp.tool()(explain_policy_path)
    mcp.tool()(verify_flow_path)
    mcp.tool()(verify_flow_path_batch)
    mcp.tool()(probe_tcp)
    mcp.tool()(suggest_telegram_cidrs)
