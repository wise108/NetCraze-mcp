"""FQDN domain-list → static /32 sync (workaround for NDMS dns-proxy gateway bug)."""

from __future__ import annotations

import ipaddress
import time
import uuid
from typing import Any

from ..client import _get_client
from ..config import assert_writable
from ..redact import redact_value
from .diagnostics import router_nslookup
from .dns_routes import _fetch_fqdn_groups, _read_list_entries, _resolve_list_key
from .report import diag_report
from .static_routes import add_static_route, delete_static_route, list_static_routes

_PLANS: dict[str, dict[str, Any]] = {}
_CDN_WARN_THRESHOLD = 8


def _tag(list_name: str) -> str:
    return f"fqdnsync:{list_name}"


def _is_ip_or_cidr(entry: str) -> bool:
    try:
        ipaddress.ip_network(entry, strict=False)
        return True
    except ValueError:
        return False


async def plan_fqdn_static_sync(
    list_name: str,
    gateway: str,
    interface: str,
    resolver: str = "",
) -> dict:
    """Resolve FQDN list entries and plan add/remove of tagged /32 static routes.

    Only manages routes with comment ``fqdnsync:<list_name>``. Never touches others.
    """
    if not gateway.strip() or not interface.strip():
        raise ValueError("gateway and interface are required")
    tag = _tag(list_name.strip())
    async with _get_client() as client:
        key = await _resolve_list_key(client, list_name.strip())
        description, entries = await _read_list_entries(client, key)

    resolved: dict[str, list[str]] = {}
    warnings: list[str] = []
    for entry in entries:
        if _is_ip_or_cidr(entry):
            try:
                net = ipaddress.ip_network(entry, strict=False)
                if net.prefixlen == 32:
                    resolved.setdefault(entry, []).append(str(net.network_address))
                else:
                    warnings.append(f"skip non-/32 literal {entry}")
            except ValueError:
                warnings.append(f"skip bad literal {entry}")
            continue
        try:
            if resolver.strip():
                # best-effort: still use router nslookup (custom resolver not always available)
                ns = await router_nslookup(entry)
            else:
                ns = await router_nslookup(entry)
            addrs = ns.get("addresses") or []
            if isinstance(addrs, dict) and addrs.get("error"):
                warnings.append(f"resolve failed {entry}: {addrs.get('error')}")
                continue
            ips = [str(a) for a in addrs if a]
            resolved[entry] = ips
            if len(ips) >= _CDN_WARN_THRESHOLD:
                warnings.append(
                    f"CDN-churn risk: {entry} resolved to {len(ips)} IPs "
                    f"(Cursor/ChatGPT-like lists churn; prefer Claude-stable FQDNs)"
                )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"resolve failed {entry}: {str(exc).split(chr(10))[0][:120]}")

    desired_ips: set[str] = set()
    for ips in resolved.values():
        for ip in ips:
            try:
                if ipaddress.ip_address(ip).version == 4:
                    desired_ips.add(ip)
            except ValueError:
                continue

    existing = await list_static_routes()
    tagged = [
        r for r in existing
        if str(r.get("comment") or "").startswith(tag)
        or str(r.get("comment") or "") == tag
    ]
    tagged_by_dest = {}
    for r in tagged:
        dest = r.get("destination") or ""
        if dest.endswith("/32"):
            tagged_by_dest[dest.split("/")[0]] = r
        elif dest:
            tagged_by_dest[dest] = r

    to_add = sorted(desired_ips - set(tagged_by_dest))
    to_remove = sorted(set(tagged_by_dest) - desired_ips)
    foreign = [
        r for r in existing
        if (r.get("destination") or "").endswith("/32")
        and (r.get("destination") or "").split("/")[0] in desired_ips
        and not str(r.get("comment") or "").startswith("fqdnsync:")
    ]

    plan_id = f"fqdnplan-{uuid.uuid4().hex[:10]}"
    plan = {
        "id": plan_id,
        "list_name": description,
        "list_key": key,
        "tag": tag,
        "gateway": gateway.strip(),
        "interface": interface.strip(),
        "created_at": time.time(),
        "resolved": resolved,
        "desired_ips": sorted(desired_ips),
        "add": [
            {
                "destination": f"{ip}/32",
                "gateway": gateway.strip(),
                "interface": interface.strip(),
                "comment": tag,
            }
            for ip in to_add
        ],
        "remove": [
            {
                "destination": tagged_by_dest[ip].get("destination"),
                "index": tagged_by_dest[ip].get("index"),
                "ip": ip,
            }
            for ip in to_remove
        ],
        "untouched_foreign": foreign[:20],
        "warnings": warnings,
    }
    _PLANS[plan_id] = plan
    return redact_value({
        "ok": True,
        "plan_id": plan_id,
        "tag": tag,
        "add_count": len(plan["add"]),
        "remove_count": len(plan["remove"]),
        "desired_count": len(desired_ips),
        "warnings": warnings,
        "plan": {
            "add": plan["add"],
            "remove": plan["remove"],
            "resolved": resolved,
            "untouched_foreign": foreign[:20],
        },
        "note": "apply_fqdn_static_sync(plan_id, confirm=true) to apply; only tagged routes.",
    })


async def apply_fqdn_static_sync(
    plan_id: str,
    confirm: bool = False,
    save: bool = False,
    max_changes: int = 50,
) -> dict:
    """Apply a plan from plan_fqdn_static_sync. confirm=false → dry-run only."""
    plan = _PLANS.get((plan_id or "").strip())
    if not plan:
        raise ValueError(f"plan not found: {plan_id}")
    changes = list(plan["add"]) + list(plan["remove"])
    if len(changes) > int(max_changes):
        raise ValueError(
            f"plan has {len(changes)} changes > max_changes={max_changes}; "
            f"raise max_changes or shrink the list"
        )
    if not confirm:
        return diag_report(
            "dry_run",
            evidence=[{"plan_id": plan_id, "add": len(plan["add"]), "remove": len(plan["remove"])}],
            changes=[],
            config_saved=False,
            ok=True,
            dry_run=True,
            would_add=plan["add"],
            would_remove=plan["remove"],
            note="Pass confirm=true to apply. Only fqdnsync-tagged routes are modified.",
        )

    assert_writable()
    applied_add = []
    applied_remove = []
    errors = []
    tag = plan["tag"]

    # Safety: re-check existing before delete
    existing = await list_static_routes()
    for item in plan["remove"]:
        dest = item.get("destination")
        match = next((r for r in existing if r.get("destination") == dest), None)
        if not match:
            continue
        if not str(match.get("comment") or "").startswith(tag):
            errors.append(f"refused to delete untagged route {dest}")
            continue
        try:
            await delete_static_route(destination=dest, save=False)
            applied_remove.append(dest)
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc).split("\n")[0][:160])

    for item in plan["add"]:
        try:
            await add_static_route(
                destination=item["destination"],
                gateway=item["gateway"],
                interface=item["interface"],
                comment=item["comment"],
                save=False,
            )
            applied_add.append(item["destination"])
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc).split("\n")[0][:160])

    config_saved = False
    if save and not errors:
        async with _get_client() as client:
            from ..config import save_payload
            from ..client import _raise_on_rci_errors
            resp = await client.rci(save_payload(True))
            _raise_on_rci_errors(resp)
            config_saved = True

    verdict = "ok" if not errors else "partial"
    return diag_report(
        verdict,
        evidence=[{"plan_id": plan_id, "tag": tag, "errors": errors}],
        changes=[{"added": applied_add, "removed": applied_remove}],
        config_saved=config_saved,
        ok=not errors,
        added=applied_add,
        removed=applied_remove,
        errors=errors,
    )


def register(mcp) -> None:
    mcp.tool()(plan_fqdn_static_sync)
    mcp.tool()(apply_fqdn_static_sync)
