"""Tests for netcraze-mcp tools."""

import httpx
import pytest

from netcraze_mcp.client import _sanitize_error
from netcraze_mcp.config import configure
from netcraze_mcp.tools.backup import download_system_file, export_backup
from netcraze_mcp.tools.components import (
    get_firmware_info,
    install_component,
    list_components,
    remove_component,
)
from netcraze_mcp.tools.dns_routes import (
    add_dns_route,
    add_domains,
    create_domain_list,
    delete_dns_route,
    delete_domain_list,
    get_dns_routes,
    get_domain_list,
    get_domain_lists,
    remove_domains,
    set_domain_list,
)
from netcraze_mcp.tools.network import (
    get_connected_clients,
    get_interface,
    get_interfaces,
    get_routes,
    get_speed,
    get_wan_speed,
    get_wan_status,
    get_wifi_associations,
    set_interface_state,
)
from netcraze_mcp.tools.static_hosts import (
    add_static_host,
    delete_static_host,
    list_static_hosts,
)
from netcraze_mcp.tools.static_routes import (
    add_static_route,
    delete_static_route,
    list_static_routes,
)
from netcraze_mcp.tools.storage import (
    delete_share,
    list_printers,
    list_shares,
    list_usb_storage,
    set_share,
    unmount_usb,
)
from netcraze_mcp.tools.system import get_system_info, reboot
from netcraze_mcp.tools.wireguard import (
    add_wireguard_from_conf,
    delete_wireguard,
    get_wireguard,
    list_wireguard,
    set_wireguard_state,
)
from netcraze_mcp.tools.ipsec import (
    get_ipsec,
    list_ipsec,
    list_ipsec_proposals,
    show_crypto,
    show_ipsec,
    show_ipsec_sa,
)


# ─── get_system_info ──────────────────────────────────────────────────────────

async def test_get_system_info_returns_parsed_fields(mock_client):
    mock_client.rci.return_value = {
        "show": {
            "version": {"model": "NetCraze Giga", "release": "4.1.7", "arch": "mips"},
            "system": {"uptime": 123456, "memory": 262144, "memory-free": 98304, "load": 12},
        }
    }
    result = await get_system_info()
    assert result["model"] == "NetCraze Giga"
    assert result["firmware"] == "4.1.7"
    assert result["uptime"] == 123456
    assert result["memory_free"] == 98304


async def test_get_system_info_omits_none_fields(mock_client):
    mock_client.rci.return_value = {
        "show": {"version": {"model": "KN-1010"}, "system": {}}
    }
    result = await get_system_info()
    assert "firmware" not in result
    assert "uptime" not in result
    assert result["model"] == "KN-1010"


# ─── backup / export ──────────────────────────────────────────────────────────

async def test_download_system_file_startup_config_via_ci(mock_client):
    mock_client.ci_get_bytes.return_value = (
        b"! $$$ Model: Netcraze Ultra\r\n! $$$ Version: 2.06.1\r\n\r\nsystem\r\n    set net.ipv4.ip_forward 1\r\n"
    )
    result = await download_system_file(file_name="startup-config", include_text=True)
    assert result["name"] == "startup-config"
    assert result["filename"] == "startup-config.txt"
    assert "ip_forward" in result["text"]
    assert result["metadata"]["model"] == "Netcraze Ultra"
    mock_client.ci_get_bytes.assert_called_once_with("startup-config.txt")


async def test_download_system_file_startup_config_fallback_parse(mock_client):
    request = httpx.Request("GET", "http://router/ci/startup-config.txt")
    mock_client.ci_get_bytes.side_effect = httpx.HTTPStatusError(
        "missing", request=request, response=httpx.Response(404, request=request),
    )
    mock_client.rci.return_value = {
        "parse": {"message": ["! $$$ Model: Netcraze Ultra", "", "interface GigabitEthernet0"]},
    }
    result = await download_system_file(file_name="startup-config", include_text=True)
    assert result["text"].startswith("! $$$ Model: Netcraze Ultra")
    assert result["used_parse_fallback"] is True
    mock_client.rci.assert_called_once_with({"parse": "more startup-config"})


async def test_download_system_file_firmware_metadata_only(mock_client):
    mock_client.rci_get.return_value = {
        "model": "Ultra (NC-1812)",
        "release": "5.01.C.1.0-0",
        "title": "5.1.1",
    }
    mock_client.ci_get_bytes.return_value = b"FIRMWARE"
    result = await download_system_file(file_name="firmware")
    assert result["name"] == "firmware"
    assert result["size_bytes"] == 8
    assert result["sha256"] == "407d47dc1f3fb482d08a63269de7eaf19e56590672c78c9bc1bbcc4bb110ba19"
    assert result["source"] == "installed"
    assert "content_base64" not in result


async def test_download_system_file_firmware_save_path(mock_client, tmp_path):
    mock_client.rci_get.return_value = {"model": "Ultra", "release": "5.01.C.1.0-0", "title": "5.1.1"}
    mock_client.ci_get_bytes.return_value = b"FIRMWARE"
    target = tmp_path / "fw.bin"
    result = await download_system_file(file_name="firmware", save_path=str(target))
    assert target.read_bytes() == b"FIRMWARE"
    assert result["saved_to"] == str(target)


async def test_download_system_file_rejects_unknown_file(mock_client):
    with pytest.raises(ValueError, match="Unsupported system file"):
        await download_system_file(file_name="unknown-file")


async def test_export_backup(mock_client):
    config_text = b"! $$$ Model: Netcraze Ultra\r\n\r\nsystem\r\n"
    mock_client.rci_get.return_value = {
        "model": "Ultra (NC-1812)",
        "release": "5.01.C.1.0-0",
        "title": "5.1.1",
        "arch": "aarch64",
    }
    mock_client.ci_get_bytes.side_effect = [config_text, b"FW"]
    result = await export_backup(files=["startup-config", "firmware"], include_text=True)
    assert result["model"] == "Ultra (NC-1812)"
    assert result["files"][0]["name"] == "startup-config"
    assert result["files"][0]["text"].startswith("! $$$ Model:")
    assert result["files"][1]["name"] == "firmware"
    assert result["files"][1]["size_bytes"] == 2
    assert "timestamp" in result


# ─── wireguard ────────────────────────────────────────────────────────────────

_WG_CONF = """[Interface]
Address = 10.13.14.2/32
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEE=
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBEE=
PresharedKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCEE=
Endpoint = 45.89.63.73:51821
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""


async def test_list_wireguard(mock_client):
    mock_client.rci_get.return_value = {
        "Wireguard2": {
            "id": "Wireguard2",
            "type": "Wireguard",
            "description": "My VPN",
            "state": "up",
            "link": "up",
            "address": "10.13.13.2",
            "wireguard": {
                "peer": [{
                    "remote-endpoint-address": "45.89.63.73",
                    "remote-port": 51820,
                }]
            },
        },
        "Bridge0": {"id": "Bridge0", "type": "Bridge"},
    }
    result = await list_wireguard()
    assert len(result) == 1
    assert result[0]["id"] == "Wireguard2"
    assert result[0]["endpoint"] == "45.89.63.73:51820"


async def test_get_wireguard_hides_secrets(mock_client):
    mock_client.rci_get.return_value = {
        "id": "Wireguard2",
        "type": "Wireguard",
        "description": "My VPN",
        "state": "up",
        "link": "up",
        "address": "10.13.13.2",
        "wireguard": {
            "public-key": "PUBKEYPUBKEYPUBKEYPUBKEYPUBKEYPUBKEYPUB=",
            "peer": [{
                "public-key": "PEERPEERPEERPEERPEERPEERPEERPEERPEERPE=",
                "remote-endpoint-address": "45.89.63.73",
                "remote-port": 51820,
                "online": True,
            }],
        },
    }
    result = await get_wireguard("Wireguard2")
    assert result["id"] == "Wireguard2"
    assert result["public_key"].startswith("PUBKEY")
    assert "private" not in str(result).lower() or "private_key" not in result
    dumped = str(result)
    assert "PresharedKey" not in dumped
    assert "PrivateKey" not in dumped


async def test_add_wireguard_from_conf_import(mock_client):
    mock_client.rci_post.return_value = {
        "created": "Wireguard3",
        "status": [{"status": "message", "message": "imported"}],
    }
    mock_client.rci.return_value = {}
    mock_client.rci_get.return_value = {
        "id": "Wireguard3",
        "type": "Wireguard",
        "description": "Cloudflare WARP",
        "state": "up",
        "link": "up",
        "address": "10.13.14.2",
        "wireguard": {
            "peer": [{
                "remote-endpoint-address": "45.89.63.73",
                "remote-port": 51821,
            }]
        },
    }
    result = await add_wireguard_from_conf(
        conf=_WG_CONF,
        description="Cloudflare WARP",
        enabled=True,
    )
    assert result["id"] == "Wireguard3"
    assert result["address"] == "10.13.14.2"
    assert result["enabled"] is True
    assert "AAAAAAAAAAAAAAAA" not in str(result)
    assert "CCCCCCCCCCCCCCCC" not in str(result)
    mock_client.rci_post.assert_called_once()
    assert mock_client.rci_post.call_args.args[0] == "interface/wireguard/import"
    # last batch includes save
    last = mock_client.rci.call_args_list[-1].args[0]
    assert {"system": {"configuration": {"save": {}}}} in last


async def test_add_wireguard_from_conf_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError):
        await add_wireguard_from_conf(conf=_WG_CONF)


async def test_set_wireguard_state(mock_client):
    mock_client.rci_get.return_value = {
        "id": "Wireguard3",
        "type": "Wireguard",
        "state": "down",
        "link": "down",
        "address": "10.13.14.2",
    }
    mock_client.rci.return_value = {}
    result = await set_wireguard_state("Wireguard3", enabled=False)
    assert result["id"] == "Wireguard3"
    assert result["enabled"] is False
    assert mock_client.rci.call_args.args[0] == [
        {"interface": {"Wireguard3": {"down": True}}},
        {"system": {"configuration": {"save": {}}}},
    ]


async def test_delete_wireguard(mock_client):
    mock_client.rci_get.return_value = {"id": "Wireguard3", "type": "Wireguard"}
    mock_client.rci.return_value = {}
    result = await delete_wireguard("Wireguard3")
    assert result == {"deleted": True, "id": "Wireguard3"}


# ─── ipsec (read-only) ────────────────────────────────────────────────────────

async def test_list_ipsec_empty(mock_client):
    mock_client.rci_get.side_effect = [[], {}]
    assert await list_ipsec() == []


async def test_list_ipsec_summaries(mock_client):
    mock_client.rci_get.side_effect = [
        {
            "office": {
                "name": "office",
                "peer": "203.0.113.1",
                "ike-protocol": "ikev2",
                "passive": False,
                "ike-psk": "super-secret",
            }
        },
        {
            "office": {
                "config": {"enabled": "yes"},
                "status": {"state": "PHASE2_ESTABLISHED", "ike_state": "ESTABLISHED"},
            }
        },
    ]
    result = await list_ipsec()
    assert len(result) == 1
    assert result[0]["id"] == "office"
    assert result[0]["connected"] is True
    assert result[0]["ike_version"] == "ikev2"
    assert result[0]["remote_gateway"] == "203.0.113.1"
    assert "super-secret" not in str(result)


async def test_get_ipsec_redacts_psk(mock_client):
    mock_client.rci_get.side_effect = [
        {
            "office": {
                "name": "office",
                "peer": "203.0.113.1",
                "ike-protocol": "ikev2",
                "ike-psk": "super-secret",
                "ike-local-id-type": "address",
                "ike-local-id": "198.51.100.1",
                "ike-remote-id-type": "address",
                "ike-remote-id": "203.0.113.1",
                "ipsec-local-networks": "192.168.1.0/24",
                "ipsec-remote-networks": "10.0.0.0/8",
                "ike-encryption": "aes-cbc-256",
                "ike-integrity": "sha256",
                "ike-dh": "14",
                "ipsec-encryption": "esp-aes-256",
                "ipsec-integrity": "esp-sha256-hmac",
                "ipsec-dh": "14",
                "dpd": True,
                "nail-up": True,
                "autoconnect": True,
                "passive": False,
            }
        },
        {
            "office": {
                "config": {"enabled": "yes"},
                "status": {
                    "state": "PHASE2_ESTABLISHED",
                    "phase1": {"rekey_time": 1000},
                    "phase2_sa_list": {"phase2_sa": [{"sa_state": "INSTALLED", "rekey_time": 500}]},
                },
            }
        },
    ]
    result = await get_ipsec("office")
    assert result["has_psk"] is True
    assert result["local_subnets"] == ["192.168.1.0/24"]
    assert result["ike_proposal"]["encryption"] == ["aes-cbc-256"]
    assert "super-secret" not in str(result)
    assert "<REDACTED>" not in str(result.get("ike_proposal"))


async def test_get_ipsec_missing(mock_client):
    mock_client.rci_get.side_effect = [[], {}]
    with pytest.raises(ValueError, match="not found"):
        await get_ipsec("missing")


async def test_list_ipsec_proposals_contains_aes256_sha256_dh14():
    result = await list_ipsec_proposals()
    assert result["contains"]["aes256"] is True
    assert result["contains"]["sha256"] is True
    assert result["contains"]["modp2048_dh14"] is True
    assert "aes-cbc-256" in result["ike"]["encryption"]
    assert "sha256" in result["ike"]["integrity"]
    assert "14" in result["ike"]["dh_groups"]
    assert "esp-aes-256" in result["esp"]["encryption"]


async def test_show_ipsec_sa_empty_fallback(mock_client):
    mock_client.rci_get.side_effect = [
        Exception("404 Not Found"),
        {},
    ]
    result = await show_ipsec_sa()
    assert result["legacy_sa_available"] is False
    assert result["count"] == 0
    assert result["established"] == 0
    assert result["sa"] == []


async def test_show_ipsec_and_crypto_redact(mock_client):
    mock_client.rci_get.side_effect = [
        {},  # show/ipsec
        {"office": {"ike-psk": "secret", "peer": "1.2.3.4"}},  # connections
        {"office": {"config": {"enabled": "yes"}}},  # status map
    ]
    dumped = await show_ipsec()
    assert dumped["site_to_site"]["office"]["ike-psk"] == "<REDACTED>"
    assert dumped["site_to_site"]["office"]["peer"] == "1.2.3.4"

    mock_client.rci_get.side_effect = [
        {"engine": {"engine": "software"}},
        {"engine": {"engine": "software"}},
        {},
        {},
        {"key": "should-redact-if-secret-field"},
    ]
    crypto = await show_crypto()
    assert crypto["crypto"]["engine"]["engine"] == "software"


# ─── components / firmware / storage ──────────────────────────────────────────

async def test_list_components_marks_installed_and_filters(mock_client):
    mock_client.rci_get.return_value = {
        "ndw": {"components": "usb,storage,tsmb,usblte"},
    }
    mock_client.rci.return_value = {
        "components": {"list": {"component": {
            "usb": {"group": "Base system", "description": {"RU": "USB"}, "version": "1", "queued": True},
            "ftp": {"group": "Storage", "description": {"EN": "FTP"}, "version": "1", "size": "100", "queued": False},
            "usblte": {"group": "USB modems", "description": {"RU": "LTE"}, "queued": True},
            "wireguard": {"group": "Networking", "description": {"RU": "WG"}, "queued": False},
        }}}
    }
    all_components = await list_components()
    assert [item["name"] for item in all_components] == ["usb", "usblte", "ftp", "wireguard"]
    assert all_components[0]["installed"] is True
    assert "queued" not in all_components[0]  # steady state: queued==installed

    storage_only = await list_components(group="Storage")
    assert [item["name"] for item in storage_only] == ["ftp"]

    usb_like = await list_components(group="usb")
    assert [item["name"] for item in usb_like] == ["usb", "usblte"]

    installed_only = await list_components(installed_only=True)
    assert [item["name"] for item in installed_only] == ["usb", "usblte"]


async def test_list_components_pending_queue(mock_client):
    mock_client.rci_get.return_value = {"ndw": {"components": "usb"}}
    mock_client.rci.return_value = {
        "components": {"list": {"component": {
            "usb": {"group": "Base system", "queued": True},
            "ftp": {"group": "Storage", "queued": True},  # pending install
        }}}
    }
    result = await list_components()
    by_name = {item["name"]: item for item in result}
    assert "queued" not in by_name["usb"]
    assert by_name["ftp"]["queued"] is True
    assert by_name["ftp"]["pending"] == "install"
    assert by_name["ftp"]["installed"] is False


async def test_get_firmware_info(mock_client):
    mock_client.rci_get.side_effect = [
        {
            "model": "Ultra (NC-1812)",
            "release": "5.01.C.1.0-0",
            "title": "5.1.1",
            "arch": "aarch64",
            "sandbox": "stable",
            "manufacturer": "Netcraze Ltd.",
            "ndw": {"components": "usb,storage"},
        },
        {"auto-update": {"disable": False, "channel": "stable"}},
    ]
    result = await get_firmware_info()
    assert result["firmware"] == "5.01.C.1.0-0"
    assert result["update_channel"] == "stable"
    assert result["auto_update"] is True
    assert result["components_installed"] == 2
    assert result["components"] == ["usb", "storage"]


async def test_list_usb_storage(mock_client):
    mock_client.rci_get.return_value = {
        "FlashStorage": {
            "bus": "mtd",
            "state": "ACTIVE",
            "manufacturer": "Netcraze",
            "product": "NC-1812",
            "size": "117964800",
            "removable": False,
            "partition": {
                "Partition1": {
                    "id": "Partition1",
                    "label": "Storage",
                    "fstype": "ubifs",
                    "state": "MOUNTED",
                    "total": "102989824",
                    "free": "102965248",
                }
            },
        }
    }
    result = await list_usb_storage()
    assert len(result) == 1
    assert result[0]["id"] == "FlashStorage"
    assert result[0]["partitions"][0]["fstype"] == "ubifs"
    assert result[0]["partitions"][0]["free_bytes"] == 102965248


async def test_list_usb_storage_falls_back_to_post_and_list_shape(mock_client):
    mock_client.rci_get.return_value = {}
    mock_client.rci.side_effect = [
        {
            "show": {
                "media": [
                    {
                        "name": "Media0",
                        "bus": "usb",
                        "state": "ACTIVE",
                        "ejectable": True,
                        "partition": {"Partition1": {"id": "Partition1", "fstype": "ntfs", "state": "MOUNTED"}},
                    }
                ]
            }
        },
        {"ls": {"entry": {}}},  # no storage: — only USB from media
    ]
    result = await list_usb_storage()
    assert result[0]["id"] == "Media0"
    assert result[0]["ejectable"] is True
    assert mock_client.rci.call_args_list[0].args[0] == {"show": {"media": {}}}
    assert mock_client.rci.call_args_list[1].args[0] == {"ls": {}}


async def test_list_usb_storage_adds_internal_from_ls_when_media_empty(mock_client):
    mock_client.rci_get.return_value = {}
    mock_client.rci.side_effect = [
        {"show": {"media": {}}},
        {
            "ls": {
                "entry": {
                    "storage:": {
                        "type": "V",
                        "dirty": "no",
                        "free": "102965248",
                        "fstype": "ubifs",
                        "mounted": "yes",
                        "storage": "none",
                        "total": "102989824",
                    }
                }
            }
        },
    ]
    result = await list_usb_storage()
    assert len(result) == 1
    assert result[0]["id"] == "FlashStorage"
    assert result[0]["bus"] == "mtd"
    assert result[0]["ejectable"] is False
    assert result[0]["partitions"][0]["fstype"] == "ubifs"
    assert result[0]["partitions"][0]["free_bytes"] == 102965248


async def test_list_usb_storage_skips_ls_when_flash_already_in_media(mock_client):
    mock_client.rci_get.return_value = {
        "FlashStorage": {
            "bus": "mtd",
            "state": "ACTIVE",
            "ejectable": False,
            "partition": {"Partition1": {"id": "Partition1", "fstype": "ubifs", "total": "1", "free": "1"}},
        }
    }
    result = await list_usb_storage()
    assert len(result) == 1
    mock_client.rci.assert_not_called()


async def test_list_shares(mock_client):
    mock_client.rci_get.return_value = {
        "enabled": False,
        "automount": True,
        "permissive": True,
        "share": [{
            "mount": "24A48978A4894D6C:",
            "label": "Seagate Backup Plus Drive",
            "description": "",
            "active": False,
        }],
    }
    result = await list_shares()
    assert result == [{
        "label": "Seagate Backup Plus Drive",
        "mount": "24A48978A4894D6C:",
        "active": False,
        "enabled": False,
        "automount": True,
        "permissive": True,
    }]


async def test_list_printers_empty(mock_client):
    mock_client.rci_get.return_value = {}
    assert await list_printers() == []


async def test_list_printers_dict_map(mock_client):
    mock_client.rci_get.return_value = {
        "printer": {
            "03f0:1d17": {
                "name": "Hewlett-Packard hp LaserJet 1320",
                "status": "OFFLINE",
                "type": "direct",
                "attached": False,
            }
        }
    }
    result = await list_printers()
    assert result == [{
        "id": "03f0:1d17",
        "name": "Hewlett-Packard hp LaserJet 1320",
        "state": "OFFLINE",
        "type": "direct",
        "attached": False,
    }]


async def test_install_component_queues_and_commits(mock_client):
    result = await install_component("ftp", commit=True)
    assert result == {"queued": True, "name": "ftp", "action": "install", "committed": True}
    assert mock_client.rci.call_args_list[0].args[0] == {"parse": "components install ftp"}
    assert mock_client.rci.call_args_list[1].args[0] == {"parse": "components commit"}


async def test_install_component_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError):
        await install_component("ftp")


async def test_remove_component_without_commit(mock_client):
    result = await remove_component("ftp", commit=False)
    assert result["committed"] is False
    mock_client.rci.assert_called_once_with({"parse": "components remove ftp"})


async def test_set_share_sends_batch(mock_client):
    result = await set_share("Backup", "ABC:", description="disk")
    assert result["added"] is True
    mock_client.rci.assert_called_once_with([
        {"cifs": {"share": {"label": "Backup", "mount": "ABC:", "description": "disk"}}},
        {"system": {"configuration": {"save": {}}}},
    ])


async def test_delete_share_by_label(mock_client):
    mock_client.rci_get.return_value = {
        "share": [{"label": "Backup", "mount": "ABC:", "active": False}],
    }
    result = await delete_share("Backup")
    assert result["deleted"] is True
    mock_client.rci.assert_called_once_with([
        {"cifs": {"share": {"label": "Backup", "mount": "ABC:", "no": True}}},
        {"system": {"configuration": {"save": {}}}},
    ])


async def test_unmount_usb_refuses_non_ejectable(mock_client):
    mock_client.rci_get.return_value = {
        "FlashStorage": {"bus": "mtd", "ejectable": False, "partition": {}},
    }
    with pytest.raises(ValueError, match="not ejectable"):
        await unmount_usb("FlashStorage")


async def test_unmount_usb_ejects(mock_client):
    mock_client.rci_get.return_value = {
        "Media0": {"bus": "usb", "ejectable": True, "partition": {}},
    }
    mock_client.rci.side_effect = [
        {"ls": {"entry": {}}},
        {"system": {"eject": {"name": "Media0"}}},
    ]
    result = await unmount_usb("Media0")
    assert result == {"ejected": True, "device": "Media0"}
    assert mock_client.rci.call_args_list[-1].args[0] == {"system": {"eject": {"name": "Media0"}}}


# ─── get_interfaces ───────────────────────────────────────────────────────────

async def test_get_interfaces_returns_list(mock_client):
    mock_client.rci_get.return_value = {
        "GigabitEthernet0": {"id": "GigabitEthernet0", "state": "up", "address": "192.168.1.1", "mask": "255.255.255.0"},
        "Wireguard0": {"id": "Wireguard0", "state": "up"},
    }
    result = await get_interfaces()
    assert len(result) == 2
    ids = {r["id"] for r in result}
    assert "GigabitEthernet0" in ids
    assert result[0]["address"] == "192.168.1.1" or result[1].get("address") == "192.168.1.1"


async def test_get_interfaces_wraps_list(mock_client):
    mock_client.rci_get.return_value = [{"id": "GigabitEthernet0", "state": "up"}]
    result = await get_interfaces()
    assert isinstance(result, list)
    assert len(result) == 1


async def test_get_interface_single(mock_client):
    mock_client.rci_get.return_value = {
        "id": "Wireguard0", "state": "up", "rxbytes": 1024, "txbytes": 2048
    }
    result = await get_interface("Wireguard0")
    assert result["id"] == "Wireguard0"
    assert result["rx_bytes"] == 1024
    mock_client.rci_get.assert_called_once_with("show/interface/Wireguard0")


# ─── get_connected_clients ────────────────────────────────────────────────────

async def test_get_connected_clients_returns_hosts(mock_client):
    mock_client.rci_get.return_value = [
        {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.10", "hostname": "laptop",
         "active": True, "rxbytes": 1_000_000, "txbytes": 500_000},
        {"mac": "11:22:33:44:55:66", "ip": "192.168.1.11", "active": False},
    ]
    result = await get_connected_clients()
    assert len(result) == 2
    assert result[0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert result[0]["rx_bytes"] == 1_000_000


async def test_get_connected_clients_empty(mock_client):
    mock_client.rci_get.return_value = []
    result = await get_connected_clients()
    assert result == []


# ─── get_speed ────────────────────────────────────────────────────────────────

async def test_get_speed_calculates_mbps(mock_client, monkeypatch):
    async def fake_sleep(_): pass
    monkeypatch.setattr("netcraze_mcp.tools.network.asyncio.sleep", fake_sleep)

    snap1 = [{"mac": "aa:bb:cc:00:00:01", "active": True, "rxbytes": 0,         "txbytes": 0},
             {"mac": "aa:bb:cc:00:00:02", "active": True, "rxbytes": 0,         "txbytes": 0}]
    snap2 = [{"mac": "aa:bb:cc:00:00:01", "active": True, "rxbytes": 5_000_000, "txbytes": 500_000},
             {"mac": "aa:bb:cc:00:00:02", "active": True, "rxbytes": 5_000_000, "txbytes": 500_000}]
    mock_client.rci_get.side_effect = [snap1, snap2]

    _times = [0.0, 3.0]
    _idx = [0]
    def fake_monotonic():
        v = _times[_idx[0] % len(_times)]
        _idx[0] += 1
        return v
    monkeypatch.setattr("netcraze_mcp.tools.network.time.monotonic", fake_monotonic)

    result = await get_speed(interval=3.0)
    assert result["download_mbps"] > 0
    assert result["upload_mbps"] > 0
    assert "top_clients" in result


async def test_get_speed_clamps_interval(mock_client, monkeypatch):
    async def fake_sleep(_): pass
    monkeypatch.setattr("netcraze_mcp.tools.network.asyncio.sleep", fake_sleep)

    snap = [{"mac": "aa:bb:cc:00:00:01", "active": True, "rxbytes": 0, "txbytes": 0}]
    mock_client.rci_get.side_effect = [snap, snap]

    _times = [0.0, 1.0]
    _idx = [0]
    def fake_monotonic():
        v = _times[_idx[0] % len(_times)]
        _idx[0] += 1
        return v
    monkeypatch.setattr("netcraze_mcp.tools.network.time.monotonic", fake_monotonic)

    result = await get_speed(interval=999)  # clamped to 10
    assert result["interval_sec"] == 1.0


# ─── get_wan_speed ────────────────────────────────────────────────────────────

# Shared ifaces dict for get_wan_speed tests
_IFACES = {
    "UsbQmi0":          {"id": "UsbQmi0",          "type": "UsbQmi",          "link": "up", "description": "Beeline-big"},
    "GigabitEthernet1": {"id": "GigabitEthernet1", "type": "GigabitEthernet", "link": "up", "address": "192.168.8.133"},
    "Wireguard1":       {"id": "Wireguard1",        "type": "Wireguard",       "link": "up", "description": "awg"},
    "Bridge0":          {"id": "Bridge0",           "type": "Bridge",          "link": "up"},
}
_STATS = [
    {"rxspeed": 1_000_000, "txspeed": 500_000},   # UsbQmi0
    {"rxspeed":     1_000, "txspeed":     500},   # GigabitEthernet1
    {"rxspeed":    50_000, "txspeed":  25_000},   # Wireguard1
    # Bridge0 is excluded by _is_wan_interface, so no stat for it
]
_RCI_STAT_RESPONSE = {"show": {"interface": {"stat": _STATS}}}


async def test_get_wan_speed_returns_wan_interfaces_only(mock_client):
    mock_client.rci_get.return_value = _IFACES
    mock_client.rci.return_value = _RCI_STAT_RESPONSE

    result = await get_wan_speed()
    ids = {r["interface"] for r in result}
    assert "UsbQmi0" in ids
    assert "GigabitEthernet1" in ids
    assert "Wireguard1" in ids
    assert "Bridge0" not in ids  # LAN bridge must be excluded


async def test_get_wan_speed_calculates_mbps(mock_client):
    mock_client.rci_get.return_value = _IFACES
    mock_client.rci.return_value = _RCI_STAT_RESPONSE

    result = await get_wan_speed()
    usb = next(r for r in result if r["interface"] == "UsbQmi0")
    # rxspeed=1_000_000 bytes/s → 8.0 Mbit/s
    assert usb["dl_mbps"] == 8.0
    assert usb["ul_mbps"] == 4.0


async def test_get_wan_speed_sorted_by_total(mock_client):
    mock_client.rci_get.return_value = _IFACES
    mock_client.rci.return_value = _RCI_STAT_RESPONSE

    result = await get_wan_speed()
    totals = [r["dl_mbps"] + r["ul_mbps"] for r in result]
    assert totals == sorted(totals, reverse=True)


async def test_get_wan_speed_gigabit_without_ip_excluded(mock_client):
    mock_client.rci_get.return_value = {
        "GigabitEthernet0": {"id": "GigabitEthernet0", "type": "GigabitEthernet", "link": "up"},
        # no address → LAN port, excluded
    }
    mock_client.rci.return_value = {"show": {"interface": {"stat": []}}}

    result = await get_wan_speed()
    assert result == []


async def test_get_wan_speed_interface_down_excluded(mock_client):
    mock_client.rci_get.return_value = {
        "PPTP0": {"id": "PPTP0", "type": "PPTP", "link": "down"},
    }
    mock_client.rci.return_value = {"show": {"interface": {"stat": []}}}

    result = await get_wan_speed()
    assert result == []


async def test_get_wan_speed_no_wan_interfaces(mock_client):
    mock_client.rci_get.return_value = {}
    result = await get_wan_speed()
    assert result == []


async def test_get_wan_speed_description_included(mock_client):
    mock_client.rci_get.return_value = _IFACES
    mock_client.rci.return_value = _RCI_STAT_RESPONSE

    result = await get_wan_speed()
    usb = next(r for r in result if r["interface"] == "UsbQmi0")
    assert usb.get("description") == "Beeline-big"
    ge = next(r for r in result if r["interface"] == "GigabitEthernet1")
    assert "description" not in ge  # no description field in iface dict


# ─── get_wifi_associations ────────────────────────────────────────────────────

async def test_get_wifi_associations(mock_client):
    mock_client.rci_get.return_value = [
        {"mac": "de:ad:be:ef:00:01", "ssid": "HomeNet", "rssi": -65, "snr": 30},
    ]
    result = await get_wifi_associations()
    assert result[0]["mac"] == "de:ad:be:ef:00:01"
    assert result[0]["rssi"] == -65


async def test_get_wifi_associations_dict_with_station_key(mock_client):
    mock_client.rci_get.return_value = {
        "station": [{"mac": "aa:00:00:00:00:01", "rssi": -70}]
    }
    result = await get_wifi_associations()
    assert len(result) == 1
    assert result[0]["rssi"] == -70


# ─── get_routes ───────────────────────────────────────────────────────────────

async def test_get_routes(mock_client):
    mock_client.rci_get.return_value = [
        {"destination": "0.0.0.0/0", "gateway": "10.0.0.1", "interface": "PPPoE0", "metric": 1, "proto": "boot"},
        {"destination": "192.168.1.0/24", "interface": "GigabitEthernet0/0", "proto": "kernel"},
    ]
    result = await get_routes()
    assert len(result) == 2
    assert result[0]["destination"] == "0.0.0.0/0"
    assert result[0]["gateway"] == "10.0.0.1"


# ─── get_wan_status ───────────────────────────────────────────────────────────

async def test_get_wan_status_returns_dict(mock_client):
    mock_client.rci_get.return_value = {"internet": True, "provider": "PPPoE0"}
    result = await get_wan_status()
    assert result["internet"] is True


# ─── domain lists ────────────────────────────────────────────────────────────

FQDN_GROUPS = {
    "show": {"sc": {"object-group": {"fqdn": {
        "domain-list0": {"description": "XEGARE", "include": [{"address": "xegare.com"}]},
        "domain-list1": {"description": "steam",  "include": [{"address": "steampowered.com"}, {"address": "steamcommunity.com"}]},
    }}}}
}

async def test_get_domain_lists(mock_client):
    mock_client.rci.return_value = FQDN_GROUPS
    result = await get_domain_lists()
    assert len(result) == 2
    names = {r["name"] for r in result}
    assert "steam" in names
    assert "XEGARE" in names
    steam = next(r for r in result if r["name"] == "steam")
    assert steam["count"] == 2
    assert steam["key"] == "domain-list1"


async def test_get_domain_list(mock_client):
    mock_client.rci.return_value = FQDN_GROUPS
    result = await get_domain_list("steam")
    assert result["name"] == "steam"
    assert "steampowered.com" in result["entries"]


async def test_get_domain_list_by_key(mock_client):
    mock_client.rci.return_value = FQDN_GROUPS
    result = await get_domain_list("domain-list1")
    assert result["name"] == "steam"


async def test_get_domain_list_not_found(mock_client):
    mock_client.rci.return_value = FQDN_GROUPS
    with pytest.raises(ValueError, match="not found"):
        await get_domain_list("nonexistent")


async def test_set_domain_list(mock_client):
    mock_client.rci.side_effect = [FQDN_GROUPS, {}]
    result = await set_domain_list("steam", ["steampowered.com", "newdomain.com"])
    assert result["count"] == 2
    assert result["key"] == "domain-list1"


async def test_set_domain_list_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError):
        await set_domain_list("steam", ["example.com"])


async def test_add_domains(mock_client):
    mock_client.rci.side_effect = [FQDN_GROUPS, {}]
    result = await add_domains("steam", ["newdomain.com"])
    assert result["added"] == 1
    assert result["total"] == 3


async def test_add_domains_deduplicates(mock_client):
    mock_client.rci.side_effect = [FQDN_GROUPS, {}]
    result = await add_domains("steam", ["steampowered.com"])  # already exists
    assert result["added"] == 0
    assert result["total"] == 2


async def test_remove_domains(mock_client):
    mock_client.rci.side_effect = [FQDN_GROUPS, {}]
    result = await remove_domains("steam", ["steampowered.com"])
    assert result["removed"] == 1
    assert result["total"] == 1


async def test_remove_domains_nonexistent_is_noop(mock_client):
    mock_client.rci.side_effect = [FQDN_GROUPS, {}]
    result = await remove_domains("steam", ["notinlist.com"])
    assert result["removed"] == 0


async def test_create_domain_list(mock_client):
    mock_client.rci.side_effect = [FQDN_GROUPS, {}, {}]
    result = await create_domain_list("mylist", ["example.com"])
    assert result["created"] == "mylist"
    assert result["key"] == "domain-list2"  # next unused after list0, list1
    assert result["count"] == 1


async def test_delete_domain_list(mock_client):
    mock_client.rci.side_effect = [FQDN_GROUPS, {}, {}]
    result = await delete_domain_list("steam")
    assert result["deleted"] == "steam"
    assert result["key"] == "domain-list1"


async def test_delete_domain_list_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError):
        await delete_domain_list("steam")


# ─── static hosts ─────────────────────────────────────────────────────────────

async def test_list_static_hosts_filters_private_and_unique(mock_client):
    mock_client.rci_get.return_value = {
        "static_a": [
            {"name": "router.home", "address": "192.168.0.1"},
            {"name": "router.home", "address": "192.168.0.1"},
            {"name": "loopback.local", "address": "127.0.0.1"},
            {"name": "public.host", "address": "8.8.8.8"},
        ]
    }
    result = await list_static_hosts()
    assert result == [{"host": "router.home", "ip": "192.168.0.1"}]


async def test_list_static_hosts_sort_ip_desc(mock_client):
    mock_client.rci_get.return_value = {
        "static_a": [
            {"name": "h1", "address": "192.168.0.2"},
            {"name": "h2", "address": "192.168.0.10"},
        ]
    }
    result = await list_static_hosts(sort_by="ip", order="desc")
    assert result[0]["ip"] == "192.168.0.10"


async def test_add_static_host_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError):
        await add_static_host("router.home", "192.168.0.1")


async def test_add_static_host_sends_batch(mock_client):
    result = await add_static_host("router.home", "192.168.0.1")
    assert result["added"] is True
    mock_client.rci.assert_called_once_with([
        {"ip": {"host": {"domain": "router.home", "address": "192.168.0.1"}}},
        {"system": {"configuration": {"save": {}}}},
    ])


async def test_add_static_host_raises_on_rci_error(mock_client):
    mock_client.rci.return_value = [{
        "ip": {"host": {"status": [{"status": "error", "message": "no input [http/rci]."}]}}
    }]
    with pytest.raises(RuntimeError, match="no input"):
        await add_static_host("router.home", "192.168.0.1")


async def test_delete_static_host_by_name(mock_client):
    mock_client.rci_get.return_value = {"static_a": [{"name": "router.home", "address": "192.168.0.1"}]}
    result = await delete_static_host("router.home")
    assert result["deleted"] is True
    mock_client.rci.assert_called_once_with([
        {"ip": {"host": {"domain": "router.home", "address": "192.168.0.1", "no": True}}},
        {"system": {"configuration": {"save": {}}}},
    ])


# ─── static routes ────────────────────────────────────────────────────────────

async def test_list_static_routes(mock_client):
    mock_client.rci_get.return_value = [
        {
            "network": "192.168.10.0",
            "mask": "255.255.255.0",
            "gateway": "10.211.114.1",
            "interface": "ZeroTier0",
            "index": "abc",
            "comment": "",
        }
    ]
    result = await list_static_routes()
    assert result == [{
        "destination": "192.168.10.0/24",
        "network": "192.168.10.0",
        "mask": "255.255.255.0",
        "gateway": "10.211.114.1",
        "interface": "ZeroTier0",
        "index": "abc",
    }]


async def test_add_static_route_sends_batch(mock_client):
    result = await add_static_route(
        "192.168.10.0/24",
        "10.211.114.1",
        "ZeroTier0",
        metric=1000,
    )
    assert result["added"] is True
    assert result["destination"] == "192.168.10.0/24"
    mock_client.rci.assert_called_once_with([
        {"ip": {"route": {
            "network": "192.168.10.0",
            "mask": "255.255.255.0",
            "gateway": "10.211.114.1",
            "interface": "ZeroTier0",
            "metric": 1000,
        }}},
        {"system": {"configuration": {"save": {}}}},
    ])


async def test_add_static_route_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError):
        await add_static_route("192.168.10.0/24", "10.211.114.1", "ZeroTier0")


async def test_add_static_route_raises_on_rci_error(mock_client):
    mock_client.rci.return_value = [{
        "ip": {"route": {"status": [{"status": "error", "message": "no input [http/rci]."}]}}
    }]
    with pytest.raises(RuntimeError, match="no input"):
        await add_static_route("192.168.10.0/24", "10.211.114.1", "ZeroTier0")


async def test_delete_static_route_by_destination(mock_client):
    mock_client.rci_get.return_value = [{
        "network": "192.168.10.0",
        "mask": "255.255.255.0",
        "gateway": "10.211.114.1",
        "interface": "ZeroTier0",
        "index": "abc",
    }]
    result = await delete_static_route(destination="192.168.10.0/24")
    assert result["deleted"] is True
    mock_client.rci.assert_called_once_with([
        {"ip": {"route": {
            "network": "192.168.10.0",
            "mask": "255.255.255.0",
            "no": True,
        }}},
        {"system": {"configuration": {"save": {}}}},
    ])


# ─── DNS routes ───────────────────────────────────────────────────────────────

DNS_ROUTES_DATA = {
    "show": {"sc": {
        "dns-proxy": {"route": [
            {"index": "abc123", "group": "domain-list1", "interface": "Wireguard0", "auto": True},
            {"index": "def456", "group": "domain-list0", "interface": "GigabitEthernet1", "auto": False, "disable": True},
        ]},
        "object-group": {"fqdn": {
            "domain-list0": {"description": "XEGARE"},
            "domain-list1": {"description": "steam"},
        }},
    }}
}


async def test_get_dns_routes(mock_client):
    mock_client.rci.return_value = DNS_ROUTES_DATA
    result = await get_dns_routes()
    assert len(result) == 2
    assert result[0]["list_name"] == "steam"
    assert result[0]["interface"] == "Wireguard0"
    assert result[0]["enabled"] is True
    assert result[1]["enabled"] is False


async def test_add_dns_route(mock_client):
    mock_client.rci.side_effect = [
        FQDN_GROUPS,  # _resolve_list_key
        {},           # rci batch (add + save)
        {"show": {"sc": {"dns-proxy": {"route": [
            {"index": "new999", "group": "domain-list1", "interface": "Wireguard0"}
        ]}}}},  # read back
    ]
    result = await add_dns_route("steam", "Wireguard0")
    assert result["created"] is True
    assert result["index"] == "new999"


async def test_add_dns_route_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError):
        await add_dns_route("steam", "Wireguard0")


async def test_delete_dns_route(mock_client):
    mock_client.rci.return_value = {}
    result = await delete_dns_route("abc123")
    assert result["deleted"] is True
    assert result["index"] == "abc123"


async def test_delete_dns_route_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError):
        await delete_dns_route("abc123")


# ─── set_interface_state ──────────────────────────────────────────────────────

async def test_set_interface_up(mock_client):
    mock_client.rci.return_value = {}
    result = await set_interface_state("GigabitEthernet0/1", up=True)
    assert result["state"] == "up"
    mock_client.rci.assert_called_once_with(
        {"interface": {"GigabitEthernet0/1": {"up": True}}}
    )


async def test_set_interface_down(mock_client):
    result = await set_interface_state("GigabitEthernet0/1", up=False)
    assert result["state"] == "down"
    mock_client.rci.assert_called_once_with(
        {"interface": {"GigabitEthernet0/1": {"down": True}}}
    )


async def test_set_interface_blocked_in_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError, match="safe mode"):
        await set_interface_state("GigabitEthernet0/1", up=False)


# ─── reboot ───────────────────────────────────────────────────────────────────

async def test_reboot_sends_command(mock_client):
    result = await reboot()
    assert "reboot" in result["status"]
    mock_client.rci.assert_called_once_with({"system": {"reboot": {}}})


async def test_reboot_blocked_in_safe_mode(mock_client):
    configure(safe_mode=True)
    with pytest.raises(PermissionError, match="safe mode"):
        await reboot()


# ─── safe mode via env var ────────────────────────────────────────────────────

async def test_safe_mode_via_env_var(mock_client, monkeypatch):
    monkeypatch.setenv("NETCRAZE_SAFE_MODE", "true")
    with pytest.raises(PermissionError):
        await reboot()


async def test_safe_mode_env_var_false_allows_write(mock_client, monkeypatch):
    monkeypatch.setenv("NETCRAZE_SAFE_MODE", "false")
    result = await reboot()
    assert result is not None


# ─── credentials validation ───────────────────────────────────────────────────

async def test_missing_host_raises(monkeypatch):
    monkeypatch.delenv("NETCRAZE_HOST", raising=False)
    monkeypatch.setenv("NETCRAZE_PASS", "pass")
    with pytest.raises(RuntimeError, match="NETCRAZE_HOST"):
        await get_system_info()


async def test_missing_pass_raises(monkeypatch):
    monkeypatch.setenv("NETCRAZE_HOST", "192.168.1.1")
    monkeypatch.delenv("NETCRAZE_PASS", raising=False)
    with pytest.raises(RuntimeError, match="NETCRAZE_PASS"):
        await get_system_info()


# ─── error sanitization ───────────────────────────────────────────────────────

def test_sanitize_error_redacts_password():
    err = Exception("Auth failed: password=my_secret_pass status=401")
    result = _sanitize_error(err)
    assert "my_secret_pass" not in result
    assert "password=<redacted>" in result


def test_sanitize_error_redacts_token():
    err = Exception("Request failed token=abc123xyz status=403")
    result = _sanitize_error(err)
    assert "abc123xyz" not in result


def test_sanitize_error_preserves_other_info():
    err = Exception("Connection refused to 192.168.1.1:80")
    result = _sanitize_error(err)
    assert "192.168.1.1" in result
    assert "Connection refused" in result


# ─── _sanitize_error in configure priority ───────────────────────────────────

async def test_configure_overrides_env_safe_mode(mock_client, monkeypatch):
    monkeypatch.setenv("NETCRAZE_SAFE_MODE", "true")
    configure(safe_mode=False)  # explicit False wins over env
    result = await reboot()
    assert result is not None


async def test_configure_none_defers_to_env(mock_client, monkeypatch):
    monkeypatch.setenv("NETCRAZE_SAFE_MODE", "1")
    configure(safe_mode=None)
    with pytest.raises(PermissionError):
        await reboot()


# ─── rci_get / redact / WAN / VPN / health (0.9.0) ────────────────────────────

from netcraze_mcp.redact import is_denied_safe_path, redact_cli_text, redact_value
from netcraze_mcp.tools.diagnostics import router_ping
from netcraze_mcp.tools.firewall import list_firewall_rules, list_nat_rules
from netcraze_mcp.tools.health import get_running_config_redacted, health_check
from netcraze_mcp.tools.policy import get_connection_priorities
from netcraze_mcp.tools.rci_access import rci_get, rci_get_safe
from netcraze_mcp.tools.vpn import list_vpn_connections
from netcraze_mcp.tools.wan import get_public_ip, get_wan_details
from netcraze_mcp.tools.zerotier import list_zerotier
from netcraze_mcp.tools.components import get_component


def test_redact_value_strips_private_key():
    data = {"interface": {"wireguard": {"private-key": "abc", "public-key": "pub"}}}
    out = redact_value(data)
    assert out["interface"]["wireguard"]["private-key"] == "<REDACTED>"
    assert out["interface"]["wireguard"]["public-key"] == "pub"


def test_redact_cli_private_key_line():
    text = "    private-key AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcde=\n    listen-port 51820"
    out = redact_cli_text(text)
    assert "AbCdEf" not in out
    assert "<REDACTED>" in out
    assert "listen-port 51820" in out


def test_rci_get_safe_denies_secrets_path():
    assert is_denied_safe_path("show/crypto/ipsec/secrets")
    assert is_denied_safe_path("interface/Wireguard0/wireguard/private-key")
    assert not is_denied_safe_path("show/system")


async def test_rci_get_redacts(mock_client):
    mock_client.rci_get.return_value = {"password": "secret", "hostname": "r1"}
    result = await rci_get("show/system")
    assert result["ok"] is True
    assert result["data"]["password"] == "<REDACTED>"
    assert result["data"]["hostname"] == "r1"


async def test_rci_get_safe_blocks(mock_client):
    result = await rci_get_safe("show/ipsec/password")
    assert result["ok"] is False
    assert result["denied"] is True
    mock_client.rci_get.assert_not_called()


async def test_get_wan_details_behind_nat(mock_client):
    mock_client.rci_get.side_effect = [
        {
            "GigabitEthernet1": {
                "id": "GigabitEthernet1",
                "interface-name": "ISP",
                "type": "GigabitEthernet",
                "address": "192.168.0.16",
                "mask": "255.255.255.0",
                "mtu": 1500,
                "global": True,
                "defaultgw": True,
                "priority": 64520,
                "link": "up",
                "state": "up",
                "connected": "yes",
                "description": "ISP",
            }
        },
        {
            "internet": True,
            "gateway": {"interface": "GigabitEthernet1", "address": "192.168.0.1"},
        },
        {"address": "", "ttp": {"direct": False, "address": "192.168.0.16"}},
        {"route": [{"destination": "0.0.0.0/0", "gateway": "192.168.0.1", "interface": "GigabitEthernet1"}]},
        {"GigabitEthernet1": {"ip": {"address": {"dhcp": True}}}},
    ]
    result = await get_wan_details()
    assert result["ok"] is True
    assert result["ipv4"]["address"] == "192.168.0.16"
    assert result["upstream_gateway"] == "192.168.0.1"
    assert result["behind_nat"] is True


async def test_get_public_ip_unsupported(mock_client):
    mock_client.rci_get.side_effect = [
        {"address": "", "ttp": {"direct": False, "address": "192.168.0.16"}},
        {"gateway": {"interface": "GigabitEthernet1"}},
        {"GigabitEthernet1": {"id": "GigabitEthernet1", "address": "192.168.0.16", "global": True, "defaultgw": True, "link": "up", "type": "GigabitEthernet"}},
    ]
    result = await get_public_ip()
    assert result["unsupported"] is True
    assert result["wan_ipv4"] == "192.168.0.16"


async def test_list_zerotier(mock_client):
    mock_client.rci_get.return_value = {
        "ZeroTier0": {
            "id": "ZeroTier0",
            "type": "ZeroTier",
            "address": "10.211.114.2",
            "mask": "255.255.255.0",
            "state": "up",
            "link": "up",
            "connected": "yes",
            "zerotier": {
                "network-id": "b9a18a606f598b24",
                "network-name": "WebSun",
                "status": "OK",
                "token": "SHOULD_NOT_LEAK",
            },
        }
    }
    mock_client.rci.return_value = {
        "show": {"interface": {"zerotier": {"peers": {"peer": [
            {"address": "abc", "latency": 10, "role": "LEAF", "path": ["1.2.3.4/9993"]},
        ]}}}}
    }
    result = await list_zerotier()
    assert result[0]["address"] == "10.211.114.2"
    assert result[0]["network_id"] == "b9a18a606f598b24"
    assert "SHOULD_NOT_LEAK" not in str(result)
    assert result[0]["peers_count"] == 1


async def test_list_vpn_connections(mock_client):
    mock_client.rci_get.side_effect = lambda path: {
        "show/interface": {
            "Wireguard0": {"id": "Wireguard0", "type": "Wireguard", "state": "up", "link": "up", "connected": "yes", "address": "10.0.0.1"},
            "ZeroTier0": {"id": "ZeroTier0", "type": "ZeroTier", "state": "up", "link": "up", "connected": "yes", "address": "10.211.114.2"},
        },
        "show/sc/crypto/ipsec/site-to-site": {},
        "show/crypto/map": {},
    }.get(path, {})
    result = await list_vpn_connections()
    ids = {item["id"] for item in result}
    assert "Wireguard0" in ids
    assert "ZeroTier0" in ids


async def test_get_connection_priorities(mock_client):
    mock_client.rci_get.side_effect = [
        {
            "GigabitEthernet1": {
                "id": "GigabitEthernet1", "type": "GigabitEthernet", "global": True,
                "defaultgw": True, "priority": 64520, "address": "192.168.0.16", "state": "up", "link": "up",
            },
            "Wireguard1": {
                "id": "Wireguard1", "type": "Wireguard", "global": True,
                "defaultgw": False, "priority": 16130, "address": "10.13.13.3", "state": "up", "link": "up",
            },
        },
        {"Policy0": {"description": "VPN", "mark": "ffffaaa", "table4": 4096, "route4": {"route": []}}},
    ]
    result = await get_connection_priorities()
    assert result["ok"] is True
    assert result["internet_order"][0]["id"] == "GigabitEthernet1"
    assert result["default_wan"]["id"] == "GigabitEthernet1"


async def test_list_firewall_and_nat(mock_client):
    async def _get(path):
        if path == "show/sc/access-list":
            return [{"acl": "_WEBADMIN_Bridge0", "action": "permit", "protocol": "ip"}]
        if path == "show/interface":
            return {"Bridge0": {"id": "Bridge0", "security-level": "private"}}
        if path == "show/sc/ip/static":
            return [{"interface": "GigabitEthernet1", "protocol": "tcpudp", "port": "6060", "comment": "RDP"}]
        if path == "show/upnp/redirect":
            return {"entry": []}
        if path == "show/ip/nat":
            return [{"protocol": "TCP"}] * 3
        return {}
    mock_client.rci_get.side_effect = _get
    fw = await list_firewall_rules()
    assert fw["ok"] is True
    assert fw["count"] == 1
    nat = await list_nat_rules()
    assert nat["port_forwards_count"] == 1
    assert nat["conntrack_sessions"] == 3


async def test_router_ping(mock_client):
    mock_client.rci_continued.return_value = {
        "messages": [
            "PING 1.1.1.1 (1.1.1.1) 56 (84) bytes of data.",
            "84 bytes from 1.1.1.1: icmp_req=1, ttl=58, time=12.0 ms.",
            "--- 1.1.1.1 ping statistics ---",
            "2 packets transmitted, 2 packets received, 0% packet loss,",
            "Round-trip min/avg/max = 12.0/12.5/13.0 ms.",
        ],
        "continued": False,
        "polls": 1,
    }
    result = await router_ping("1.1.1.1", count=2)
    assert result["ok"] is True
    assert result["received"] == 2


async def test_running_config_redacted(mock_client):
    mock_client.rci_get.return_value = {
        "message": [
            "interface Wireguard0",
            "    wireguard",
            "        private-key AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd=",
            "    up",
            "!",
            "system",
            "    set hostname router",
            "!",
        ]
    }
    result = await get_running_config_redacted(filter="interface")
    assert result["ok"] is True
    assert "private-key" in result["config"]
    assert "AbCdEfGh" not in result["config"]
    assert "<REDACTED>" in result["config"]
    assert "set hostname" not in result["config"]


async def test_health_check_ok(mock_client):
    mock_client.rci_get.side_effect = [
        {"release": "5.01", "title": "Ultra", "sandbox": "stable"},
        {"hostname": "router.websun", "uptime": "100"},
        {"internet": True, "reliable": True, "gateway": {"interface": "GigabitEthernet1", "address": "192.168.0.1"}},
    ]
    result = await health_check()
    assert result["ok"] is True
    assert result["auth_ok"] is True
    assert result["wan_internet"] is True
    assert result["firmware"] == "5.01"


async def test_health_check_connect_error(monkeypatch):
    from netcraze_mcp.client import NetCrazeError
    import netcraze_mcp.tools.health as ht

    class Boom:
        async def __aenter__(self):
            raise NetCrazeError("ConnectTimeout to 10.0.0.1 (GET /auth): router unreachable")

        async def __aexit__(self, *_):
            return False

    monkeypatch.setattr(ht, "_get_client", lambda: Boom())
    result = await health_check()
    assert result["ok"] is False
    assert "ConnectTimeout" in result["error"]

async def test_get_component(mock_client):
    mock_client.rci_get.return_value = {
        "ndw": {"components": "base,zerotier", "features": "usb_3"},
    }
    mock_client.rci.return_value = {
        "components": {"list": {"component": {
            "zerotier": {
                "group": "VPN",
                "description": {"EN": "ZeroTier"},
                "version": "1.16",
                "size": "100",
                "depends": "base",
            }
        }}}
    }
    result = await get_component("zerotier")
    assert result["installed"] is True
    assert result["version"] == "1.16"
    assert result["dependencies"] == ["base"]
