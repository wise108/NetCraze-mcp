# NetCraze-mcp

MCP-сервер для роутеров **NetCraze** — управление через Cursor и другие MCP-клиенты (RCI HTTP API).

Форк community-проекта [Patr56/keenetic-mcp](https://github.com/Patr56/keenetic-mcp) (MIT), адаптированный под NetCraze.

## Инструменты

### Static DNS hosts (NetCraze)

| Инструмент | Описание |
|---|---|
| `list_static_hosts` | Список static hosts из `show dns-proxy` (фильтр private IP) |
| `add_static_host` | Добавить host и сохранить конфигурацию |
| `delete_static_host` | Удалить host по имени и сохранить конфигурацию |

### Static IP routes (NetCraze)

| Инструмент | Описание |
|---|---|
| `list_static_routes` | Список configured static routes (`show sc ip route`) |
| `add_static_route` | Добавить `ip route` (CIDR + gateway + interface) и save |
| `delete_static_route` | Удалить по destination CIDR или index и save |

### Компоненты, USB/хранилище, шары

| Инструмент | Описание |
|---|---|
| `list_components` | NDMS-компоненты; `group` — substring (`usb` → USB modems + usb*) |
| `get_firmware_info` | Версия прошивки, sandbox/channel, список установленных компонентов |
| `install_component` | Поставить компонент (`commit=true` запускает установку) |
| `remove_component` | Удалить компонент (`commit=true` применяет удаление) |
| `list_usb_storage` | Накопители из `show media` + встроенный flash из `ls` → `storage:` (как в UI) |
| `unmount_usb` | Безопасно извлечь USB (`system eject`), только ejectable |
| `list_shares` | SMB/CIFS-шары из `show cifs` |
| `set_share` / `delete_share` | Создать/удалить SMB-шару и save |
| `list_printers` | Принтеры из `show printers` |

> Remount USB после `unmount_usb` — переподключением диска (отдельной RCI mount-команды нет).

### Backup / export

| Инструмент | Описание |
|---|---|
| `download_system_file` | Универсальная выгрузка системного файла (`startup-config`, `running-config`, `default-config`, `log`, `self-test`, `firmware`) |
| `export_backup` | Экспорт набора системных файлов + metadata роутера (model/version/timestamp) |

> Бинарник прошивки ~20–25 MB. По умолчанию в ответе только sha256/size; для файла укажите `save_path`. Параметр `sandbox` добавляет метаданные канала обновлений, но .bin — только текущая установленная прошивка.

### WireGuard

| Инструмент | Описание |
|---|---|
| `list_wireguard` | Список `WireguardN`: id, description, state, link, address, endpoint |
| `get_wireguard` | Детали одного интерфейса (без PrivateKey/PresharedKey) |
| `add_wireguard_from_conf` | Импорт из `.conf` (`conf` текст или `path` к `.conf`); save; опционально `interface_id`, `enabled`, `description` |
| `set_wireguard_state` | up/down без удаления + save |
| `delete_wireguard` | Удалить интерфейс + save |

Пример:

```text
add_wireguard_from_conf(
  conf="<содержимое peer_xxx.conf>",
  description="Cloudflare WARP",
  enabled=true
)
→ { "id": "Wireguard3", "description": "Cloudflare WARP", "address": "10.13.14.2", ... }

add_dns_route(list_name="Gemini", interface="Wireguard3", auto=true, enabled=true)
```

> PrivateKey/PresharedKey никогда не возвращаются и маскируются в ошибках. Импорт идёт через `/rci/interface/wireguard/import` (как UI «из файла»).

### IPsec site-to-site (read-only)

| Инструмент | Описание | RCI на NDMS 5.01 |
|---|---|---|
| `list_ipsec` / `list_ipsec_connections` | Список S2S: id, enabled, connected/state, remote gateway, IKE version | `GET show/sc/crypto/ipsec/site-to-site` + `GET show/crypto/map` |
| `get_ipsec` | Детали (ID, subnets, IKE/ESP, DPD, nailed-up, autoconnect, Phase1/2); PSK → только `has_psk` | те же |
| `list_ipsec_proposals` | IKE/ESP/DH алгоритмы (aes-cbc-256, sha256, DH14/modp2048…) | UI static (live catalog на 5.01 нет) |
| `show_ipsec_sa` | SA: legacy `show/crypto/ipsec/sa` (часто 404) → fallback из `show/crypto/map` | см. ответ `rci_paths` |
| `show_ipsec` | Dump ipsec + site-to-site + crypto_map без секретов | `show/ipsec`, site-to-site, map |
| `show_crypto` | Dump crypto/sc crypto/ike без секретов | `show/crypto`, `show/sc/crypto`, `show/crypto/map` |

> WRITE (`create_ipsec_s2s` / `set_ipsec_state` / `delete_ipsec`) — отдельно, пока не реализовано.  
> На NDMS 5.01 путь `show/crypto/ipsec/sa` отсутствует (404); статус туннелей — в `show/crypto/map`.

### Raw RCI + аудит (read-only, 0.9.0)

| Инструмент | Описание |
|---|---|
| `rci_get` | GET `/rci/<path>` с auth MCP; авто-redact password/psk/private-key/secret/token |
| `rci_get_safe` | То же + deny-list путей с секретами |
| `get_wan_details` | WAN: IP/mask/gw/DNS/MTU/тип, `behind_nat`, `upstream_gateway`, public IP hint |
| `get_public_ip` | Public IP из NDNS/CrazeDNS или `unsupported` (без смены маршрутов) |
| `list_zerotier` / `get_zerotier` | Сеть/IP/status + peers (без tokens) |
| `list_vpn_connections` / `get_vpn_connection` | Единый список WG/OpenVPN/PPTP/L2TP/SSTP/IPsec/GRE/ZT… |
| `get_connection_priorities` | `ip global` priority + Policy tables |
| `get_policy_routing_summary` | DNS-routes + static routes + ip rule/policy |
| `list_firewall_rules` | access-list + security-level |
| `list_nat_rules` | port forwards + UPnP + count conntrack (без полного dump) |
| `router_ping` / `router_traceroute` / `router_nslookup` | Диагностика с лимитами (ping count≤5; traceroute hops≤15) |
| `get_running_config_redacted` | `show/running-config` без секретов; `filter=interface|crypto|ip|…` |
| `health_check` | auth/firmware/uptime/WAN + понятные ошибки (timeout/auth/HTTP) |
| `get_component` | Один NDMS-компонент: installed/version/deps |

> WRITE только у существующих `set_*` / `add_*` / `delete_*` / `reboot` / components (и только вне safe-mode). Диагностические tools никогда не меняют конфиг.

### Система, сеть, DNS-маршрутизация (upstream)

`get_system_info`, `reboot`, `get_interfaces`, `get_interface`, `get_connected_clients`, `get_wifi_associations`, `get_speed`, `get_routes`, `get_wan_status`, `get_wan_speed`, `get_domain_lists`, `get_domain_list`, `create_domain_list`, `delete_domain_list`, `set_domain_list`, `add_domains`, `remove_domains`, `get_dns_routes`, `add_dns_route`, `delete_dns_route`, `set_interface_state`

## Установка

```bash
cd NetCraze-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `NETCRAZE_HOST` | — | IP роутера (**обязательно**) |
| `NETCRAZE_USER` | `admin` | Логин RCI |
| `NETCRAZE_PASS` | — | Пароль (**обязательно**) |
| `NETCRAZE_SAFE_MODE` | `true` | Блокировать write-инструменты |
| `NETCRAZE_CREDS_FILE` | — | Путь к файлу creds (для Cursor) |

## Подключение в Cursor

### 1. Creds — секреты вне репозитория

По одному файлу creds на каждый роутер:

```bash
mkdir -p ~/.config/mcp-netcraze
chmod 700 ~/.config/mcp-netcraze

cp examples/creds.router.home.example ~/.config/mcp-netcraze/creds.router.home
cp examples/creds.router.work.example ~/.config/mcp-netcraze/creds.router.work
cp examples/run-mcp.sh ~/.config/mcp-netcraze/run-mcp.sh
chmod 600 ~/.config/mcp-netcraze/creds.router.*
chmod 700 ~/.config/mcp-netcraze/run-mcp.sh
# заполните NETCRAZE_HOST и NETCRAZE_PASS в каждом creds-файле
```

Пароль **только** в `creds.router.*`, не в `mcp.json`.

### 2. Конфиг `~/.cursor/mcp.json`

Два MCP-сервера — два роутера. В `mcp.json` только путь к creds:

```json
{
  "mcpServers": {
    "router.home": {
      "command": "$HOME/.config/mcp-netcraze/run-mcp.sh",
      "env": {
        "NETCRAZE_CREDS_FILE": "$HOME/.config/mcp-netcraze/creds.router.home"
      }
    },
    "router.work": {
      "command": "$HOME/.config/mcp-netcraze/run-mcp.sh",
      "env": {
        "NETCRAZE_CREDS_FILE": "$HOME/.config/mcp-netcraze/creds.router.work"
      }
    }
  }
}
```

`run-mcp.sh` читает `NETCRAZE_CREDS_FILE` и подгружает HOST/USER/PASS/Safe mode оттуда.

### 3. Проверка

1. Перезапуск Cursor (Cmd+Q)
2. **Settings → Tools & MCPs** → `router.home` и `router.work` зелёные
3. В чате указывайте сервер явно:
   - «На **router.home** покажи static hosts»
   - «На **router.work** добавь host …»

## Safe mode

- `NETCRAZE_SAFE_MODE=true` (или не задано) → write-инструменты блокируются
- Для записи: `export NETCRAZE_SAFE_MODE="false"` в нужном creds-файле

## Разработка

```
netcraze_mcp/
  client.py          # NetCrazeClient, auth, RCI
  config.py          # safe_mode (по умолчанию true)
  server.py          # FastMCP init, main()
  tools/
    system.py        # get_system_info, reboot
    network.py       # interfaces, clients, WAN, routes
    dns_routes.py    # domain lists, DNS routing
    static_hosts.py  # list/add/delete static hosts
    static_routes.py # list/add/delete static IP routes
    components.py    # list_components, get_firmware_info
    storage.py       # list_usb_storage, list_shares, list_printers
    backup.py        # download_system_file, export_backup
    wireguard.py     # list/get/add_from_conf/set_state/delete WireGuard
    ipsec.py         # list/get/proposals/show_* IPsec S2S (read-only)
tests/
  test_tools.py
```

```bash
pytest
```

## Лицензия

MIT (на базе upstream [Patr56/keenetic-mcp](https://github.com/Patr56/keenetic-mcp)).
