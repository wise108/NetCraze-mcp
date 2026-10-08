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

> На NDMS 5.01 путь `show/crypto/ipsec/sa` отсутствует (404); статус туннелей — в `show/crypto/map`.

### IPsec site-to-site WRITE (0.10.0)

| Инструмент | Описание |
|---|---|
| `create_ipsec_s2s` | Создать/обновить S2S (idempotent по `name`); `source_name`+keep_psk без PSK в args; **confirm=true** |
| `clone_ipsec` | Clone профиля (PSK только в памяти); **confirm=true** |
| `rename_ipsec` | Rename без PSK в args (create+delete в памяти); **confirm=true** |
| `update_ipsec_s2s` | Full-replace RMW; `keep_psk=true` читает PSK из RC только в памяти |
| `set_ipsec_state` | Только `parse crypto map … enable` / `no crypto map … enable` (+ `service.ipsec=true` при enable) |
| `delete_ipsec` | Flat `{name, no: true}` → «removed crypto map.» |

Каноническая последовательность:

```text
1) POST /rci/  [{"crypto":{"ipsec":{"site-to-site":{ "name":"…", …все поля + lifetimes… }}}}]
2) parse: crypto map <name> enable          # или: no crypto map <name> enable
3) system.configuration.save
```

Пример (NC → strongSwan IKEv2 PSK):

```text
create_ipsec_s2s(
  name="nc-office",
  peer="45.89.63.73",
  ike_psk="<PSK>",
  local_id="office-nc1812",
  remote_id="weaselcloud-ipsec",
  local_networks="192.168.1.0/24",
  remote_networks="1.1.1.1/32",
  force_encaps=true,
  enable=true,
  save=true,
  confirm=true
)
```

**Known limitations (NDMS 5.01):**
- Nested `site-to-site.{name}` → `not found` — только flat с полем `name`
- Partial `{"name","enable":true}` в site-to-site JSON **сбрасывает** peer/autoconnect — запрещено в tools
- `show/sc` до save устаревший; verify сначала `show/rc`
- `ike-prf` может остаться `""` в RC; `force-encaps` может отсутствовать в RC после set (для double-NAT смотри `show/crypto/map`)
- `crypto map X disable` не существует → используем `no crypto map X enable`
- PSK никогда не возвращается (`has_psk` only); нужен `confirm=true` + writable (не safe-mode)

### 0.14.0 — multi-router, txn, CLI parse, policy/FQDN sync, granular WG

| Инструмент | Описание |
|---|---|
| `snapshot_config` / `diff_config` / `rollback_hint` / `save_config` | Снапшот redacted RC, diff, подсказки отката, **явный** save |
| `apply_cli_batch` | baseline → parse commands → verify → rollback_on_fail; `save=False` |
| `rci_parse_readonly` / `cli_help` / `rci_parse_write` | Whitelist parse / help без `?` / write через batch |
| `get_policy_tables` / `diagnose_dns_proxy_route` | Таблицы 4097+, fwmark, флаг **ON_LINK_DEFAULT** |
| `plan_fqdn_static_sync` / `apply_fqdn_static_sync` | FQDN→/32 с тегом `fqdnsync:<list>` (обход бага gateway) |
| `create_wireguard` / `add|update|remove_wireguard_peer` | Без .conf; `connect_via` только после `cli_help` |
| `find_leftover_interfaces` / `wireguard_handshake_check` | Пустые WG/ACL; handshake двух роутеров |
| `get_access_list` / `add_acl_rule` / `remove_acl_rule` | Тело ACL + mutate через batch |
| `get_interface_security` / `check_udp_listen` | security-level; UDP listen = unsupported + косвенные признаки |
| `cross_router_reachability` | Ping с src_router; optional capture на dst |

**Поведение write:** все write-tools по умолчанию `save=False`. Сохранение — `save_config(confirm=true)` или `save=true` на операции.

**Multi-router (один процесс):**

```bash
export NETCRAZE_ROUTERS='{
  "router.home": {"host":"192.168.10.1","user":"admin","password":"…",
                  "fallback_hosts":["10.211.114.1","https://xxx.keenetic.link"]},
  "router.websun": {"host":"192.168.1.1","user":"admin","password":"…",
                    "fallback_hosts":["10.211.114.2"]}
}'
```

Каждый tool принимает опциональный `router="router.home"`. `NETCRAZE_HOST` может быть `https://host:port`; `NETCRAZE_VERIFY_TLS=false` при необходимости.

**403 vs auth:** `GET /auth` → 403 без `X-NDM-Challenge` = `RCI_FORBIDDEN_BY_SECURITY_LEVEL` (ACL/security-level интерфейса), не неверный пароль.

### Known NDMS 5.1.6 limitations

- **FQDN → ZeroTier/VPN gateway ignored:** dns-proxy route с `gateway` материализуется как `0.0.0.0/0 via 0.0.0.0 <iface>` (**ON_LINK_DEFAULT**). Workaround: `plan_fqdn_static_sync` /32.
- **`?` help не работает** («no such command: ?») — используйте `cli_help` (`help <cmd>` + неполная команда).
- **403 по ZeroTier** при `security-level public` / без permit в `_WEBADMIN_ZeroTier0`.
- **L7 с роутера** (curl/tcp/exit-IP) — нет в RCI; tools честно `unsupported`.
- **UDP listen sockets** — RCI не отдаёт; `check_udp_listen` = unsupported + косвенные признаки.

### VPN datapath diagnostics (0.13.0)

| Инструмент | Статус на NDMS 5.01 |
|---|---|
| `get_wireguard_runtime` | handshake age, rx/tx, endpoint, keepalive, peer_online |
| `get_interface_counters` | rx/tx/errors/drops + optional delta |
| `explain_dns_route` | domain-list → dns-proxy interface |
| `explain_route` | LPM show/ip/route + dns hint |
| `list_datapath_capabilities` / `list_rci_readonly_catalog` | честная матрица / каталог RCI |
| `get_conntrack` / `get_hotspot` | фильтр NAT sessions / RO hotspot hosts |
| `capture_flow_summary` | start→stop→summary→cleanup (`confirm=true`) |
| `router_http_probe` / `router_tcp_check` / `router_exit_ip` / `router_http_speed` | **unsupported** (нет tools.curl/tcp) — явный ответ + fallbacks |

### Packet capture / monitor (0.12.0)

| Инструмент | Описание |
|---|---|
| `get_packet_capture_status` | monitor installed / available / running + rci_paths |
| `list_packet_captures` / `get_packet_capture` | инстансы по интерфейсу |
| `ensure_packet_capture` | install `monitor` при confirm (не стартует capture) |
| `start_packet_capture` | create+filter+enable; `filter_preset=ike` → udp/500|4500 |
| `stop_packet_capture` | `no … enable` |
| `download_packet_capture` | summary (pcap parse) или pcap на диск via `/ci/temp:…` |
| `delete_packet_capture` | удалить instance |

NDMS: start=`enable`, stop=`no enable`; BPF в кавычках; pcap часто gzip.

### IPsec runtime bring-up (0.11.0 / hotfix 0.11.1 / 0.11.2)

| Инструмент | Описание |
|---|---|
| `get_ipsec_runtime` | Read-only: enabled / ike_state / state / endpoints / map.connect|nail-up / ui_status |
| `diagnose_ipsec_bringup` | Read-only checklist + `charon` + `ike_path.conntrack` |
| `get_ike_conntrack` | Read-only фильтр `show/ip/nat` по peer + UDP/500|4500 (без полного dump) |
| `get_packet_capture_status` | Read-only: установлен ли `monitor` / доступен ли capture (**не** ставит компонент) |
| `rename_ipsec` | Rename S2S без передачи PSK агенту (PSK только в памяти) |
| `clone_ipsec` / `create_ipsec_s2s(source_name=…)` | Clone с `keep_psk`; `ike_psk` не required |

**0.11.1:** `get_running_config_redacted` redact’ит `crypto ike key …`; runtime endpoints одинаковы в diagnose/get; diagnose не врёт «IKE не стартовал», если charon CONNECTING.

**0.15.1:** polish live acceptance — `expected_dst_out`=iface SNAT + `gateway_configured`; one matched `policy[]` table; batch `expect=WAN`→PASS/`path=WAN` + `name`; compact `wireguard_counter_delta`.

**0.15.0:** sc/rc honesty (`source`/`dirty`/`applied_to`/`persisted`); `get_domain_list` defaults to rc; `diff_sc_rc`; `explain_policy_path` / `verify_flow_path` / `verify_flow_path_batch`; `domain_list_covers_ip` + `list_dns_route_metadata`; WG `AllowedIPs` + `add_wireguard_allowed_ips` + `wireguard_counter_delta`; `get_conntrack` src+dst/path_class/watch; `probe_tcp` (ICMP+NAT only); `suggest_telegram_cidrs`; `save_config` post-check sc==rc.

**0.14.0:** multi-router + https/fallback; save=False default; snapshot/diff/rollback/apply_cli_batch; CLI parse/help; policy tables + ON_LINK_DEFAULT; FQDN→/32 sync; granular WireGuard; ACL/security; cross-router reachability.

**0.13.1:** `get_conntrack(host/port/protocol)` + RO `get_hotspot`; pip metadata synced.

**0.13.0:** VPN datapath explain/runtime/counters; L7 probes marked unsupported on NDMS.

**0.12.0:** packet capture lifecycle (monitor enable/no enable + /ci/temp pcap).

**0.11.3:** diagnose warnings согласованы с conntrack; clone/rename не шлют force-encaps если absent у source.

**0.11.2:** `rename_ipsec` / `clone_ipsec` / `source_name`; `get_ike_conntrack`; `ike_phase=none` при `0 up, 0 connecting`; `ike_prf=""` omit; `get_packet_capture_status`.

**Research (websun NC-1812, NDMS 5.01 + ipsec 6.0.1-6) — runtime initiate NOT FOUND:**

| Флаг / действие | Семантика |
|---|---|
| `set_ipsec_state(enable)` / UI toggle / `crypto.map.{name}.enable` | Config: map enabled. **≠ IKE_SA_INIT** |
| `crypto map X connect` / `map.connect=true` | Config: «enable autoconnection» (≈ autoconnect). **≠ initiate** |
| `nail-up` | «active renegotiation» — держать SA после установления, не первый bring-up |
| UI Connect button | **Нет** — только toggle enable |
| `initiate` / `start` / `up` / `clear crypto sa` | **Нет таких CLI** |

Вывод (семантика **B**): после enable+autoconnect+nail-up `ike_state` может остаться `UNDEFINED` (UI `NO_LINK`) до interesting traffic на remote TS и/или пока peer сам не инициирует.  
Поэтому **`connect_ipsec` / `disconnect_ipsec` не публикуются** (нет честного runtime endpoint).

Последовательность NC→strongSwan:

```text
create_ipsec_s2s → set_ipsec_state(enable) → diagnose_ipsec_bringup
→ трафик LAN(local TS) → remote TS  ИЛИ  swanctl initiate на VPS
→ get_ipsec_runtime / show_ipsec_sa
```

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
| `get_conntrack` | фильтр live NAT (host/src/dst/port/protocol/path_class/only_unreplied/group_by/watch_seconds) |
| `explain_policy_path` | dns-proxy policy path (list hit → route → table → expected dst_out); **не** FIB-only |
| `verify_flow_path` | одна карточка: list + NAT + AllowedIPs + handshake + verdict A–G |
| `verify_flow_path_batch` | batch regression (Claude/YouTube→WG0, ya.ru→WAN) |
| `diff_sc_rc` | sc≠rc для domain-lists / dns-routes / WG AllowedIPs |
| `domain_list_covers_ip` | CIDR/IP match + linked dns-route interface |
| `list_dns_route_metadata` | таблица list_key/name/route/iface/counts/sc_dirty |
| `add_wireguard_allowed_ips` | additive merge AllowedIPs (reject 0.0.0.0/0) |
| `wireguard_counter_delta` | snapshot → sleep → Δ rx/tx/handshake |
| `probe_tcp` | ICMP+conntrack only (TCP connect unsupported on NDMS) |
| `suggest_telegram_cidrs` | suggest-only CIDR из core.telegram.org (+ backup 95.161.64.0/20) |
| `get_hotspot` | RO hotspot hosts (policy/access/wifi) |
| `router_ping` / `router_traceroute` / `router_nslookup` | Диагностика с лимитами (ping count≤5; traceroute hops≤15) |
| `get_running_config_redacted` | `show/running-config` без секретов; `filter=interface|crypto|ip|…` |
| `health_check` | auth/firmware/uptime/WAN + понятные ошибки (timeout/auth/HTTP) |
| `get_component` | Один NDMS-компонент: installed/version/deps |

> WRITE только у существующих `set_*` / `add_*` / `delete_*` / `reboot` / components (и только вне safe-mode). Диагностические tools никогда не меняют конфиг.

### Система, сеть, DNS-маршрутизация (upstream)

`get_system_info`, `reboot`, `get_interfaces`, `get_interface`, `get_connected_clients`, `get_wifi_associations`, `get_speed`, `get_routes`, `get_wan_status`, `get_wan_speed`, `get_domain_lists`, `get_domain_list` (default **rc**; `saved=true` → sc; always `source`/`dirty`), `create_domain_list`, `delete_domain_list`, `set_domain_list`, `add_domains`, `remove_domains`, `get_dns_routes`, `add_dns_route`, `delete_dns_route`, `set_interface_state`

Write-tools возвращают `applied_to=rc`, `persisted`, `dirty` — `added`/`created` только если rc реально изменился. `save_config` после save проверяет sc==rc.

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

**Вариант A (0.14.0) — один процесс, multi-router:** задайте `NETCRAZE_ROUTERS` (JSON) и вызывайте tools с `router="router.home"` / `router="router.websun"`.

**Вариант B — два MCP-сервера** (как раньше). В `mcp.json` только путь к creds:

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

## Не удалось реализовать из‑за лимитов RCI (с доказательствами)

| Запрос | Почему нельзя | Доказательство / обход |
|---|---|---|
| HTTP/TCP/exit-IP/speed с роутера | Нет `tools.curl` / `tools.tcp` на NDMS 5.01 | Live: L7 tools → `unsupported`; `probe_tcp` = ICMP+NAT; ping + counters + capture |
| bare IP «куда уйдёт» через `explain_route` | FIB main table ≠ dns-proxy policy | `explain_policy_path` / `verify_flow_path` |
| SSH/tcpdump на HAPP (.254) | MCP не читает SSH-ключи | Вне скоупа; host SSH вручную |
| DNS cache inspect/flush | Часто 404 / нет стабильного RCI | Нереалистично на 5.1.6 |
| `connect_via` без подтверждения | Синтаксис не документирован; `?` не работает | Только после `cli_help` → `supported`; иначе `not_supported` |
| Список listening UDP sockets | RCI не отдаёт сокеты | `check_udp_listen` = unsupported + WG listen-port / port-forward / ACL |
| Entware curl helper | Осознанный риск (shell на роутере) | Вне скоупа MCP |
| Полный dump `show/ip/conntrack` | Текстовый шум, огромный | `get_conntrack(host/src/dst/port/…)` по `show/ip/nat` |
| auto-apply Telegram CIDR | Только suggest | `suggest_telegram_cidrs` → ручной `add_domains` + `add_wireguard_allowed_ips` |

## Лицензия

MIT (на базе upstream [Patr56/keenetic-mcp](https://github.com/Patr56/keenetic-mcp)).
