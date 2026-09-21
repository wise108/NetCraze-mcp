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
tests/
  test_tools.py
```

```bash
pytest
```

## Лицензия

MIT (на базе upstream [Patr56/keenetic-mcp](https://github.com/Patr56/keenetic-mcp)).
