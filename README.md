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
tests/
  test_tools.py
```

```bash
pytest
```

## Лицензия

MIT (на базе upstream [Patr56/keenetic-mcp](https://github.com/Patr56/keenetic-mcp)).
