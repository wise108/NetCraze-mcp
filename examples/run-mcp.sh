#!/usr/bin/env bash
# Запуск netcraze-mcp для Cursor: подгружает creds и exec stdio-сервер.
set -euo pipefail

CREDS="${NETCRAZE_CREDS_FILE:?Задайте NETCRAZE_CREDS_FILE или запускайте через mcp.json}"
if [[ -f "${CREDS}" ]]; then
  # shellcheck disable=SC1090
  source "${CREDS}"
fi

export NETCRAZE_HOST="${NETCRAZE_HOST:-192.168.0.1}"
export NETCRAZE_USER="${NETCRAZE_USER:-admin}"
export NETCRAZE_SAFE_MODE="${NETCRAZE_SAFE_MODE:-true}"

if [[ -z "${NETCRAZE_PASS:-}" ]]; then
  echo "netcraze-mcp: задайте NETCRAZE_PASS в ${CREDS}" >&2
  exit 1
fi

NETCRAZE_MCP_ROOT="${NETCRAZE_MCP_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
exec "${NETCRAZE_MCP_ROOT}/.venv/bin/netcraze-mcp" "$@"
