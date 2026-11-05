#!/usr/bin/env bash
set -euo pipefail
# Explicit bootstrap only AFTER the remote Lua server is confirmed active.
HOST="${PS4_HOST:-192.168.1.5}"
SRC="${REMOTE_LUA_SRC:-$HOME/remote_lua_loader}"
[[ "${1:-}" == '--send' ]] || {
  echo "Uso: PS4_HOST=192.168.1.5 bash scripts/send_bin_loader_lua.sh --send" >&2
  echo "Prerequisito: remote_lua_loader attivo (gioco/savedata compatibili)." >&2
  exit 2
}
[[ -f "$SRC/payloads/send_lua.py" && -f "$SRC/payloads/bin_loader.lua" ]] || {
  echo "Remote Lua Loader non presente. Prima: bash scripts/setup_remote_lua.sh" >&2; exit 2
}
python3 - "$HOST" <<'PYCODE'
import ipaddress,sys
ip = ipaddress.ip_address(sys.argv[1]); assert ip.is_private and not ip.is_unspecified
PYCODE
python3 "$SRC/payloads/send_lua.py" "$HOST" 9026 "$SRC/payloads/bin_loader.lua"
echo "Lua inviato; il fatto che sia stato trasmesso non dimostra che il server 9020 sia partito."
