#!/usr/bin/env bash
set -euo pipefail
# Optional: requires a compatible Artemis game and its configured save data.
URL=https://github.com/n0llptr/remote_lua_loader.git
SRC="${REMOTE_LUA_SRC:-$HOME/remote_lua_loader}"
command -v git >/dev/null || { echo "git mancante" >&2; exit 2; }
if [[ -e "$SRC" && ! -d "$SRC/.git" ]]; then
  echo "Cartella esistente che non e' un checkout: $SRC" >&2; exit 2
fi
if [[ ! -d "$SRC/.git" ]]; then git clone "$URL" "$SRC"; fi
printf 'Repository: %s\nRevision: ' "$SRC"
git -C "$SRC" rev-parse HEAD
printf '\nATTENZIONE: il clone NON installa il savedata, NON avvia Lua e NON esegue un jailbreak.\n'
printf 'Leggi %s/SETUP.md e docs/loader-install.md prima di proseguire.\n' "$SRC"
