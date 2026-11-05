#!/usr/bin/env bash
set -euo pipefail
# Port 9020 is ONE-SHOT. Never pre-connect or probe it.
SRC="${ELFLDR_SRC:-$HOME/ps4-payload-elfldr}"
HOST="${PS4_HOST:-192.168.1.5}"
SDK="${PS4_PAYLOAD_SDK:-$HOME/ps4-payload-sdk-1252}"
if [[ "${1:-}" != '--send' || "${2:-}" != '--bootstrap-ready' ]]; then
  echo "Uso (solo con bin_loader.lua GIA' attivo sulla porta 9020):" >&2
  echo "PS4_HOST=$HOST bash scripts/deploy_elfldr.sh --send --bootstrap-ready" >&2
  echo "Non eseguire Test-NetConnection, nc -z o altre probe su 9020!" >&2
  exit 2
fi
[[ -d "$SRC/.git" ]] || { echo "elfldr mancante: bash scripts/setup_elfldr.sh" >&2; exit 2; }
[[ -x "$SDK/bin/orbis-clang" ]] || { echo "SDK non valido: $SDK" >&2; exit 2; }
python3 - "$HOST" <<'PYCODE'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1]); assert ip.is_private and not ip.is_unspecified
PYCODE
export PS4_PAYLOAD_SDK="$SDK" PS4_HOST="$HOST" PS4_PORT=9020
# Official upstream make test transmits the loader's first stage.
make -C "$SRC" test
echo "Invio bootstrap effettuato; esecuzione da confermare."
echo "Ora puoi verificare 9021: python3 -m host.ps4_sender.diagnostics --host $HOST --port 9021 --require-open"
