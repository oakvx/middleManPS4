#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ELFLDR_SRC:-$HOME/ps4-payload-elfldr}"
BIN="$SRC/elfldr.bin"
[[ -f "$BIN" ]] || {
  printf 'ERRORE: %s non esiste. Prima esegui: bash scripts/setup_elfldr.sh\n' "$BIN" >&2
  exit 2
}
python3 - "$BIN" <<'PYCODE'
from pathlib import Path
import sys
p=Path(sys.argv[1]); contents=p.read_bytes()
if len(contents) < 128:
    raise SystemExit("ERRORE: elfldr.bin troppo piccolo o vuoto")
if contents.startswith(b'\x7fELF'):
    raise SystemExit("ERRORE: elfldr.bin contiene un ELF; non rinominare un .elf in .bin")
print(f"Loader flat BIN valido come formato: {len(contents)} byte (esecuzione non verificata)")
PYCODE
mkdir -p "$ROOT/dist"
cp "$BIN" "$ROOT/dist/elfldr.bin"
(cd "$ROOT/dist" && sha256sum elfldr.bin > elfldr.bin.sha256)
echo '=== Bootstrap elfldr BIN pronto (non inviato) ==='
ls -lh "$ROOT/dist/elfldr.bin"
cat "$ROOT/dist/elfldr.bin.sha256"
echo '=== GoldHEN port 9090 per .bin. elfldr port 9021 per .elf ==='
