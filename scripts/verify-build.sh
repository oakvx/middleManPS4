#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if command -v llvm-readelf-18 >/dev/null; then READELF=llvm-readelf-18
elif command -v readelf >/dev/null; then READELF=readelf
else echo 'Servono llvm-readelf-18 o readelf' >&2; exit 2; fi
for file in dist/hello_world.elf dist/firmware_info.elf; do
  [[ -s "$file" ]] || { echo "ELF mancante o vuoto: $file" >&2; exit 1; }
  echo "===== $file ====="
  sha256sum "$file"
  "$READELF" -h "$file" | grep -E 'Class:|Machine:|Type:|Entry point'
  python3 -m host.ps4_sender.elfcheck --file "$file"
done
printf 'Build verificata localmente; esecuzione su PS4 NON verificata.\n'
