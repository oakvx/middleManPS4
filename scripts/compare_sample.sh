#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_SRC="${SDK_SRC:-$HOME/ps4-payload-sdk-src}"
SDK="${PS4_PAYLOAD_SDK:-$HOME/ps4-payload-sdk-1252}"
SAMPLE="$SDK_SRC/samples/hello_world"
[[ -d "$SAMPLE" ]] || { echo "Sample assente: $SAMPLE" >&2; exit 2; }
PS4_PAYLOAD_SDK="$SDK" make -C "$SAMPLE" clean all
mkdir -p "$ROOT/dist"
cp "$SAMPLE/hello_world.elf" "$ROOT/dist/hello_world_official.elf"
sha256sum "$ROOT/dist/hello_world_official.elf" "$ROOT/dist/hello_world.elf"
cd "$ROOT"
python3 -m host.ps4_sender.elfcheck --file "dist/hello_world_official.elf"
