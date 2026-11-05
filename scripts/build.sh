#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PS4_PAYLOAD_SDK="${PS4_PAYLOAD_SDK:-$HOME/ps4-payload-sdk-1252}"
[[ -x "$PS4_PAYLOAD_SDK/bin/orbis-clang" && -f "$PS4_PAYLOAD_SDK/toolchain/orbis.mk" ]] || {
  echo "SDK mancante: $PS4_PAYLOAD_SDK (atteso bin/orbis-clang e toolchain/orbis.mk)" >&2
  exit 2
}
cd "$ROOT"
# Forced rebuild prevents accidentally using a binary built with another SDK.
make -B PS4_PAYLOAD_SDK="$PS4_PAYLOAD_SDK" all
bash scripts/verify-build.sh
