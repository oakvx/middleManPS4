#!/usr/bin/env bash
set -euo pipefail
# Download and compile upstream elfldr; upstream is GPLv3+, not redistributed in this ZIP.
SDK="${PS4_PAYLOAD_SDK:-$HOME/ps4-payload-sdk-1252}"
SRC="${ELFLDR_SRC:-$HOME/ps4-payload-elfldr}"
REF="${ELFLDR_REF:-v0.7}"
URL=https://github.com/ps4-payload-dev/elfldr.git
[[ -x "$SDK/bin/orbis-clang" && -f "$SDK/toolchain/orbis.mk" ]] || {
  echo "SDK non valido: $SDK" >&2; exit 2;
}
for cmd in git make xxd; do
  command -v "$cmd" >/dev/null || { echo "Manca $cmd. Vedi scripts/install_deps.sh" >&2; exit 2; }
done
if [[ ! -d "$SRC/.git" ]]; then
  if [[ -e "$SRC" ]]; then echo "La cartella $SRC esiste ma non e' un checkout git: fermo." >&2; exit 2; fi
  git clone "$URL" "$SRC"
fi
[[ "$(git -C "$SRC" remote get-url origin)" == "$URL" || "$(git -C "$SRC" remote get-url origin)" == 'https://github.com/ps4-payload-dev/elfldr' ]] || {
  echo "Repository inatteso in $SRC. Verificalo manualmente." >&2; exit 2;
}
if [[ -n "$(git -C "$SRC" status --porcelain --untracked-files=no)" ]]; then
  echo "Il repository $SRC ha modifiche locali: non cambio versione." >&2; exit 2
fi
git -C "$SRC" fetch --tags origin
if ! git -C "$SRC" rev-parse --verify "${REF}^{commit}" >/dev/null 2>&1; then
  echo "Tag/commit non disponibile: $REF" >&2; exit 2
fi
git -C "$SRC" switch --detach "$REF"
echo "=== Versione elfldr ==="
git -C "$SRC" rev-parse HEAD
export PS4_PAYLOAD_SDK="$SDK"
make -C "$SRC" clean
make -C "$SRC"
echo "=== Output ELF/bin (non avviati sulla console) ==="
find "$SRC" -maxdepth 2 -type f \( -name '*.elf' -o -name '*.bin' \) -print -exec sha256sum '{}' \;
echo "=== Completato: per il bootstrap consulta docs/loader-install.md ==="
