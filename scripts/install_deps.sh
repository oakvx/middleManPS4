#!/usr/bin/env bash
set -euo pipefail
# Optional explicit installation; never executed as part of build or deploy.
sudo apt-get update
sudo apt-get install -y git make bash clang-18 lld-18 llvm-18 binutils xxd python3 \
  python3-pyelftools wget netcat-openbsd socat
