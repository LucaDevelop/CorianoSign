#!/usr/bin/env bash
# Prepara l'archivio di release macOS firmato per l'auto-update.
#
#   ./packaging/make_release_macos.sh           # usa la versione da __init__.py
#   ./packaging/make_release_macos.sh 0.2.0     # forza la versione nel nome file
#
# Prerequisiti: dist/CorianoSign.app già compilata (packaging/build_macos.sh)
# e la chiave privata in packaging/update_private_key.pem.
set -euo pipefail
cd "$(dirname "$0")/.."

APP="dist/CorianoSign.app"
[ -d "$APP" ] || { echo "Manca $APP: esegui prima packaging/build_macos.sh"; exit 1; }

PY="${PYTHON:-.venv/bin/python}"
VER="${1:-$($PY -c 'import sys; sys.path.insert(0,"src"); import corianosign; print(corianosign.__version__)')}"

OUT="dist/CorianoSign-${VER}-macos.zip"
echo "==> Creo $OUT"
rm -f "$OUT"
# ditto -c -k --keepParent produce uno zip con dentro CorianoSign.app
ditto -c -k --keepParent "$APP" "$OUT"

echo "==> Firmo l'archivio (Ed25519)"
$PY packaging/update_keys.py firma "$OUT"

echo
echo "==> Fatto. Carica su una GitHub Release con tag v${VER}:"
echo "      $OUT"
echo "      ${OUT}.sig"
