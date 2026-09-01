#!/usr/bin/env bash
# Crea un DMG di installazione per macOS (trascina l'app in Applicazioni).
#
#   ./packaging/make_dmg_macos.sh            # versione da __init__.py
#   ./packaging/make_dmg_macos.sh 0.2.0      # forza la versione nel nome file
#
# Prerequisiti:
#   - dist/CorianoSign.app già compilata (packaging/build_macos.sh)
#   - create-dmg installato:  brew install create-dmg
set -euo pipefail
cd "$(dirname "$0")/.."

APP="dist/CorianoSign.app"
[ -d "$APP" ] || { echo "Manca $APP: esegui prima packaging/build_macos.sh"; exit 1; }

# versione letta direttamente da __init__.py (nessuna dipendenza dal venv)
VER="${1:-$(sed -n 's/^__version__ = "\(.*\)"/\1/p' src/corianosign/__init__.py)}"
[ -n "$VER" ] || { echo "Impossibile determinare la versione"; exit 1; }

OUT="dist/CorianoSign-${VER}.dmg"
ICON="packaging/CorianoSign.icns"
echo "==> Creo $OUT"
rm -f "$OUT"

# sfondo con freccia "Trascina in Applicazioni": TIFF Retina (72+144 dpi) da
# packaging/dmg_background.png + @2x. Se manca Pillow non serve: i PNG sono gia'
# committati; tiffutil (sempre presente su macOS) unisce le due risoluzioni.
BG_ARG=()
BG_PNG="packaging/dmg_background.png"
BG_2X="packaging/dmg_background@2x.png"
if [ -f "$BG_PNG" ]; then
    BG="$BG_PNG"
    if [ -f "$BG_2X" ] && command -v tiffutil >/dev/null 2>&1; then
        BG_TIFF="$(mktemp -t dmgbg).tiff"
        if tiffutil -cathidpicheck "$BG_PNG" "$BG_2X" -out "$BG_TIFF" >/dev/null 2>&1; then
            BG="$BG_TIFF"
        fi
    fi
    BG_ARG=(--background "$BG")
fi

# 1) create-dmg (impaginazione curata). Richiede il permesso «Automazione ▸ Finder»:
#    la prima volta il Terminale lo chiede; in ambienti headless non è concedibile
#    e si ricade sul fallback hdiutil.
if command -v create-dmg >/dev/null; then
    STAGE="$(mktemp -d)"
    cp -R "$APP" "$STAGE/"
    create-dmg \
      --volname "CorianoSign ${VER}" \
      ${ICON:+--volicon "$ICON"} \
      "${BG_ARG[@]}" \
      --window-pos 200 120 --window-size 640 400 --icon-size 128 \
      --icon "CorianoSign.app" 160 200 --hide-extension "CorianoSign.app" \
      --app-drop-link 480 200 --no-internet-enable \
      "$OUT" "$STAGE" || true
    rm -rf "$STAGE"
fi

# 2) fallback: DMG semplice con hdiutil (nessun controllo del Finder)
if [ ! -f "$OUT" ]; then
    echo "==> create-dmg non disponibile o non autorizzato: uso hdiutil (DMG semplice)."
    STAGE="$(mktemp -d)"
    cp -R "$APP" "$STAGE/"
    ln -s /Applications "$STAGE/Applications"
    hdiutil create -volname "CorianoSign ${VER}" -srcfolder "$STAGE" \
        -ov -format UDZO "$OUT" >/dev/null
    rm -rf "$STAGE"
fi

[ -f "$OUT" ] || { echo "DMG non creato."; exit 1; }
echo
echo "==> Fatto: $OUT"
echo "    L'utente lo apre, trascina CorianoSign in Applicazioni e l'app è installata."
echo "    (App non firmata: alla prima apertura vedi docs/distribuzione.md)"
