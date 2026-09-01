#!/usr/bin/env bash
# Rende l'app macOS DISTRIBUIBILE senza avvisi: firma Developer ID + hardened
# runtime, notarizzazione Apple e staple. Produce anche l'archivio firmato per
# l'auto-update (Ed25519) e il DMG, entrambi con l'app notarizzata dentro.
#
#   ./packaging/make_distributable_macos.sh
#
# Prerequisiti (UNA TANTUM, vedi docs/distribuzione.md):
#   1) Account Apple Developer a pagamento.
#   2) Certificato "Developer ID Application" installato nel portachiavi
#      (verifica: security find-identity -v -p codesigning).
#   3) Credenziali di notarizzazione salvate in un profilo del portachiavi:
#        xcrun notarytool store-credentials corianosign-notary \
#          --apple-id TUA_APPLE_ID --team-id TEAMID --password APP_SPECIFIC_PASSWORD
#      (la password specifica per app si crea su https://account.apple.com ▸
#       Sicurezza ▸ Password per le app; NON è la password dell'Apple ID.)
#
# Variabili d'ambiente opzionali:
#   CODESIGN_IDENTITY  stringa dell'identità (default: primo "Developer ID
#                      Application" trovato nel portachiavi)
#   NOTARY_PROFILE     nome del profilo notarytool (default: corianosign-notary)
#   SKIP_DMG=1         non creare/notarizzare il DMG (solo app + zip auto-update)
set -euo pipefail
cd "$(dirname "$0")/.."

APP="dist/CorianoSign.app"
ENT="packaging/entitlements_macos.plist"
NOTARY_PROFILE="${NOTARY_PROFILE:-corianosign-notary}"
VER="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' src/corianosign/__init__.py)"

[ -d "$APP" ] || { echo "Manca $APP: esegui prima packaging/build_macos.sh"; exit 1; }
[ -f "$ENT" ] || { echo "Manca $ENT"; exit 1; }
[ -n "$VER" ] || { echo "Impossibile determinare la versione"; exit 1; }

# --- 1) identità di firma ------------------------------------------------- #
if [ -z "${CODESIGN_IDENTITY:-}" ]; then
    CODESIGN_IDENTITY="$(security find-identity -v -p codesigning \
        | sed -n 's/.*"\(Developer ID Application:[^"]*\)"/\1/p' | head -1)"
fi
if [ -z "$CODESIGN_IDENTITY" ]; then
    cat <<'EOF'
[ERRORE] Nessun certificato "Developer ID Application" nel portachiavi.
Passi (una tantum):
  1. Iscriviti all'Apple Developer Program (99 $/anno).
  2. In Xcode ▸ Settings ▸ Accounts aggiungi l'Apple ID, poi "Manage
     Certificates" ▸ "+" ▸ "Developer ID Application" (oppure crealo su
     https://developer.apple.com/account/resources/certificates e installalo).
  3. Verifica con:  security find-identity -v -p codesigning
EOF
    exit 1
fi
echo "==> Identità di firma: $CODESIGN_IDENTITY"

# --- 2) firma di tutto il codice annidato + app (hardened runtime) -------- #
echo "==> Firmo i binari annidati (dylib/.so/plugin) …"
while IFS= read -r -d '' f; do
    if file -b "$f" | grep -q "Mach-O"; then
        codesign --force --timestamp --options runtime \
            --sign "$CODESIGN_IDENTITY" "$f" >/dev/null
    fi
done < <(find "$APP/Contents" -type f -print0)

echo "==> Firmo i framework …"
while IFS= read -r -d '' fw; do
    codesign --force --timestamp --options runtime \
        --sign "$CODESIGN_IDENTITY" "$fw" >/dev/null
done < <(find "$APP/Contents" -type d -name "*.framework" -print0)

echo "==> Firmo l'app (con entitlements) …"
codesign --force --timestamp --options runtime --entitlements "$ENT" \
    --sign "$CODESIGN_IDENTITY" "$APP"

echo "==> Verifica firma …"
codesign --verify --deep --strict --verbose=2 "$APP"

# --- 3) notarizzazione + staple dell'app ---------------------------------- #
ZIP_NOTARIZE="dist/CorianoSign-${VER}-notarize.zip"
echo "==> Creo lo zip per la notarizzazione …"
rm -f "$ZIP_NOTARIZE"
ditto -c -k --keepParent "$APP" "$ZIP_NOTARIZE"

echo "==> Invio a Apple (notarytool, attendo l'esito) …"
if ! xcrun notarytool submit "$ZIP_NOTARIZE" \
        --keychain-profile "$NOTARY_PROFILE" --wait; then
    cat <<EOF
[ERRORE] Notarizzazione fallita o profilo credenziali assente.
Salva le credenziali (una tantum) con:
  xcrun notarytool store-credentials $NOTARY_PROFILE \\
    --apple-id TUA_APPLE_ID --team-id TEAMID --password APP_SPECIFIC_PASSWORD
Per il dettaglio degli errori:
  xcrun notarytool log <submission-id> --keychain-profile $NOTARY_PROFILE
EOF
    exit 1
fi
rm -f "$ZIP_NOTARIZE"

echo "==> Applico il ticket all'app (staple) …"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
echo "==> Gatekeeper:"
spctl --assess --type exec -vv "$APP" || true

# --- 4) archivio firmato per l'auto-update (Ed25519) ---------------------- #
echo "==> Archivio auto-update (app ora notarizzata) …"
./packaging/make_release_macos.sh "$VER"

# --- 5) DMG e sua notarizzazione ------------------------------------------ #
if [ "${SKIP_DMG:-0}" != "1" ]; then
    echo "==> Creo il DMG …"
    ./packaging/make_dmg_macos.sh "$VER"
    DMG="dist/CorianoSign-${VER}.dmg"
    echo "==> Notarizzo e stapleo il DMG …"
    if xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait; then
        xcrun stapler staple "$DMG"
        xcrun stapler validate "$DMG"
    else
        echo "[avviso] Notarizzazione DMG non riuscita: il DMG resta valido ma"
        echo "         non stapleato (l'app dentro è comunque notarizzata)."
    fi
fi

echo
echo "==> FATTO. Artefatti distribuibili (nessun avviso Gatekeeper):"
echo "    dist/CorianoSign-${VER}-macos.zip      (+ .sig, per l'auto-update)"
[ "${SKIP_DMG:-0}" != "1" ] && echo "    dist/CorianoSign-${VER}.dmg            (installer)"
