#!/usr/bin/env bash
# SPIKE PKCS#11: crea un token SoftHSM2 di TEST con una chiave RSA + certificato
# self-signed, per provare la firma da "dispositivo" senza hardware reale.
#
#   ./packaging/spike_softhsm_setup.sh
#   ./packaging/spike_pkcs11_demo.py         # poi firma+verifica (vedi demo)
#
# Prerequisiti (macOS): brew install softhsm opensc ; pip install PyKCS11
# Tutto vive in una cartella isolata (SPIKE_HOME), NON tocca la config SoftHSM
# di sistema. Per ripulire: rm -rf "$SPIKE_HOME".
set -euo pipefail

SPIKE_HOME="${SPIKE_HOME:-$HOME/.cache/corianosign-pkcs11-spike}"
TOKEN_LABEL="${TOKEN_LABEL:-CorianoSignTest}"
PIN="${PIN:-1234}"
SO_PIN="${SO_PIN:-123456}"
OBJ_LABEL="signkey"
OBJ_ID="01"

# modulo SoftHSM2
MODULE="${PKCS11_MODULE:-}"
if [ -z "$MODULE" ]; then
    for p in /opt/homebrew/lib/softhsm/libsofthsm2.so \
             "$(brew --prefix softhsm 2>/dev/null)/lib/softhsm/libsofthsm2.so" \
             /usr/local/lib/softhsm/libsofthsm2.so \
             /usr/lib/softhsm/libsofthsm2.so; do
        [ -f "$p" ] && MODULE="$p" && break
    done
fi
[ -n "$MODULE" ] && [ -f "$MODULE" ] || { echo "libsofthsm2.so non trovato. Installa: brew install softhsm"; exit 1; }

echo "==> SPIKE_HOME: $SPIKE_HOME"
rm -rf "$SPIKE_HOME"
mkdir -p "$SPIKE_HOME/tokens"

# config SoftHSM isolata
export SOFTHSM2_CONF="$SPIKE_HOME/softhsm2.conf"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $SPIKE_HOME/tokens
objectstore.backend = file
log.level = ERROR
EOF

echo "==> Inizializzo il token '$TOKEN_LABEL'"
softhsm2-util --init-token --free --label "$TOKEN_LABEL" --pin "$PIN" --so-pin "$SO_PIN" >/dev/null

echo "==> Genero chiave RSA 2048 + certificato self-signed (test)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$SPIKE_HOME/key.pem" 2>/dev/null
openssl req -new -x509 -key "$SPIKE_HOME/key.pem" -days 825 \
    -subj "/C=IT/O=CorianoSign Test/CN=Mario Rossi (TEST)" \
    -out "$SPIKE_HOME/cert.pem" 2>/dev/null
openssl x509 -in "$SPIKE_HOME/cert.pem" -outform DER -out "$SPIKE_HOME/cert.der"

echo "==> Importo la chiave privata nel token"
softhsm2-util --import "$SPIKE_HOME/key.pem" --token "$TOKEN_LABEL" \
    --label "$OBJ_LABEL" --id "$OBJ_ID" --pin "$PIN" >/dev/null

echo "==> Scrivo il certificato nel token (pkcs11-tool)"
pkcs11-tool --module "$MODULE" --token-label "$TOKEN_LABEL" --login --pin "$PIN" \
    --write-object "$SPIKE_HOME/cert.der" --type cert \
    --label "$OBJ_LABEL" --id "$OBJ_ID" >/dev/null 2>&1

# file di ambiente per la demo
cat > "$SPIKE_HOME/spike.env" <<EOF
export SOFTHSM2_CONF="$SOFTHSM2_CONF"
export PKCS11_MODULE="$MODULE"
export SPIKE_TOKEN="$TOKEN_LABEL"
export SPIKE_PIN="$PIN"
EOF

echo
echo "==> Token di test pronto. Per la demo:"
echo "    source \"$SPIKE_HOME/spike.env\""
echo "    .venv/bin/python packaging/spike_pkcs11_demo.py"
