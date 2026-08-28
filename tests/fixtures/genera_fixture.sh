#!/usr/bin/env bash
# Rigenera i file di prova (.p7m) usati per collaudare CorianoSign.
# Richiede OpenSSL. Le chiavi generate sono SOLO per test.
set -euo pipefail
cd "$(dirname "$0")"

printf 'Contenuto di prova per CorianoSign.\nRiga due.\n' > documento.txt

# --- caso 1: firma self-signed (esito: NON fidato) ---
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -nodes \
  -subj "/C=IT/O=Test SPA/CN=MARIO ROSSI/serialNumber=TINIT-RSSMRA80A01H501U"
openssl cms -sign -in documento.txt -signer cert.pem -inkey key.pem \
  -outform DER -nodetach -binary -out documento.txt.p7m

# --- caso 2: catena Root CA -> titolare (esito: fidato con ca_cert.pem come radice) ---
openssl req -x509 -newkey rsa:2048 -keyout ca_key.pem -out ca_cert.pem -days 3650 -nodes \
  -subj "/C=IT/O=CoricaTest CA/CN=CoricaTest Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:2048 -keyout leaf_key.pem -out leaf.csr -nodes \
  -subj "/C=IT/O=Comune di Coriano/CN=GIULIA BIANCHI/serialNumber=TINIT-BNCGLI85M41H294X"
openssl x509 -req -in leaf.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial \
  -days 730 -out leaf_cert.pem \
  -extfile <(printf "keyUsage=critical,digitalSignature,nonRepudiation\nbasicConstraints=CA:FALSE")
openssl cms -sign -in documento.txt -signer leaf_cert.pem -inkey leaf_key.pem \
  -certfile ca_cert.pem -outform DER -nodetach -binary -out chained.txt.p7m

# --- caso 3: CAdES-T (marca temporale RFC 3161 sulla firma) ---
# TSA firmata dalla CA, con EKU timeStamping
openssl req -newkey rsa:2048 -keyout tsa_key.pem -out tsa.csr -nodes \
  -subj "/C=IT/O=Coriano TSA/CN=Coriano Time Stamping Authority"
openssl x509 -req -in tsa.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial \
  -days 730 -out tsa_cert.pem \
  -extfile <(printf "extendedKeyUsage=critical,timeStamping\nkeyUsage=critical,digitalSignature")
echo "01" > tsaserial.txt
cat > tsa.cnf <<'CFG'
[tsa]
default_tsa = tsa_config1
[tsa_config1]
serial = tsaserial.txt
crypto_device = builtin
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_alg = sha256
CFG
python3 genera_cades_t.py

# --- caso 4: CAdES-LT e CAdES-LTA (materiale di validazione incapsulato) ---
python3 genera_cades_lt.py

echo "Fixture generati: documento.txt.p7m, chained.txt.p7m, chained_ts.txt.p7m (T), chained_lt.txt.p7m (LT), chained_lta.txt.p7m (LTA)"
