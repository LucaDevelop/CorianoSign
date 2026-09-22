# Spike — firma locale da smart card / token USB (PKCS#11)

Prova di fattibilità della firma con la chiave privata su un **dispositivo
hardware** (smart card / token USB), in alternativa alla firma remota Aruba.
Tutto ruota attorno allo standard **PKCS#11**: in sviluppo si usa **SoftHSM2**
(token virtuale software), in produzione basta puntare alla libreria del token
reale (Bit4id, Aruba, OpenSC, …) — il resto del codice non cambia.

**Esito dello spike:** firma di un documento con SoftHSM via PKCS#11 → `.p7m`
CAdES-BES → verificato sia dal verificatore interno (`verifier.analyze_bytes`,
firma valida + digest coerente) sia da `openssl cms -verify` (interoperabile).

## Cosa serve (una tantum)

```bash
brew install softhsm opensc            # SoftHSM2 (token virtuale) + pkcs11-tool
.venv/bin/pip install 'pyhanko[pkcs11]' # firma PKCS#11 (CAdES + PAdES)
```

La firma da token usa **pyHanko** (che usa `python-pkcs11`): **una sola**
libreria per entrambi i formati, e aggiunge da sé gli attributi CAdES
(`signing-certificate-v2`). È in `requirements.txt`.

## Eseguire lo spike

```bash
./packaging/spike_softhsm_setup.sh                       # crea un token di TEST
source ~/.cache/corianosign-pkcs11-spike/spike.env       # SOFTHSM2_CONF, modulo, PIN
.venv/bin/python packaging/spike_pkcs11_demo.py          # firma + verifica
```

Il setup crea, in una cartella isolata (`~/.cache/corianosign-pkcs11-spike`, non
tocca la config SoftHSM di sistema): un token, una chiave RSA 2048 e un
certificato self-signed di test, importati nel token. Per ripulire:
`rm -rf ~/.cache/corianosign-pkcs11-spike`.

## Come funziona (i pezzi)

- **`src/corianosign/pkcs11_sign.py`** — il core riusabile (pyHanko):
  - `default_module()` — trova il modulo PKCS#11 (`$PKCS11_MODULE` o SoftHSM);
  - `list_objects()` — certificati e chiavi sul token (per "Rileva token");
  - `sign_p7m(...)` — CAdES-BES `.p7m` (`async_sign_general_data(use_cades=True)`);
  - `sign_pdf(...)` — PAdES-BES, anche con **riquadro visibile** (box+testo+immagine),
    con `box`/`page` presi dall'anteprima di firma esistente (stesse coordinate).
- La chiave privata **non lascia il dispositivo**: il token firma solo il digest;
  il PIN non viene mai salvato.
- La verifica riusa **interamente** la pipeline esistente
  (`verifier.analyze_bytes`). Provato: CAdES e PAdES(visibile) → `*-BES`,
  cripto valida + digest coerente; il `.p7m` è verificato anche da `openssl cms`.

## Integrazione nell'app (com'è cablata)

La firma da dispositivo è una **scelta fissa** nel menu «Firma come» della
schermata di firma (non un profilo): l'utente sceglie «🔑 Dispositivo (smart
card / token USB)», il pulsante diventa «Firma con dispositivo (PIN)» e al
momento della firma viene chiesto **solo il PIN** (mai salvato).

- `SignWorker` fa dispatch su `params["kind"]` → `pkcs11_sign.sign_p7m/sign_pdf`.
- Il **token e il certificato** sono scelti automaticamente (primo slot con un
  certificato); la **libreria** PKCS#11 è auto-rilevata (SoftHSM/OpenSC) oppure
  indicata in *Impostazioni ▸ Firma ▸ Dispositivo ▸ Libreria PKCS#11*
  (`AppConfig.pkcs11_module`), con un pulsante "Rileva token" per provarla.
- **Certificato reale**: una firma *qualificata legale* richiede un certificato
  qualificato su dispositivo certificato; basta puntare la libreria a quella del
  token reale, il resto del codice non cambia.
- **Hardware di prova economico**: una YubiKey in modalità PIV (~50 €) funziona
  con OpenSC/PKCS#11.
