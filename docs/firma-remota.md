# Firma remota Aruba — spike CLI

Spike per firmare documenti con la **firma remota Aruba** (con OTP), tramite il
servizio SOAP **ArubaSignService (ARSS)**. Il documento viene inviato ad Aruba,
che lo firma con la chiave dell'utente sul proprio HSM e restituisce il file
firmato (**PAdES** visibile o **CAdES** `.p7m`).

> Stato: **✓ validato con firma reale** su Aruba produzione (`arss.arubapec.it`,
> v1.0.5). Un PDF è stato firmato in **PAdES visibile** con OTP e verificato con
> ArubaSign. Parametri confermati per un account reale: `--otp-type firma`,
> `certID=AS0`, `typeHSM=COSIGN`, `transport=BYNARYNET`.

> ⚠️ Attenzione al **Backspace** durante l'inserimento di password/OTP: il
> terminale può inserirlo come carattere di controllo nella stringa. L'app lo
> rimuove per evitare il crash, ma la credenziale potrebbe restare errata:
> reinserisci il valore digitandolo senza correggere con Backspace.

## 1. Verifica connettività (senza credenziali)

```bash
corianosign-cli aruba-info
```

Mostra la versione del servizio e l'elenco delle operazioni. Utile come primo
controllo. Aggiungi `--demo` per l'endpoint di test.

## 2. Parametri specifici del tuo contratto

Tre valori dipendono dal tuo abbonamento Aruba e vanno confermati:

| Opzione | Campo Aruba | Default | Note |
|---|---|---|---|
| `--otp-type` | `typeOtpAuth` | *(obbligatorio)* | tipo/dominio OTP del contratto |
| `--hsm` | `typeHSM` | `COSIGN` | tipo HSM |
| `--cert-id` | `certID` | `AS0` | id del certificato |

L'**OTP** lo generi al momento con l'app Aruba OTP (o lo ricevi via SMS).

## 3. Firma un PDF in PAdES **visibile**

```bash
corianosign-cli firma-remota documento.pdf \
  --user IL_TUO_USER --otp-type IL_TUO_TIPO_OTP \
  --visibile --pagina 1 --pos 50 50 300 130 \
  --testo "Firmato da MARIO ROSSI" --motivo "Approvazione" --luogo "Coriano" \
  --livello LTA \
  -o documento-firmato.pdf
```

- `--pos X1 Y1 X2 Y2` è il riquadro della firma in punti PDF (origine in basso a sx).
- `--immagine logo.png` per un logo nel riquadro.
- `--livello` mappa su `signatureLevel` Aruba (es. `B`, `T`, `LT`, `LTA`).

## 4. Firma un file in CAdES (`.p7m`)

```bash
corianosign-cli firma-remota contratto.pdf --cades \
  --user IL_TUO_USER --otp-type IL_TUO_TIPO_OTP --livello T
```

Il `.p7m` risultante viene **ri-verificato automaticamente** con il verificatore
di CorianoSign (chiusura del cerchio: firmi e vedi subito l'esito).

## Sicurezza

- **Password di firma** e **OTP** non si passano da riga di comando (sarebbero
  visibili nella lista processi): vengono chiesti in modo interattivo, oppure
  letti dalle variabili d'ambiente `ARUBA_PWD` / `ARUBA_OTP`.
- Il documento viene inviato ad Aruba (è il flusso previsto: è il tuo provider di
  firma). L'app non memorizza credenziali.

## Endpoint

- Produzione (default): `https://arss.arubapec.it/ArubaSignService/ArubaSignService?wsdl`
- Demo: `--demo` → `https://arss.demo.firma-automatica.it/...`
- Personalizzato: `--wsdl https://...`
