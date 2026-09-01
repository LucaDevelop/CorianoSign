# Distribuzione — installer per macOS e Windows

Questi installer servono per la **prima installazione**. Gli aggiornamenti
successivi sono automatici (vedi [aggiornamenti.md](aggiornamenti.md)).

Gli installer prodotti qui **non sono firmati**: funzionano, ma alla prima
apertura il sistema mostra un avviso. In fondo trovi come superarlo.

## macOS — DMG (trascina in Applicazioni)

```bash
brew install create-dmg            # una tantum (opzionale: senza, usa hdiutil)
./packaging/build_macos.sh         # compila l'app E crea già il DMG in dist/
```

`build_macos.sh` genera **sempre** anche l'installer `dist/CorianoSign-<ver>.dmg`.
Per rigenerare solo il DMG (app già compilata): `./packaging/make_dmg_macos.sh`.

L'utente apre il `.dmg` e trascina **CorianoSign** nella cartella **Applicazioni**.

### Prima apertura (app non firmata/notarizzata)
Al primo avvio compare «*Impossibile aprire… sviluppatore non identificato*».
Una volta sola:
- **clic destro** sull'app in *Applicazioni* ▸ **Apri** ▸ **Apri**; oppure
- *Impostazioni di Sistema ▸ Privacy e Sicurezza* ▸ «Apri comunque».

Da lì in poi si apre con un normale doppio clic.

## Windows — installer con Inno Setup

Sul PC Windows, una tantum, installa **Inno Setup 6**
(<https://jrsoftware.org/isdl.php>). Poi:

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
```

`build_windows.ps1` compila l'app e crea **già** l'installer in `dist\` (se Inno
Setup è installato; altrimenti avvisa e prosegue). Per rigenerare solo
l'installer: `powershell -ExecutionPolicy Bypass -File packaging\make_installer_windows.ps1`.

Risultato: `dist\CorianoSign-<ver>-setup.exe`, un installer wizard che crea la
voce nel menu Start, la disinstallazione e (opzionale) l'associazione dei `.p7m`.
Può essere installato **senza privilegi di amministratore** (installazione per
l'utente corrente).

### Prima apertura (eseguibile non firmato)
L'installer **non è firmato** (nessun certificato Authenticode). Chi lo **scarica
da internet** vedrà, una volta sola, l'avviso **SmartScreen**. È normale e non
indica un problema: l'app non è firmata, non è pericolosa.

Istruzioni da girare ai colleghi (installazione **per l'utente corrente**, quindi
**senza password di amministratore**):

1. Scarica `CorianoSign-<ver>-setup.exe` dalla pagina delle release.
2. Doppio clic. Se compare **«Windows ha protetto il PC»**:
   → clicca **Ulteriori informazioni** → **Esegui comunque**.
3. Segui la procedura guidata (Avanti → Installa). Non serve l'amministratore.

Se il pulsante «Esegui comunque» non compare, sblocca prima il file: **clic destro
sul `.exe` → Proprietà → in fondo spunta «Annulla blocco» (Unblock) → OK**, poi
riapri.

> Nota: gli **aggiornamenti automatici** successivi non mostrano SmartScreen
> (l'app scarica e applica l'update da sola), quindi l'avviso riguarda solo la
> **prima** installazione.

Per eliminare del tutto l'avviso servirebbe firmare l'eseguibile e il setup con un
certificato Authenticode (o Azure Trusted Signing): vedi la sezione «Windows
silenzioso» più sotto.

## macOS senza avvisi: firma Developer ID + notarizzazione

Per eliminare del tutto l'avviso di Gatekeeper (app che si apre con un doppio
clic) serve firmare con un **Developer ID Apple** e **notarizzare**. Tutto il
processo è automatizzato in `packaging/make_distributable_macos.sh`.

### Setup una tantum
1. **Account Apple Developer** a pagamento (99 $/anno):
   <https://developer.apple.com/programs/>.
2. **Certificato «Developer ID Application»** nel portachiavi. In Xcode ▸
   *Settings ▸ Accounts* aggiungi l'Apple ID, poi *Manage Certificates ▸ +
   ▸ Developer ID Application*. Verifica con:
   ```bash
   security find-identity -v -p codesigning
   ```
3. **Credenziali di notarizzazione** salvate in un profilo del portachiavi (le
   digiti tu, restano nel portachiavi):
   ```bash
   xcrun notarytool store-credentials corianosign-notary \
     --apple-id TUA_APPLE_ID --team-id TEAMID --password APP_SPECIFIC_PASSWORD
   ```
   `APP_SPECIFIC_PASSWORD` è una *password per le app* creata su
   <https://account.apple.com> ▸ *Sicurezza ▸ Password per le app* (NON è la
   password dell'Apple ID). Il `TEAMID` è nel tuo account developer.

### Produrre gli artefatti distribuibili
Dopo aver compilato l'app (`packaging/build_macos.sh`):
```bash
./packaging/make_distributable_macos.sh
```
Firma l'app con hardened runtime (`packaging/entitlements_macos.plist`), la
notarizza e vi applica il *ticket* (staple), poi rigenera **l'archivio Ed25519
per l'auto-update** e il **DMG**, entrambi con l'app notarizzata dentro. Da lì
in poi gli aggiornamenti automatici distribuiscono un'app già notarizzata.

Variabili opzionali: `CODESIGN_IDENTITY` (identità specifica), `NOTARY_PROFILE`
(nome profilo, default `corianosign-notary`), `SKIP_DMG=1` (solo app + zip).

## Windows «silenzioso» (senza SmartScreen)

Per togliere l'avviso SmartScreen serve firmare `CorianoSign.exe` **e** il
`setup.exe` con `signtool` (firma **Authenticode**). Tre strade:

- **Azure Trusted Signing** (~10 $/mese, consigliato per progetti piccoli):
  servizio Microsoft, reputazione SmartScreen immediata, nessun token hardware;
  si integra con `signtool` tramite una dlib. Richiede un account Azure e una
  verifica d'identità.
- **Certificato OV/EV** da una CA (DigiCert, Sectigo…): ~250–600 $/anno; dal
  2023 la chiave sta su **token USB** o **HSM cloud**. OV costruisce la
  reputazione col tempo, EV la ha subito.
- **Non firmare** (scelta attuale): nessun costo, avviso alla prima apertura —
  vedi «Prima apertura (eseguibile non firmato)» sopra.

Quando avrai le credenziali, la firma si aggiunge in `make_installer_windows.ps1`
(firma dell'exe prima di impacchettarlo e del setup dopo), es.:
`signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a <file>`.

## Riepilogo file prodotti

| Piattaforma | Comando | Output |
|---|---|---|
| macOS | `make_dmg_macos.sh` | `dist/CorianoSign-<ver>.dmg` |
| Windows | `make_installer_windows.ps1` | `dist\CorianoSign-<ver>-setup.exe` |
