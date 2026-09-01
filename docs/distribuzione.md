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
Windows SmartScreen mostra «*Windows ha protetto il PC*». Una volta sola:
- clicca **Ulteriori informazioni** ▸ **Esegui comunque**.

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

Per togliere l'avviso SmartScreen serve un certificato **Authenticode** (OV/EV)
con cui firmare `CorianoSign.exe` e il setup con `signtool`. Si aggiunge come
passaggio in `build_windows.ps1` quando lo avrai.

## Riepilogo file prodotti

| Piattaforma | Comando | Output |
|---|---|---|
| macOS | `make_dmg_macos.sh` | `dist/CorianoSign-<ver>.dmg` |
| Windows | `make_installer_windows.ps1` | `dist\CorianoSign-<ver>-setup.exe` |
