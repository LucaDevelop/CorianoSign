# Distribuzione — installer per macOS e Windows

Questi installer servono per la **prima installazione**. Gli aggiornamenti
successivi sono automatici (vedi [aggiornamenti.md](aggiornamenti.md)).

Gli installer prodotti qui **non sono firmati**: funzionano, ma alla prima
apertura il sistema mostra un avviso. In fondo trovi come superarlo.

## macOS — DMG (trascina in Applicazioni)

```bash
brew install create-dmg            # una tantum
./packaging/build_macos.sh         # compila dist/CorianoSign.app
./packaging/make_dmg_macos.sh      # crea dist/CorianoSign-<ver>.dmg
```

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
powershell -ExecutionPolicy Bypass -File packaging\make_installer_windows.ps1
```

Risultato: `dist\CorianoSign-<ver>-setup.exe`, un installer wizard che crea la
voce nel menu Start, la disinstallazione e (opzionale) l'associazione dei `.p7m`.
Può essere installato **senza privilegi di amministratore** (installazione per
l'utente corrente).

### Prima apertura (eseguibile non firmato)
Windows SmartScreen mostra «*Windows ha protetto il PC*». Una volta sola:
- clicca **Ulteriori informazioni** ▸ **Esegui comunque**.

## Rendere gli installer «silenziosi» (senza avvisi)

Per eliminare del tutto gli avvisi servono i certificati di firma (a pagamento):

- **macOS**: iscrizione Apple Developer (99 $/anno) → firma *Developer ID* +
  **notarizzazione** dell'app e del DMG (`codesign` + `xcrun notarytool` +
  `stapler`).
- **Windows**: certificato **Authenticode** (OV/EV) → firma di `CorianoSign.exe`
  e del setup con `signtool`.

Quando li avrai, si aggiungono come passaggi negli script di build/packaging.

## Riepilogo file prodotti

| Piattaforma | Comando | Output |
|---|---|---|
| macOS | `make_dmg_macos.sh` | `dist/CorianoSign-<ver>.dmg` |
| Windows | `make_installer_windows.ps1` | `dist\CorianoSign-<ver>-setup.exe` |
