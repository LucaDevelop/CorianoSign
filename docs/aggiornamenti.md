# Aggiornamenti automatici dell'app

CorianoSign si aggiorna da solo (macOS e Windows) scaricando le release da
**GitHub Releases**. Ogni aggiornamento è **firmato con Ed25519**: l'app porta
incorporata solo la chiave *pubblica* e rifiuta qualsiasi archivio la cui firma
non sia valida, quindi né una release manomessa né un download intercettato
possono installare codice non autentico.

## Come funziona (lato utente)

- All'avvio (se attivo in *Impostazioni ▸ Generali ▸ Aggiornamenti*) l'app
  interroga l'ultima release del repository e confronta la versione.
- Se ce n'è una più recente, mostra un avviso con le note di rilascio e i
  pulsanti **Aggiorna ora** / **Più tardi**.
- «Aggiorna ora» scarica l'archivio, **ne verifica la firma**, poi chiude l'app,
  sostituisce i file e la riavvia automaticamente.
- C'è anche il pulsante **Controlla aggiornamenti ora** nelle impostazioni.

L'auto-update funziona solo sull'app impacchettata (macOS `.app` / Windows
onedir), non eseguendo da sorgente.

## Configurazione una tantum

1. **Repository**: in `src/corianosign/updater.py` imposta `GITHUB_OWNER` e
   `GITHUB_REPO` sul repo che ospiterà le release (attualmente
   `lucasirri/CorianoSign`).
2. **Chiavi di firma**: la coppia è già stata generata:
   - chiave pubblica → già incollata in `updater.UPDATE_PUBKEY_HEX`;
   - chiave privata → `packaging/update_private_key.pem` (in `.gitignore`,
     **non va committata né condivisa**; se la perdi non potrai più firmare
     aggiornamenti che le installazioni esistenti accettino).

   Per rigenerarle da zero:
   ```bash
   python packaging/update_keys.py genera
   # copia la riga UPDATE_PUBKEY_HEX stampata dentro src/corianosign/updater.py
   ```

## Pubblicare una nuova versione

1. Aggiorna la versione in `src/corianosign/__init__.py` (`__version__`).
2. Compila l'app:
   - macOS: `./packaging/build_macos.sh`
   - Windows: `powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1`
3. Crea l'archivio di release **firmato**:
   - macOS: `./packaging/make_release_macos.sh`
     → `dist/CorianoSign-<ver>-macos.zip` + `.sig`
   - Windows: `powershell -ExecutionPolicy Bypass -File packaging\make_release_windows.ps1`
     → `dist\CorianoSign-<ver>-windows.zip` + `.sig`
4. Su GitHub crea una **Release** con tag `v<ver>` (es. `v0.2.0`), scrivi le note
   nel corpo (verranno mostrate nell'avviso) e **carica i 4 file**: i due `.zip`
   e i due `.zip.sig`.

L'app cerca gli asset per nome: l'archivio deve contenere `macos`/`mac` oppure
`windows`/`win` e finire in `.zip`; la firma è lo stesso nome con `.sig` in coda.

## Note sulla firma del codice (Gatekeeper / SmartScreen)

- **macOS**: l'archivio viene scaricato dal processo dell'app, che **non applica
  la quarantena**; lo swap rimuove comunque l'attributo `com.apple.quarantine`,
  quindi il riavvio non mostra il blocco Gatekeeper anche se l'app non è
  notarizzata. Per distribuire la *prima* installazione fuori dal proprio Mac
  resta consigliata la firma Developer ID + notarizzazione (vedi
  `build_macos.sh`).
- **Windows**: per evitare l'avviso SmartScreen serve firmare l'eseguibile con un
  certificato Authenticato (signtool). L'auto-update in sé funziona comunque.
