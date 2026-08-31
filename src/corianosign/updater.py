"""Auto-aggiornamento dell'app (macOS .app / Windows onedir) via GitHub Releases.

Modello di sicurezza: ogni release pubblica, oltre all'archivio del programma,
una **firma Ed25519** dell'archivio (file ``.sig``). L'app porta incorporata la
sola chiave PUBBLICA (``UPDATE_PUBKEY_HEX``); l'archivio scaricato viene
verificato con quella chiave prima di essere applicato, così nemmeno una release
manomessa o un download intercettato possono installare codice non autentico.
La chiave PRIVATA resta segreta presso chi pubblica le release
(``packaging/update_private_key.pem``) e serve solo a firmare.

Flusso: ``check_for_update`` interroga l'API di GitHub per l'ultima release,
confronta la versione, individua l'asset della piattaforma e la sua firma;
``download_and_verify`` scarica e verifica; ``apply_update`` sostituisce l'app e
la riavvia tramite un piccolo script esterno (l'eseguibile in uso non può
sovrascrivere sé stesso).
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import __app_name__, __version__

# --- configurazione (da personalizzare prima di pubblicare) ---------------- #
# Repository GitHub che ospita le release (owner/repo).
GITHUB_OWNER = "LucaDevelop"
GITHUB_REPO = "CorianoSign"
# Chiave pubblica Ed25519 (32 byte in hex) per verificare le release firmate.
UPDATE_PUBKEY_HEX = "fb73c7114c65abc9f57820b74bddf724f892a20bc5159c6c13e257dbce68ddd2"

# Nome degli asset per piattaforma (case-insensitive) cercati nella release.
_ASSET_HINTS = {
    "macos": ("macos", "mac", "darwin", "osx"),
    "windows": ("windows", "win"),
}

_API_LATEST = "https://api.github.com/repos/{owner}/{repo}/releases/latest"
_UA = {"User-Agent": f"{__app_name__}/{__version__}", "Accept": "application/vnd.github+json"}


class UpdateError(Exception):
    """Errore durante il controllo o l'applicazione di un aggiornamento."""


@dataclass
class UpdateInfo:
    version: str
    notes: str
    asset_name: str
    asset_url: str
    sig_url: str
    size: int


# --------------------------------------------------------------------------- #
# Versioni
# --------------------------------------------------------------------------- #
def parse_version(text: str) -> tuple[int, ...]:
    """'v1.2.3' / '1.2.3' -> (1, 2, 3); parti non numeriche ignorate."""
    text = (text or "").strip().lstrip("vV")
    parts: list[int] = []
    for chunk in text.split("."):
        num = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(num) if num else 0)
    return tuple(parts) or (0,)


def is_newer(remote: str, local: str) -> bool:
    a, b = parse_version(remote), parse_version(local)
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    return a > b


# --------------------------------------------------------------------------- #
# Piattaforma / stato
# --------------------------------------------------------------------------- #
def platform_key() -> Optional[str]:
    if sys.platform == "darwin":
        return "macos"
    if os.name == "nt":
        return "windows"
    return None


def is_frozen() -> bool:
    """True se in esecuzione come app impacchettata (PyInstaller)."""
    return bool(getattr(sys, "frozen", False))


def can_auto_update() -> bool:
    """L'auto-update è applicabile solo su app impacchettata mac/Windows."""
    return is_frozen() and platform_key() is not None


# --------------------------------------------------------------------------- #
# Controllo aggiornamenti
# --------------------------------------------------------------------------- #
def _pick_asset(assets: list[dict], plat: str) -> tuple[Optional[dict], Optional[dict]]:
    """Sceglie (archivio, firma) per la piattaforma tra gli asset della release."""
    hints = _ASSET_HINTS[plat]
    archive = None
    for a in assets:
        name = a.get("name", "").lower()
        if name.endswith(".sig"):
            continue
        if any(h in name for h in hints) and name.endswith((".zip", ".tar.gz", ".tgz")):
            archive = a
            break
    if archive is None:
        return None, None
    sig_name = archive["name"] + ".sig"
    sig = next((a for a in assets if a.get("name", "").lower() == sig_name.lower()), None)
    return archive, sig


def check_for_update(timeout: float = 8.0) -> Optional[UpdateInfo]:
    """Ritorna le info sull'aggiornamento se disponibile, altrimenti ``None``."""
    plat = platform_key()
    if plat is None:
        return None
    url = _API_LATEST.format(owner=GITHUB_OWNER, repo=GITHUB_REPO)
    try:
        r = requests.get(url, headers=_UA, timeout=timeout)
        # 404 = nessuna release pubblicata (o repo/asset non ancora presenti):
        # non è un errore, semplicemente non c'è nulla da aggiornare.
        if r.status_code == 404:
            return None
        r.raise_for_status()
        data = r.json()
    except (requests.RequestException, ValueError) as exc:
        raise UpdateError(f"Controllo aggiornamenti non riuscito: {exc}") from exc

    tag = data.get("tag_name") or data.get("name") or ""
    if not tag or not is_newer(tag, __version__):
        return None
    archive, sig = _pick_asset(data.get("assets", []), plat)
    if archive is None:
        raise UpdateError(
            f"Release {tag} trovata ma senza archivio per {plat}."
        )
    if sig is None:
        raise UpdateError(
            f"Release {tag} priva della firma (.sig): aggiornamento rifiutato "
            "per sicurezza."
        )
    return UpdateInfo(
        version=tag.lstrip("vV"),
        notes=data.get("body", "") or "",
        asset_name=archive["name"],
        asset_url=archive["browser_download_url"],
        sig_url=sig["browser_download_url"],
        size=int(archive.get("size", 0)),
    )


# --------------------------------------------------------------------------- #
# Download + verifica firma
# --------------------------------------------------------------------------- #
def _download(url: str, dest: Path, progress: Optional[Callable[[int, int], None]] = None) -> None:
    with requests.get(url, headers=_UA, stream=True, timeout=30) as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0))
        done = 0
        with open(dest, "wb") as fh:
            for chunk in r.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                fh.write(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)


def verify_signature(data: bytes, signature: bytes) -> bool:
    """Verifica la firma Ed25519 dell'archivio con la chiave pubblica incorporata."""
    if not UPDATE_PUBKEY_HEX:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(UPDATE_PUBKEY_HEX))
        pub.verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def download_and_verify(
    info: UpdateInfo, progress: Optional[Callable[[int, int], None]] = None
) -> Path:
    """Scarica archivio + firma, verifica la firma e ritorna il path dell'archivio."""
    tmp = Path(tempfile.mkdtemp(prefix="corianosign_update_"))
    archive = tmp / info.asset_name
    sig = tmp / (info.asset_name + ".sig")
    _download(info.asset_url, archive, progress)
    _download(info.sig_url, sig)

    data = archive.read_bytes()
    signature = sig.read_bytes()
    # la firma può essere binaria (64 byte) o esadecimale/armor: normalizza
    if len(signature) != 64:
        text = signature.strip()
        try:
            signature = bytes.fromhex(text.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            pass
    if not verify_signature(data, signature):
        raise UpdateError(
            "Firma dell'aggiornamento NON valida: file scartato. L'aggiornamento "
            "non proviene da una fonte autentica ed è stato annullato."
        )
    return archive


# --------------------------------------------------------------------------- #
# Applicazione dell'aggiornamento (swap + riavvio)
# --------------------------------------------------------------------------- #
def _extract(archive: Path) -> Path:
    """Estrae l'archivio in una cartella temporanea e ritorna quella cartella."""
    out = archive.parent / "extracted"
    out.mkdir(exist_ok=True)
    if sys.platform == "darwin":
        # ditto preserva symlink, bit di esecuzione e firma del bundle .app:
        # zipfile di Python li perde e rende l'app non avviabile.
        subprocess.run(["/usr/bin/ditto", "-x", "-k", str(archive), str(out)],
                       check=True)
    elif archive.suffix.lower() == ".zip":
        with zipfile.ZipFile(archive) as z:
            z.extractall(out)
    else:  # tar.gz / tgz
        import tarfile

        with tarfile.open(archive) as t:
            t.extractall(out)
    return out


def _find_macos_app(root: Path) -> Optional[Path]:
    if root.name.endswith(".app"):
        return root
    apps = list(root.rglob("*.app"))
    return apps[0] if apps else None


def _find_windows_dir(root: Path) -> Optional[Path]:
    exe = f"{__app_name__}.exe"
    for p in [root, *root.rglob("*")]:
        if p.is_dir() and (p / exe).is_file():
            return p
    return None


def apply_update(archive: Path) -> None:
    """Estrae, sostituisce l'installazione corrente e riavvia. Termina il processo.

    L'eseguibile in uso non può sovrascriversi: si lancia uno script esterno che
    attende la chiusura di questo processo, sostituisce i file e riavvia l'app.
    """
    if not can_auto_update():
        raise UpdateError("Auto-update disponibile solo sull'app impacchettata.")
    extracted = _extract(archive)
    plat = platform_key()
    pid = os.getpid()
    if plat == "macos":
        _apply_macos(extracted, pid)
    elif plat == "windows":
        _apply_windows(extracted, pid)
    else:
        raise UpdateError("Piattaforma non supportata per l'auto-update.")


def _current_macos_bundle() -> Path:
    # sys.executable = .../CorianoSign.app/Contents/MacOS/CorianoSign
    return Path(sys.executable).resolve().parents[2]


def _apply_macos(extracted: Path, pid: int) -> None:
    new_app = _find_macos_app(extracted)
    if new_app is None:
        raise UpdateError("Archivio macOS privo del bundle .app.")
    old_app = _current_macos_bundle()
    script = extracted.parent / "apply_update.sh"
    script.write_text(
        "#!/bin/bash\n"
        "set -e\n"
        'OLD="$1"; NEW="$2"; PID="$3"\n'
        'while kill -0 "$PID" 2>/dev/null; do sleep 0.3; done\n'
        'rm -rf "$OLD"\n'
        'ditto "$NEW" "$OLD"\n'
        'xattr -dr com.apple.quarantine "$OLD" 2>/dev/null || true\n'
        'open "$OLD"\n',
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    subprocess.Popen(
        ["/bin/bash", str(script), str(old_app), str(new_app), str(pid)],
        start_new_session=True,
    )
    os._exit(0)


def _current_windows_dir() -> Path:
    # sys.executable = ...\CorianoSign\CorianoSign.exe
    return Path(sys.executable).resolve().parent


def _apply_windows(extracted: Path, pid: int) -> None:
    new_dir = _find_windows_dir(extracted)
    if new_dir is None:
        raise UpdateError(f"Archivio Windows privo di {__app_name__}.exe.")
    old_dir = _current_windows_dir()
    exe = f"{__app_name__}.exe"
    log = extracted.parent / "update.log"
    bat = extracted.parent / "apply_update.bat"
    # NB: 'set "VAR=valore"' NON include le virgolette nel valore; si quota all'uso
    # ("%VAR%"), altrimenti i percorsi con spazi si rompono.
    bat.write_text(
        "@echo off\r\n"
        "setlocal\r\n"
        f'set "PID={pid}"\r\n'
        f'set "OLD={old_dir}"\r\n'
        f'set "NEW={new_dir}"\r\n'
        f'set "LOG={log}"\r\n'
        'cd /d "%TEMP%"\r\n'
        'echo [%DATE% %TIME%] avvio aggiornamento > "%LOG%"\r\n'
        ":waitloop\r\n"
        'tasklist /FI "PID eq %PID%" 2>nul | find "%PID%" >nul\r\n'
        "if not errorlevel 1 (\r\n"
        "  timeout /t 1 /nobreak >nul\r\n"
        "  goto waitloop\r\n"
        ")\r\n"
        "timeout /t 1 /nobreak >nul\r\n"
        'robocopy "%NEW%" "%OLD%" /MIR /NFL /NDL /NJH /NJS /NC /NS >> "%LOG%" 2>&1\r\n'
        'set "RC=%ERRORLEVEL%"\r\n'
        'echo robocopy exit=%RC% >> "%LOG%"\r\n'
        'if %RC% GEQ 8 echo COPIA FALLITA (permessi? prova a reinstallare) >> "%LOG%"\r\n'
        f'start "" "%OLD%\\{exe}"\r\n',
        encoding="utf-8",
    )
    DETACHED = 0x00000008  # DETACHED_PROCESS
    subprocess.Popen(
        ["cmd", "/c", str(bat)],
        creationflags=DETACHED,
        close_fds=True,
    )
    os._exit(0)
