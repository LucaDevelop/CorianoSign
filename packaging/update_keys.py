"""Gestione delle chiavi di firma per gli aggiornamenti + firma degli archivi.

  # genera una nuova coppia di chiavi (scrive la privata, stampa la pubblica)
  python packaging/update_keys.py genera [percorso_chiave_privata]

  # stampa la chiave pubblica (hex) da incollare in updater.UPDATE_PUBKEY_HEX
  python packaging/update_keys.py pubkey [percorso_chiave_privata]

  # firma un archivio di release -> crea <archivio>.sig (firma Ed25519 binaria)
  python packaging/update_keys.py firma <archivio> [percorso_chiave_privata]

La chiave PRIVATA non va mai distribuita né committata (vedi .gitignore).
"""
from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DEFAULT_KEY = Path(__file__).resolve().parent / "update_private_key.pem"


def _load_priv(path: Path) -> Ed25519PrivateKey:
    key = ser.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("La chiave non è Ed25519.")
    return key


def _pub_hex(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes(
        ser.Encoding.Raw, ser.PublicFormat.Raw
    ).hex()


def cmd_genera(path: Path) -> None:
    if path.exists():
        raise SystemExit(f"Esiste già: {path} (non la sovrascrivo).")
    priv = Ed25519PrivateKey.generate()
    path.write_bytes(priv.private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    print(f"Chiave privata scritta in: {path}")
    print(f"UPDATE_PUBKEY_HEX = {_pub_hex(priv)}")
    print("Incolla la riga sopra in src/corianosign/updater.py e NON committare la privata.")


def cmd_pubkey(path: Path) -> None:
    print(_pub_hex(_load_priv(path)))


def cmd_firma(archive: Path, path: Path) -> None:
    if not archive.is_file():
        raise SystemExit(f"Archivio non trovato: {archive}")
    priv = _load_priv(path)
    sig = priv.sign(archive.read_bytes())
    out = archive.with_name(archive.name + ".sig")
    out.write_bytes(sig)
    # verifica di cortesia
    Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(_pub_hex(priv))
    ).verify(sig, archive.read_bytes())
    print(f"Firma scritta in: {out}  ({len(sig)} byte, verificata ✓)")


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    cmd = argv[0]
    if cmd == "genera":
        cmd_genera(Path(argv[1]) if len(argv) > 1 else DEFAULT_KEY)
    elif cmd == "pubkey":
        cmd_pubkey(Path(argv[1]) if len(argv) > 1 else DEFAULT_KEY)
    elif cmd == "firma":
        if len(argv) < 2:
            raise SystemExit("Uso: update_keys.py firma <archivio> [chiave]")
        cmd_firma(Path(argv[1]), Path(argv[2]) if len(argv) > 2 else DEFAULT_KEY)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
