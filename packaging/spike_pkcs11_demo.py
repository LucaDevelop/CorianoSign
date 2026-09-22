#!/usr/bin/env python3
"""SPIKE PKCS#11: firma un documento con il token SoftHSM e lo verifica.

    ./packaging/spike_softhsm_setup.sh          # una volta: crea il token di test
    source ~/.cache/corianosign-pkcs11-spike/spike.env
    .venv/bin/python packaging/spike_pkcs11_demo.py

Dimostra la catena completa: token PKCS#11 → firma → .p7m CAdES-BES → verifica
con il verificatore già presente (verifier.analyze_bytes). Il certificato di
test è self-signed, quindi la catena non è "fidata" (giusto): controlliamo la
validità CRITTOGRAFICA (firma valida + digest coerente) e il contenuto estratto.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from corianosign import pkcs11_sign, verifier  # noqa: E402

SPIKE_HOME = Path(os.environ.get(
    "SPIKE_HOME", Path.home() / ".cache" / "corianosign-pkcs11-spike"))

# se non già nell'ambiente, usa i default dello spike
os.environ.setdefault("SOFTHSM2_CONF", str(SPIKE_HOME / "softhsm2.conf"))
MODULE = os.environ.get("PKCS11_MODULE") or pkcs11_sign.default_module()
TOKEN = os.environ.get("SPIKE_TOKEN", "CorianoSignTest")
PIN = os.environ.get("SPIKE_PIN", "1234")


def main() -> int:
    if not MODULE:
        print("Modulo PKCS#11 non trovato. Esegui prima spike_softhsm_setup.sh")
        return 2
    print(f"Modulo PKCS#11 : {MODULE}")
    print(f"Token          : {TOKEN}")

    # 1) cosa c'è sul token
    info = pkcs11_sign.list_objects(MODULE, pin=PIN, token_label=TOKEN)
    print(f"Certificati    : {info['certificates']}")
    print(f"Chiavi private : {info['private_keys']}")

    # 2) firma un documento di test
    doc = b"Documento di prova firmato via PKCS#11 (SoftHSM).\n"
    print(f"\nFirmo {len(doc)} byte con il token...")
    p7m = pkcs11_sign.sign_p7m(
        doc, module_path=MODULE, pin=PIN, token_label=TOKEN, attached=True)
    out = SPIKE_HOME / "documento.txt.p7m"
    out.write_bytes(p7m)
    print(f".p7m prodotto  : {out} ({len(p7m)} byte)")

    # 3) verifica con il verificatore esistente (solo crittografia: cert di test)
    res = verifier.analyze_bytes(
        p7m, [], verifier.VerifyOptions(check_trust=False))
    if res.parse_errors:
        print("ERRORI parsing:", res.parse_errors)
        return 1
    ok = True
    for i, s in enumerate(res.signatures, 1):
        crypto = s.crypto_valid and s.digest_match
        ok = ok and crypto
        print(f"\nFirma #{i}: livello={s.level}")
        print(f"  firmatario   : {s.signer.display_name}")
        print(f"  cripto valida: {'SI' if s.crypto_valid else 'NO'}")
        print(f"  digest match : {'SI' if s.digest_match else 'NO'}")
    # 4) contenuto estratto coincide?
    print(f"\nContenuto estratto == originale: "
          f"{'SI' if res.content == doc else 'NO'}")

    print("\n==> ESITO:", "OK (firma da token verificata)" if ok
          and res.content == doc else "FALLITO")
    return 0 if ok and res.content == doc else 1


if __name__ == "__main__":
    raise SystemExit(main())
