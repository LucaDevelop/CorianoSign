"""Diagnostica dei tempi di verifica di una firma.

    .venv/bin/python packaging/diagnose_verify.py <file firmato>

Stampa, fase per fase e richiesta per richiesta, dove se ne va il tempo:
caricamento trust store, e per ogni download di revoca (OCSP/CRL) l'URL, il
metodo, il tempo e la dimensione. Serve a capire perché una verifica è lenta.
"""
from __future__ import annotations

import logging
import sys
import time

import requests as _rq

_reqs: list[tuple[str, str, float, int, object]] = []
_send = _rq.sessions.Session.send


def _timed_send(self, request, **kw):
    t0 = time.time()
    try:
        resp = _send(self, request, **kw)
        _reqs.append(
            (request.method, request.url, time.time() - t0,
             len(resp.content or b""), resp.status_code)
        )
        return resp
    except Exception as e:  # noqa: BLE001
        _reqs.append((request.method, request.url, time.time() - t0, -1,
                      type(e).__name__))
        raise


_rq.sessions.Session.send = _timed_send


def main() -> int:
    if len(sys.argv) < 2:
        print("Uso: python packaging/diagnose_verify.py <file firmato>")
        return 2
    path = sys.argv[1]

    # mostra cosa scarica pyhanko (OCSP/CRL/AIA)
    logging.basicConfig(level=logging.INFO, format="    [net] %(message)s")
    logging.getLogger("pyhanko_certvalidator").setLevel(logging.INFO)

    from corianosign import trust, verifier
    from corianosign.validation import RevocationMode

    t = time.time()
    store = trust.load_trust_store()
    print(f"[fase] load_trust_store: {time.time() - t:.2f}s "
          f"({len(store.certificates)} CA, {len(store.tsa_certificates)} TSA)")

    opts = verifier.VerifyOptions(
        check_trust=True, revocation_mode=RevocationMode.SOFT_FAIL,
        allow_fetching=True,
    )
    print(f"\n=== VERIFICA {path} ===")
    _reqs.clear()
    t = time.time()
    res = verifier.analyze_file(path, store.certificates, opts,
                                store.tsa_certificates)
    dt = time.time() - t

    print(f"\n[fase] analyze_file TOTALE: {dt:.2f}s")
    net = sum(r[2] for r in _reqs)
    print(f"[rete] {len(_reqs)} richieste, {net:.2f}s "
          f"({net / max(dt, 0.01) * 100:.0f}% del tempo totale)")
    for m, u, tt, n, st in sorted(_reqs, key=lambda r: -r[2]):
        size = f"{n / 1024:.1f}KB" if n >= 0 else "ERR"
        print(f"    {tt:7.2f}s  {m:4}  {size:>10}  {st}  {u[:90]}")

    print("\n[firme]")
    for i, s in enumerate(res.signatures, 1):
        print(f"  #{i} {s.level}  trust={s.trust_status.name}  "
              f"marca={'si' if s.has_timestamp else 'no'}  "
              f"archive-ts={getattr(s, 'archive_timestamps', 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
