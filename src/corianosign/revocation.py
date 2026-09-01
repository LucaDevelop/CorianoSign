"""Ottimizzazione dei controlli di revoca (CRL/OCSP).

Il costo dominante della verifica di una firma NON è la crittografia (millisecondi)
ma il download delle informazioni di revoca. Le CRL delle CA qualificate italiane
possono pesare molti MB e vengono scaricate/riparse per intero.

Qui costruiamo un unico oggetto :class:`Fetchers` condiviso da TUTTE le catene di
una singola verifica (firmatario, TSA, ogni archive-timestamp): pyhanko memoizza le
CRL/OCSP nell'istanza dei fetcher, quindi la stessa CRL di CA/TSA viene scaricata
UNA volta invece che una per catena.

In più il fetcher delle CRL usa una cache **su disco** con TTL (dal ``nextUpdate``
della CRL): tra un avvio e l'altro le CRL già scaricate non vengono riscaricate.

L'OCSP NON viene messo in cache su disco: pyhanko invia un *nonce* nella richiesta e
verifica che la risposta lo riporti; una risposta salvata e riproposta a un avvio
successivo fallirebbe il controllo del nonce. L'OCSP resta comunque deduplicato in
memoria nel singolo run tramite il ``Fetchers`` condiviso (ed è piccolo e veloce).
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Optional

from asn1crypto import crl, pem
from pyhanko_certvalidator.fetchers.api import Fetchers
from pyhanko_certvalidator.fetchers.requests_fetchers.cert_fetch_client import (
    RequestsCertificateFetcher,
)
from pyhanko_certvalidator.fetchers.requests_fetchers.crl_client import (
    RequestsCRLFetcher,
)
from pyhanko_certvalidator.fetchers.requests_fetchers.ocsp_client import (
    RequestsOCSPFetcher,
)

from .paths import revocation_cache_dir

# timeout per singola richiesta HTTP: più corto del default (10s) così un
# distribution point irraggiungibile non blocca a lungo (in soft-fail la revoca
# non verificabile non blocca comunque l'esito).
DEFAULT_TIMEOUT = 8

# quanto tenere una CRL priva di nextUpdate (o con nextUpdate già passato):
# abbastanza per accelerare riverifiche ravvicinate, senza rischiare dati troppo
# vecchi.
_FALLBACK_TTL = 6 * 3600          # 6 ore
# non riusare mai una CRL più vecchia di questo, anche se il nextUpdate è lontano.
_MAX_TTL = 7 * 24 * 3600          # 7 giorni
# tetto complessivo della cache su disco.
_MAX_CACHE_BYTES = 250 * 1024 * 1024   # 250 MB


class _CachedResponse:
    """Risposta HTTP minimale con i soli campi usati dal fetcher CRL."""

    def __init__(self, content: bytes) -> None:
        self.content = content
        self.status_code = 200


def _crl_next_update(raw: bytes) -> Optional[float]:
    """Ritorna il nextUpdate (epoch) della CRL, o None se assente/illeggibile."""
    try:
        data = raw
        if pem.detect(data):
            _, _, data = pem.unarmor(data)
        cl = crl.CertificateList.load(data)
        nu = cl["tbs_cert_list"]["next_update"]
        if nu is None or nu.native is None:
            return None
        return nu.native.timestamp()
    except Exception:  # noqa: BLE001
        return None


class DiskCachingCRLFetcher(RequestsCRLFetcher):
    """CRL fetcher con cache su disco (chiave = URL, TTL = nextUpdate della CRL)."""

    def __init__(self, *args, cache_dir: Optional[Path] = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cache_dir = cache_dir or revocation_cache_dir()

    # --- disco --------------------------------------------------------- #
    def _paths(self, url: str) -> tuple[Path, Path]:
        key = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return self._cache_dir / f"{key}.crl", self._cache_dir / f"{key}.json"

    def _disk_load(self, url: str) -> Optional[bytes]:
        blob, meta = self._paths(url)
        try:
            if not blob.is_file() or not meta.is_file():
                return None
            info = json.loads(meta.read_text("utf-8"))
            if time.time() >= float(info.get("expires_at", 0)):
                blob.unlink(missing_ok=True)
                meta.unlink(missing_ok=True)
                return None
            return blob.read_bytes()
        except Exception:  # noqa: BLE001
            return None

    def _disk_store(self, url: str, content: bytes) -> None:
        blob, meta = self._paths(url)
        now = time.time()
        nu = _crl_next_update(content)
        if nu is not None and nu > now:
            expires_at = min(nu, now + _MAX_TTL)
        else:
            expires_at = now + _FALLBACK_TTL
        try:
            blob.write_bytes(content)
            meta.write_text(
                json.dumps({"url": url, "fetched_at": now, "expires_at": expires_at}),
                "utf-8",
            )
            self._enforce_size_cap()
        except Exception:  # noqa: BLE001
            pass

    def _enforce_size_cap(self) -> None:
        """Elimina le CRL scadute e, se serve, le più vecchie oltre il tetto."""
        try:
            entries = []
            total = 0
            for blob in self._cache_dir.glob("*.crl"):
                meta = blob.with_suffix(".json")
                size = blob.stat().st_size
                total += size
                expires_at = 0.0
                fetched_at = blob.stat().st_mtime
                try:
                    info = json.loads(meta.read_text("utf-8"))
                    expires_at = float(info.get("expires_at", 0))
                    fetched_at = float(info.get("fetched_at", fetched_at))
                except Exception:  # noqa: BLE001
                    pass
                entries.append([blob, meta, size, expires_at, fetched_at])
            now = time.time()
            # 1) via le scadute
            for e in entries:
                if now >= e[3]:
                    e[0].unlink(missing_ok=True)
                    e[1].unlink(missing_ok=True)
                    total -= e[2]
            # 2) se ancora oltre il tetto, via le più vecchie
            if total > _MAX_CACHE_BYTES:
                alive = [e for e in entries if now < e[3]]
                alive.sort(key=lambda e: e[4])  # per fetched_at crescente
                for e in alive:
                    if total <= _MAX_CACHE_BYTES:
                        break
                    e[0].unlink(missing_ok=True)
                    e[1].unlink(missing_ok=True)
                    total -= e[2]
        except Exception:  # noqa: BLE001
            pass

    # --- override del GET del mixin ------------------------------------ #
    def _get(self, url, *, acceptable_content_types):
        async def run():
            cached = self._disk_load(url)
            if cached is not None:
                return _CachedResponse(cached)
            resp = await super(DiskCachingCRLFetcher, self)._get(
                url, acceptable_content_types=acceptable_content_types
            )
            content = getattr(resp, "content", None)
            if content:
                self._disk_store(url, content)
            return resp

        return run()


def build_shared_fetchers(timeout: int = DEFAULT_TIMEOUT) -> Fetchers:
    """Un ``Fetchers`` da riusare per tutte le catene di una singola verifica.

    Il CRL fetcher usa la cache su disco; OCSP e certificati sono standard.
    """
    return Fetchers(
        ocsp_fetcher=RequestsOCSPFetcher(per_request_timeout=timeout),
        crl_fetcher=DiskCachingCRLFetcher(per_request_timeout=timeout),
        cert_fetcher=RequestsCertificateFetcher(per_request_timeout=timeout),
    )
