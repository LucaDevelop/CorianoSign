"""Test della cache di revoca (CRL su disco + fetcher condivisi)."""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone

import pytest
from asn1crypto import crl, x509

from corianosign import revocation
from corianosign.revocation import (
    DiskCachingCRLFetcher,
    _crl_next_update,
    build_shared_fetchers,
)


def _make_crl(next_update: datetime | None) -> bytes:
    """Costruisce una CRL DER minimale (basta la struttura, non la firma)."""
    name = x509.Name.build({"common_name": "Test CA"})
    tbs = {
        "version": "v2",
        "signature": {"algorithm": "sha256_rsa"},
        "issuer": name,
        "this_update": x509.Time({"utc_time": datetime.now(timezone.utc)}),
        "revoked_certificates": [],
    }
    if next_update is not None:
        tbs["next_update"] = x509.Time({"utc_time": next_update})
    cl = crl.CertificateList({
        "tbs_cert_list": tbs,
        "signature_algorithm": {"algorithm": "sha256_rsa"},
        "signature": b"\x00",
    })
    return cl.dump()


def test_crl_next_update_parsing():
    future = datetime.now(timezone.utc) + timedelta(days=3)
    ts = _crl_next_update(_make_crl(future))
    assert ts is not None
    assert abs(ts - future.timestamp()) < 2
    # CRL senza nextUpdate -> None
    assert _crl_next_update(_make_crl(None)) is None
    # byte non-CRL -> None (nessuna eccezione)
    assert _crl_next_update(b"not a crl") is None


def test_disk_roundtrip_and_ttl_from_next_update(tmp_path):
    f = DiskCachingCRLFetcher(cache_dir=tmp_path)
    future = datetime.now(timezone.utc) + timedelta(days=2)
    data = _make_crl(future)
    f._disk_store("http://ca.example/crl", data)
    assert f._disk_load("http://ca.example/crl") == data
    # TTL deve rispettare il nextUpdate (~2 giorni), non il fallback 6h
    import json
    _, meta = f._paths("http://ca.example/crl")
    info = json.loads(meta.read_text("utf-8"))
    assert info["expires_at"] > time.time() + 24 * 3600


def test_disk_fallback_ttl_when_no_next_update(tmp_path):
    f = DiskCachingCRLFetcher(cache_dir=tmp_path)
    data = _make_crl(None)  # niente nextUpdate -> TTL di fallback
    f._disk_store("http://ca.example/crl2", data)
    assert f._disk_load("http://ca.example/crl2") == data


def test_disk_expired_entry_is_dropped(tmp_path):
    f = DiskCachingCRLFetcher(cache_dir=tmp_path)
    past = datetime.now(timezone.utc) - timedelta(days=1)
    data = _make_crl(past)  # nextUpdate passato -> fallback (6h), quindi ancora valido
    # forziamo la scadenza scrivendo un meta gia' scaduto
    f._disk_store("http://ca.example/old", data)
    import json
    blob, meta = f._paths("http://ca.example/old")
    info = json.loads(meta.read_text("utf-8"))
    info["expires_at"] = time.time() - 10
    meta.write_text(json.dumps(info), "utf-8")
    assert f._disk_load("http://ca.example/old") is None
    # i file scaduti vengono rimossi
    assert not blob.is_file() and not meta.is_file()


def test_get_uses_disk_cache_and_skips_network(tmp_path, monkeypatch):
    f = DiskCachingCRLFetcher(cache_dir=tmp_path)
    url = "http://ca.example/net.crl"
    data = _make_crl(datetime.now(timezone.utc) + timedelta(days=1))

    calls = {"n": 0}

    async def fake_super_get(self, u, *, acceptable_content_types):
        calls["n"] += 1
        return revocation._CachedResponse(data)

    # sostituisce il _get del mixin (la "rete")
    from pyhanko_certvalidator.fetchers.requests_fetchers.util import (
        RequestsFetcherMixin,
    )
    monkeypatch.setattr(RequestsFetcherMixin, "_get", fake_super_get)

    async def go():
        r1 = await f._get(url, acceptable_content_types=("application/pkix-crl",))
        r2 = await f._get(url, acceptable_content_types=("application/pkix-crl",))
        return r1.content, r2.content

    c1, c2 = asyncio.run(go())
    assert c1 == data and c2 == data
    # la rete e' stata contattata UNA sola volta: il secondo giro e' cache su disco
    assert calls["n"] == 1


def test_build_shared_fetchers_types():
    fetchers = build_shared_fetchers(timeout=5)
    assert isinstance(fetchers.crl_fetcher, DiskCachingCRLFetcher)
    assert fetchers.crl_fetcher.per_request_timeout == 5
    assert fetchers.ocsp_fetcher.per_request_timeout == 5
