"""Test di config, cache trust e verifica firma delle Trusted List.

I test marcati 'network' richiedono connessione (scaricano LOTL/TSL):
    pytest -m "not network"     # solo test offline
"""
import time

import pytest

from corianosign import config as C
from corianosign import trust
from corianosign import tsl_signature as ts


# --------------------------- offline --------------------------------------- #
def test_config_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "config_file", lambda: tmp_path / "config.json")
    cfg = C.AppConfig(auto_update=False, interval_days=14, territories=["*"],
                      verify_signatures=False, revocation_online=False)
    C.save_config(cfg)
    back = C.load_config()
    assert back.auto_update is False
    assert back.interval_days == 14
    assert back.territories == ["*"]
    assert back.verify_signatures is False


def test_config_clamp():
    cfg = C.AppConfig(interval_days=0, territories=[])
    cfg.clamp()
    assert cfg.interval_days == 1
    assert cfg.territories == ["IT"]


def test_needs_update():
    store = trust.TrustStore()
    # cache vuota -> serve aggiornamento
    assert trust.needs_update(store, 7) is True
    # cache fresca con certificati -> non serve
    store.certificates = ["x"]  # basta la lunghezza
    store.updated_at = time.time()
    assert trust.needs_update(store, 7) is False
    # cache vecchia -> serve
    store.updated_at = time.time() - 10 * 86400
    assert trust.needs_update(store, 7) is True


def test_lotl_anchors_bundled():
    """L'anchor OJ del LOTL deve essere impacchettato con l'app."""
    anchors = ts.load_lotl_anchors()
    assert len(anchors) >= 1


def test_verify_garbage_signature():
    res = ts.verify_xml_signature(b"<root>nessuna firma</root>")
    assert res.signature_valid is False
    assert res.signer_trusted is False


# --------------------------- online ---------------------------------------- #
@pytest.mark.network
def test_full_chain_authentic():
    """Catena completa: anchor OJ -> LOTL -> TSL-IT (AgID)."""
    from lxml import etree

    lotl = trust._fetch(trust.EU_LOTL_URL)
    r = ts.verify_lotl(lotl)
    assert r.ok, r.messages

    root = etree.fromstring(lotl)
    expected = ts.national_signer_certs(root, "IT")
    assert expected, "il LOTL deve dichiarare i certificati firmatari IT"

    it = trust._fetch(trust.IT_TSL_FALLBACK_URL)
    r2 = ts.verify_national_tsl(it, expected)
    assert r2.ok, r2.messages
