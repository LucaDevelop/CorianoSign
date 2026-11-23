"""Test della verifica XAdES (firma XML) e del routing del formato.

La firma XAdES viene generata al volo con un certificato self-signed (il trust
non è l'oggetto del test: qui si verificano crittografia, estrazione dati del
firmatario, livello e rilevamento manomissioni).
"""
from __future__ import annotations

import datetime

import pytest

from corianosign import verifier, xades
from corianosign.model import TrustStatus

signxml_xades = pytest.importorskip("signxml.xades")


def _signed_xml(content: bytes = b"contenuto di prova") -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from lxml import etree
    from signxml.xades import XAdESSigner

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Mario Rossi"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "TINIT-RSSMRA80A01H294X"),
    ])
    cert = (
        x509.CertificateBuilder().subject_name(subj).issuer_name(subj)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    root = etree.fromstring(b"<Documento><Dato>" + content + b"</Dato></Documento>")
    signed = XAdESSigner(signature_algorithm="rsa-sha256",
                         digest_algorithm="sha256").sign(root, key=key, cert=pem)
    return etree.tostring(signed, xml_declaration=True, encoding="UTF-8")


def test_is_xml_discrimina_i_formati():
    assert xades.is_xml(b'<?xml version="1.0"?><a/>')
    assert xades.is_xml(b"\xef\xbb\xbf<Doc/>")        # BOM iniziale
    assert not xades.is_xml(b"\x30\x82\x01\x02")      # CMS (.p7m) inizia con 0x30
    assert not xades.is_xml(b"%PDF-1.7")               # PDF


def test_verifica_xades_valida():
    data = _signed_xml()
    res = verifier.analyze_bytes(
        data, [], verifier.VerifyOptions(check_trust=False, allow_fetching=False), [])
    assert not res.parse_errors
    assert len(res.signatures) == 1
    s = res.signatures[0]
    assert s.crypto_valid and s.digest_match
    assert s.level == "XAdES-BES"
    assert s.signer.common_name == "Mario Rossi"
    assert s.signer.fiscal_code == "TINIT-RSSMRA80A01H294X"
    assert s.trust_status is TrustStatus.NOT_CHECKED


def test_verifica_xades_manomessa():
    data = _signed_xml(b"originale")
    tampered = data.replace(b"originale", b"modificato")
    res = verifier.analyze_bytes(
        tampered, [], verifier.VerifyOptions(check_trust=False, allow_fetching=False), [])
    assert len(res.signatures) == 1
    assert not res.signatures[0].crypto_valid
    assert res.signatures[0].errors


def test_xml_non_firmato():
    res = verifier.analyze_bytes(
        b"<Documento><Dato>senza firma</Dato></Documento>", [],
        verifier.VerifyOptions(check_trust=False, allow_fetching=False), [])
    assert res.parse_errors          # "nessuna firma XAdES trovata"
    assert not res.signatures
