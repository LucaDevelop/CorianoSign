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


def _signed_xml_filter2(content: bytes = b"contenuto di prova") -> bytes:
    """XAdES enveloped che usa il transform XPath Filter 2.0 ``subtract``.

    E' l'idioma ETSI usato da Aruba (e altri servizi italiani): al posto del
    transform ``enveloped-signature`` la Reference del documento elenca un filtro
    ``subtract`` che toglie il sottoalbero ``ds:Signature``. signxml lo genera con
    il transform standard, quindi qui lo sostituiamo e rifirmiamo la ``SignedInfo``
    (il contenuto digerito e' identico, cambia solo il modo di descrivere la
    sottrazione della firma, percio' il DigestValue resta valido).
    """
    import base64

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID
    from lxml import etree
    from signxml.xades import XAdESSigner

    DS = "http://www.w3.org/2000/09/xmldsig#"
    FILTER2 = "http://www.w3.org/2002/06/xmldsig-filter2"

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mario Rossi")])
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

    ref0 = next(r for r in signed.findall(f".//{{{DS}}}Reference")
                if r.get("URI") == "")
    transforms = ref0.find(f"{{{DS}}}Transforms")
    for t in list(transforms):
        transforms.remove(t)
    t = etree.SubElement(transforms, f"{{{DS}}}Transform")
    t.set("Algorithm", FILTER2)
    xp = etree.SubElement(t, f"{{{FILTER2}}}XPath")
    xp.set("Filter", "subtract")
    xp.text = "/descendant::ds:Signature"

    # rifirma SignedInfo (C14N): il transform e' cambiato dentro SignedInfo
    si = signed.find(f".//{{{DS}}}SignedInfo")
    si_c14n = etree.tostring(si, method="c14n", with_comments=False)
    sigval = key.sign(si_c14n, padding.PKCS1v15(), hashes.SHA256())
    signed.find(f".//{{{DS}}}SignatureValue").text = \
        base64.encodebytes(sigval).decode()
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


def test_verifica_xades_filter2_enveloped_stile_aruba():
    """Le firme enveloped con XPath Filter 2.0 (Aruba/ETSI) sono verificabili.

    signxml da solo ignora il transform ``xmldsig-filter2`` e darebbe "Digest
    mismatch for reference 0": il nostro verifier applica il filtro ``subtract``.
    """
    data = _signed_xml_filter2(b"documento aruba")
    res = verifier.analyze_bytes(
        data, [], verifier.VerifyOptions(check_trust=False, allow_fetching=False), [])
    assert len(res.signatures) == 1
    s = res.signatures[0]
    assert s.crypto_valid and s.digest_match
    assert not s.errors

    # controllo negativo: il verifier "liscio" di signxml NON ce la fa (prova che
    # il test esercita davvero la gestione di filter2 e non un caso banale).
    from signxml import InvalidDigest
    from signxml.xades import XAdESVerifier
    signer_cert = xades._signer_certs(xades.find_signature_elements(data)[0])[0]
    pem = xades._pem(signer_cert).decode()
    with pytest.raises(InvalidDigest):
        XAdESVerifier().verify(data, x509_cert=pem)


def test_verifica_xades_filter2_manomessa():
    """Anche con filter2, un documento alterato deve risultare non valido."""
    data = _signed_xml_filter2(b"originale")
    tampered = data.replace(b"originale", b"modificato")
    res = verifier.analyze_bytes(
        tampered, [], verifier.VerifyOptions(check_trust=False, allow_fetching=False), [])
    assert len(res.signatures) == 1
    assert not res.signatures[0].crypto_valid


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
