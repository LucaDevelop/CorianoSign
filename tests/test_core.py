"""Test del core di verifica (parsing, crittografia, catena).

Esegui:  pytest        (dalla radice, con il pacchetto installato: pip install -e .)
I fixture .p7m sono generati da tests/fixtures/genera_fixture.sh
"""
from pathlib import Path

import pytest
from asn1crypto import pem, x509

from corianosign import cms, verifier
from corianosign.model import TrustStatus

FIX = Path(__file__).parent / "fixtures"


def _load_root() -> x509.Certificate:
    der = pem.unarmor((FIX / "ca_cert.pem").read_bytes())[2]
    return x509.Certificate.load(der)


@pytest.mark.skipif(not (FIX / "documento.txt.p7m").exists(),
                    reason="fixture assenti: esegui genera_fixture.sh")
def test_parsing_ed_estrazione():
    res = verifier.analyze_file(str(FIX / "documento.txt.p7m"), [],
                                verifier.VerifyOptions(check_trust=False))
    assert not res.parse_errors
    assert res.content == b"Contenuto di prova per CorianoSign.\nRiga due.\n"
    assert res.content_filename == "documento.txt"
    assert len(res.signatures) == 1


@pytest.mark.skipif(not (FIX / "documento.txt.p7m").exists(), reason="fixture assenti")
def test_firma_crittografica_valida():
    res = verifier.analyze_file(str(FIX / "documento.txt.p7m"), [],
                                verifier.VerifyOptions(check_trust=False))
    s = res.signatures[0]
    assert s.crypto_valid and s.digest_match
    assert s.signer.fiscal_code == "TINIT-RSSMRA80A01H501U"


@pytest.mark.skipif(not (FIX / "documento.txt.p7m").exists(), reason="fixture assenti")
def test_self_signed_non_fidato():
    res = verifier.analyze_file(str(FIX / "documento.txt.p7m"), [_load_root()],
                                verifier.VerifyOptions(check_trust=True, allow_fetching=False))
    s = res.signatures[0]
    # cripto ok ma non riconducibile a CA fidata
    assert s.crypto_valid
    assert s.trust_status in (TrustStatus.UNTRUSTED, TrustStatus.ERROR)
    assert not s.is_valid


@pytest.mark.skipif(not (FIX / "chained.txt.p7m").exists(), reason="fixture assenti")
def test_catena_fidata():
    res = verifier.analyze_file(str(FIX / "chained.txt.p7m"), [_load_root()],
                                verifier.VerifyOptions(check_trust=True, allow_fetching=False))
    s = res.signatures[0]
    assert s.crypto_valid and s.digest_match
    assert s.trust_status is TrustStatus.TRUSTED
    assert s.is_valid
    assert "CoricaTest Root CA" in s.trust_anchor_cn


@pytest.mark.skipif(not (FIX / "documento.txt.p7m").exists(), reason="fixture assenti")
def test_rilevamento_manomissione():
    """Se il contenuto viene alterato, il digest non deve piu' corrispondere."""
    data = (FIX / "documento.txt.p7m").read_bytes()
    ci = cms.load_content_info(data)
    sd = cms.get_signed_data(ci)
    _, econtent = cms.extract_content(sd)
    certs = cms.collect_certificates(sd)
    si = sd["signer_infos"][0]
    cert = cms._find_signer_cert(si, certs)
    tampered = econtent + b"ALTERATO"
    crypto_valid, digest_match, errors, _ = cms.verify_signature(sd, si, tampered, cert)
    assert digest_match is False
    assert any("NON corrisponde" in e for e in errors)


@pytest.mark.skipif(not (FIX / "chained_ts.txt.p7m").exists(),
                    reason="fixture CAdES-T assente: esegui genera_fixture.sh")
def test_cades_t_marca_temporale():
    root = _load_root()
    res = verifier.analyze_file(str(FIX / "chained_ts.txt.p7m"), [root],
                                verifier.VerifyOptions(check_trust=True, allow_fetching=False),
                                tsa_roots=[root])
    s = res.signatures[0]
    assert s.is_valid
    assert s.has_timestamp
    assert s.timestamp_valid
    assert s.timestamp_trust is TrustStatus.TRUSTED
    assert s.timestamp_time is not None
    # il tempo fidato per la validazione è quello della marca
    assert s.trusted_time == s.timestamp_time


@pytest.mark.skipif(not (FIX / "chained.txt.p7m").exists(), reason="fixture assenti")
def test_cades_bes_senza_marca():
    root = _load_root()
    res = verifier.analyze_file(str(FIX / "chained.txt.p7m"), [root],
                                verifier.VerifyOptions(check_trust=True, allow_fetching=False))
    s = res.signatures[0]
    assert s.has_timestamp is False
    assert s.trusted_time == s.signer.signing_time


@pytest.mark.skipif(not (FIX / "chained_ts.txt.p7m").exists(), reason="fixture assenti")
def test_marca_imprint_mismatch():
    """Una marca riferita a un valore di firma diverso non deve combaciare."""
    from asn1crypto import cms as acms

    from corianosign import timestamp
    ci = acms.ContentInfo.load((FIX / "chained_ts.txt.p7m").read_bytes())
    si = ci["content"]["signer_infos"][0]
    tok = timestamp.extract_timestamp_tokens(si)[0]
    r = timestamp.verify_timestamp(tok, b"valore-di-firma-sbagliato",
                                   None, check_trust=False)
    assert r.imprint_match is False
    assert r.valid is False


@pytest.mark.skipif(not (FIX / "chained_lt.txt.p7m").exists(),
                    reason="fixture CAdES-LT assente: esegui genera_fixture.sh")
def test_cades_lt_livello_e_materiale():
    root = _load_root()
    res = verifier.analyze_file(str(FIX / "chained_lt.txt.p7m"), [root],
                                verifier.VerifyOptions(check_trust=True, allow_fetching=False),
                                tsa_roots=[root])
    s = res.signatures[0]
    assert s.level == "CAdES-LT"
    assert s.embedded_certs >= 3
    assert s.embedded_crls >= 1
    assert s.is_valid


@pytest.mark.skipif(not (FIX / "chained_lt.txt.p7m").exists(), reason="fixture assenti")
def test_cades_lt_revoca_offline_hardfail():
    """Con CRL incapsulata la validazione hard-fail OFFLINE deve riuscire;
    senza materiale LT deve fallire."""
    from corianosign.validation import RevocationMode
    root = _load_root()
    opts = verifier.VerifyOptions(check_trust=True, allow_fetching=False,
                                  revocation_mode=RevocationMode.HARD_FAIL)
    lt = verifier.analyze_file(str(FIX / "chained_lt.txt.p7m"), [root], opts,
                               tsa_roots=[root]).signatures[0]
    assert lt.ltv_used is True
    assert lt.trust_status is TrustStatus.TRUSTED
    # senza materiale LT (solo CAdES-T) -> revoca non verificabile offline
    t = verifier.analyze_file(str(FIX / "chained_ts.txt.p7m"), [root], opts,
                              tsa_roots=[root]).signatures[0]
    assert t.trust_status is not TrustStatus.TRUSTED


@pytest.mark.skipif(not (FIX / "chained_lta.txt.p7m").exists(), reason="fixture assenti")
def test_cades_lta_archive_timestamp():
    root = _load_root()
    res = verifier.analyze_file(str(FIX / "chained_lta.txt.p7m"), [root],
                                verifier.VerifyOptions(check_trust=True, allow_fetching=False),
                                tsa_roots=[root])
    s = res.signatures[0]
    assert s.level == "CAdES-LTA"
    assert s.archive_timestamps == 1
    assert s.archive_valid == 1
    assert s.archive_time is not None
    # l'impronta d'archivio (ats-hash-index-v3) è ricalcolata e coerente
    assert s.archive_imprint_verified == 1


@pytest.mark.skipif(not (FIX / "chained_lta.txt.p7m").exists(), reason="fixture assenti")
def test_archive_imprint_ricalcolo_e_manomissione():
    from asn1crypto import cms as acms

    from corianosign import archive_ts, cades_lt
    from corianosign import cms as ccms
    ci = acms.ContentInfo.load((FIX / "chained_lta.txt.p7m").read_bytes())
    sd = ci["content"]
    si = sd["signer_infos"][0]
    _, econtent = ccms.extract_content(sd)
    tok = cades_lt.extract_archive_timestamps(si)[0]

    ok = archive_ts.verify_archive_imprint(tok, sd, si, econtent)
    assert ok.recomputed and ok.index_valid and ok.imprint_match

    # contenuto alterato -> l'impronta d'archivio non deve piu' combaciare
    bad = archive_ts.verify_archive_imprint(tok, sd, si, econtent + b"X")
    assert bad.imprint_match is False


def test_file_non_valido():
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".p7m", delete=False) as fh:
        fh.write(b"non sono una busta cms")
        name = fh.name
    res = verifier.analyze_file(name, [], verifier.VerifyOptions(check_trust=False))
    assert res.parse_errors


# --------------------------------------------------------------------------- #
# PAdES (firme dentro i PDF)
# --------------------------------------------------------------------------- #
PADES = FIX / "pades_firmato.pdf"


@pytest.mark.skipif(not PADES.exists(), reason="fixture PAdES assente")
def test_pades_rilevamento_firme():
    from corianosign import pades

    data = PADES.read_bytes()
    assert pades.is_pdf(data)
    sigs = pades.find_signatures(data)
    assert len(sigs) >= 1
    s = sigs[0]
    assert s.signed_data is not None
    assert s.sub_filter in ("ETSI.CAdES.detached", "adbe.pkcs7.detached")
    assert s.covers_whole_document


@pytest.mark.skipif(not PADES.exists(), reason="fixture PAdES assente")
def test_pades_verifica_crittografica():
    res = verifier.analyze_file(str(PADES), [],
                                verifier.VerifyOptions(check_trust=False))
    assert not res.parse_errors
    assert res.content_filename == "pades_firmato.pdf"
    assert res.content == PADES.read_bytes()  # il documento e' il PDF stesso
    assert len(res.signatures) == 1
    s = res.signatures[0]
    assert s.crypto_valid and s.digest_match
    assert s.level.startswith("PAdES")
    assert s.trust_status is TrustStatus.NOT_CHECKED


# regressione: un .p7m che racchiude un PDF NON va scambiato per un PAdES
PDF_IN_P7M = FIX / "documento.pdf.p7m"


@pytest.mark.skipif(not PDF_IN_P7M.exists(), reason="fixture assente")
def test_p7m_che_racchiude_un_pdf_e_cades_non_pades():
    from corianosign import pades

    data = PDF_IN_P7M.read_bytes()
    assert not pades.is_pdf(data)  # inizia con 0x30 (DER), non con %PDF-
    res = verifier.analyze_file(str(PDF_IN_P7M), [],
                                verifier.VerifyOptions(check_trust=False))
    assert not res.parse_errors
    assert len(res.signatures) == 1
    s = res.signatures[0]
    assert s.crypto_valid and s.digest_match
    assert s.level.startswith("CAdES")           # CAdES, non PAdES
    assert res.content[:5] == b"%PDF-"            # il PDF estratto dalla busta
