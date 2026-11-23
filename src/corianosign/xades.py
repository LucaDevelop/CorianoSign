"""Verifica delle firme XAdES (XML Advanced Electronic Signatures).

Una firma XAdES e' una firma **XML-DSig** (``ds:Signature``) arricchita con le
proprieta' qualificanti ETSI (``xades:QualifyingProperties``): certificato del
firmatario, istante di firma, eventuale marca temporale e materiale di
validazione a lungo termine. E' il terzo formato della firma digitale italiana,
accanto a CAdES (``.p7m``) e PAdES (PDF).

Qui:
  * individuiamo le ``ds:Signature`` nel documento XML;
  * verifichiamo la firma crittografica con **signxml** (``XAdESVerifier``),
    "pinnando" il certificato incorporato cosi' da NON delegare a signxml la
    validazione PKI: la fiducia la stabiliamo noi verso le Trusted List
    (``validation.validate_chain``), esattamente come per CAdES/PAdES;
  * riconosciamo il livello XAdES-BES/T/LT/LTA dagli elementi presenti.

Il certificato del firmatario e la catena vengono presi da ``ds:X509Certificate``
dentro ``ds:KeyInfo``; l'istante di firma da ``xades:SigningTime``.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Optional

from asn1crypto import x509

from .model import SignatureResult, SignerInfo, TrustStatus
from .validation import validate_chain

# --- namespace XML-DSig / XAdES ------------------------------------------- #
DS = "http://www.w3.org/2000/09/xmldsig#"
XADES = "http://uri.etsi.org/01903/v1.3.2#"
XADES141 = "http://uri.etsi.org/01903/v1.4.1#"
_NS = {"ds": DS, "xades": XADES, "xades141": XADES141}


def is_xml(data: bytes) -> bool:
    """Riconosce un documento XML (eventuale BOM/whitespace iniziale tollerato).

    Un CMS/PKCS#7 (``.p7m``) inizia con ``0x30`` (SEQUENCE DER) e un PDF con
    ``%PDF-``: quindi un file che inizia con ``<`` non collide con quei formati.
    L'effettiva presenza di una firma viene stabilita da ``find_signatures``.
    """
    head = data[:64].lstrip(b"\x00\x09\x0a\x0c\x0d\x20\xef\xbb\xbf")
    return head[:1] == b"<"


def _parse(data: bytes):
    """Carica l'XML in modo sicuro (niente entita'/DTD esterne)."""
    from lxml import etree

    parser = etree.XMLParser(resolve_entities=False, no_network=True,
                             load_dtd=False, dtd_validation=False)
    return etree.fromstring(data, parser=parser)


def find_signature_elements(data: bytes) -> list:
    """Elenca gli elementi ``ds:Signature`` presenti nel documento."""
    root = _parse(data)
    return root.findall(f".//{{{DS}}}Signature")


def _text(el, path: str) -> str:
    found = el.find(path, _NS)
    return (found.text or "").strip() if found is not None else ""


def _signer_certs(sig_el) -> list[x509.Certificate]:
    """Certificati in ``ds:KeyInfo`` di questa firma (il primo = firmatario)."""
    out: list[x509.Certificate] = []
    for node in sig_el.findall(f".//{{{DS}}}X509Certificate"):
        b64 = (node.text or "").strip()
        if not b64:
            continue
        try:
            der = base64.b64decode(b64)
            out.append(x509.Certificate.load(der))
        except Exception:  # noqa: BLE001 - certificato illeggibile: lo saltiamo
            continue
    return out


def _parse_signing_time(sig_el) -> Optional[datetime]:
    """``xades:SigningTime`` (ISO 8601) -> datetime UTC, se presente."""
    raw = ""
    st = sig_el.find(f".//{{{XADES}}}SigningTime")
    if st is not None and st.text:
        raw = st.text.strip()
    if not raw:
        return None
    try:
        # Python 3.11+ gestisce la 'Z'; normalizziamo per sicurezza
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _detect_level(sig_el) -> str:
    """Riconosce il livello XAdES dagli elementi presenti nella firma."""
    has_sig_ts = sig_el.find(f".//{{{XADES}}}SignatureTimeStamp") is not None
    has_certvals = sig_el.find(f".//{{{XADES}}}CertificateValues") is not None
    has_revvals = sig_el.find(f".//{{{XADES}}}RevocationValues") is not None
    has_archive = (
        sig_el.find(f".//{{{XADES}}}ArchiveTimeStamp") is not None
        or sig_el.find(f".//{{{XADES141}}}ArchiveTimeStamp") is not None
    )
    if has_archive:
        return "XAdES-LTA"
    if has_certvals or has_revvals:
        return "XAdES-LT"
    if has_sig_ts:
        return "XAdES-T"
    return "XAdES-BES"


def _first(val) -> str:
    if isinstance(val, (list, tuple)):
        return str(val[0]) if val else ""
    return str(val) if val is not None else ""


def _signer_info_from_cert(cert: x509.Certificate,
                           signing_time: Optional[datetime]) -> SignerInfo:
    """Costruisce ``SignerInfo`` dai campi del certificato del firmatario."""
    subj = cert.subject.native if cert else {}
    info = SignerInfo(
        common_name=_first(subj.get("common_name", "")),
        organization=_first(subj.get("organization_name", "")),
        country=_first(subj.get("country_name", "")),
        fiscal_code=_first(subj.get("serial_number", "")),
        email=_first(subj.get("email_address", "")),
    )
    if cert:
        issuer = cert.issuer.native
        info.issuer_cn = _first(issuer.get("common_name", "")) or _first(
            issuer.get("organization_name", "")
        )
        info.serial_number = format(cert.serial_number, "x")
        info.not_before = cert["tbs_certificate"]["validity"]["not_before"].native
        info.not_after = cert["tbs_certificate"]["validity"]["not_after"].native
    info.signing_time = signing_time
    return info


def _pem(cert: x509.Certificate) -> bytes:
    body = base64.encodebytes(cert.dump()).decode()
    return ("-----BEGIN CERTIFICATE-----\n" + body
            + "-----END CERTIFICATE-----\n").encode()


def _verify_crypto(data: bytes, signer_cert: x509.Certificate,
                   multi: bool) -> tuple[bool, Optional[str]]:
    """Verifica crittografica della firma via signxml, pinnando il certificato.

    Pinnare il certificato fa saltare la validazione PKI interna di signxml: la
    fiducia la stabiliamo noi verso le Trusted List. Ritorna (valida, errore).
    """
    try:
        from signxml.xades import XAdESVerifier
        from signxml import InvalidSignature, InvalidDigest, InvalidCertificate
    except ImportError as exc:  # pragma: no cover
        return False, f"Libreria signxml non disponibile: {exc}"

    try:
        XAdESVerifier().verify(data, x509_cert=_pem(signer_cert).decode())
        return True, None
    except (InvalidSignature, InvalidDigest, InvalidCertificate) as exc:
        if multi:
            # In un documento multi-firma il pin di un certificato fa fallire le
            # ALTRE firme: non possiamo attestare la crittografia per-firma qui.
            return False, (
                "Documento con piu' firme XML: la verifica crittografica "
                "per singola firma non e' supportata."
            )
        return False, f"Firma XML non valida: {exc}"
    except Exception as exc:  # noqa: BLE001
        return False, f"Verifica XAdES non riuscita: {exc}"


def analyze(
    data: bytes,
    trust_roots: list[x509.Certificate],
    tsa_roots: list[x509.Certificate],
    options,
    fetchers=None,
) -> list[SignatureResult]:
    """Analizza tutte le firme XAdES del documento XML.

    ``options`` e' un ``verifier.VerifyOptions`` (check_trust / revocation_mode /
    allow_fetching). Ritorna un ``SignatureResult`` per ogni ``ds:Signature``.
    """
    try:
        sig_els = find_signature_elements(data)
    except Exception as exc:  # noqa: BLE001 - XML malformato
        sr = SignatureResult(signer=SignerInfo())
        sr.errors.append(f"XML non interpretabile: {exc}")
        return [sr]

    if not sig_els:
        return []

    multi = len(sig_els) > 1
    results: list[SignatureResult] = []
    for sig_el in sig_els:
        results.append(
            _verify_one(sig_el, data, trust_roots, tsa_roots, options,
                        fetchers, multi)
        )
    return results


def _verify_one(sig_el, data: bytes, trust_roots, tsa_roots, options,
                fetchers, multi: bool) -> SignatureResult:
    certs = _signer_certs(sig_el)
    signing_time = _parse_signing_time(sig_el)

    if not certs:
        sr = SignatureResult(signer=SignerInfo())
        sr.errors.append(
            "Certificato del firmatario non presente nella firma XML: "
            "verifica impossibile."
        )
        return sr

    signer_cert = certs[0]
    info = _signer_info_from_cert(signer_cert, signing_time)
    sr = SignatureResult(signer=info)
    sr.level = _detect_level(sig_el)

    # --- verifica crittografica ---------------------------------------- #
    crypto_ok, err = _verify_crypto(data, signer_cert, multi)
    sr.crypto_valid = crypto_ok
    # In XML-DSig il confronto d'impronta (Reference DigestValue) e' parte
    # integrante della verifica della firma: se la firma e' valida, lo e' anche
    # l'integrita' del contenuto referenziato.
    sr.digest_match = crypto_ok
    if err:
        (sr.warnings if multi else sr.errors).append(err)

    if sr.level in ("XAdES-T", "XAdES-LT", "XAdES-LTA"):
        sr.has_timestamp = True
        sr.warnings.append(
            "Marca temporale XAdES presente: rilevata ma non ancora verificata "
            "crittograficamente in questa versione."
        )

    # --- validazione della catena verso le Trusted List ---------------- #
    if not options.check_trust:
        sr.trust_status = TrustStatus.NOT_CHECKED
        return sr

    moment = sr.trusted_time  # marca non ancora verificata -> signing-time
    intermediates = certs[1:]
    chain = validate_chain(
        signer_cert,
        intermediates,
        trust_roots,
        moment=moment,
        revocation_mode=options.revocation_mode,
        allow_fetching=options.allow_fetching,
        fetchers=fetchers,
    )
    sr.trust_status = chain.status
    sr.trust_anchor_cn = chain.trust_anchor_cn
    sr.revocation_info = chain.revocation_info
    sr.warnings.extend(chain.messages)
    return sr
