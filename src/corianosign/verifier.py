"""Orchestratore: analisi completa di un file .p7m.

Combina il parsing/verifica crittografica (``cms``) con la validazione della
catena verso le Trusted List (``validation``), gestendo firme multiple
parallele e buste annidate (p7m dentro p7m).
"""
from __future__ import annotations

import os
from typing import Optional

from asn1crypto import x509

from . import cades_lt, cms, pades, revocation, timestamp
from .model import P7MResult, SignatureResult, SignerInfo, TrustStatus
from .validation import RevocationMode, validate_chain


class VerifyOptions:
    def __init__(
        self,
        check_trust: bool = True,
        revocation_mode: RevocationMode = RevocationMode.SOFT_FAIL,
        allow_fetching: bool = True,
    ) -> None:
        self.check_trust = check_trust
        self.revocation_mode = revocation_mode
        self.allow_fetching = allow_fetching


def _strip_p7m_suffix(name: str) -> str:
    base = os.path.basename(name)
    while base.lower().endswith(".p7m"):
        base = base[: -len(".p7m")]
    return base or "documento_estratto"


def analyze_file(
    path: str,
    trust_roots: Optional[list[x509.Certificate]] = None,
    options: Optional[VerifyOptions] = None,
    tsa_roots: Optional[list[x509.Certificate]] = None,
) -> P7MResult:
    with open(path, "rb") as fh:
        data = fh.read()
    result = analyze_bytes(data, trust_roots, options, tsa_roots)
    result.source_path = path
    if pades.is_pdf(data):
        # firma PAdES: il "contenuto" e' il PDF stesso, col nome originale
        result.content_filename = os.path.basename(path) or "documento.pdf"
    else:
        # eredita l'estensione originale dal nome file sorgente
        result.content_filename = _strip_p7m_suffix(path)
    return result


def analyze_bytes(
    data: bytes,
    trust_roots: Optional[list[x509.Certificate]] = None,
    options: Optional[VerifyOptions] = None,
    tsa_roots: Optional[list[x509.Certificate]] = None,
) -> P7MResult:
    options = options or VerifyOptions()
    trust_roots = trust_roots or []
    tsa_roots = tsa_roots or []
    result = P7MResult()

    # Un solo set di fetcher (rete) per l'intera verifica: le CRL/OCSP di una CA
    # si scaricano una volta sola, condivise tra firmatario, TSA e archive-ts.
    fetchers = (
        revocation.build_shared_fetchers()
        if options.allow_fetching and options.check_trust
        else None
    )

    # PDF firmato (PAdES): percorso dedicato
    if pades.is_pdf(data):
        return _analyze_pdf(data, trust_roots, tsa_roots, options, fetchers)

    try:
        signatures, content, levels = _analyze_layer(
            data, trust_roots, tsa_roots, options, depth=1, fetchers=fetchers
        )
    except cms.CmsError as exc:
        result.parse_errors.append(str(exc))
        return result

    result.signatures = signatures
    result.content = content or b""
    result.nested_levels = levels
    return result


def _analyze_pdf(
    data: bytes,
    trust_roots: list[x509.Certificate],
    tsa_roots: list[x509.Certificate],
    options: VerifyOptions,
    fetchers=None,
) -> P7MResult:
    """Analizza un PDF firmato PAdES riusando la verifica CMS/trust."""
    result = P7MResult()
    result.content = data  # il documento firmato e' il PDF stesso
    sigs = pades.find_signatures(data)
    if not sigs:
        result.parse_errors.append(
            "Nessuna firma PAdES trovata nel PDF (il documento non risulta firmato)."
        )
        return result

    has_doc_ts = any(s.is_doc_timestamp and s.signed_data is not None for s in sigs)
    max_end = max(s.byte_range[2] + s.byte_range[3] for s in sigs)

    out: list[SignatureResult] = []
    for ps in sigs:
        is_last = (ps.byte_range[2] + ps.byte_range[3]) == max_end

        if ps.is_doc_timestamp:
            out.append(_verify_doc_timestamp(ps, tsa_roots, options, fetchers))
            continue

        if ps.signed_data is None:
            sr = SignatureResult(signer=SignerInfo())
            sr.errors.append(ps.error or "Firma PAdES non interpretabile.")
            out.append(sr)
            continue

        certs = cms.collect_certificates(ps.signed_data)
        for si in ps.signed_data["signer_infos"]:
            sr = _verify_one(
                ps.signed_data, si, ps.signed_bytes, certs,
                trust_roots, tsa_roots, options, fetchers,
            )
            # rietichetta il livello come PAdES (stesse regole degli attributi CAdES)
            sr.level = sr.level.replace("CAdES", "PAdES")
            if has_doc_ts and sr.level in ("PAdES-LT", "PAdES-T", "PAdES-BES"):
                sr.level = "PAdES-LTA"
            _annotate_coverage(sr, ps, is_last)
            out.append(sr)

    result.signatures = out
    return result


def _annotate_coverage(sr: SignatureResult, ps, is_last: bool) -> None:
    """Aggiunge note sulla copertura del documento (revisioni incrementali)."""
    if ps.covers_whole_document:
        return
    if is_last:
        sr.warnings.append(
            "La firma non copre l'intero documento: sono presenti byte "
            "aggiunti dopo la firma (possibile modifica successiva)."
        )
    else:
        sr.warnings.append(
            "Dopo questa firma il documento contiene una o piu' revisioni "
            "successive (altre firme o marche apposte in seguito)."
        )


def _verify_doc_timestamp(
    ps, tsa_roots, options: VerifyOptions, fetchers=None
) -> SignatureResult:
    """Verifica un document-timestamp PAdES (SubFilter ETSI.RFC3161)."""
    si = SignerInfo()
    sr = SignatureResult(signer=si)
    sr.level = "PAdES document-timestamp"
    if ps.content_info is None:
        sr.errors.append(ps.error or "Document-timestamp non interpretabile.")
        return sr
    r = timestamp.verify_timestamp(
        ps.content_info,
        ps.signed_bytes,
        tsa_roots,
        revocation_mode=options.revocation_mode,
        allow_fetching=options.allow_fetching,
        check_trust=options.check_trust,
        fetchers=fetchers,
    )
    si.common_name = r.tsa_name or "Marca temporale sul documento"
    si.signing_time = r.gen_time
    sr.crypto_valid = r.signature_valid
    sr.digest_match = r.imprint_match
    sr.has_timestamp = True
    sr.timestamp_valid = r.valid
    sr.timestamp_time = r.gen_time
    sr.timestamp_tsa = r.tsa_name
    sr.timestamp_trust = r.trust_status if options.check_trust else TrustStatus.NOT_CHECKED
    sr.trust_status = sr.timestamp_trust
    for m in r.messages:
        sr.warnings.append(m)
    return sr


def _analyze_layer(
    data: bytes,
    trust_roots: list[x509.Certificate],
    tsa_roots: list[x509.Certificate],
    options: VerifyOptions,
    depth: int,
    fetchers=None,
) -> tuple[list[SignatureResult], Optional[bytes], int]:
    """Analizza un singolo livello CMS, ricorrendo se il contenuto e' un p7m."""
    ci = cms.load_content_info(data)
    signed_data = cms.get_signed_data(ci)
    ctype, econtent = cms.extract_content(signed_data)
    certs = cms.collect_certificates(signed_data)

    layer_sigs: list[SignatureResult] = []
    for signer_info in signed_data["signer_infos"]:
        layer_sigs.append(
            _verify_one(
                signed_data, signer_info, econtent, certs, trust_roots,
                tsa_roots, options, fetchers,
            )
        )

    # Contenuto annidato: il documento firmato e' a sua volta una busta p7m
    if econtent and depth < 10 and cms.is_cms(econtent):
        inner_sigs, inner_content, inner_levels = _analyze_layer(
            econtent, trust_roots, tsa_roots, options, depth + 1, fetchers
        )
        # le firme del livello esterno vengono prima (piu' recenti)
        return layer_sigs + inner_sigs, inner_content, max(depth, inner_levels)

    return layer_sigs, econtent, depth


def _verify_one(
    signed_data,
    signer_info,
    econtent: Optional[bytes],
    certs: list[x509.Certificate],
    trust_roots: list[x509.Certificate],
    tsa_roots: list[x509.Certificate],
    options: VerifyOptions,
    fetchers=None,
) -> SignatureResult:
    cert = cms._find_signer_cert(signer_info, certs)
    info = cms.build_signer_info(cert, signer_info)
    res = SignatureResult(signer=info)

    if cert is None:
        res.errors.append(
            "Certificato del firmatario non presente nella busta: verifica "
            "impossibile."
        )
        return res

    crypto_valid, digest_match, errors, warnings = cms.verify_signature(
        signed_data, signer_info, econtent, cert
    )
    res.crypto_valid = crypto_valid
    res.digest_match = digest_match
    res.errors.extend(errors)
    res.warnings.extend(warnings)

    # --- marca temporale CAdES-T -------------------------------------- #
    signed_value = signer_info["signature"].native
    ts = timestamp.verify_signature_timestamps(
        signer_info,
        signed_value,
        tsa_roots,
        revocation_mode=options.revocation_mode,
        allow_fetching=options.allow_fetching,
        check_trust=options.check_trust,
        fetchers=fetchers,
    )
    if ts is not None:
        res.has_timestamp = True
        res.timestamp_valid = ts.valid
        res.timestamp_time = ts.gen_time
        res.timestamp_tsa = ts.tsa_name
        res.timestamp_trust = ts.trust_status
        res.timestamp_info = "; ".join(ts.messages)
        for m in ts.messages:
            res.warnings.append(f"Marca temporale: {m}")

    # --- CAdES-LT / LTA: materiale di validazione e archive-timestamp -- #
    lt = cades_lt.extract_validation_data(signer_info)
    res.level = cades_lt.signature_level(signer_info)
    res.embedded_certs = len(lt.certificates)
    res.embedded_crls = len(lt.crls)
    res.embedded_ocsps = len(lt.ocsps)

    archive_tokens = cades_lt.extract_archive_timestamps(signer_info)
    res.archive_timestamps = len(archive_tokens)
    latest_archive = None
    for tok in archive_tokens:
        ar = timestamp.verify_archive_timestamp(
            tok,
            tsa_roots,
            revocation_mode=options.revocation_mode,
            allow_fetching=options.allow_fetching,
            check_trust=options.check_trust,
            outer_signed_data=signed_data,
            outer_signer_info=signer_info,
            econtent=econtent,
            fetchers=fetchers,
        )
        if ar.signature_valid and (
            ar.trust_status in (TrustStatus.TRUSTED, TrustStatus.NOT_CHECKED)
        ):
            res.archive_valid += 1
        if ar.imprint_recomputed and ar.imprint_match:
            res.archive_imprint_verified += 1
        if ar.gen_time and (latest_archive is None or ar.gen_time > latest_archive):
            latest_archive = ar.gen_time
    res.archive_time = latest_archive

    if not options.check_trust:
        res.trust_status = TrustStatus.NOT_CHECKED
        return res

    # istante di validazione: archive-ts (LTA) > marca (T) > signing-time (BES)
    moment = res.archive_time or res.trusted_time

    # intermedi = certificati della busta + quelli incapsulati (LT), tranne il firmatario
    pool = {c.sha256: c for c in certs}
    for c in lt.certificates:
        pool.setdefault(c.sha256, c)
    intermediates = [c for c in pool.values() if c.sha256 != cert.sha256]

    # materiale di revoca incapsulato (CAdES-LT) per validazione storica offline
    crls = lt.crls or None
    ocsps = lt.ocsps or None
    res.ltv_used = bool(crls or ocsps)

    chain = validate_chain(
        cert,
        intermediates,
        trust_roots,
        moment=moment,
        revocation_mode=options.revocation_mode,
        allow_fetching=options.allow_fetching,
        crls=crls,
        ocsps=ocsps,
        fetchers=fetchers,
    )
    res.trust_status = chain.status
    res.trust_anchor_cn = chain.trust_anchor_cn
    res.revocation_info = chain.revocation_info
    if res.ltv_used:
        res.revocation_info += " (materiale di revoca incapsulato LT)"
    res.warnings.extend(chain.messages)
    return res
