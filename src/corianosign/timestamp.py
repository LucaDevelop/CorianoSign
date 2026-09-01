"""Verifica delle marche temporali CAdES-T (RFC 3161).

Una firma CAdES-T porta un attributo *non firmato*
``id-aa-signatureTimeStampToken`` (OID 1.2.840.113549.1.9.16.2.14): è un
TimeStampToken RFC 3161 (a sua volta una busta CMS SignedData) emesso da una
TSA che attesta l'esistenza della *firma* a una certa data.

La verifica accerta che:
  * l'impronta nella marca corrisponda al valore della firma (``signature``);
  * la marca sia firmata dalla TSA (firma CMS valida);
  * il certificato della TSA sia accreditato nella Trusted List (servizio TSA).

Il tempo attestato viene poi usato come istante di validazione del certificato
del firmatario: è il valore aggiunto di CAdES-T rispetto a CAdES-BES.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from asn1crypto import cms as acms
from asn1crypto import core, tsp, x509

from . import cms
from .model import TrustStatus
from .validation import RevocationMode, validate_chain

SIGNATURE_TS_ATTR = "signature_time_stamp_token"


@dataclass
class TimestampResult:
    present: bool = False
    imprint_match: bool = False
    signature_valid: bool = False       # firma CMS della TSA valida
    gen_time: Optional[datetime] = None
    tsa_name: str = ""
    trust_status: TrustStatus = TrustStatus.NOT_CHECKED
    messages: list[str] = field(default_factory=list)
    # solo per archive-timestamp (LTA): impronta d'archivio ricalcolata?
    imprint_recomputed: bool = False
    index_valid: bool = False

    @property
    def valid(self) -> bool:
        """Marca crittograficamente valida e coerente con la firma."""
        return self.present and self.imprint_match and self.signature_valid


def extract_timestamp_tokens(signer_info: acms.SignerInfo) -> list[acms.ContentInfo]:
    """Estrae i TimeStampToken dagli attributi non firmati della firma."""
    tokens: list[acms.ContentInfo] = []
    unsigned = signer_info["unsigned_attrs"]
    if unsigned is None or isinstance(unsigned, core.Void):
        return tokens
    for attr in unsigned:
        if attr["type"].native == SIGNATURE_TS_ATTR:
            for value in attr["values"]:
                tokens.append(value)
    return tokens


def _tsa_name(cert: Optional[x509.Certificate]) -> str:
    if cert is None:
        return ""
    subj = cert.subject.native
    return subj.get("common_name") or subj.get("organization_name") or ""


def _verify_token_core(
    token: acms.ContentInfo,
    tsa_trust_roots: list[x509.Certificate],
    revocation_mode: RevocationMode,
    allow_fetching: bool,
    check_trust: bool,
    fetchers=None,
) -> tuple[TimestampResult, Optional[str], Optional[bytes]]:
    """Verifica firma TSA + trust del token; ritorna (res, hash_algo, imprint).

    Non confronta l'impronta con alcun dato (compito del chiamante).
    """
    res = TimestampResult(present=True)
    try:
        der = token.dump()
        ci = cms.load_content_info(der)
        signed_data = cms.get_signed_data(ci)
        ctype, econtent = cms.extract_content(signed_data)
        if econtent is None:
            res.messages.append("Marca temporale priva di contenuto (TSTInfo).")
            return res, None, None
        tst_info = tsp.TSTInfo.load(econtent)
    except Exception as exc:  # noqa: BLE001
        res.messages.append(f"TimeStampToken illeggibile: {exc}")
        return res, None, None

    try:
        res.gen_time = tst_info["gen_time"].native
    except Exception:  # noqa: BLE001
        res.gen_time = None

    mi = tst_info["message_imprint"]
    halgo = mi["hash_algorithm"]["algorithm"].native
    imprint = mi["hashed_message"].native

    # firma CMS della TSA
    certs = cms.collect_certificates(signed_data)
    tsa_si = signed_data["signer_infos"][0]
    tsa_cert = cms._find_signer_cert(tsa_si, certs)
    res.tsa_name = _tsa_name(tsa_cert)
    if tsa_cert is None:
        res.messages.append("Certificato della TSA assente nella marca.")
        return res, halgo, imprint
    crypto_valid, digest_match, errors, _ = cms.verify_signature(
        signed_data, tsa_si, econtent, tsa_cert
    )
    res.signature_valid = crypto_valid and digest_match
    res.messages.extend(errors)

    # TSA accreditata nella Trusted List
    if not check_trust:
        res.trust_status = TrustStatus.NOT_CHECKED
    elif not tsa_trust_roots:
        res.trust_status = TrustStatus.ERROR
        res.messages.append("Nessuna TSA fidata caricata: impossibile validare la TSA.")
    else:
        intermediates = [c for c in certs if c.sha256 != tsa_cert.sha256]
        chain = validate_chain(
            tsa_cert,
            intermediates,
            tsa_trust_roots,
            moment=res.gen_time,
            revocation_mode=revocation_mode,
            allow_fetching=allow_fetching,
            fetchers=fetchers,
        )
        res.trust_status = chain.status
        if chain.trust_anchor_cn:
            res.messages.append(f"TSA accreditata: {chain.trust_anchor_cn}.")

    return res, halgo, imprint


def verify_timestamp(
    token: acms.ContentInfo,
    signed_value: bytes,
    tsa_trust_roots: Optional[list[x509.Certificate]] = None,
    *,
    revocation_mode: RevocationMode = RevocationMode.SOFT_FAIL,
    allow_fetching: bool = True,
    check_trust: bool = True,
    fetchers=None,
) -> TimestampResult:
    """Verifica una singola marca temporale sul ``signed_value`` della firma."""
    res, halgo, imprint = _verify_token_core(
        token, tsa_trust_roots or [], revocation_mode, allow_fetching, check_trust,
        fetchers=fetchers,
    )
    if halgo is None or imprint is None:
        return res
    # impronta della marca == hash del valore della firma
    try:
        digest = hashlib.new(halgo, signed_value).digest()
        res.imprint_match = digest == imprint
    except Exception as exc:  # noqa: BLE001
        res.messages.append(f"Algoritmo di impronta non supportato ({halgo}): {exc}")
        res.imprint_match = False
    if not res.imprint_match:
        res.messages.append(
            "L'impronta della marca non corrisponde alla firma: marca non "
            "riferita a questa firma."
        )
    return res


def verify_archive_timestamp(
    token: acms.ContentInfo,
    tsa_trust_roots: Optional[list[x509.Certificate]] = None,
    *,
    revocation_mode: RevocationMode = RevocationMode.SOFT_FAIL,
    allow_fetching: bool = True,
    check_trust: bool = True,
    outer_signed_data=None,
    outer_signer_info=None,
    econtent: Optional[bytes] = None,
    fetchers=None,
) -> TimestampResult:
    """Verifica un archive-timestamp CAdES-LTA.

    Verifica la firma della TSA e la sua accreditazione. Se il contesto esterno
    è fornito e la marca è di tipo v3 (con ats-hash-index-v3), **ricalcola
    l'impronta d'archivio** e verifica che copra questa firma, i suoi
    certificati e il materiale di revoca.
    """
    res, _halgo, _imprint = _verify_token_core(
        token, tsa_trust_roots or [], revocation_mode, allow_fetching, check_trust,
        fetchers=fetchers,
    )

    if outer_signed_data is not None and outer_signer_info is not None and econtent is not None:
        from . import archive_ts

        imp = archive_ts.verify_archive_imprint(
            token, outer_signed_data, outer_signer_info, econtent
        )
        res.imprint_recomputed = imp.recomputed
        res.index_valid = imp.index_valid
        res.messages.extend(imp.messages)
        if imp.recomputed:
            res.imprint_match = imp.imprint_match
        else:
            res.imprint_match = res.signature_valid
    else:
        res.imprint_match = res.signature_valid
    return res


def verify_signature_timestamps(
    signer_info: acms.SignerInfo,
    signed_value: bytes,
    tsa_trust_roots: Optional[list[x509.Certificate]] = None,
    *,
    revocation_mode: RevocationMode = RevocationMode.SOFT_FAIL,
    allow_fetching: bool = True,
    check_trust: bool = True,
    fetchers=None,
) -> Optional[TimestampResult]:
    """Verifica tutte le marche di una firma; ritorna la migliore (o None)."""
    tokens = extract_timestamp_tokens(signer_info)
    if not tokens:
        return None
    best: Optional[TimestampResult] = None
    for token in tokens:
        r = verify_timestamp(
            token,
            signed_value,
            tsa_trust_roots,
            revocation_mode=revocation_mode,
            allow_fetching=allow_fetching,
            check_trust=check_trust,
            fetchers=fetchers,
        )
        if r.valid and r.trust_status is TrustStatus.TRUSTED:
            return r  # marca pienamente valida e fidata: la migliore possibile
        if best is None or (r.valid and not best.valid):
            best = r
    return best
