"""Ricalcolo dell'impronta degli archive-timestamp CAdES-LTA (ETSI EN 319 122).

Implementa l'algoritmo **archive-time-stamp-v3** con **ats-hash-index-v3**:
la marca d'archivio copre l'intera firma, e la sua impronta è

    messageImprint = H( DER(eContentType) || H(eContent) || DER(ATSHashIndexV3) )

dove ``ATSHashIndexV3`` elenca gli hash di:
  * ogni certificato in ``SignedData.certificates``;
  * ogni CRL/OCSP in ``SignedData.crls``;
  * ogni valore di attributo non firmato del ``SignerInfo`` (esclusi gli
    archive-timestamp stessi).

La verifica: (1) ricalcola l'indice dalla struttura esterna e lo confronta con
quello incapsulato nel token; (2) ricalcola l'impronta e la confronta con il
``messageImprint`` della marca. Così si prova che la marca copre davvero questa
firma, i suoi certificati e il suo materiale di revoca.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional

from asn1crypto import algos
from asn1crypto import cms as acms
from asn1crypto import core, tsp

# OID EN 319 122
OID_ARCHIVE_TS_V3 = "0.4.0.1733.2.4"
OID_ATS_HASH_INDEX_V3 = "0.4.0.1733.2.5"
OID_ARCHIVE_TS_V2 = "1.2.840.113549.1.9.16.2.48"
_ARCHIVE_TS_OIDS = {OID_ARCHIVE_TS_V3, OID_ARCHIVE_TS_V2}


class _SeqOfOctetString(core.SequenceOf):
    _child_spec = core.OctetString


class _SetOfAny(core.SetOf):
    _child_spec = core.Any


class _GenericAttribute(core.Sequence):
    """Attribute generico (indipendente dal registro OID di asn1crypto)."""

    _fields = [
        ("type", core.ObjectIdentifier),
        ("values", _SetOfAny),
    ]


class ATSHashIndexV3(core.Sequence):
    _fields = [
        ("hash_ind_algorithm", algos.DigestAlgorithm),
        ("certificates_hash_index", _SeqOfOctetString),
        ("crls_hash_index", _SeqOfOctetString),
        ("unsigned_attr_values_hash_index", _SeqOfOctetString),
    ]


@dataclass
class ArchiveImprintResult:
    recomputed: bool = False        # impronta ricalcolata (era v3 con indice)
    imprint_match: bool = False     # impronta ricalcolata == messageImprint marca
    index_valid: bool = False       # ats-hash-index coerente con la struttura
    messages: list[str] = field(default_factory=list)


def _h(algo: str, data: bytes) -> bytes:
    return hashlib.new(algo, data).digest()


# --------------------------------------------------------------------------- #
# Calcolo delle liste di hash (usato sia in verifica sia nel generatore)
# --------------------------------------------------------------------------- #
def _iter_choices(field_value):
    if field_value is None or isinstance(field_value, core.Void):
        return
    for choice in field_value:
        yield choice


def single_attr_value_der(attr_type, value) -> bytes:
    """DER di un attributo con un singolo valore (type + SET{value})."""
    attr = _GenericAttribute()
    attr["type"] = core.ObjectIdentifier(attr_type.dotted)
    attr["values"] = _SetOfAny([core.Any.load(value.dump())])
    return attr.dump()


def compute_hash_lists(
    signed_data: acms.SignedData,
    signer_info: acms.SignerInfo,
    digest_algo: str,
    *,
    exclude_archive_ts: bool = True,
) -> tuple[list[bytes], list[bytes], list[bytes]]:
    """Ritorna (cert_hashes, crl_hashes, attr_value_hashes) dalla struttura."""
    cert_hashes = [
        _h(digest_algo, c.dump()) for c in _iter_choices(signed_data["certificates"])
    ]
    crl_hashes = [
        _h(digest_algo, c.dump()) for c in _iter_choices(signed_data["crls"])
    ]
    attr_hashes: list[bytes] = []
    unsigned = signer_info["unsigned_attrs"]
    if unsigned is not None and not isinstance(unsigned, core.Void):
        for attr in unsigned:
            if exclude_archive_ts and attr["type"].dotted in _ARCHIVE_TS_OIDS:
                continue
            for value in attr["values"]:
                attr_hashes.append(
                    _h(digest_algo, single_attr_value_der(attr["type"], value))
                )
    return cert_hashes, crl_hashes, attr_hashes


def build_ats_hash_index_v3(
    signed_data: acms.SignedData,
    signer_info: acms.SignerInfo,
    digest_algo: str = "sha256",
) -> ATSHashIndexV3:
    cert_hashes, crl_hashes, attr_hashes = compute_hash_lists(
        signed_data, signer_info, digest_algo
    )
    return ATSHashIndexV3({
        "hash_ind_algorithm": algos.DigestAlgorithm({"algorithm": digest_algo}),
        "certificates_hash_index": [core.OctetString(h) for h in cert_hashes],
        "crls_hash_index": [core.OctetString(h) for h in crl_hashes],
        "unsigned_attr_values_hash_index": [core.OctetString(h) for h in attr_hashes],
    })


def archive_timestamp_data_v3(
    signed_data: acms.SignedData,
    ats_hash_index_der: bytes,
    digest_algo: str,
    econtent: bytes,
) -> bytes:
    """Concatenazione su cui è calcolata l'impronta della marca d'archivio v3."""
    econtent_type_der = signed_data["encap_content_info"]["content_type"].dump()
    return econtent_type_der + _h(digest_algo, econtent) + ats_hash_index_der


# --------------------------------------------------------------------------- #
# Estrazione dal token e verifica
# --------------------------------------------------------------------------- #
def _extract_ats_hash_index(token: acms.ContentInfo) -> Optional[ATSHashIndexV3]:
    """Estrae l'ats-hash-index-v3 dagli attributi non firmati del token."""
    try:
        sd = token["content"]
        si = sd["signer_infos"][0]
    except Exception:  # noqa: BLE001
        return None
    unsigned = si["unsigned_attrs"]
    if unsigned is None or isinstance(unsigned, core.Void):
        return None
    for attr in unsigned:
        if attr["type"].dotted == OID_ATS_HASH_INDEX_V3:
            try:
                return ATSHashIndexV3.load(attr["values"][0].dump())
            except Exception:  # noqa: BLE001
                return None
    return None


def _token_message_imprint(token: acms.ContentInfo) -> tuple[Optional[str], Optional[bytes]]:
    """(hash_algo, hashed_message) dal TSTInfo del token."""
    try:
        sd = token["content"]
        eci = sd["encap_content_info"]
        raw = eci["content"]
        econtent = raw.native if isinstance(raw.native, (bytes, bytearray)) else raw.contents
        tst = tsp.TSTInfo.load(bytes(econtent))
        mi = tst["message_imprint"]
        return mi["hash_algorithm"]["algorithm"].native, mi["hashed_message"].native
    except Exception:  # noqa: BLE001
        return None, None


def _multiset_equal(a: list[bytes], b: list[bytes]) -> bool:
    return sorted(a) == sorted(b)


def verify_archive_imprint(
    token: acms.ContentInfo,
    outer_signed_data: acms.SignedData,
    outer_signer_info: acms.SignerInfo,
    econtent: bytes,
) -> ArchiveImprintResult:
    """Ricalcola e verifica l'impronta di un archive-timestamp-v3."""
    res = ArchiveImprintResult()

    index = _extract_ats_hash_index(token)
    if index is None:
        res.messages.append(
            "Archive-timestamp senza ats-hash-index-v3 (v2 o legacy): impronta "
            "d'archivio non ricalcolata."
        )
        return res

    ts_algo, ts_imprint = _token_message_imprint(token)
    if not ts_algo or ts_imprint is None:
        res.messages.append("Impossibile leggere il messageImprint della marca.")
        return res

    digest_algo = index["hash_ind_algorithm"]["algorithm"].native

    # 1) l'indice deve corrispondere alla struttura esterna
    exp_certs, exp_crls, exp_attrs = compute_hash_lists(
        outer_signed_data, outer_signer_info, digest_algo
    )
    idx_certs = [bytes(o) for o in index["certificates_hash_index"]]
    idx_crls = [bytes(o) for o in index["crls_hash_index"]]
    idx_attrs = [bytes(o) for o in index["unsigned_attr_values_hash_index"]]
    res.index_valid = (
        _multiset_equal(idx_certs, exp_certs)
        and _multiset_equal(idx_crls, exp_crls)
        and _multiset_equal(idx_attrs, exp_attrs)
    )
    if not res.index_valid:
        res.messages.append(
            "L'ats-hash-index non corrisponde a certificati/CRL/attributi della "
            "firma: la marca d'archivio non copre coerentemente questa struttura."
        )

    # 2) ricalcolo dell'impronta d'archivio
    ats_data = archive_timestamp_data_v3(
        outer_signed_data, index.dump(), ts_algo, econtent
    )
    recomputed = _h(ts_algo, ats_data)
    res.recomputed = True
    res.imprint_match = (recomputed == ts_imprint) and res.index_valid
    if recomputed != ts_imprint:
        res.messages.append(
            "L'impronta d'archivio ricalcolata non corrisponde al messageImprint "
            "della marca."
        )
    elif res.index_valid:
        res.messages.append("Impronta d'archivio ricalcolata e verificata.")
    return res
