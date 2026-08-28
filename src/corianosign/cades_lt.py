"""Supporto CAdES-LT / CAdES-LTA (validazione a lungo termine).

CAdES-LT incapsula nella firma, come attributi *non firmati*, il materiale di
validazione:
  * ``id-aa-ets-certValues``      (1.2.840.113549.1.9.16.2.23) -> certificati;
  * ``id-aa-ets-revocationValues``(1.2.840.113549.1.9.16.2.24) -> CRL/OCSP.

Così la firma resta verificabile anche dopo la scadenza dei certificati o la
dismissione delle CA/OCSP. CAdES-LTA aggiunge uno o più *archive-timestamp*
(``id-aa-ets-archiveTimestampV2/V3``) che marcano l'intera struttura.

Questo modulo estrae quel materiale e riconosce il livello della firma; la
verifica delle marche riusa ``timestamp.verify_timestamp``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from asn1crypto import cms as acms
from asn1crypto import core, crl, ocsp, x509

# OID degli attributi ETSI (non registrati in asn1crypto)
OID_SIGNATURE_TS = "1.2.840.113549.1.9.16.2.14"
OID_CERT_VALUES = "1.2.840.113549.1.9.16.2.23"
OID_REVOCATION_VALUES = "1.2.840.113549.1.9.16.2.24"
OID_CERT_REFS = "1.2.840.113549.1.9.16.2.21"
OID_REVOCATION_REFS = "1.2.840.113549.1.9.16.2.22"
OID_ARCHIVE_TS_V2 = "1.2.840.113549.1.9.16.2.48"
OID_ARCHIVE_TS_V3 = "0.4.0.1733.2.4"
_ARCHIVE_TS_OIDS = {OID_ARCHIVE_TS_V2, OID_ARCHIVE_TS_V3}


# --- strutture ASN.1 (RFC 5126 / ETSI TS 101 733) -------------------------- #
class CertificateValues(core.SequenceOf):
    _child_spec = x509.Certificate


class _SeqOfCertificateList(core.SequenceOf):
    _child_spec = crl.CertificateList


class _SeqOfBasicOCSP(core.SequenceOf):
    _child_spec = ocsp.BasicOCSPResponse


class RevocationValues(core.Sequence):
    _fields = [
        ("crl_vals", _SeqOfCertificateList, {"explicit": 0, "optional": True}),
        ("ocsp_vals", _SeqOfBasicOCSP, {"explicit": 1, "optional": True}),
        ("other_rev_vals", core.Any, {"explicit": 2, "optional": True}),
    ]


@dataclass
class LTData:
    certificates: list[x509.Certificate] = field(default_factory=list)
    crls: list[crl.CertificateList] = field(default_factory=list)
    ocsps: list[ocsp.OCSPResponse] = field(default_factory=list)

    has_cert_values: bool = False
    has_revocation_values: bool = False
    has_cert_refs: bool = False
    has_revocation_refs: bool = False

    @property
    def has_lt_material(self) -> bool:
        return self.has_cert_values or self.has_revocation_values

    def summary(self) -> str:
        return (
            f"{len(self.certificates)} cert, {len(self.crls)} CRL, "
            f"{len(self.ocsps)} OCSP incapsulati"
        )


def _iter_unsigned(signer_info: acms.SignerInfo):
    unsigned = signer_info["unsigned_attrs"]
    if unsigned is None or isinstance(unsigned, core.Void):
        return
    for attr in unsigned:
        yield attr


def _wrap_basic_ocsp(basic: ocsp.BasicOCSPResponse) -> ocsp.OCSPResponse:
    """Incapsula una BasicOCSPResponse in una OCSPResponse (attesa da pyhanko)."""
    return ocsp.OCSPResponse({
        "response_status": "successful",
        "response_bytes": {
            "response_type": "basic_ocsp_response",
            "response": basic.dump(),
        },
    })


def extract_validation_data(signer_info: acms.SignerInfo) -> LTData:
    """Estrae certificati e materiale di revoca incapsulati (CAdES-LT)."""
    data = LTData()
    for attr in _iter_unsigned(signer_info):
        oid = attr["type"].dotted
        values = list(attr["values"])
        if oid == OID_CERT_VALUES and values:
            data.has_cert_values = True
            try:
                certvals = CertificateValues.load(values[0].dump())
                data.certificates.extend(list(certvals))
            except Exception:  # noqa: BLE001
                pass
        elif oid == OID_REVOCATION_VALUES and values:
            data.has_revocation_values = True
            try:
                revvals = RevocationValues.load(values[0].dump())
                if revvals["crl_vals"] is not None and not isinstance(
                    revvals["crl_vals"], core.Void
                ):
                    data.crls.extend(list(revvals["crl_vals"]))
                if revvals["ocsp_vals"] is not None and not isinstance(
                    revvals["ocsp_vals"], core.Void
                ):
                    for basic in revvals["ocsp_vals"]:
                        data.ocsps.append(_wrap_basic_ocsp(basic))
            except Exception:  # noqa: BLE001
                pass
        elif oid == OID_CERT_REFS:
            data.has_cert_refs = True
        elif oid == OID_REVOCATION_REFS:
            data.has_revocation_refs = True
    return data


def extract_archive_timestamps(
    signer_info: acms.SignerInfo,
) -> list[acms.ContentInfo]:
    """Estrae i token di archive-timestamp (CAdES-LTA), V2 e V3."""
    tokens: list[acms.ContentInfo] = []
    for attr in _iter_unsigned(signer_info):
        if attr["type"].dotted in _ARCHIVE_TS_OIDS:
            for value in attr["values"]:
                try:
                    # il valore è un TimeStampToken (ContentInfo)
                    tokens.append(acms.ContentInfo.load(value.dump()))
                except Exception:  # noqa: BLE001
                    continue
    return tokens


def signature_level(signer_info: acms.SignerInfo) -> str:
    """Riconosce il livello CAdES: BES / T / LT / LTA."""
    oids = {attr["type"].dotted for attr in _iter_unsigned(signer_info)}
    if oids & _ARCHIVE_TS_OIDS:
        return "CAdES-LTA"
    if OID_CERT_VALUES in oids or OID_REVOCATION_VALUES in oids:
        return "CAdES-LT"
    if OID_SIGNATURE_TS in oids:
        return "CAdES-T"
    return "CAdES-BES"
