"""Parsing di buste CMS/PKCS#7 (.p7m) e verifica crittografica delle firme.

Gestisce le firme CAdES-BES tipiche della firma digitale italiana:
  * busta DER grezza oppure codificata in Base64/PEM;
  * firma "attached" (enveloping): il documento originale e' dentro la busta;
  * firme multiple parallele (piu' SignerInfo) e annidate (p7m dentro p7m).

La sola verifica crittografica (firma <-> contenuto) e' qui; la validazione
della catena verso le Trusted List sta in ``validation.py``.
"""
from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
from typing import Optional

from asn1crypto import cms, core, x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import load_der_x509_certificate

from .model import SignerInfo

# OID -> classe hash di ``cryptography``
_HASH_BY_NAME = {
    "md5": hashes.MD5,
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
    "sha3_256": hashes.SHA3_256,
    "sha3_384": hashes.SHA3_384,
    "sha3_512": hashes.SHA3_512,
}

CONTENT_TYPE_DATA = "data"
CONTENT_TYPE_SIGNED = "signed_data"


class CmsError(Exception):
    """Errore di parsing/struttura della busta CMS."""


# --------------------------------------------------------------------------- #
# Caricamento e riconoscimento
# --------------------------------------------------------------------------- #
def _strip_pem(data: bytes) -> bytes:
    """Rimuove eventuale armatura PEM restituendo il DER decodificato."""
    text = data.strip()
    if text.startswith(b"-----BEGIN"):
        lines = [ln for ln in text.splitlines() if not ln.startswith(b"-----")]
        return base64.b64decode(b"".join(lines))
    return data


def _maybe_base64(data: bytes) -> bytes:
    """Alcuni .p7m sono Base64 puri (senza armatura). Prova a decodificarli."""
    sample = data.strip()
    # euristica: solo caratteri dell'alfabeto base64
    if not sample:
        return data
    allowed = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n \t")
    if set(sample) <= allowed:
        try:
            decoded = base64.b64decode(sample, validate=False)
            # una busta CMS inizia con SEQUENCE (0x30)
            if decoded[:1] == b"\x30":
                return decoded
        except (binascii.Error, ValueError):
            pass
    return data


def load_content_info(data: bytes) -> cms.ContentInfo:
    """Carica i byte grezzi in un ``ContentInfo`` gestendo PEM/Base64/DER."""
    raw = _strip_pem(data)
    raw = _maybe_base64(raw)
    try:
        ci = cms.ContentInfo.load(raw)
        # forza il parse per far emergere subito eventuali errori
        _ = ci["content_type"].native
        return ci
    except Exception as exc:  # noqa: BLE001 - vogliamo un messaggio unico
        raise CmsError(f"Il file non e' una busta CMS/PKCS#7 valida: {exc}") from exc


def is_cms(data: bytes) -> bool:
    try:
        ci = load_content_info(data)
        return ci["content_type"].native == CONTENT_TYPE_SIGNED
    except CmsError:
        return False


def get_signed_data(ci: cms.ContentInfo) -> cms.SignedData:
    if ci["content_type"].native != CONTENT_TYPE_SIGNED:
        raise CmsError(
            f"Tipo di contenuto non gestito: {ci['content_type'].native!r} "
            "(atteso 'signed_data')."
        )
    return ci["content"]


# --------------------------------------------------------------------------- #
# Estrazione contenuto
# --------------------------------------------------------------------------- #
def extract_content(signed_data: cms.SignedData) -> tuple[str, Optional[bytes]]:
    """Restituisce (content_type_oid_native, byte_contenuto | None).

    ``None`` indica firma "detached" (il documento non e' nella busta).
    """
    eci = signed_data["encap_content_info"]
    ctype = eci["content_type"].native
    raw = eci["content"]
    if raw is None or isinstance(raw, core.Void):
        return ctype, None
    try:
        content = raw.native
    except Exception:  # noqa: BLE001
        content = None
    # Per contenuti "parsable" (es. tst_info) .native restituisce l'oggetto
    # parsato, non i byte: in quel caso servono i byte grezzi dell'OCTET STRING
    # (il payload), che sono ciò che la firma copre.
    if not isinstance(content, (bytes, bytearray)):
        content = raw.contents
    return ctype, bytes(content)


# --------------------------------------------------------------------------- #
# Certificati e firmatari
# --------------------------------------------------------------------------- #
def collect_certificates(signed_data: cms.SignedData) -> list[x509.Certificate]:
    certs: list[x509.Certificate] = []
    if signed_data["certificates"] is None or isinstance(
        signed_data["certificates"], core.Void
    ):
        return certs
    for choice in signed_data["certificates"]:
        if choice.name == "certificate":
            certs.append(choice.chosen)
    return certs


def _find_signer_cert(
    signer_info: cms.SignerInfo, certs: list[x509.Certificate]
) -> Optional[x509.Certificate]:
    sid = signer_info["sid"]
    if sid.name == "issuer_and_serial_number":
        issuer = sid.chosen["issuer"]
        serial = sid.chosen["serial_number"].native
        for c in certs:
            if c.serial_number == serial and c.issuer == issuer:
                return c
    elif sid.name == "subject_key_identifier":
        ski = sid.chosen.native
        for c in certs:
            if c.key_identifier == ski:
                return c
    return None


def _dt_utc(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    return None


def build_signer_info(
    cert: x509.Certificate, signer_info: cms.SignerInfo
) -> SignerInfo:
    """Popola i dati anagrafici a partire dal certificato del firmatario."""
    subj = cert.subject.native if cert else {}

    def _first(val) -> str:
        if isinstance(val, (list, tuple)):
            return str(val[0]) if val else ""
        return str(val) if val is not None else ""

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
        info.not_before = _dt_utc(cert["tbs_certificate"]["validity"]["not_before"].native)
        info.not_after = _dt_utc(cert["tbs_certificate"]["validity"]["not_after"].native)

    info.digest_algorithm = signer_info["digest_algorithm"]["algorithm"].native
    info.signature_algorithm = signer_info["signature_algorithm"]["algorithm"].native
    info.signing_time = _extract_signing_time(signer_info)
    return info


def _extract_signing_time(signer_info: cms.SignerInfo) -> Optional[datetime]:
    attrs = signer_info["signed_attrs"]
    if attrs is None or isinstance(attrs, core.Void):
        return None
    for attr in attrs:
        if attr["type"].native == "signing_time":
            return _dt_utc(attr["values"][0].native)
    return None


def _signed_attr_value(signer_info: cms.SignerInfo, name: str):
    attrs = signer_info["signed_attrs"]
    if attrs is None or isinstance(attrs, core.Void):
        return None
    for attr in attrs:
        if attr["type"].native == name:
            return attr["values"][0]
    return None


# --------------------------------------------------------------------------- #
# Verifica crittografica
# --------------------------------------------------------------------------- #
def _hash_cls(name: str):
    cls = _HASH_BY_NAME.get(name)
    if cls is None:
        raise CmsError(f"Algoritmo di digest non supportato: {name}")
    return cls


def verify_signature(
    signed_data: cms.SignedData,
    signer_info: cms.SignerInfo,
    econtent: Optional[bytes],
    cert: x509.Certificate,
) -> tuple[bool, bool, list[str], list[str]]:
    """Verifica una singola firma.

    Ritorna: (crypto_valid, digest_match, errori, warning).
    ``crypto_valid``  = la firma sui signed-attrs (o sul contenuto) e' valida.
    ``digest_match``  = l'hash del contenuto coincide con il message-digest firmato.
    """
    errors: list[str] = []
    warnings: list[str] = []

    digest_name = signer_info["digest_algorithm"]["algorithm"].native
    try:
        hash_cls = _hash_cls(digest_name)
    except CmsError as exc:
        return False, False, [str(exc)], warnings

    if digest_name in ("md5", "sha1"):
        warnings.append(
            f"Algoritmo di digest debole ({digest_name}): firma tecnicamente "
            "verificabile ma non conforme agli standard attuali."
        )

    digest_match = False
    signed_attrs = signer_info["signed_attrs"]
    has_signed_attrs = signed_attrs is not None and not isinstance(signed_attrs, core.Void)

    if econtent is not None:
        digest = hashes.Hash(hash_cls())
        digest.update(econtent)
        content_hash = digest.finalize()

        if has_signed_attrs:
            md_attr = _signed_attr_value(signer_info, "message_digest")
            if md_attr is None:
                errors.append("Attributo 'message-digest' assente nella firma.")
            else:
                digest_match = md_attr.native == content_hash
                if not digest_match:
                    errors.append(
                        "L'hash del contenuto NON corrisponde al message-digest "
                        "firmato: il documento potrebbe essere stato alterato."
                    )
        else:
            # firma diretta sul contenuto: il match si valuta con la firma stessa
            digest_match = True
    else:
        warnings.append("Firma 'detached': il contenuto non e' incluso nella busta.")

    # Dati effettivamente firmati
    if has_signed_attrs:
        signed_bytes = signed_attrs.untag().dump()
    else:
        signed_bytes = econtent or b""

    crypto_valid = _verify_raw(cert, signer_info, signed_bytes, hash_cls, errors)

    if not has_signed_attrs and crypto_valid:
        # senza signed-attrs, la validita' crittografica implica il match
        digest_match = True

    return crypto_valid, digest_match, errors, warnings


def _verify_raw(
    cert: x509.Certificate,
    signer_info: cms.SignerInfo,
    signed_bytes: bytes,
    hash_cls,
    errors: list[str],
) -> bool:
    try:
        crypto_cert = load_der_x509_certificate(cert.dump())
    except Exception as exc:  # noqa: BLE001
        errors.append(f"Certificato del firmatario illeggibile: {exc}")
        return False

    pub = crypto_cert.public_key()
    signature = signer_info["signature"].native
    sig_algo = signer_info["signature_algorithm"].signature_algo

    try:
        if isinstance(pub, rsa.RSAPublicKey):
            if sig_algo == "rsassa_pss":
                params = signer_info["signature_algorithm"]
                pss = _build_pss(params, hash_cls)
                pub.verify(signature, signed_bytes, pss, hash_cls())
            else:
                pub.verify(signature, signed_bytes, padding.PKCS1v15(), hash_cls())
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, signed_bytes, ec.ECDSA(hash_cls()))
        else:
            errors.append(
                f"Tipo di chiave pubblica non supportato: {type(pub).__name__}"
            )
            return False
        return True
    except InvalidSignature:
        errors.append("Firma crittografica NON valida.")
        return False
    except Exception as exc:  # noqa: BLE001
        errors.append(f"Errore durante la verifica della firma: {exc}")
        return False


def _build_pss(sig_alg_params, hash_cls) -> padding.PSS:
    """Costruisce i parametri RSASSA-PSS dalla busta (con fallback ragionevoli)."""
    try:
        salt_len = sig_alg_params["parameters"]["salt_length"].native
    except Exception:  # noqa: BLE001
        salt_len = padding.PSS.AUTO  # type: ignore[attr-defined]
    return padding.PSS(mgf=padding.MGF1(hash_cls()), salt_length=salt_len)
