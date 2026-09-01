"""Validazione della catena di certificazione verso le Trusted List + revoca.

Usa ``pyhanko-certvalidator`` per costruire e validare il percorso PKIX dal
certificato del firmatario fino a una CA presente nella Trusted List
(EU LOTL / AgID), con controllo di revoca CRL/OCSP.
"""
from __future__ import annotations

import asyncio
import enum
from datetime import datetime
from typing import Optional

from asn1crypto import x509
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import (
    ExpiredError,
    InsufficientRevinfoError,
    NotYetValidError,
    PathBuildingError,
    PathValidationError,
    RevokedError,
    ValidationError,
)

from .model import TrustStatus


class RevocationMode(enum.Enum):
    """Rigore del controllo di revoca."""

    SOFT_FAIL = "soft-fail"   # se CRL/OCSP non raggiungibile -> non blocca
    HARD_FAIL = "hard-fail"   # revoca obbligatoria: se non verificabile -> errore


class ChainResult:
    def __init__(self) -> None:
        self.status: TrustStatus = TrustStatus.ERROR
        self.trust_anchor_cn: str = ""
        self.revocation_info: str = ""
        self.messages: list[str] = []


def _anchor_cn(path) -> str:
    try:
        anchor = path.trust_anchor
        cert = getattr(anchor, "certificate", None) or getattr(anchor, "cert", None)
        if cert is None and hasattr(path, "first"):
            cert = path.first
        subj = cert.subject.native
        return subj.get("common_name") or subj.get("organization_name") or ""
    except Exception:  # noqa: BLE001
        return ""


def validate_chain(
    signer_cert: x509.Certificate,
    other_certs: list[x509.Certificate],
    trust_roots: list[x509.Certificate],
    *,
    moment: Optional[datetime] = None,
    revocation_mode: RevocationMode = RevocationMode.SOFT_FAIL,
    allow_fetching: bool = True,
    crls=None,
    ocsps=None,
    fetchers=None,
) -> ChainResult:
    """Valida la catena del ``signer_cert`` verso ``trust_roots``.

    ``moment``      istante di validazione (signing-time o tempo della marca).
    ``other_certs`` certificati intermedi (dalla busta o incapsulati LT).
    ``crls``/``ocsps`` materiale di revoca incapsulato (CAdES-LT), usato per la
                    validazione storica senza dover contattare la rete.
    ``fetchers``    oggetto ``Fetchers`` condiviso (rete): passandone lo stesso a
                    tutte le catene di una verifica, le CRL/OCSP di una CA vengono
                    scaricate una volta sola (memoizzazione + cache su disco).
    """
    result = ChainResult()

    if not trust_roots:
        result.status = TrustStatus.ERROR
        result.messages.append(
            "Nessuna CA fidata caricata: aggiorna le Trusted List per validare "
            "la catena."
        )
        return result

    try:
        vc = ValidationContext(
            trust_roots=trust_roots,
            other_certs=other_certs or [],
            moment=moment,
            allow_fetching=allow_fetching,
            crls=crls,
            ocsps=ocsps,
            # riusa i fetcher condivisi solo se il fetch è abilitato
            fetchers=fetchers if allow_fetching else None,
            revocation_mode=revocation_mode.value,
            weak_hash_algos={"md5", "md2"},
        )
        validator = CertificateValidator(
            signer_cert, intermediate_certs=other_certs or [], validation_context=vc
        )
        path = _run(validator.async_validate_path())
        result.status = TrustStatus.TRUSTED
        result.trust_anchor_cn = _anchor_cn(path)
        result.revocation_info = (
            "Revoca verificata (CRL/OCSP)."
            if allow_fetching
            else "Controllo revoca non eseguito (fetch disattivato)."
        )
        result.messages.append(
            f"Catena valida fino alla CA fidata: {result.trust_anchor_cn or 'radice'}."
        )
    except RevokedError as exc:
        result.status = TrustStatus.REVOKED
        result.revocation_info = str(exc)
        result.messages.append(f"Certificato REVOCATO: {exc}")
    except InsufficientRevinfoError as exc:
        if revocation_mode is RevocationMode.HARD_FAIL:
            result.status = TrustStatus.ERROR
        else:
            result.status = TrustStatus.TRUSTED
        result.revocation_info = f"Info di revoca non disponibili: {exc}"
        result.messages.append(result.revocation_info)
    except (ExpiredError, NotYetValidError) as exc:
        result.status = TrustStatus.UNTRUSTED
        result.messages.append(f"Certificato fuori validita' temporale: {exc}")
    except PathBuildingError as exc:
        result.status = TrustStatus.UNTRUSTED
        result.messages.append(
            "Impossibile ricondurre il certificato a una CA fidata (catena "
            f"incompleta o CA non accreditata): {exc}"
        )
    except PathValidationError as exc:
        result.status = TrustStatus.UNTRUSTED
        result.messages.append(f"Validazione della catena fallita: {exc}")
    except ValidationError as exc:
        result.status = TrustStatus.ERROR
        result.messages.append(f"Errore di validazione: {exc}")
    except ValueError as exc:
        # es.: hard-fail offline senza materiale di revoca disponibile
        result.status = TrustStatus.ERROR
        result.revocation_info = "Revoca non verificabile offline."
        result.messages.append(
            f"Impossibile validare la revoca (nessun materiale disponibile): {exc}"
        )
    except Exception as exc:  # noqa: BLE001
        result.status = TrustStatus.ERROR
        result.messages.append(f"Errore imprevisto nella validazione: {exc}")

    return result


def _run(coro):
    """Esegue una coroutine anche se esiste gia' un event loop (GUI)."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # loop gia' attivo: esegui in un loop dedicato su thread separato
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(coro)).result()
