"""Strutture dati per i risultati di verifica."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class TrustStatus(enum.Enum):
    """Esito della validazione della catena verso le Trusted List."""

    TRUSTED = "trusted"          # catena valida fino a una CA accreditata + revoca ok
    UNTRUSTED = "untrusted"      # catena non riconducibile a una CA fidata
    REVOKED = "revoked"          # certificato revocato
    ERROR = "error"              # impossibile completare la validazione
    NOT_CHECKED = "not_checked"  # validazione trust disattivata


@dataclass
class SignerInfo:
    """Dati anagrafici e certificato di un firmatario."""

    common_name: str = ""
    organization: str = ""
    country: str = ""
    # codice fiscale / identificativo estratto dal serialNumber del subject
    fiscal_code: str = ""
    email: str = ""

    issuer_cn: str = ""
    serial_number: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None

    signing_time: Optional[datetime] = None
    digest_algorithm: str = ""
    signature_algorithm: str = ""

    @property
    def display_name(self) -> str:
        return self.common_name or self.organization or self.fiscal_code or "(sconosciuto)"


@dataclass
class SignatureResult:
    """Esito della verifica di una singola firma."""

    signer: SignerInfo

    # verifica crittografica: la firma corrisponde al contenuto?
    crypto_valid: bool = False
    digest_match: bool = False

    # validazione della catena / trust
    trust_status: TrustStatus = TrustStatus.NOT_CHECKED
    trust_anchor_cn: str = ""      # CA radice fidata a cui risale la catena
    revocation_info: str = ""      # descrizione esito revoca

    # marca temporale CAdES-T (RFC 3161)
    has_timestamp: bool = False
    timestamp_valid: bool = False           # marca crittograficamente valida + imprint ok
    timestamp_time: Optional[datetime] = None  # tempo attestato dalla TSA
    timestamp_tsa: str = ""                 # nome della TSA
    timestamp_trust: TrustStatus = TrustStatus.NOT_CHECKED  # TSA accreditata?
    timestamp_info: str = ""

    # livello CAdES e validazione a lungo termine (LT / LTA)
    level: str = "CAdES-BES"                # BES / T / LT / LTA
    embedded_certs: int = 0                 # certificati incapsulati (LT)
    embedded_crls: int = 0
    embedded_ocsps: int = 0
    ltv_used: bool = False                  # revoca validata con materiale incapsulato
    archive_timestamps: int = 0             # numero di archive-timestamp (LTA)
    archive_valid: int = 0                  # archive-ts con firma TSA valida e fidata
    archive_imprint_verified: int = 0       # archive-ts con impronta d'archivio ricalcolata e valida
    archive_time: Optional[datetime] = None  # tempo del piu' recente archive-ts

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def trusted_time(self) -> Optional[datetime]:
        """Tempo fidato: quello della marca se valida, altrimenti il signing-time."""
        if self.timestamp_valid and self.timestamp_time is not None:
            return self.timestamp_time
        return self.signer.signing_time

    @property
    def is_valid(self) -> bool:
        """Firma pienamente valida (cripto + trust + non revocata)."""
        return (
            self.crypto_valid
            and self.digest_match
            and self.trust_status is TrustStatus.TRUSTED
        )


@dataclass
class P7MResult:
    """Esito complessivo dell'analisi di un file .p7m."""

    source_path: str = ""
    signatures: list[SignatureResult] = field(default_factory=list)

    # contenuto estratto (documento originale) e nome file suggerito
    content: bytes = b""
    content_filename: str = ""

    # profondita' di annidamento (firme multiple / p7m dentro p7m)
    nested_levels: int = 1

    parse_errors: list[str] = field(default_factory=list)

    @property
    def all_valid(self) -> bool:
        return bool(self.signatures) and all(s.is_valid for s in self.signatures)

    @property
    def any_crypto_valid(self) -> bool:
        return any(s.crypto_valid and s.digest_match for s in self.signatures)
