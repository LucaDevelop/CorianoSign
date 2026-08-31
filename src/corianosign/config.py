"""Impostazioni persistenti dell'app (verifica + firma)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from .paths import config_file

DEFAULT_INTERVAL_DAYS = 7

# Domini di firma remota Aruba (typeOtpAuth) selezionabili; il primo è il default.
SIGN_DOMAINS = [
    "firma",
    "frLispa",
    "frRegioneMarche",
    "frFastweb",
    "maggioli",
    "enerj-fr",
    "frNextware",
    "frPesaro",
    "frComuneRE",
]
DEFAULT_SIGN_DOMAIN = SIGN_DOMAINS[0]


@dataclass
class SignProfile:
    """Profilo utente di firma remota Aruba (senza password/OTP)."""

    name: str = ""              # etichetta mostrata all'utente
    user: str = ""              # username firma remota
    domain: str = "firma"       # typeOtpAuth (Dominio)
    cert_id: str = "AS0"
    hsm: str = "COSIGN"
    demo: bool = False

    def label(self) -> str:
        return self.name or self.user or "(profilo)"


@dataclass
class AppConfig:
    # --- generali --- #
    timezone: str = "Europe/Rome"
    auto_update_app: bool = True        # controlla aggiornamenti dell'app all'avvio

    # --- verifica --- #
    auto_update: bool = True
    interval_days: int = DEFAULT_INTERVAL_DAYS
    territories: list[str] = field(default_factory=lambda: ["IT"])
    verify_signatures: bool = True
    check_trust: bool = True            # valida catena verso le Trusted List
    revocation_online: bool = True      # controllo revoca CRL/OCSP

    # --- firma: aspetto grafico PAdES --- #
    # il testo della firma grafica è sempre il Nome Cognome dal certificato.
    sign_ask_reason: bool = False       # chiede la motivazione al momento della firma
    sign_ask_location: bool = False     # chiede il luogo al momento della firma
    sign_show_datetime: bool = True     # data/ora nel riquadro (default attivo)
    sign_image_mode: str = "default"    # "default" | "none" | "custom"
    sign_logo_path: str = ""            # usato solo con sign_image_mode == "custom"
    sign_image_only: bool = False

    # --- firma: profili utenti remoti --- #
    profiles: list[SignProfile] = field(default_factory=list)

    def clamp(self) -> "AppConfig":
        self.interval_days = max(1, min(int(self.interval_days), 365))
        if not self.territories:
            self.territories = ["IT"]
        return self


def load_config() -> AppConfig:
    path = config_file()
    if not path.exists():
        return AppConfig()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - config corrotta -> default
        return AppConfig()

    profiles = [
        SignProfile(
            name=str(p.get("name", "")),
            user=str(p.get("user", "")),
            domain=str(p.get("domain", "")),
            cert_id=str(p.get("cert_id", "AS0")) or "AS0",
            hsm=str(p.get("hsm", "COSIGN")) or "COSIGN",
            demo=bool(p.get("demo", False)),
        )
        for p in data.get("profiles", [])
    ]
    # migrazione dai vecchi campi singoli aruba_*
    if not profiles and data.get("aruba_user"):
        profiles = [SignProfile(
            name=str(data.get("aruba_user", "")),
            user=str(data.get("aruba_user", "")),
            domain=str(data.get("aruba_otp_type", "")),
            cert_id=str(data.get("aruba_cert_id", "AS0")) or "AS0",
            hsm=str(data.get("aruba_hsm", "COSIGN")) or "COSIGN",
            demo=bool(data.get("aruba_demo", False)),
        )]

    cfg = AppConfig(
        timezone=str(data.get("timezone", "Europe/Rome")) or "Europe/Rome",
        auto_update_app=bool(data.get("auto_update_app", True)),
        auto_update=bool(data.get("auto_update", True)),
        interval_days=int(data.get("interval_days", DEFAULT_INTERVAL_DAYS)),
        territories=list(data.get("territories", ["IT"])) or ["IT"],
        verify_signatures=bool(data.get("verify_signatures", True)),
        check_trust=bool(data.get("check_trust", True)),
        revocation_online=bool(data.get("revocation_online", True)),
        sign_ask_reason=bool(data.get("sign_ask_reason", False)),
        sign_ask_location=bool(data.get("sign_ask_location", False)),
        sign_show_datetime=bool(data.get("sign_show_datetime", True)),
        sign_image_mode=str(data.get("sign_image_mode", "")),
        sign_logo_path=str(data.get("sign_logo_path", "")),
        sign_image_only=bool(data.get("sign_image_only", False)),
        profiles=profiles,
    )
    # migrazione: config vecchie senza sign_image_mode
    if cfg.sign_image_mode not in ("default", "none", "custom"):
        cfg.sign_image_mode = "custom" if cfg.sign_logo_path else "default"
    return cfg.clamp()


def save_config(cfg: AppConfig) -> None:
    cfg.clamp()
    config_file().write_text(json.dumps(asdict(cfg), indent=2), encoding="utf-8")
