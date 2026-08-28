"""Gestione delle Trusted List (EU LOTL / AgID) come radici di fiducia.

Scarica la Lista delle Liste europea (LOTL), individua le TSL nazionali,
ne estrae i certificati delle CA che emettono certificati qualificati
(ServiceType ``CA/QC``) e li usa come trust anchor per la validazione.

I certificati estratti vengono messi in cache su disco cosi' l'app funziona
anche offline dopo il primo aggiornamento.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import requests
from asn1crypto import x509
from lxml import etree

from .paths import trust_cache_dir

# LOTL ufficiale dell'Unione Europea
EU_LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
# TSL italiana (fallback se la discovery dal LOTL non la individua)
IT_TSL_FALLBACK_URL = "https://eidas.agid.gov.it/TL/TSL-IT.xml"

_NS = {
    "tsl": "http://uri.etsi.org/02231/v2#",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

# tipi di servizio che rappresentano CA emittenti certificati qualificati
_CA_SERVICE_TYPES = {
    "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
    "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC",
}
# tipi di servizio di marcatura temporale (TSA) per CAdES-T
_TSA_SERVICE_TYPES = {
    "http://uri.etsi.org/TrstSvc/Svctype/TSA",
    "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
    "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC",
    "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES",
}
# stati considerati validi/positivi
_GOOD_STATUS = {
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel",
    # stati legacy (pre-2016)
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited",
    "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/undersupervision",
    "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/Svcstatus/accredited",
}

_HEADERS = {"User-Agent": "CorianoSign/0.1 (+https://localhost) TrustList fetcher"}
_TIMEOUT = 30

ProgressCb = Optional[Callable[[str], None]]


@dataclass
class TrustStore:
    """Insieme di certificati CA fidati con metadati di provenienza."""

    certificates: list[x509.Certificate] = field(default_factory=list)
    tsa_certificates: list[x509.Certificate] = field(default_factory=list)
    territories: list[str] = field(default_factory=list)
    updated_at: float = 0.0

    # esito della verifica di autenticità delle liste (firma XAdES)
    verify_attempted: bool = False
    lotl_verified: bool = False
    lotl_signer: str = ""
    territory_status: dict = field(default_factory=dict)  # terr -> "verified"|"unverified"|...

    def __len__(self) -> int:
        return len(self.certificates)

    @property
    def authentic(self) -> bool:
        """True se le liste caricate sono state autenticate via firma."""
        if not self.verify_attempted:
            return False
        if self.territories and not self.lotl_verified:
            return False
        return all(
            self.territory_status.get(t) == "verified" for t in self.territories
        )


# --------------------------------------------------------------------------- #
# Download / parsing TSL
# --------------------------------------------------------------------------- #
def _fetch(url: str) -> bytes:
    resp = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT)
    resp.raise_for_status()
    return resp.content


def _parse_xml(data: bytes) -> etree._Element:
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=True)
    return etree.fromstring(data, parser=parser)


def _discover_national_tsls(lotl_xml: bytes) -> dict[str, str]:
    """Dal LOTL restituisce {territorio: url_TSL} per le liste nazionali."""
    root = _parse_xml(lotl_xml)
    result: dict[str, str] = {}
    for ptr in root.iter("{http://uri.etsi.org/02231/v2#}OtherTSLPointer"):
        location = ptr.findtext("tsl:TSLLocation", namespaces=_NS)
        if not location or not location.lower().endswith(".xml"):
            continue
        territory = None
        mime_ok = False
        for other in ptr.iter("{http://uri.etsi.org/02231/v2#}OtherInformation"):
            terr = other.findtext("tsl:SchemeTerritory", namespaces=_NS)
            if terr:
                territory = terr.strip()
            mime = other.findtext(
                "{http://uri.etsi.org/02231/v2/additionaltypes#}MimeType"
            )
            if mime and "etsi.tsl" in mime:
                mime_ok = True
        # una TSL nazionale ha territorio a 2 lettere e mimetype TSL
        if territory and len(territory) == 2 and (mime_ok or "TL-" in location or "TSL-" in location):
            result.setdefault(territory, location)
    return result


def _extract_service_certs(
    tsl_xml: bytes,
) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
    """Estrae i certificati di CA/QC e TSA in stato valido da una TSL nazionale.

    Ritorna ``(ca_certs, tsa_certs)``.
    """
    import base64

    root = _parse_xml(tsl_xml)
    ca_certs: list[x509.Certificate] = []
    tsa_certs: list[x509.Certificate] = []
    seen_ca: set[bytes] = set()
    seen_tsa: set[bytes] = set()

    for service in root.iter("{http://uri.etsi.org/02231/v2#}TSPService"):
        info = service.find("tsl:ServiceInformation", namespaces=_NS)
        if info is None:
            continue
        stype = info.findtext("tsl:ServiceTypeIdentifier", namespaces=_NS)
        status = info.findtext("tsl:ServiceStatus", namespaces=_NS)
        if status not in _GOOD_STATUS:
            continue
        if stype in _CA_SERVICE_TYPES:
            target, seen = ca_certs, seen_ca
        elif stype in _TSA_SERVICE_TYPES:
            target, seen = tsa_certs, seen_tsa
        else:
            continue
        # Nota: nella TSL italiana gli <X509Certificate> stanno nel namespace
        # tsl (default), non nello standard xmldsig -> match per local-name.
        for x509_el in info.iter():
            if etree.QName(x509_el).localname != "X509Certificate":
                continue
            b64 = (x509_el.text or "").strip()
            if not b64:
                continue
            try:
                der = base64.b64decode(b64)
                cert = x509.Certificate.load(der)
                fp = cert.sha256
                if fp not in seen:
                    seen.add(fp)
                    target.append(cert)
            except Exception:  # noqa: BLE001 - salta certificati malformati
                continue
    return ca_certs, tsa_certs


# --------------------------------------------------------------------------- #
# Aggiornamento e cache
# --------------------------------------------------------------------------- #
def update_trust_store(
    territories: Optional[list[str]] = None,
    progress: ProgressCb = None,
    verify_signatures: bool = True,
    strict: bool = True,
) -> TrustStore:
    """Scarica le Trusted List, ne verifica l'autenticità e aggiorna la cache.

    ``territories``: elenco di codici paese (es. ["IT"]); ``None`` = solo IT.
                     Usa ["*"] per tutte le TSL nazionali europee (più lento).
    ``verify_signatures``: verifica la firma XAdES di LOTL e TSL (autenticità).
    ``strict``: se True, non carica le CA di una lista la cui firma non è
                verificata (o non appuntata). Se ``verify_signatures`` è False,
                ``strict`` è ignorato.
    """
    from lxml import etree as _etree

    from . import tsl_signature as _ts

    def _log(msg: str) -> None:
        if progress:
            progress(msg)

    if territories is None:
        territories = ["IT"]

    store = TrustStore(updated_at=time.time(), verify_attempted=verify_signatures)

    _log("Scarico la Lista delle Liste europea (LOTL)...")
    tsl_map: dict[str, str] = {}
    lotl_root = None
    try:
        lotl = _fetch(EU_LOTL_URL)
        tsl_map = _discover_national_tsls(lotl)
        lotl_root = _etree.fromstring(lotl)
        _log(f"Trovate {len(tsl_map)} liste nazionali nel LOTL.")
        if verify_signatures:
            r = _ts.verify_lotl(lotl)
            store.lotl_verified = r.ok
            store.lotl_signer = r.signer_cn
            for m in r.messages:
                _log("LOTL: " + m)
            if not r.ok and strict:
                _log("⚠ LOTL non autenticato: le TSL non verranno considerate fidate.")
    except Exception as exc:  # noqa: BLE001
        _log(f"LOTL non raggiungibile ({exc}); uso i fallback noti.")

    if "IT" not in tsl_map:
        tsl_map["IT"] = IT_TSL_FALLBACK_URL

    if territories == ["*"]:
        wanted = sorted(tsl_map.keys())
    else:
        wanted = [t.upper() for t in territories]

    for terr in wanted:
        url = tsl_map.get(terr)
        if not url:
            _log(f"[{terr}] nessuna TSL individuata, salto.")
            store.territory_status[terr] = "not_found"
            continue
        try:
            _log(f"[{terr}] scarico e analizzo la TSL...")
            xml = _fetch(url)

            verified = True
            if verify_signatures:
                expected = (
                    _ts.national_signer_certs(lotl_root, terr)
                    if lotl_root is not None
                    else []
                )
                vr = _ts.verify_national_tsl(xml, expected)
                verified = vr.ok and store.lotl_verified
                store.territory_status[terr] = "verified" if verified else "unverified"
                for m in vr.messages:
                    _log(f"[{terr}] {m}")
                if not verified and strict:
                    _log(f"[{terr}] ⚠ firma non autenticata: CA NON caricate.")
                    continue
            else:
                store.territory_status[terr] = "not_checked"

            certs, tsa_certs = _extract_service_certs(xml)
            store.certificates.extend(certs)
            store.tsa_certificates.extend(tsa_certs)
            store.territories.append(terr)
            mark = "✓ autenticata" if store.territory_status.get(terr) == "verified" else ""
            _log(
                f"[{terr}] {len(certs)} CA accreditate, {len(tsa_certs)} TSA. {mark}"
            )
        except Exception as exc:  # noqa: BLE001
            _log(f"[{terr}] errore: {exc}")
            store.territory_status[terr] = "error"

    # dedup globale per fingerprint
    _dedup(store)
    _save_cache(store)
    auth = "autenticata" if store.authentic else "NON pienamente autenticata"
    _log(f"Aggiornamento completato: {len(store)} CA fidate ({auth}).")
    return store


def _dedup(store: TrustStore) -> None:
    def _u(certs: list[x509.Certificate]) -> list[x509.Certificate]:
        seen: set[bytes] = set()
        out: list[x509.Certificate] = []
        for c in certs:
            if c.sha256 not in seen:
                seen.add(c.sha256)
                out.append(c)
        return out

    store.certificates = _u(store.certificates)
    store.tsa_certificates = _u(store.tsa_certificates)


# --------------------------------------------------------------------------- #
# Persistenza
# --------------------------------------------------------------------------- #
def _bundle_path() -> Path:
    return trust_cache_dir() / "ca_bundle.pem"


def _tsa_bundle_path() -> Path:
    return trust_cache_dir() / "tsa_bundle.pem"


def _meta_path() -> Path:
    return trust_cache_dir() / "meta.json"


def _certs_to_pem(certs: list[x509.Certificate]) -> str:
    import base64

    lines: list[str] = []
    for cert in certs:
        b64 = base64.encodebytes(cert.dump()).decode("ascii").strip()
        lines.append("-----BEGIN CERTIFICATE-----")
        lines.append(b64)
        lines.append("-----END CERTIFICATE-----")
    return "\n".join(lines)


def _save_cache(store: TrustStore) -> None:
    _bundle_path().write_text(_certs_to_pem(store.certificates), encoding="ascii")
    _tsa_bundle_path().write_text(
        _certs_to_pem(store.tsa_certificates), encoding="ascii"
    )
    _meta_path().write_text(
        json.dumps(
            {
                "updated_at": store.updated_at,
                "territories": store.territories,
                "count": len(store),
                "verify_attempted": store.verify_attempted,
                "lotl_verified": store.lotl_verified,
                "lotl_signer": store.lotl_signer,
                "territory_status": store.territory_status,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _load_pem_certs(path: Path) -> list[x509.Certificate]:
    import base64
    import re

    out: list[x509.Certificate] = []
    if not path.exists():
        return out
    text = path.read_text(encoding="ascii")
    for block in re.findall(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S
    ):
        try:
            der = base64.b64decode("".join(block.split()))
            out.append(x509.Certificate.load(der))
        except Exception:  # noqa: BLE001
            continue
    return out


def load_trust_store() -> TrustStore:
    """Carica la cache locale delle CA/TSA fidate (vuota se mai aggiornata)."""
    store = TrustStore()
    if not _bundle_path().exists():
        return store
    store.certificates = _load_pem_certs(_bundle_path())
    store.tsa_certificates = _load_pem_certs(_tsa_bundle_path())
    if _meta_path().exists():
        try:
            meta = json.loads(_meta_path().read_text(encoding="utf-8"))
            store.updated_at = meta.get("updated_at", 0.0)
            store.territories = meta.get("territories", [])
            store.verify_attempted = meta.get("verify_attempted", False)
            store.lotl_verified = meta.get("lotl_verified", False)
            store.lotl_signer = meta.get("lotl_signer", "")
            store.territory_status = meta.get("territory_status", {})
        except Exception:  # noqa: BLE001
            pass
    return store


def store_age_days(store: TrustStore) -> Optional[float]:
    """Età della cache in giorni (None se mai aggiornata)."""
    if not store.updated_at:
        return None
    return (time.time() - store.updated_at) / 86400.0


def needs_update(store: TrustStore, interval_days: int) -> bool:
    """True se la cache è assente o più vecchia dell'intervallo richiesto."""
    if len(store) == 0:
        return True
    age = store_age_days(store)
    return age is None or age >= interval_days
