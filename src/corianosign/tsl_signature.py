"""Verifica della firma XAdES delle Trusted List (LOTL / TSL nazionali).

Modello di fiducia eIDAS (ETSI TS 119 612):

    anchor OJ (bundled)  ─firma→  EU LOTL
    EU LOTL dichiara il certificato firmatario di ogni TSL nazionale
    certificato dichiarato  ─firma→  TSL nazionale (es. AgID per l'Italia)

Così l'autenticità della lista non dipende solo dal canale HTTPS: la firma
XML viene verificata e il certificato firmatario viene "appuntato" (pinning)
all'anchor ufficiale (per il LOTL) o al certificato dichiarato nel LOTL
(per le TSL nazionali).
"""
from __future__ import annotations

import base64
import hashlib
import warnings
from dataclasses import dataclass, field
from typing import Optional

from asn1crypto import x509 as ax
from cryptography.x509 import load_der_x509_certificate
from lxml import etree

from .paths import bundled_resource

DS = "http://www.w3.org/2000/09/xmldsig#"


@dataclass
class TLVerifyResult:
    signature_valid: bool = False        # firma XML crittograficamente valida
    signer_trusted: bool = False         # firmatario ancorato/atteso
    signer_cn: str = ""
    signer_der: Optional[bytes] = None
    messages: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.signature_valid and self.signer_trusted


def _fp(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _embedded_cert_der(root: etree._Element) -> Optional[bytes]:
    el = root.find(
        f".//{{{DS}}}Signature/{{{DS}}}KeyInfo/{{{DS}}}X509Data/{{{DS}}}X509Certificate"
    )
    if el is None or not el.text:
        return None
    try:
        return base64.b64decode("".join(el.text.split()))
    except Exception:  # noqa: BLE001
        return None


def _count_references(root: etree._Element) -> int:
    return len(
        root.findall(
            f".//{{{DS}}}Signature/{{{DS}}}SignedInfo/{{{DS}}}Reference"
        )
    )


def _cn(der: bytes) -> str:
    try:
        subj = ax.Certificate.load(der).subject.native
        return subj.get("common_name") or subj.get("organization_name") or ""
    except Exception:  # noqa: BLE001
        return ""


def verify_xml_signature(xml_bytes: bytes) -> TLVerifyResult:
    """Verifica la firma XAdES *interna* (con il certificato incorporato).

    Prova SOLO la coerenza crittografica firma<->documento; il pinning del
    firmatario va fatto a parte (vedi ``verify_lotl`` / ``verify_national_tsl``).
    """
    res = TLVerifyResult()
    try:
        root = etree.fromstring(xml_bytes)
    except Exception as exc:  # noqa: BLE001
        res.messages.append(f"XML non valido: {exc}")
        return res

    der = _embedded_cert_der(root)
    if not der:
        res.messages.append("Firma XML assente o priva di certificato firmatario.")
        return res
    res.signer_der = der
    res.signer_cn = _cn(der)

    try:
        from signxml import XMLVerifier
        from signxml.verifier import SignatureConfiguration
    except Exception as exc:  # noqa: BLE001
        res.messages.append(f"Libreria di verifica XML non disponibile: {exc}")
        return res

    nref = _count_references(root) or 1
    try:
        cert = load_der_x509_certificate(der)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            XMLVerifier().verify(
                xml_bytes,
                x509_cert=cert,
                validate_schema=False,
                expect_config=SignatureConfiguration(
                    require_x509=True, expect_references=nref
                ),
            )
        res.signature_valid = True
    except Exception as exc:  # noqa: BLE001
        res.messages.append(f"Firma XML NON valida: {type(exc).__name__}: {exc}")
    return res


def load_lotl_anchors() -> list[bytes]:
    """Certificati OJ (Gazzetta UE) che firmano il LOTL, impacchettati con l'app.

    Per rigenerare l'anchor quando la UE ruota i certificati OJ, estrai il
    certificato firmatario dal LOTL corrente e salvalo in PEM:

        python - <<'PY'
        from corianosign import trust
        from lxml import etree; import base64
        lotl = trust._fetch(trust.EU_LOTL_URL)
        el = etree.fromstring(lotl).find(
            './/{http://www.w3.org/2000/09/xmldsig#}Signature'
            '/{http://www.w3.org/2000/09/xmldsig#}KeyInfo'
            '/{http://www.w3.org/2000/09/xmldsig#}X509Data'
            '/{http://www.w3.org/2000/09/xmldsig#}X509Certificate')
        der = base64.b64decode(''.join(el.text.split()))
        pem = b'-----BEGIN CERTIFICATE-----\\n' + base64.encodebytes(der) \\
              + b'-----END CERTIFICATE-----\\n'
        open('packaging/trust_anchors/eu_lotl_signers.pem','wb').write(pem)
        PY

    Puoi conservare più blocchi CERTIFICATE nel file per coprire più anchor OJ.
    """
    path = bundled_resource("trust_anchors", "eu_lotl_signers.pem")
    if not path:
        return []
    ders: list[bytes] = []
    import re

    text = open(path, encoding="ascii").read()
    for block in re.findall(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S
    ):
        try:
            ders.append(base64.b64decode("".join(block.split())))
        except Exception:  # noqa: BLE001
            continue
    return ders


def verify_lotl(xml_bytes: bytes) -> TLVerifyResult:
    """Verifica la firma del LOTL e appunta il firmatario agli anchor OJ."""
    res = verify_xml_signature(xml_bytes)
    if not res.signature_valid:
        return res
    anchors = {_fp(d) for d in load_lotl_anchors()}
    if not anchors:
        res.messages.append(
            "Anchor OJ del LOTL non presenti nel pacchetto: firma valida ma "
            "firmatario non appuntato."
        )
        return res
    if res.signer_der and _fp(res.signer_der) in anchors:
        res.signer_trusted = True
        res.messages.append(
            f"LOTL firmato dall'anchor OJ atteso ({res.signer_cn})."
        )
    else:
        res.messages.append(
            "Il firmatario del LOTL non corrisponde agli anchor OJ noti: "
            "possibile rotazione dei certificati OJ, aggiornare gli anchor."
        )
    return res


def national_signer_certs(lotl_root: etree._Element, territory: str) -> list[bytes]:
    """Certificati firmatari attesi per la TSL di ``territory``, dal LOTL."""
    ns_terr = territory.strip().upper()
    out: list[bytes] = []
    for ptr in lotl_root.iter("{http://uri.etsi.org/02231/v2#}OtherTSLPointer"):
        terr = None
        for oi in ptr.iter("{http://uri.etsi.org/02231/v2#}OtherInformation"):
            t = oi.findtext(
                "SchemeTerritory",
            ) or oi.findtext("{http://uri.etsi.org/02231/v2#}SchemeTerritory")
            if t:
                terr = t.strip()
        if terr != ns_terr:
            continue
        for xe in ptr.iter():
            if etree.QName(xe).localname == "X509Certificate" and xe.text:
                try:
                    out.append(base64.b64decode("".join(xe.text.split())))
                except Exception:  # noqa: BLE001
                    continue
    return out


def verify_national_tsl(xml_bytes: bytes, expected_ders: list[bytes]) -> TLVerifyResult:
    """Verifica una TSL nazionale e appunta il firmatario ai certificati attesi."""
    res = verify_xml_signature(xml_bytes)
    if not res.signature_valid:
        return res
    expected = {_fp(d) for d in expected_ders}
    if not expected:
        res.messages.append(
            "Nessun certificato firmatario atteso dal LOTL: firma valida ma non "
            "appuntata."
        )
        return res
    if res.signer_der and _fp(res.signer_der) in expected:
        res.signer_trusted = True
        res.messages.append(
            f"TSL firmata dal certificato dichiarato nel LOTL ({res.signer_cn})."
        )
    else:
        res.messages.append(
            "Il firmatario della TSL non corrisponde a quanto dichiarato nel "
            "LOTL: lista potenzialmente non autentica."
        )
    return res
