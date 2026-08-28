"""Client per la firma remota Aruba (ArubaSignService / ARSS) — SPIKE.

Firma un documento con la firma remota Aruba (con OTP): il documento viene
inviato al servizio Aruba, che appone la firma con la chiave dell'utente
custodita sul proprio HSM, e restituisce il file firmato.

Formati:
  * PAdES (PDF firmato, anche VISIBILE)  -> operazione ``pdfsignatureV2``
  * CAdES (.p7m)                          -> operazione ``pkcs7signV2``

Campi (dal WSDL/XSD ufficiale, namespace http://arubasignservice.arubapec.it/):
  auth:            user, userPWD, otpPwd, typeOtpAuth, typeHSM
  signRequestV2:   certID, requiredmark, transport, binaryinput, identity
  pdfSignApparence: leftx, lefty, rightx, righty, reason, location, page,
                    image, imageBin, testo, imageOnly

NOTA: i valori di ``typeOtpAuth``, ``typeHSM`` e ``certID`` dipendono dal tuo
contratto Aruba. Lo spike li rende parametrici e offre ``inspect()`` per
leggere dal WSDL reale le operazioni e i valori ammessi prima di firmare.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# caratteri di controllo C0 (tranne \t \n \r) e DEL: XML non li ammette e nei
# campi credenziale sono sempre spuri (es. Backspace catturato da getpass)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _xml_safe(value: Optional[str]) -> Optional[str]:
    """Rimuove i caratteri di controllo non ammessi in XML (accenti/Unicode ok)."""
    if value is None:
        return None
    return _CTRL_RE.sub("", value)

# Endpoint pubblici noti (sovrascrivibili). Il WSDL è pubblico.
WSDL_PROD = "https://arss.arubapec.it/ArubaSignService/ArubaSignService?wsdl"
WSDL_DEMO = "https://arss.demo.firma-automatica.it/ArubaSignService/ArubaSignService?wsdl"

# valori di default comuni (verificare col proprio contratto)
DEFAULT_CERT_ID = "AS0"
# NB: il valore corretto dell'enum Aruba è "BYNARYNET" (refuso nello schema),
# non "BINARYNET". Invia/riceve i byte via binaryinput/binaryoutput.
DEFAULT_TRANSPORT = "BYNARYNET"
DEFAULT_TYPE_HSM = "COSIGN"


class ArubaError(Exception):
    pass


@dataclass
class VisibleSignature:
    """Aspetto della firma PAdES visibile (coordinate in punti PDF)."""

    page: int = 1
    leftx: int = 50
    lefty: int = 50
    rightx: int = 300
    righty: int = 130
    testo: str = ""          # testo mostrato nel riquadro
    reason: str = ""
    location: str = ""
    image_bin: Optional[bytes] = None   # logo/immagine (PNG/JPG) opzionale
    image_only: bool = False
    scale_font: bool = True             # bScaleFont
    show_datetime: bool = True          # bShowDateTime
    preserve_pdfa: bool = False         # preservePDFA
    resize_mode: int = 0                # resizeMode


def _client(wsdl_url: str):
    try:
        from zeep import Client
        from zeep.plugins import HistoryPlugin
        from zeep.transports import Transport
    except Exception as exc:  # noqa: BLE001
        raise ArubaError(f"Libreria SOAP 'zeep' non disponibile: {exc}") from exc
    try:
        transport = Transport(timeout=60, operation_timeout=120)
        history = HistoryPlugin()
        client = Client(wsdl_url, transport=transport, plugins=[history])
        client._corianosign_history = history
        return client
    except Exception as exc:  # noqa: BLE001
        raise ArubaError(f"Impossibile caricare il WSDL Aruba ({wsdl_url}): {exc}") from exc


def _dump_diagnostics(client, path: str = "corianosign-aruba-debug.xml") -> Optional[str]:
    """Salva l'ultimo envelope inviato/ricevuto (credenziali oscurate).

    Ritorna il percorso del file scritto, o None se non c'è nulla da salvare.
    """
    from lxml import etree

    history = getattr(client, "_corianosign_history", None)
    if history is None:
        return None

    def _xml(entry) -> str:
        if not entry or entry.get("envelope") is None:
            return ""
        return etree.tostring(entry["envelope"], pretty_print=True).decode(errors="replace")

    try:
        sent = _xml(history.last_sent)
        received = _xml(history.last_received)
    except Exception:  # noqa: BLE001
        return None

    # oscura le credenziali nell'inviato
    import re

    for tag in ("user", "userPWD", "otpPwd"):
        sent = re.sub(rf"(<[^>]*{tag}>)[^<]*(</[^>]*{tag}>)", r"\1***\2", sent)

    if not sent and not received:
        return None
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("=== INVIATO (credenziali oscurate) ===\n")
        fh.write(sent or "(vuoto: errore prima dell'invio)\n")
        fh.write("\n\n=== RICEVUTO ===\n")
        fh.write(received or "(vuoto: nessuna risposta ricevuta)\n")
    return path


def inspect(wsdl_url: str) -> str:
    """Restituisce un dump leggibile di operazioni e tipi del servizio reale.

    Utile per confermare, sul TUO endpoint, i nomi/valori esatti prima di firmare.
    """
    client = _client(wsdl_url)
    lines: list[str] = [f"WSDL: {wsdl_url}", ""]
    for service in client.wsdl.services.values():
        for port in service.ports.values():
            ops = sorted(port.binding._operations.keys())
            lines.append(f"Operazioni ({len(ops)}):")
            lines.append("  " + ", ".join(ops))
            for name in ("pdfsignatureV2", "pkcs7signV2", "getVersion", "verifyOtp"):
                if name in port.binding._operations:
                    op = port.binding._operations[name]
                    lines.append(f"\n{name} input:\n  {op.input.signature()}")
            break
        break
    return "\n".join(lines)


def get_version(wsdl_url: str) -> str:
    """Chiama getVersion: verifica connettività e endpoint (senza credenziali)."""
    client = _client(wsdl_url)
    try:
        return str(client.service.getVersion())
    except Exception as exc:  # noqa: BLE001
        raise ArubaError(f"getVersion fallito: {exc}") from exc


def fetch_signer_name(
    wsdl_url: str,
    user: str,
    user_pwd: str,
    type_otp_auth: str,
    type_hsm: str = DEFAULT_TYPE_HSM,
    cert_id: str = DEFAULT_CERT_ID,
) -> Optional[str]:
    """Recupera Nome Cognome dal certificato del firmatario (senza OTP).

    Usa ``listCert`` (richiede solo user+password) e ne estrae il nome dal
    subject del certificato. Ritorna None se non disponibile.
    """
    from asn1crypto import x509 as _x509

    client = _client(wsdl_url)
    # listCert non richiede OTP: otpPwd vuoto
    identity = _identity(client, user, user_pwd, "", type_otp_auth, type_hsm)
    try:
        resp = client.service.listCert(Identity=identity)
    except Exception:  # noqa: BLE001
        return None

    certs = []
    for grp in ("app1", "app2"):
        v = getattr(resp, grp, None)
        if v:
            certs.extend(list(v))
    if not certs:
        return None
    chosen = next((c for c in certs if getattr(c, "id", None) == cert_id), certs[0])
    der = getattr(chosen, "value", None)
    if not der:
        return None
    try:
        subj = _x509.Certificate.load(der).subject.native
    except Exception:  # noqa: BLE001
        return None
    gn = subj.get("given_name")
    sn = subj.get("surname")
    if gn and sn:
        return f"{gn} {sn}".strip()
    return subj.get("common_name") or None


def _identity(client, user, user_pwd, otp, type_otp_auth, type_hsm):
    auth_t = client.get_type("ns0:auth")
    return auth_t(
        user=_xml_safe(user),
        userPWD=_xml_safe(user_pwd),
        otpPwd=_xml_safe(otp),
        typeOtpAuth=_xml_safe(type_otp_auth),
        typeHSM=_xml_safe(type_hsm),
    )


def _check_return(resp) -> bytes:
    """Estrae il file firmato o solleva un errore leggibile dalla risposta."""
    code = getattr(resp, "return_code", None) or getattr(resp, "returnCode", None)
    status = getattr(resp, "status", None)
    descr = getattr(resp, "description", "") or ""
    out = getattr(resp, "binaryoutput", None)
    if out:
        return out
    raise ArubaError(
        f"Firma non riuscita (status={status}, code={code}): {descr}"
    )


def sign_pdf(
    pdf_bytes: bytes,
    *,
    user: str,
    user_pwd: str,
    otp: str,
    wsdl_url: str = WSDL_PROD,
    cert_id: str = DEFAULT_CERT_ID,
    type_otp_auth: str,
    type_hsm: str = DEFAULT_TYPE_HSM,
    transport: str = DEFAULT_TRANSPORT,
    signature_level: Optional[str] = None,
    signing_time: Optional[str] = None,
    visible: Optional[VisibleSignature] = None,
) -> bytes:
    """Firma un PDF in PAdES (opzionalmente VISIBILE) via ``pdfsignatureV2``."""
    client = _client(wsdl_url)
    identity = _identity(client, user, user_pwd, otp, type_otp_auth, type_hsm)

    req_t = client.get_type("ns0:signRequestV2")
    req = req_t(
        certID=cert_id,
        requiredmark=False,
        transport=transport,
        binaryinput=pdf_bytes,
        identity=identity,
        signatureLevel=signature_level,
        signingTime=_xml_safe(signing_time),
    )

    app = None
    if visible is not None:
        app_t = client.get_type("ns0:pdfSignApparence")
        app = app_t(
            leftx=visible.leftx, lefty=visible.lefty,
            rightx=visible.rightx, righty=visible.righty,
            page=visible.page,
            testo=_xml_safe(visible.testo) or None,
            reason=_xml_safe(visible.reason) or None,
            location=_xml_safe(visible.location) or None,
            imageBin=visible.image_bin,
            imageOnly=visible.image_only,
            bScaleFont=visible.scale_font,
            bShowDateTime=visible.show_datetime,
            preservePDFA=visible.preserve_pdfa,
            resizeMode=visible.resize_mode,
        )
    try:
        # parametri dal WSDL reale: SignRequestV2, Apparence, fieldName,
        # pdfprofile, password, dict_signed_attributes
        resp = client.service.pdfsignatureV2(SignRequestV2=req, Apparence=app)
    except Exception as exc:  # noqa: BLE001
        dbg = _dump_diagnostics(client)
        hint = f" [diagnostica salvata in {dbg}]" if dbg else ""
        raise ArubaError(f"Chiamata pdfsignatureV2 fallita: {exc}{hint}") from exc
    return _check_return(resp)


def sign_p7m(
    data_bytes: bytes,
    *,
    user: str,
    user_pwd: str,
    otp: str,
    wsdl_url: str = WSDL_PROD,
    cert_id: str = DEFAULT_CERT_ID,
    type_otp_auth: str,
    type_hsm: str = DEFAULT_TYPE_HSM,
    transport: str = DEFAULT_TRANSPORT,
    signature_level: Optional[str] = None,
    signing_time: Optional[str] = None,
) -> bytes:
    """Firma un file qualsiasi in CAdES (.p7m) via ``pkcs7signV2``."""
    client = _client(wsdl_url)
    identity = _identity(client, user, user_pwd, otp, type_otp_auth, type_hsm)
    req_t = client.get_type("ns0:signRequestV2")
    req = req_t(
        certID=cert_id,
        requiredmark=False,
        transport=transport,
        binaryinput=data_bytes,
        identity=identity,
        signatureLevel=signature_level,
        signingTime=_xml_safe(signing_time),
    )
    try:
        # parametri dal WSDL reale: SignRequestV2, detached, returnder
        # detached=False -> busta .p7m con contenuto incluso (enveloping)
        resp = client.service.pkcs7signV2(
            SignRequestV2=req, detached=False, returnder=False
        )
    except Exception as exc:  # noqa: BLE001
        dbg = _dump_diagnostics(client)
        hint = f" [diagnostica salvata in {dbg}]" if dbg else ""
        raise ArubaError(f"Chiamata pkcs7signV2 fallita: {exc}{hint}") from exc
    return _check_return(resp)
