"""Firma locale da smart card / token USB via PKCS#11 (basata su pyHanko).

In alternativa alla firma remota Aruba, la chiave privata resta sul dispositivo
hardware e firma tramite lo standard **PKCS#11**. In sviluppo si usa **SoftHSM2**
(token virtuale); in produzione basta puntare alla libreria del token reale
(Bit4id, Aruba, OpenSC, …) via ``$PKCS11_MODULE`` o il campo del profilo.

Usa **pyHanko** (che usa ``python-pkcs11``) per entrambi i formati:
  * CAdES ``.p7m`` -> ``Signer.async_sign_general_data(..., use_cades=True)``
    (pyHanko aggiunge gli attributi CAdES, incl. signing-certificate-v2);
  * PAdES (PDF, anche con riquadro VISIBILE) -> firma incrementale del PDF.

La verifica si fa con ``verifier.analyze_bytes`` già esistente.
"""
from __future__ import annotations

import asyncio
import io
import os
from datetime import datetime
from typing import Optional

# possibili percorsi del modulo SoftHSM2 (dev); override con $PKCS11_MODULE
_SOFTHSM_CANDIDATES = [
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    r"C:\SoftHSM2\lib\softhsm2-x64.dll",
]


class Pkcs11Error(RuntimeError):
    pass


def default_module() -> Optional[str]:
    """Modulo PKCS#11: $PKCS11_MODULE, altrimenti SoftHSM se presente."""
    env = os.environ.get("PKCS11_MODULE")
    if env and os.path.exists(env):
        return env
    for p in _SOFTHSM_CANDIDATES:
        if os.path.exists(p):
            return p
    return None


def _require_pyhanko():
    try:
        from pyhanko.sign import signers  # noqa: PLC0415,F401
        from pyhanko.sign.pkcs11 import PKCS11Signer, open_pkcs11_session  # noqa
        from pyhanko.config.pkcs11 import TokenCriteria  # noqa
        return signers, PKCS11Signer, open_pkcs11_session, TokenCriteria
    except ImportError as exc:  # pragma: no cover
        raise Pkcs11Error(
            "pyHanko non installato. Per la firma da token: "
            "pip install 'pyhanko[pkcs11]'"
        ) from exc


def list_objects(module_path: str, pin: Optional[str] = None,
                 token_label: Optional[str] = None) -> dict:
    """Elenca certificati e chiavi sul token (per 'Rileva token')."""
    try:
        import pkcs11 as p11  # python-pkcs11
    except ImportError as exc:  # pragma: no cover
        raise Pkcs11Error("python-pkcs11 non installato.") from exc
    from asn1crypto import x509

    lib = p11.lib(module_path)
    tokens = list(lib.get_tokens(token_label=token_label)) if token_label \
        else list(lib.get_tokens())
    if not tokens:
        raise Pkcs11Error("Nessun token trovato.")
    token = tokens[0]
    out: dict = {"token": token.label, "certificates": [], "private_keys": []}
    with token.open(user_pin=pin) as session:
        for obj in session.get_objects({p11.Attribute.CLASS: p11.ObjectClass.CERTIFICATE}):
            der = bytes(obj[p11.Attribute.VALUE])
            label = obj[p11.Attribute.LABEL]
            cn = ""
            try:
                cn = x509.Certificate.load(der).subject.native.get("common_name", "")
            except Exception:  # noqa: BLE001
                pass
            out["certificates"].append({"label": label, "cn": cn})
        for obj in session.get_objects({p11.Attribute.CLASS: p11.ObjectClass.PRIVATE_KEY}):
            out["private_keys"].append({"label": obj[p11.Attribute.LABEL]})
    return out


def _resolve_token_label(module_path: str, token_label: Optional[str]) -> Optional[str]:
    """Se il token non è indicato, sceglie il primo slot con un certificato.

    Necessario coi moduli multi-slot (SoftHSM, lettori con slot vuoti): senza,
    pyHanko non sa quale token usare.
    """
    if token_label:
        return token_label
    try:
        import pkcs11 as p11  # python-pkcs11
        lib = p11.lib(module_path)
        fallback = None
        for tok in lib.get_tokens():
            fallback = fallback or tok.label
            try:
                with tok.open() as s:  # i certificati sono pubblici (niente PIN)
                    for _ in s.get_objects(
                            {p11.Attribute.CLASS: p11.ObjectClass.CERTIFICATE}):
                        return tok.label
            except Exception:  # noqa: BLE001
                continue
        return fallback
    except Exception:  # noqa: BLE001
        return None


def _signer(module_path, pin, token_label, cert_label, key_label):
    _signers, PKCS11Signer, open_session, TokenCriteria = _require_pyhanko()
    label = _resolve_token_label(module_path, token_label)
    crit = TokenCriteria(label=label) if label else None
    session = open_session(module_path, token_criteria=crit, user_pin=pin)
    signer = PKCS11Signer(
        session, cert_label=cert_label, key_label=key_label or cert_label)
    return session, signer


def signer_name(module_path: str, pin: str, *, token_label: Optional[str] = None,
                cert_label: Optional[str] = None) -> str:
    """Nome del firmatario dal certificato sul token (per la firma grafica)."""
    from asn1crypto import x509  # noqa: F401
    info = list_objects(module_path, pin=pin, token_label=token_label)
    # se serve il nome preciso, si rilegge il cert; qui basta il CN elencato
    for c in info["certificates"]:
        if cert_label is None or c["label"] == cert_label:
            return c["cn"] or ""
    return ""


def sign_p7m(data: bytes, *, module_path: str, pin: str,
             token_label: Optional[str] = None, cert_label: Optional[str] = None,
             key_label: Optional[str] = None, attached: bool = True) -> bytes:
    """Firma ``data`` in CAdES-BES (.p7m) usando il token PKCS#11."""
    session, signer = _signer(module_path, pin, token_label, cert_label, key_label)
    try:
        ci = asyncio.run(signer.async_sign_general_data(
            data, "sha256", detached=not attached, use_cades=True))
        return ci.dump()
    finally:
        _close(session)


def sign_pdf(data: bytes, *, module_path: str, pin: str,
             token_label: Optional[str] = None, cert_label: Optional[str] = None,
             key_label: Optional[str] = None,
             visible: bool = False, page: int = 1, box=None,
             text: Optional[str] = None, image_png: Optional[bytes] = None,
             reason: Optional[str] = None, location: Optional[str] = None) -> bytes:
    """Firma un PDF in PAdES-BES (opzionalmente con riquadro visibile).

    ``box`` = (leftx, lefty, rightx, righty) in punti PDF (origine in basso a
    sinistra), ``page`` 1-based: gli stessi valori dell'anteprima di firma.
    """
    signers, _PKCS11Signer, _open, _crit = _require_pyhanko()
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields

    session, signer = _signer(module_path, pin, token_label, cert_label, key_label)
    try:
        w = IncrementalPdfFileWriter(io.BytesIO(data))
        field_name = "Signature1"
        stamp_style = None

        if visible and box:
            lx, ly, rx, ry = box
            fields.append_signature_field(
                w, fields.SigFieldSpec(
                    sig_field_name=field_name,
                    on_page=max(0, page - 1),
                    box=(lx, ly, rx, ry),
                ),
            )
            stamp_style = _stamp_style(signers, text, image_png)

        meta = signers.PdfSignatureMetadata(
            field_name=field_name,
            reason=reason or None,
            location=location or None,
            subfilter=fields.SigSeedSubFilter.PADES,
        )
        pdf_signer = signers.PdfSigner(meta, signer=signer, stamp_style=stamp_style)
        out = io.BytesIO()
        pdf_signer.sign_pdf(w, output=out)
        return out.getvalue()
    finally:
        _close(session)


class _Pkcs11RSAKey:
    """Fa da chiave privata RSA per signxml, firmando pero' sul token PKCS#11.

    signxml (``XMLSigner``) accetta qualsiasi oggetto come ``key`` e per RSA ne
    chiama ``key.sign(data, padding, algorithm)``; serve anche ``public_key()``
    per serializzare il ``KeyValue`` (informazione pubblica, presa dal
    certificato). La chiave privata NON lascia mai il dispositivo: la firma
    avviene dentro il token col meccanismo ``SHA256_RSA_PKCS``.
    """

    def __init__(self, priv, public_key, key_size: int) -> None:
        self._priv = priv
        self._public_key = public_key
        self.key_size = key_size

    def public_key(self):
        return self._public_key

    def sign(self, data, padding=None, algorithm=None):  # firma RSA PKCS#1 v1.5
        from pkcs11 import Mechanism
        return self._priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)


def _pkcs11_rsa_signing_key(module_path: str, pin: str,
                            token_label: Optional[str],
                            cert_label: Optional[str],
                            key_label: Optional[str]):
    """Apre il token e prepara (session, shim signxml, cert DER) per XAdES.

    Il chiamante deve chiudere la ``session`` a firma conclusa.
    """
    try:
        import pkcs11 as p11  # python-pkcs11
    except ImportError as exc:  # pragma: no cover
        raise Pkcs11Error("python-pkcs11 non installato.") from exc
    from cryptography.x509 import load_der_x509_certificate
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    label = _resolve_token_label(module_path, token_label)
    lib = p11.lib(module_path)
    tokens = list(lib.get_tokens(token_label=label)) if label \
        else list(lib.get_tokens())
    if not tokens:
        raise Pkcs11Error("Nessun token trovato per la firma XAdES.")
    session = tokens[0].open(user_pin=pin)
    try:
        # certificato (per KeyInfo e per la chiave pubblica)
        cert_query = {p11.Attribute.CLASS: p11.ObjectClass.CERTIFICATE}
        if cert_label:
            cert_query[p11.Attribute.LABEL] = cert_label
        cert_objs = list(session.get_objects(cert_query))
        if not cert_objs:
            raise Pkcs11Error("Nessun certificato sul token per la firma XAdES.")
        der = bytes(cert_objs[0][p11.Attribute.VALUE])
        cc = load_der_x509_certificate(der)
        pub = cc.public_key()
        if not isinstance(pub, _rsa.RSAPublicKey):
            raise Pkcs11Error(
                "Firma XAdES da dispositivo supportata solo per chiavi RSA "
                "(il certificato sul token non e' RSA)."
            )
        # chiave privata corrispondente
        key_query = {p11.Attribute.CLASS: p11.ObjectClass.PRIVATE_KEY}
        lbl = key_label or cert_label
        if lbl:
            key_query[p11.Attribute.LABEL] = lbl
        priv_objs = list(session.get_objects(key_query))
        if not priv_objs:
            raise Pkcs11Error("Chiave privata non trovata sul token.")
        shim = _Pkcs11RSAKey(priv_objs[0], pub, pub.key_size)
        return session, shim, der
    except Exception:
        _close(session)
        raise


def sign_xades(data: bytes, *, module_path: str, pin: str,
               token_label: Optional[str] = None, cert_label: Optional[str] = None,
               key_label: Optional[str] = None) -> bytes:
    """Firma un documento XML in XAdES-BES *enveloped* usando il token PKCS#11.

    ``data`` deve essere un XML: la firma viene inserita dentro il documento
    (enveloped), il caso piu' comune in Italia per gli XML firmati.
    """
    try:
        from signxml.xades import XAdESSigner
    except ImportError as exc:  # pragma: no cover
        raise Pkcs11Error(
            "Libreria signxml non disponibile per la firma XAdES.") from exc
    from lxml import etree

    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True,
                                 load_dtd=False)
        root = etree.fromstring(data, parser=parser)
    except Exception as exc:  # noqa: BLE001
        raise Pkcs11Error(
            "La firma XAdES *enveloped* richiede un documento XML valido: "
            f"il file non e' XML interpretabile ({exc})."
        ) from exc

    session, shim, der = _pkcs11_rsa_signing_key(
        module_path, pin, token_label, cert_label, key_label)
    try:
        import base64
        pem = ("-----BEGIN CERTIFICATE-----\n"
               + base64.encodebytes(der).decode()
               + "-----END CERTIFICATE-----\n")
        signed = XAdESSigner(
            signature_algorithm="rsa-sha256", digest_algorithm="sha256",
        ).sign(root, key=shim, cert=pem)
        return etree.tostring(signed, xml_declaration=True, encoding="UTF-8")
    finally:
        _close(session)


def _stamp_style(signers, text: Optional[str], image_png: Optional[bytes]):
    """Aspetto del riquadro: testo (multi-riga) ed eventuale immagine di sfondo."""
    from pyhanko import stamp
    from pyhanko.pdf_utils import text as pdf_text

    kwargs = {}
    if text:
        kwargs["stamp_text"] = text
        kwargs["text_box_style"] = pdf_text.TextBoxStyle()
    else:
        kwargs["stamp_text"] = ""
    if image_png:
        from pyhanko.pdf_utils.images import PdfImage
        try:
            kwargs["background"] = PdfImage(io.BytesIO(image_png))
        except Exception:  # noqa: BLE001
            pass
    return stamp.TextStampStyle(**kwargs)


def _close(session) -> None:
    try:
        session.close()
    except Exception:  # noqa: BLE001
        pass
