"""Estrazione delle firme PAdES da un PDF firmato.

Una firma PAdES e' una busta CMS/PKCS#7 ``SignedData`` "detached" contenuta nel
campo ``/Contents`` di un dizionario di firma del PDF; i byte effettivamente
firmati sono quelli indicati da ``/ByteRange`` (tutto il file tranne il buco in
cui e' scritto ``/Contents``). Qui individuiamo tutte le firme e i document
timestamp, restituendo per ciascuna la busta CMS gia' caricata e i byte firmati,
in modo da riusare la stessa verifica crittografica/trust delle firme CAdES.
"""
from __future__ import annotations

import binascii
import re
from dataclasses import dataclass, field
from typing import Optional

from asn1crypto import cms as asn1cms

from . import cms

# /ByteRange [ a b c d ]  (i quattro interi possono essere separati da spazi vari)
_BR_RE = re.compile(
    rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]?", re.DOTALL
)
_SUBFILTER_RE = re.compile(rb"/SubFilter\s*/([A-Za-z0-9_.]+)")
_TYPE_RE = re.compile(rb"/Type\s*/([A-Za-z0-9_]+)")

# SubFilter che rappresentano una firma (non un semplice document-timestamp)
_SIG_SUBFILTERS = {
    "adbe.pkcs7.detached",
    "adbe.pkcs7.sha1",
    "ETSI.CAdES.detached",
}
_TS_SUBFILTER = "ETSI.RFC3161"  # DocTimeStamp (PAdES-LTA)


@dataclass
class PadesSignature:
    """Una firma (o document-timestamp) trovata nel PDF."""

    signed_data: Optional[asn1cms.SignedData]
    signed_bytes: bytes                 # concatenazione dei ByteRange (contenuto firmato)
    content_info: Optional[asn1cms.ContentInfo] = None  # busta CMS completa
    sub_filter: str = ""
    is_doc_timestamp: bool = False
    covers_whole_document: bool = True  # la firma copre l'intero file
    byte_range: tuple[int, int, int, int] = (0, 0, 0, 0)
    error: str = ""


def is_pdf(data: bytes) -> bool:
    """Riconosce un PDF vero (che *inizia* con ``%PDF-``).

    Attenzione: un ``.p7m`` che racchiude un PDF contiene ``%PDF-`` poco dopo
    l'inizio (nel contenuto incapsulato), quindi non basta cercarlo nei primi
    byte: un PDF ha ``%PDF-`` all'inizio, un CMS/PKCS#7 inizia con ``0x30``
    (SEQUENCE DER). Si tollera solo un BOM/whitespace iniziale.
    """
    head = data[:64].lstrip(b"\x00\x09\x0a\x0c\x0d\x20\xef\xbb\xbf")
    return head[:5] == b"%PDF-"


def _trailing_is_blank(data: bytes, end: int) -> bool:
    """True se dopo l'offset ``end`` ci sono solo spazi/EOF (nessuna modifica)."""
    tail = data[end:]
    return tail.strip(b" \r\n\t\x00") == b""


def find_signatures(data: bytes) -> list[PadesSignature]:
    """Individua tutte le firme PAdES e i document-timestamp nel PDF."""
    sigs: list[PadesSignature] = []
    n = len(data)
    for m in _BR_RE.finditer(data):
        a, b, c, d = (int(m.group(i)) for i in range(1, 5))
        # validita' minima degli offset
        if a < 0 or b < 0 or c < 0 or d < 0 or a + b > n or c + d > n or c < a + b:
            continue
        signed_bytes = data[a : a + b] + data[c : c + d]

        # il DER della firma sta nel "buco" tra i due segmenti, come stringa <hex>
        gap = data[a + b : c]
        lt = gap.find(b"<")
        gt = gap.rfind(b">")
        if lt < 0 or gt < 0 or gt <= lt:
            continue
        hexstr = re.sub(rb"\s", b"", gap[lt + 1 : gt])
        # tolleranza per hex dispari (padding con zeri)
        if len(hexstr) % 2:
            hexstr = hexstr[:-1]

        # contesto del dizionario di firma: la testata (/Type /SubFilter) sta
        # subito prima del "buco" /Contents (che inizia a a+b); il /ByteRange
        # segue dopo c. Cerco in entrambe le zone, saltando i ~16KB di hex.
        head = data[max(0, (a + b) - 4000) : a + b]
        tail = data[c : min(n, c + 400)]
        ctx = head + tail
        sf_m = _SUBFILTER_RE.search(ctx)
        sub_filter = sf_m.group(1).decode("latin-1") if sf_m else ""
        is_ts = sub_filter == _TS_SUBFILTER or (b"DocTimeStamp" in ctx)

        sig = PadesSignature(
            signed_data=None,
            signed_bytes=signed_bytes,
            sub_filter=sub_filter,
            is_doc_timestamp=is_ts,
            covers_whole_document=(a == 0 and _trailing_is_blank(data, c + d)),
            byte_range=(a, b, c, d),
        )
        try:
            der = binascii.unhexlify(hexstr)
        except (binascii.Error, ValueError) as exc:
            sig.error = f"Contenuto della firma illeggibile: {exc}"
            sigs.append(sig)
            continue
        try:
            ci = asn1cms.ContentInfo.load(der)
            sig.content_info = ci
            sig.signed_data = cms.get_signed_data(ci)
        except Exception as exc:  # noqa: BLE001
            sig.error = f"Busta CMS della firma non valida: {exc}"
        sigs.append(sig)

    # ordina per posizione del secondo segmento (le firme piu' recenti coprono di piu')
    sigs.sort(key=lambda s: s.byte_range[2] + s.byte_range[3])
    return sigs
