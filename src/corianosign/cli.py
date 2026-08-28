"""Interfaccia a riga di comando per verifica ed estrazione (headless).

Esempi:
    corianosign-cli verifica documento.pdf.p7m
    corianosign-cli estrai documento.pdf.p7m -o documento.pdf
    corianosign-cli aggiorna-trust --tutti-eu
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __app_name__, __version__, trust, verifier
from .model import TrustStatus
from .validation import RevocationMode


def _fmt_dt(dt) -> str:
    return dt.strftime("%d/%m/%Y %H:%M:%S UTC") if dt else "n/d"


_TRUST_LABEL = {
    TrustStatus.TRUSTED: "FIDATO (CA accreditata)",
    TrustStatus.UNTRUSTED: "NON fidato",
    TrustStatus.REVOKED: "REVOCATO",
    TrustStatus.ERROR: "errore validazione",
    TrustStatus.NOT_CHECKED: "non verificato",
}


def _cmd_verifica(args) -> int:
    store = trust.load_trust_store()
    if not store and args.check_trust:
        print("[!] Nessuna Trusted List in cache. Esegui prima 'aggiorna-trust'.",
              file=sys.stderr)
    opts = verifier.VerifyOptions(
        check_trust=args.check_trust,
        revocation_mode=RevocationMode.HARD_FAIL if args.revoca_stringente
        else RevocationMode.SOFT_FAIL,
        allow_fetching=not args.offline,
    )
    res = verifier.analyze_file(
        args.file, store.certificates, opts, store.tsa_certificates
    )

    if res.parse_errors:
        for e in res.parse_errors:
            print(f"[ERRORE] {e}", file=sys.stderr)
        return 2

    print(f"File:       {res.source_path}")
    print(f"Contenuto:  {res.content_filename} ({len(res.content)} byte)")
    print(f"Firme:      {len(res.signatures)} (livelli annidamento: {res.nested_levels})")
    print("-" * 60)
    for i, s in enumerate(res.signatures, 1):
        print(f"Firma #{i}: {s.signer.display_name}  [{s.level}]")
        if s.signer.organization:
            print(f"  Organizzazione: {s.signer.organization}")
        if s.signer.fiscal_code:
            print(f"  Identificativo: {s.signer.fiscal_code}")
        print(f"  Emesso da:      {s.signer.issuer_cn}")
        print(f"  Data firma:     {_fmt_dt(s.signer.signing_time)}")
        print(f"  Algoritmi:      {s.signer.digest_algorithm} / {s.signer.signature_algorithm}")
        print(f"  Cripto valida:  {'SI' if s.crypto_valid and s.digest_match else 'NO'}")
        print(f"  Trust:          {_TRUST_LABEL[s.trust_status]}"
              + (f" -> {s.trust_anchor_cn}" if s.trust_anchor_cn else ""))
        if s.revocation_info:
            print(f"  Revoca:         {s.revocation_info}")
        if s.has_timestamp:
            if s.timestamp_valid and s.timestamp_trust is TrustStatus.TRUSTED:
                tsl = "valida (TSA accreditata)"
            elif s.timestamp_valid:
                tsl = "valida (TSA non accreditata)"
            else:
                tsl = "NON verificata"
            print(f"  Marca temporale:{_fmt_dt(s.timestamp_time)} — {tsl}"
                  + (f" · {s.timestamp_tsa}" if s.timestamp_tsa else ""))
        else:
            print("  Marca temporale: assente (CAdES-BES)")
        if s.embedded_certs or s.embedded_crls or s.embedded_ocsps:
            ltv = " (usato per la revoca)" if s.ltv_used else ""
            print(f"  Materiale LT:   {s.embedded_certs} cert, {s.embedded_crls} CRL, "
                  f"{s.embedded_ocsps} OCSP incapsulati{ltv}")
        if s.archive_timestamps:
            imp = (f", {s.archive_imprint_verified} con impronta ricalcolata"
                   if s.archive_imprint_verified else "")
            print(f"  Archive-ts:     {s.archive_valid}/{s.archive_timestamps} validi{imp}"
                  + (f" · {_fmt_dt(s.archive_time)}" if s.archive_time else ""))
        verdict = "VALIDA" if s.is_valid else "NON valida / non pienamente verificata"
        print(f"  ESITO:          {verdict}")
        for w in s.warnings:
            print(f"    - {w}")
        for e in s.errors:
            print(f"    [!] {e}")
        print()

    return 0 if res.all_valid else 1


def _cmd_estrai(args) -> int:
    res = verifier.analyze_file(args.file, [], verifier.VerifyOptions(check_trust=False))
    if res.parse_errors:
        for e in res.parse_errors:
            print(f"[ERRORE] {e}", file=sys.stderr)
        return 2
    if not res.content:
        print("[ERRORE] Nessun contenuto da estrarre (firma detached?).", file=sys.stderr)
        return 2
    out = Path(args.output) if args.output else Path(res.content_filename)
    out.write_bytes(res.content)
    print(f"Estratto: {out} ({len(res.content)} byte)")
    if not args.no_verifica:
        ok = res.any_crypto_valid
        print(f"Firma crittografica: {'valida' if ok else 'NON valida'}")
    return 0


def _cmd_aggiorna_trust(args) -> int:
    territories = ["*"] if args.tutti_eu else (args.paesi or ["IT"])
    store = trust.update_trust_store(
        territories,
        progress=lambda m: print("  " + m),
        verify_signatures=not args.no_verifica_firma,
    )
    auth = "autentiche" if store.authentic else "NON pienamente autenticate"
    print(f"CA fidate totali: {len(store)} (territori: {', '.join(store.territories)})")
    print(f"Autenticità liste: {auth}"
          + (f" · firmatario LOTL: {store.lotl_signer}" if store.lotl_signer else ""))
    return 0 if len(store) else 1


def _wsdl_from_args(args) -> str:
    from . import aruba
    if getattr(args, "wsdl", None):
        return args.wsdl
    return aruba.WSDL_DEMO if getattr(args, "demo", False) else aruba.WSDL_PROD


def _cmd_aruba_info(args) -> int:
    from . import aruba
    wsdl = _wsdl_from_args(args)
    print(f"Endpoint: {wsdl}\n")
    try:
        print("Versione servizio:", aruba.get_version(wsdl))
    except aruba.ArubaError as exc:
        print(f"[!] {exc}", file=sys.stderr)
    try:
        print("\n" + aruba.inspect(wsdl))
    except aruba.ArubaError as exc:
        print(f"[ERRORE] {exc}", file=sys.stderr)
        return 2
    return 0


def _secret(env: str, prompt: str) -> str:
    import re
    val = os.environ.get(env)
    if not val:
        val = getpass.getpass(prompt)
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", val):
        print("  [!] rilevato un carattere di controllo nell'input (es. Backspace): "
              "verrà ignorato. Se la firma fallisce per credenziali, reinserisci "
              "il valore SENZA correggere con Backspace.", file=sys.stderr)
    return val


def _cmd_firma_remota(args) -> int:
    from . import aruba
    src = Path(args.file)
    if not src.is_file():
        print(f"[ERRORE] File non trovato: {src}", file=sys.stderr)
        return 2
    data = src.read_bytes()
    wsdl = _wsdl_from_args(args)

    # segreti: mai da argv (visibili nella lista processi)
    user_pwd = _secret("ARUBA_PWD", "Password di firma Aruba: ")
    otp = _secret("ARUBA_OTP", "Codice OTP: ")

    common = dict(
        user=args.user, user_pwd=user_pwd, otp=otp, wsdl_url=wsdl,
        cert_id=args.cert_id, type_otp_auth=args.otp_type, type_hsm=args.hsm,
        signature_level=args.livello,
    )
    try:
        if args.cades:
            print("Firma CAdES (.p7m) via Aruba…")
            signed = aruba.sign_p7m(data, **common)
            out = Path(args.output) if args.output else src.with_suffix(src.suffix + ".p7m")
        else:
            visible = None
            if args.visibile:
                img = Path(args.immagine).read_bytes() if args.immagine else None
                x1, y1, x2, y2 = args.pos
                visible = aruba.VisibleSignature(
                    page=args.pagina, leftx=x1, lefty=y1, rightx=x2, righty=y2,
                    testo=args.testo or "", reason=args.motivo or "",
                    location=args.luogo or "", image_bin=img,
                )
            print("Firma PAdES" + (" VISIBILE" if visible else "") + " via Aruba…")
            signed = aruba.sign_pdf(data, visible=visible, **common)
            out = Path(args.output) if args.output else src.with_name(src.stem + "-firmato.pdf")
    except aruba.ArubaError as exc:
        print(f"[ERRORE] {exc}", file=sys.stderr)
        return 1

    out.write_bytes(signed)
    print(f"\n✓ File firmato salvato: {out} ({len(signed)} byte)")

    # chiusura del cerchio: ri-verifica il .p7m col nostro verificatore
    if args.cades:
        store = trust.load_trust_store()
        res = verifier.analyze_file(str(out), store.certificates,
                                    verifier.VerifyOptions(check_trust=bool(len(store)),
                                                           allow_fetching=False),
                                    store.tsa_certificates)
        if res.signatures:
            s = res.signatures[0]
            print(f"  Ri-verifica: firmatario={s.signer.display_name} "
                  f"livello={s.level} cripto={'OK' if s.crypto_valid and s.digest_match else 'NO'}")
    else:
        ok = signed[:5] == b"%PDF-"
        print(f"  PDF firmato ({'valido' if ok else 'formato inatteso'}). "
              "Verificalo in un lettore PDF; la verifica PAdES nell'app è un passo successivo.")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="corianosign-cli",
                                description=f"{__app_name__} {__version__} - verifica p7m")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verifica", help="verifica firma/e di un .p7m")
    v.add_argument("file")
    v.add_argument("--no-trust", dest="check_trust", action="store_false",
                   help="salta la validazione della catena verso le Trusted List")
    v.add_argument("--offline", action="store_true",
                   help="non scaricare CRL/OCSP durante la validazione")
    v.add_argument("--revoca-stringente", action="store_true",
                   help="fallisce se la revoca non e' verificabile (hard-fail)")
    v.set_defaults(func=_cmd_verifica)

    e = sub.add_parser("estrai", help="estrae il documento contenuto")
    e.add_argument("file")
    e.add_argument("-o", "--output", help="percorso file di output")
    e.add_argument("--no-verifica", action="store_true")
    e.set_defaults(func=_cmd_estrai)

    t = sub.add_parser("aggiorna-trust", help="scarica/aggiorna le Trusted List")
    t.add_argument("--paesi", nargs="+", help="codici paese (es. IT FR DE)")
    t.add_argument("--tutti-eu", action="store_true", help="tutte le TSL europee")
    t.add_argument("--no-verifica-firma", action="store_true",
                   help="non verificare la firma XAdES delle liste (sconsigliato)")
    t.set_defaults(func=_cmd_aggiorna_trust)

    # --- firma remota Aruba (SPIKE) --- #
    ai = sub.add_parser("aruba-info",
                        help="verifica connettività ed elenca le operazioni del servizio Aruba")
    ai.add_argument("--wsdl", help="URL WSDL personalizzato")
    ai.add_argument("--demo", action="store_true", help="usa l'endpoint demo Aruba")
    ai.set_defaults(func=_cmd_aruba_info)

    fr = sub.add_parser("firma-remota", help="firma un file con la firma remota Aruba (OTP)")
    fr.add_argument("file")
    fr.add_argument("--user", required=True, help="username della firma remota Aruba")
    fr.add_argument("--cades", action="store_true",
                    help="firma CAdES (.p7m) invece di PAdES (PDF)")
    fr.add_argument("--wsdl", help="URL WSDL personalizzato")
    fr.add_argument("--demo", action="store_true", help="usa l'endpoint demo Aruba")
    fr.add_argument("--cert-id", default="AS0", help="certID (default AS0)")
    fr.add_argument("--otp-type", required=True,
                    help="typeOtpAuth del tuo contratto (es. 'demo', dominio azienda…)")
    fr.add_argument("--hsm", default="COSIGN", help="typeHSM (default COSIGN)")
    fr.add_argument("--livello", help="signatureLevel Aruba (es. B, T, LT, LTA)")
    # PAdES visibile
    fr.add_argument("--visibile", action="store_true", help="firma PAdES visibile")
    fr.add_argument("--pagina", type=int, default=1, help="pagina della firma visibile")
    fr.add_argument("--pos", nargs=4, type=int, metavar=("X1", "Y1", "X2", "Y2"),
                    default=[50, 50, 300, 130], help="riquadro firma (punti PDF)")
    fr.add_argument("--testo", help="testo nel riquadro firma")
    fr.add_argument("--motivo", help="reason")
    fr.add_argument("--luogo", help="location")
    fr.add_argument("--immagine", help="immagine/logo del riquadro (PNG/JPG)")
    fr.add_argument("-o", "--output", help="percorso file firmato di output")
    fr.set_defaults(func=_cmd_firma_remota)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
