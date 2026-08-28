"""Genera fixture CAdES-LT e CAdES-LTA a partire da chained_ts.txt.p7m.

Aggiunge:
  * certificate-values (leaf + CA + TSA);
  * revocation-values  (una CRL firmata dalla CA);
  * (LTA) un archive-timestamp.

Produce: chained_lt.txt.p7m, chained_lta.txt.p7m
Richiede: chained_ts.txt.p7m, ca_cert.pem, ca_key.pem, tsa_cert.pem, tsa_key.pem, tsa.cnf
"""
import datetime
import subprocess
import sys
from pathlib import Path

from asn1crypto import cms, core, crl, pem, tsp, x509
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent.parent / "src"))
from corianosign import archive_ts  # noqa: E402
from corianosign import cms as ccms  # noqa: E402
from corianosign.cades_lt import (  # noqa: E402
    CertificateValues,
    OID_ARCHIVE_TS_V3,
    OID_CERT_VALUES,
    OID_REVOCATION_VALUES,
    RevocationValues,
)


def _load_asn1_cert(path: Path) -> x509.Certificate:
    return x509.Certificate.load(pem.unarmor(path.read_bytes())[2])


def _build_crl() -> crl.CertificateList:
    ca_cert = cx509.load_pem_x509_certificate((HERE / "ca_cert.pem").read_bytes())
    ca_key = load_pem_private_key((HERE / "ca_key.pem").read_bytes(), password=None)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        cx509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - datetime.timedelta(days=1))
        .next_update(now + datetime.timedelta(days=90))
        .add_extension(cx509.CRLNumber(1), critical=False)
    )
    crl_obj = builder.sign(ca_key, hashes.SHA256())
    der = crl_obj.public_bytes(serialization.Encoding.DER)
    return crl.CertificateList.load(der)


def _make_archive_ts(payload: bytes) -> cms.ContentInfo:
    (HERE / "arc.bin").write_bytes(payload)
    subprocess.run(
        ["openssl", "ts", "-query", "-data", str(HERE / "arc.bin"),
         "-sha256", "-cert", "-out", str(HERE / "arc.tsq")],
        check=True,
    )
    subprocess.run(
        ["openssl", "ts", "-reply", "-queryfile", str(HERE / "arc.tsq"),
         "-signer", str(HERE / "tsa_cert.pem"), "-inkey", str(HERE / "tsa_key.pem"),
         "-chain", str(HERE / "ca_cert.pem"),
         "-out", str(HERE / "arc.tsr"), "-config", str(HERE / "tsa.cnf")],
        check=True, cwd=str(HERE),
    )
    resp = tsp.TimeStampResp.load((HERE / "arc.tsr").read_bytes())
    token = resp["time_stamp_token"]
    for tmp in ("arc.bin", "arc.tsq", "arc.tsr"):
        (HERE / tmp).unlink(missing_ok=True)
    return token


def _attr(oid: str, value) -> cms.CMSAttribute:
    # l'OID non è nel registro di asn1crypto -> values è SetOfAny
    return cms.CMSAttribute({
        "type": cms.CMSAttributeType(oid),
        "values": [core.Any(value)],
    })


def main() -> int:
    ci = cms.ContentInfo.load((HERE / "chained_ts.txt.p7m").read_bytes())
    sd = ci["content"]
    si = sd["signer_infos"][0]

    leaf = _load_asn1_cert(HERE / "leaf_cert.pem")
    ca = _load_asn1_cert(HERE / "ca_cert.pem")
    tsa = _load_asn1_cert(HERE / "tsa_cert.pem")

    cert_values = CertificateValues([leaf, ca, tsa])
    rev_values = RevocationValues({"crl_vals": [_build_crl()]})

    existing = list(si["unsigned_attrs"])
    lt_attrs = existing + [
        _attr(OID_CERT_VALUES, cert_values),
        _attr(OID_REVOCATION_VALUES, rev_values),
    ]
    si["unsigned_attrs"] = cms.CMSAttributes(lt_attrs)
    out_lt = HERE / "chained_lt.txt.p7m"
    out_lt.write_bytes(ci.dump())
    print("creato", out_lt.name, f"({out_lt.stat().st_size} byte)")

    # LTA: archive-timestamp-v3 con ats-hash-index-v3 (EN 319 122)
    _ctype, econtent = ccms.extract_content(sd)
    index = archive_ts.build_ats_hash_index_v3(sd, si, "sha256")
    ats_data = archive_ts.archive_timestamp_data_v3(sd, index.dump(), "sha256", econtent)
    # marca temporale sull'archiveTimestampData (messageImprint = sha256(ats_data))
    archive_token = _make_archive_ts(ats_data)
    # incapsula l'ats-hash-index-v3 come attributo NON firmato del token
    tsi = archive_token["content"]["signer_infos"][0]
    hidx_attr = _attr(archive_ts.OID_ATS_HASH_INDEX_V3, index)
    tsi["unsigned_attrs"] = cms.CMSAttributes([hidx_attr])
    # allega la marca d'archivio alla firma esterna
    lta_attrs = lt_attrs + [_attr(OID_ARCHIVE_TS_V3, archive_token)]
    si["unsigned_attrs"] = cms.CMSAttributes(lta_attrs)
    out_lta = HERE / "chained_lta.txt.p7m"
    out_lta.write_bytes(ci.dump())
    print("creato", out_lta.name, f"({out_lta.stat().st_size} byte)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
