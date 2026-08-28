"""Genera un fixture CAdES-T: allega una marca temporale RFC 3161 a chained.txt.p7m.

Richiede: chained.txt.p7m, tsa_cert.pem, tsa_key.pem, ca_cert.pem, tsa.cnf
Produce:  chained_ts.txt.p7m
"""
import subprocess
import sys
from pathlib import Path

from asn1crypto import cms, tsp

HERE = Path(__file__).parent


def main() -> int:
    data = (HERE / "chained.txt.p7m").read_bytes()
    ci = cms.ContentInfo.load(data)
    sd = ci["content"]
    si = sd["signer_infos"][0]

    # valore della firma da marcare temporalmente
    sig_value = si["signature"].native
    (HERE / "sigval.bin").write_bytes(sig_value)

    # 1) richiesta di marca (hash sha256 del valore della firma)
    subprocess.run(
        ["openssl", "ts", "-query", "-data", str(HERE / "sigval.bin"),
         "-sha256", "-cert", "-out", str(HERE / "req.tsq")],
        check=True,
    )
    # 2) risposta della TSA (contiene il TimeStampToken)
    subprocess.run(
        ["openssl", "ts", "-reply", "-queryfile", str(HERE / "req.tsq"),
         "-signer", str(HERE / "tsa_cert.pem"), "-inkey", str(HERE / "tsa_key.pem"),
         "-chain", str(HERE / "ca_cert.pem"),
         "-out", str(HERE / "resp.tsr"), "-config", str(HERE / "tsa.cnf")],
        check=True,
        cwd=str(HERE),
    )

    resp = tsp.TimeStampResp.load((HERE / "resp.tsr").read_bytes())
    token = resp["time_stamp_token"]  # ContentInfo

    # 3) allega come attributo NON firmato id-aa-signatureTimeStampToken
    attr = cms.CMSAttribute({
        "type": "signature_time_stamp_token",
        "values": [token],
    })
    si["unsigned_attrs"] = cms.CMSAttributes([attr])

    out = HERE / "chained_ts.txt.p7m"
    out.write_bytes(ci.dump())
    print("creato", out.name, f"({out.stat().st_size} byte)")

    # pulizia file intermedi
    for tmp in ("sigval.bin", "req.tsq", "resp.tsr"):
        (HERE / tmp).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
