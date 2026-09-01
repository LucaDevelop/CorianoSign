"""Test della logica di auto-aggiornamento (senza rete)."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser

from corianosign import updater


def test_parse_e_confronto_versioni():
    assert updater.parse_version("v1.10.2") == (1, 10, 2)
    assert updater.parse_version("2.0") == (2, 0)
    assert updater.is_newer("0.2.0", "0.1.0")
    assert not updater.is_newer("0.1.0", "0.1.0")
    # 1.2 NON è più recente di 1.10 (confronto numerico, non lessicale)
    assert not updater.is_newer("1.2", "1.10")
    assert updater.is_newer("1.10", "1.2")


def test_pick_asset_per_piattaforma():
    assets = [
        {"name": "CorianoSign-1.0.0-macos.zip", "browser_download_url": "u", "size": 1},
        {"name": "CorianoSign-1.0.0-macos.zip.sig", "browser_download_url": "u", "size": 64},
        {"name": "CorianoSign-1.0.0-windows.zip", "browser_download_url": "u", "size": 2},
        {"name": "CorianoSign-1.0.0-windows.zip.sig", "browser_download_url": "u", "size": 64},
    ]
    arc, sig = updater._pick_asset(assets, "macos")
    assert arc["name"].endswith("macos.zip") and sig["name"].endswith("macos.zip.sig")
    arc, sig = updater._pick_asset(assets, "windows")
    assert arc["name"].endswith("windows.zip") and sig["name"].endswith("windows.zip.sig")


def test_verifica_firma(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(
        ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    monkeypatch.setattr(updater, "UPDATE_PUBKEY_HEX", pub_hex)

    data = b"archivio di aggiornamento"
    sig = priv.sign(data)
    assert updater.verify_signature(data, sig)
    assert not updater.verify_signature(data + b"x", sig)   # dati manomessi
    # ultimo byte SEMPRE diverso dall'originale (XOR), cosi' la firma e'
    # davvero rotta: usare b"\x00" era flaky (~1/256) se il byte era gia' 0x00
    assert not updater.verify_signature(data, sig[:-1] + bytes([sig[-1] ^ 0x01]))


def test_verifica_firma_senza_chiave(monkeypatch):
    # senza chiave pubblica la verifica deve fallire (fail-closed)
    monkeypatch.setattr(updater, "UPDATE_PUBKEY_HEX", "")
    assert not updater.verify_signature(b"x", b"y" * 64)
