# -*- mode: python ; coding: utf-8 -*-
"""Spec PyInstaller per CorianoSign (macOS e Windows).

Uso:
    pyinstaller packaging/corianosign.spec

Produce:
    * macOS   -> dist/CorianoSign.app  (bundle .app, universal2 se il Python lo e')
    * Windows -> dist/CorianoSign/CorianoSign.exe  (cartella onedir)

La Trusted List NON viene inclusa: e' scaricata a runtime nella cartella dati
utente al primo «Aggiorna Trusted List».
"""
import os
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# SPECPATH e' iniettato da PyInstaller: cartella di questo file .spec
_ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
_ENTRY = os.path.join(_ROOT, "src", "corianosign", "__main__.py")
_SRC = os.path.join(_ROOT, "src")

# icona: .ico su Windows, .icns su macOS
_ICON = os.path.join(
    _ROOT, "packaging",
    "CorianoSign.ico" if sys.platform == "win32" else "CorianoSign.icns",
)
# PNG dell'icona per la finestra/dock (caricata a runtime da assets/)
_ICON_PNG = os.path.join(_ROOT, "packaging", "icons", "icon_256.png")
# immagine di firma grafica predefinita (caricata a runtime da assets/)
_SIGN_PNG = os.path.join(_ROOT, "packaging", "assets", "default_signature.png")


def _read_version() -> str:
    """Legge __version__ da src/corianosign/__init__.py (senza importare il pkg)."""
    init = os.path.join(_SRC, "corianosign", "__init__.py")
    with open(init, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("__version__"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return "0.0.0"


_VERSION = _read_version()

block_cipher = None

hidden = ["corianosign.updater", "corianosign.aruba", "corianosign.pades"]
# alcune sottodipendenze sono importate dinamicamente
for pkg in ("pyhanko_certvalidator", "asn1crypto", "oscrypto", "signxml", "zeep", "tzdata"):
    hidden += collect_submodules(pkg)

# dati di signxml (schemi XML), zeep (template WSDL), tzdata (fusi) e anchor OJ
_extra_datas = (
    collect_data_files("signxml")
    + collect_data_files("zeep")
    + collect_data_files("tzdata")
)
_extra_datas.append(
    (os.path.join(_ROOT, "packaging", "trust_anchors", "eu_lotl_signers.pem"),
     "trust_anchors")
)

a = Analysis(
    [_ENTRY],
    pathex=[_SRC],
    binaries=[],
    datas=[(_ICON_PNG, "assets"), (_SIGN_PNG, "assets")] + _extra_datas,
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        # moduli Qt non usati: alleggeriscono il bundle
        "PySide6.QtQml",
        "PySide6.QtQuick",
        "PySide6.Qt3DCore",
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
        "PySide6.QtMultimedia",
        "PySide6.QtCharts",
        "PySide6.QtDataVisualization",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CorianoSign",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,  # universal2 se l'interprete lo supporta
    codesign_identity=None,
    entitlements_file=None,
    icon=_ICON if os.path.isfile(_ICON) else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="CorianoSign",
)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="CorianoSign.app",
        icon=_ICON if os.path.isfile(_ICON) else None,
        bundle_identifier="it.coriano.corianosign",
        info_plist={
            "CFBundleName": "CorianoSign",
            "CFBundleDisplayName": "CorianoSign",
            "CFBundleShortVersionString": _VERSION,
            "CFBundleVersion": _VERSION,
            "NSHumanReadableCopyright": "CorianoSign",
            "NSHighResolutionCapable": True,
            # associazione tipo file .p7m
            "CFBundleDocumentTypes": [
                {
                    "CFBundleTypeName": "File firmato PKCS#7 (CAdES)",
                    "CFBundleTypeExtensions": ["p7m"],
                    "CFBundleTypeRole": "Viewer",
                    "LSHandlerRank": "Alternate",
                    "CFBundleTypeIconFile": "CorianoSign.icns",
                }
            ],
        },
    )
