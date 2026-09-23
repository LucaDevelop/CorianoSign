"""App predefinita per i .p7m su Windows (via registro).

Controlla/associa CorianoSign come handler predefinito dei file ``.p7m``.

Nota: su Windows 10/11 la scelta dell'utente (``FileExts\\.p7m\\UserChoice``) è
protetta da hash e non è sovrascrivibile da un programma. Quindi:
  * il controllo legge PRIMA la UserChoice dell'utente, poi l'associazione
    "classica" ``HKCU\\Software\\Classes\\.p7m``;
  * l'impostazione scrive l'associazione classica (efficace quando l'utente non
    ha ancora scelto un'app per i .p7m) e notifica Explorer. Se esiste già una
    UserChoice verso un'altra app, va cambiata dall'utente in Impostazioni di
    Windows (l'installer resta il metodo consigliato in quel caso).
"""
from __future__ import annotations

import os
import sys

PROGID = "CorianoSign.p7m"


def available() -> bool:
    """True solo su Windows nell'app impacchettata."""
    return os.name == "nt" and getattr(sys, "frozen", False)


def _read(hive, subkey, name=""):
    import winreg
    try:
        with winreg.OpenKey(hive, subkey) as k:
            val, _ = winreg.QueryValueEx(k, name)
            return val
    except OSError:
        return None


def current_handler() -> str | None:
    """ProgId attualmente associato ai .p7m (UserChoice o associazione classica)."""
    import winreg
    uc = _read(winreg.HKEY_CURRENT_USER,
               r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.p7m\UserChoice",
               "ProgId")
    if uc:
        return uc
    return (_read(winreg.HKEY_CURRENT_USER, r"Software\Classes\.p7m")
            or _read(winreg.HKEY_CLASSES_ROOT, r".p7m"))


def is_default() -> bool:
    return current_handler() == PROGID


def _register_progid() -> None:
    """Registra il ProgId CorianoSign.p7m e lo aggiunge tra gli handler dei .p7m.

    Serve perché l'app COMPAIA nella finestra «Apri con» di Windows. Non imposta
    la predefinita (su Win10/11 quella la sceglie l'utente).
    """
    import winreg
    exe = sys.executable
    base = r"Software\Classes\%s" % PROGID
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base) as k:
        winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "File firmato PKCS#7 (CAdES)")
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\DefaultIcon") as k:
        winreg.SetValueEx(k, "", 0, winreg.REG_SZ, f'"{exe}",0')
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\shell\open\command") as k:
        winreg.SetValueEx(k, "", 0, winreg.REG_SZ, f'"{exe}" "%1"')
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                          r"Software\Classes\.p7m\OpenWithProgids") as k:
        winreg.SetValueEx(k, PROGID, 0, winreg.REG_SZ, "")  # REG_SZ = stringa


def set_default() -> bool:
    """Prova a impostare la predefinita scrivendo l'associazione classica.

    Funziona nel caso comune (nessuna scelta utente preesistente); su Win10/11
    con una UserChoice già impostata NON è possibile da programma: in quel caso
    ritorna False e si usa ``open_with_dialog`` (la finestra nativa «Apri con»).
    """
    import winreg
    try:
        _register_progid()
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.p7m") as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, PROGID)
        try:
            import ctypes
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x0000, None, None)
        except Exception:  # noqa: BLE001
            pass
        return is_default()
    except Exception:  # noqa: BLE001
        return False
