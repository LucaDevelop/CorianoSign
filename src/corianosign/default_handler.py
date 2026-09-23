"""App predefinita per i .p7m — dispatcher per sistema operativo.

Espone ``available`` / ``is_default`` / ``set_default`` indipendenti dalla
piattaforma, delegando all'implementazione macOS o Windows. Su altri sistemi
(o da sorgente, non impacchettato) le funzioni sono no-op sicure.
"""
from __future__ import annotations

import os
import sys


def _impl():
    if sys.platform == "darwin":
        from . import macos_default_handler as m
        return m
    if os.name == "nt":
        from . import windows_default_handler as m
        return m
    return None


def available() -> bool:
    try:
        impl = _impl()
        return bool(impl and impl.available())
    except Exception:  # noqa: BLE001
        return False


def is_default() -> bool:
    try:
        impl = _impl()
        return bool(impl and impl.is_default())
    except Exception:  # noqa: BLE001
        return False


def set_default() -> bool:
    try:
        impl = _impl()
        return bool(impl and impl.set_default())
    except Exception:  # noqa: BLE001
        return False


def open_with_dialog() -> bool:
    """Windows: mostra la finestra nativa «Apri con» per i .p7m. Altrove no-op."""
    try:
        impl = _impl()
        fn = getattr(impl, "open_with_dialog", None)
        return bool(fn and fn())
    except Exception:  # noqa: BLE001
        return False
