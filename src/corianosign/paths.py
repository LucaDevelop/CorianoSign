"""Percorsi delle cartelle applicative (cache Trusted List, config).

Rispetta le convenzioni per piattaforma:
  * macOS   -> ~/Library/Application Support/CorianoSign
  * Windows -> %LOCALAPPDATA%\\CorianoSign
  * Linux   -> $XDG_DATA_HOME/CorianoSign (fallback ~/.local/share)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from . import __app_name__


def data_dir() -> Path:
    """Cartella per dati persistenti (cache TSL)."""
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    d = base / __app_name__
    d.mkdir(parents=True, exist_ok=True)
    return d


def trust_cache_dir() -> Path:
    d = data_dir() / "trust"
    d.mkdir(parents=True, exist_ok=True)
    return d


def config_file() -> Path:
    return data_dir() / "config.json"


def bundled_resource(category: str, name: str) -> str:
    """Risolve un file impacchettato (anchor, asset) in dev e in PyInstaller.

    ``category`` es. "trust_anchors" / "assets"; ``name`` il nome file.
    """
    base = getattr(sys, "_MEIPASS", None)
    candidates = []
    if base:
        candidates.append(Path(base) / category / name)
    here = Path(__file__).resolve().parent
    # in sviluppo gli anchor stanno in packaging/<category>/
    candidates.append(here.parent.parent / "packaging" / category / name)
    candidates.append(here / category / name)
    for c in candidates:
        if Path(c).is_file():
            return str(c)
    return ""
