"""Gestione dell'app predefinita per i .p7m su macOS (via LaunchServices).

macOS non ha un installer con schermate (l'app si trascina in Applicazioni),
quindi la richiesta "vuoi rendere CorianoSign l'app predefinita per i .p7m?"
si fa al primo avvio (vedi gui.run). Qui ci sono i tre mattoncini:
``is_default`` / ``set_default`` / ``available``.

Usa ``ctypes`` sulle API LaunchServices (deprecate ma funzionanti) per non
introdurre dipendenze come PyObjC. Tutto è racchiuso in try/except: su
piattaforme non-macOS o in caso di errore le funzioni degradano a no-op.
"""
from __future__ import annotations

import sys

_UTF8 = 0x08000100
_ROLES_ALL = 0xFFFFFFFF


def _lib():
    import ctypes
    import ctypes.util

    cf = ctypes.CDLL(ctypes.util.find_library("CoreFoundation"))
    ls = ctypes.CDLL(ctypes.util.find_library("CoreServices"))

    cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
    cf.CFStringGetCStringPtr.restype = ctypes.c_char_p
    cf.CFStringGetCStringPtr.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFStringGetCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32]
    cf.CFRelease.restype = None
    cf.CFRelease.argtypes = [ctypes.c_void_p]
    cf.CFBundleGetMainBundle.restype = ctypes.c_void_p
    cf.CFBundleGetIdentifier.restype = ctypes.c_void_p
    cf.CFBundleGetIdentifier.argtypes = [ctypes.c_void_p]

    ls.UTTypeCreatePreferredIdentifierForTag.restype = ctypes.c_void_p
    ls.UTTypeCreatePreferredIdentifierForTag.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    ls.LSCopyDefaultRoleHandlerForContentType.restype = ctypes.c_void_p
    ls.LSCopyDefaultRoleHandlerForContentType.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    ls.LSSetDefaultRoleHandlerForContentType.restype = ctypes.c_int32
    ls.LSSetDefaultRoleHandlerForContentType.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
    return ctypes, cf, ls


def _cfstr(ctypes, cf, s: str):
    return cf.CFStringCreateWithCString(None, s.encode("utf-8"), _UTF8)


def _tostr(ctypes, cf, ref) -> str | None:
    if not ref:
        return None
    p = cf.CFStringGetCStringPtr(ref, _UTF8)
    if p:
        return p.decode("utf-8")
    buf = ctypes.create_string_buffer(512)
    if cf.CFStringGetCString(ref, buf, 512, _UTF8):
        return buf.value.decode("utf-8")
    return None


def _bundle_id(ctypes, cf) -> str | None:
    """Bundle id dell'app in esecuzione (None se non impacchettata)."""
    main = cf.CFBundleGetMainBundle()
    if not main:
        return None
    # get-rule: NON rilasciare (CFBundleGetIdentifier non trasferisce ownership)
    return _tostr(ctypes, cf, cf.CFBundleGetIdentifier(main))


def _p7m_uti(ctypes, cf, ls):
    """UTI (create-rule: da rilasciare) associato all'estensione .p7m."""
    tagclass = _cfstr(ctypes, cf, "public.filename-extension")
    ext = _cfstr(ctypes, cf, "p7m")
    try:
        return ls.UTTypeCreatePreferredIdentifierForTag(tagclass, ext, None)
    finally:
        cf.CFRelease(tagclass)
        cf.CFRelease(ext)


def available() -> bool:
    """True solo su macOS e nell'app impacchettata (.app con bundle id)."""
    if sys.platform != "darwin" or not getattr(sys, "frozen", False):
        return False
    try:
        ctypes, cf, ls = _lib()
        return bool(_bundle_id(ctypes, cf))
    except Exception:  # noqa: BLE001
        return False


def current_handler() -> str | None:
    """Bundle id dell'app predefinita per i .p7m (None se nessuna)."""
    try:
        ctypes, cf, ls = _lib()
        uti = _p7m_uti(ctypes, cf, ls)
        try:
            h = ls.LSCopyDefaultRoleHandlerForContentType(uti, _ROLES_ALL)
            try:
                return _tostr(ctypes, cf, h)
            finally:
                if h:
                    cf.CFRelease(h)
        finally:
            if uti:
                cf.CFRelease(uti)
    except Exception:  # noqa: BLE001
        return None


def is_default() -> bool:
    """True se CorianoSign è già l'app predefinita per i .p7m."""
    try:
        ctypes, cf, ls = _lib()
        me = _bundle_id(ctypes, cf)
        cur = current_handler()
        return bool(me and cur and me.lower() == cur.lower())
    except Exception:  # noqa: BLE001
        return False


def set_default() -> bool:
    """Imposta CorianoSign come app predefinita per i .p7m. True se riuscito."""
    if sys.platform != "darwin":
        return False
    try:
        ctypes, cf, ls = _lib()
        me = _bundle_id(ctypes, cf)
        if not me:
            return False
        uti = _p7m_uti(ctypes, cf, ls)
        bid = _cfstr(ctypes, cf, me)
        try:
            status = ls.LSSetDefaultRoleHandlerForContentType(uti, _ROLES_ALL, bid)
            return status == 0
        finally:
            cf.CFRelease(uti)
            cf.CFRelease(bid)
    except Exception:  # noqa: BLE001
        return False
