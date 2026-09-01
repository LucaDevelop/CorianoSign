"""Interfaccia grafica PySide6 di CorianoSign."""
from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

import os
import sys

from PySide6.QtCore import QEvent, QPoint, QRect, QSize, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import (
    QAction,
    QColor,
    QDesktopServices,
    QFont,
    QGuiApplication,
    QIcon,
    QImage,
    QPainter,
    QPen,
)
from PySide6.QtWidgets import (
    QAbstractSpinBox,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from . import __app_name__, __version__, config as appconfig, trust, verifier
from .model import P7MResult, SignatureResult, TrustStatus
from .paths import bundled_resource
from .validation import RevocationMode


def _default_signature_path() -> str:
    """Percorso dell'immagine di firma predefinita (dev o pacchetto)."""
    return bundled_resource("assets", "default_signature.png")


def _signature_bytes(cfg) -> bytes:
    """Byte dell'immagine da usare nella firma grafica secondo la config."""
    mode = getattr(cfg, "sign_image_mode", "default")
    if mode == "none":
        return b""
    if mode == "custom":
        p = cfg.sign_logo_path
    else:  # "default"
        p = _default_signature_path()
    if p and Path(p).is_file():
        try:
            return Path(p).read_bytes()
        except OSError:
            return b""
    return b""

try:
    from PySide6.QtPdf import QPdfDocument
    _HAS_QTPDF = True
except Exception:  # noqa: BLE001
    QPdfDocument = None  # type: ignore
    _HAS_QTPDF = False

# --------------------------------------------------------------------------- #
# Palette / colori esito
# --------------------------------------------------------------------------- #
_OK = "#1a7f37"
_WARN = "#9a6700"
_BAD = "#cf222e"
_MUTED = "#57606a"

_TRUST_TEXT = {
    TrustStatus.TRUSTED: ("Certificato di CA accreditata (Trusted List)", _OK),
    TrustStatus.UNTRUSTED: ("CA non riconosciuta / catena incompleta", _BAD),
    TrustStatus.REVOKED: ("Certificato REVOCATO", _BAD),
    TrustStatus.ERROR: ("Impossibile validare la catena", _WARN),
    TrustStatus.NOT_CHECKED: ("Validazione catena non eseguita", _MUTED),
}


def _fmt_dt(dt) -> str:
    return dt.strftime("%d/%m/%Y %H:%M:%S UTC") if dt else "non disponibile"


def _signing_time_str(tz_name: str) -> str:
    """Ora corrente nel fuso indicato, nel formato atteso da Aruba.

    Aruba ArubaSignService accetta ``signingTime`` SOLO come 'dd/MM/yyyy HH:mm:ss'
    (verificato sul servizio reale: altri formati -> KO 0002 'Wrong Signing Time';
    il valore non è vincolato all'ora del server).
    """
    try:
        from zoneinfo import ZoneInfo
        now = datetime.now(ZoneInfo(tz_name))
    except Exception:  # noqa: BLE001 - fuso non valido -> ora locale di sistema
        now = datetime.now().astimezone()
    return now.strftime("%d/%m/%Y %H:%M:%S")  # es. 27/08/2026 15:47:08


def _now_in_tz(tz_name: str):
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo(tz_name))
    except Exception:  # noqa: BLE001
        return datetime.now().astimezone()


def _sig_text_lines(name: str, tz_name: str, show_datetime: bool) -> list[str]:
    """Righe del testo della firma grafica: NOME COGNOME / data / ora."""
    lines: list[str] = []
    if name.strip():
        lines.append(name.strip().upper())
    if show_datetime:
        now = _now_in_tz(tz_name)
        lines.append(now.strftime("%d/%m/%Y"))
        lines.append(now.strftime("%H:%M:%S"))
    return lines


def _resource(*parts: str):
    """Risolve un file risorsa sia in sviluppo sia nel bundle PyInstaller."""
    base = getattr(sys, "_MEIPASS", None)
    candidates = []
    if base:
        candidates.append(os.path.join(base, "assets", *parts))
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, "..", "..", "packaging", "icons", *parts))
    candidates.append(os.path.join(here, "assets", *parts))
    for c in candidates:
        if os.path.isfile(c):
            return c
    return ""


def app_icon() -> QIcon:
    path = _resource("icon_256.png")
    return QIcon(path) if path else QIcon()


# --------------------------------------------------------------------------- #
# Worker in background
# --------------------------------------------------------------------------- #
class AnalyzeWorker(QThread):
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, path: str, trust_roots, options: verifier.VerifyOptions,
                 tsa_roots=None):
        super().__init__()
        self._path = path
        self._roots = trust_roots
        self._options = options
        self._tsa_roots = tsa_roots or []

    def run(self) -> None:
        try:
            res = verifier.analyze_file(
                self._path, self._roots, self._options, self._tsa_roots
            )
            self.done.emit(res)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class TrustWorker(QThread):
    progress = Signal(str)
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, territories, verify_signatures: bool = True):
        super().__init__()
        self._territories = territories
        self._verify = verify_signatures

    def run(self) -> None:
        try:
            store = trust.update_trust_store(
                self._territories,
                progress=self.progress.emit,
                verify_signatures=self._verify,
            )
            self.done.emit(store)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class UpdateCheckWorker(QThread):
    """Controlla la disponibilità di un aggiornamento dell'app in background."""

    found = Signal(object)   # updater.UpdateInfo
    none = Signal()
    failed = Signal(str)

    def run(self) -> None:
        try:
            from . import updater
            info = updater.check_for_update()
            if info is None:
                self.none.emit()
            else:
                self.found.emit(info)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class UpdateDownloadWorker(QThread):
    """Scarica e verifica l'archivio dell'aggiornamento, poi lo applica."""

    progress = Signal(int, int)   # scaricati, totali
    ready = Signal(str)           # path archivio verificato
    failed = Signal(str)

    def __init__(self, info):
        super().__init__()
        self._info = info

    def run(self) -> None:
        try:
            from . import updater
            archive = updater.download_and_verify(
                self._info, progress=lambda d, t: self.progress.emit(d, t)
            )
            self.ready.emit(str(archive))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class SignWorker(QThread):
    """Firma remota Aruba in background (non blocca la UI durante rete/OTP)."""

    done = Signal(bytes)
    failed = Signal(str)

    def __init__(self, params: dict):
        super().__init__()
        self._p = params

    def run(self) -> None:
        try:
            from . import aruba
            p = self._p
            common = dict(
                user=p["user"], user_pwd=p["pwd"], otp=p["otp"],
                wsdl_url=p["wsdl"], cert_id=p["cert_id"],
                type_otp_auth=p["otp_type"], type_hsm=p["hsm"],
                signature_level=p["level"] or None,
                signing_time=p.get("signing_time"),
            )
            if p["cades"]:
                out = aruba.sign_p7m(p["data"], **common)
                self.done.emit(out)
                return

            visible = None
            if p["want_visible"]:
                # nome dal CERTIFICATO (listCert, senza OTP); fallback: profilo
                name = aruba.fetch_signer_name(
                    p["wsdl"], p["user"], p["pwd"], p["otp_type"], p["hsm"], p["cert_id"]
                ) or p["profile_name"]
                lines = ([name.strip().upper()] if name and name.strip() else []) \
                    + p["date_lines"]
                testo = "\n".join(lines) if lines else None
                lx, ly, rx, ry = p["rect"]
                visible = aruba.VisibleSignature(
                    page=p["page"], leftx=lx, lefty=ly, rightx=rx, righty=ry,
                    testo=testo, reason=p["reason"], location=p["location"],
                    image_bin=p["image_bin"] or None, image_only=p["image_only"],
                    show_datetime=False,
                )
            out = aruba.sign_pdf(p["data"], visible=visible, **common)
            self.done.emit(out)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


# --------------------------------------------------------------------------- #
# Widget scheda firma
# --------------------------------------------------------------------------- #
def _row(label: str, value: str, color: str = "#24292f") -> QWidget:
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 1, 0, 1)
    k = QLabel(label)
    k.setStyleSheet(f"color:{_MUTED};")
    k.setFixedWidth(150)
    v = QLabel(value or "—")
    v.setStyleSheet(f"color:{color};")
    v.setWordWrap(True)
    v.setTextInteractionFlags(Qt.TextSelectableByMouse)
    lay.addWidget(k)
    lay.addWidget(v, 1)
    return w


class BusyOverlay(QWidget):
    """Velo modale a tutta finestra che blocca le interazioni durante un'attività."""

    def __init__(self, parent: QWidget, text: str = "Verifica in corso…"):
        super().__init__(parent)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setStyleSheet("BusyOverlay { background: rgba(20,24,28,150); }")
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignCenter)

        card = QFrame()
        card.setObjectName("busycard")
        card.setStyleSheet(
            "QFrame#busycard { background:#ffffff; border:1px solid #d0d7de; "
            "border-radius:14px; }"
        )
        card.setFixedWidth(320)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(28, 26, 28, 26)
        cl.setSpacing(16)

        self._label = QLabel(text)
        lf = QFont()
        lf.setPointSize(14)
        lf.setBold(True)
        self._label.setFont(lf)
        self._label.setAlignment(Qt.AlignCenter)
        self._label.setStyleSheet("color:#24292f;")
        cl.addWidget(self._label)

        bar = QProgressBar()
        bar.setRange(0, 0)  # indeterminato
        bar.setTextVisible(False)
        bar.setFixedHeight(8)
        cl.addWidget(bar)

        lay.addWidget(card)
        self.hide()

    def set_text(self, text: str) -> None:
        self._label.setText(text)

    def show_over(self, text: str = "") -> None:
        if text:
            self.set_text(text)
        parent = self.parentWidget()
        if parent is not None:
            self.setGeometry(parent.rect())
        self.raise_()
        self.show()

    def mousePressEvent(self, event):  # noqa: N802 - assorbe i click
        event.accept()

    def keyPressEvent(self, event):  # noqa: N802 - assorbe la tastiera
        event.accept()


class SignatureCard(QFrame):
    def __init__(self, index: int, sig: SignatureResult):
        super().__init__()
        self.setFrameShape(QFrame.StyledPanel)
        crypto_ok = sig.crypto_valid and sig.digest_match
        if sig.is_valid:
            border = _OK
        elif crypto_ok:
            border = _WARN
        else:
            border = _BAD
        self.setObjectName("sigcard")
        self.setStyleSheet(
            "QFrame#sigcard { border:1px solid #d0d7de; border-left:5px solid "
            + border
            + "; border-radius:8px; background:#ffffff; }"
        )
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(2)

        title = QLabel(f"Firma #{index}  —  {sig.signer.display_name}")
        tf = QFont()
        tf.setPointSize(13)
        tf.setBold(True)
        title.setFont(tf)
        lay.addWidget(title)

        # verdetto sintetico
        if sig.is_valid:
            verdict, vcolor = "✓  Firma valida e riconducibile a CA accreditata", _OK
        elif crypto_ok and sig.trust_status is TrustStatus.NOT_CHECKED:
            verdict, vcolor = "✓  Firma crittograficamente valida (trust non verificato)", _WARN
        elif crypto_ok:
            verdict, vcolor = "!  Firma integra ma catena non validata", _WARN
        else:
            verdict, vcolor = "✗  Firma NON valida", _BAD
        vlabel = QLabel(verdict)
        vlabel.setStyleSheet(f"color:{vcolor}; font-weight:600; padding:2px 0 2px 0;")
        lay.addWidget(vlabel)

        # badge livello CAdES
        lvl_desc = {
            "CAdES-BES": "firma base",
            "CAdES-T": "con marca temporale",
            "CAdES-LT": "validazione a lungo termine",
            "CAdES-LTA": "archiviazione a lungo termine",
            "PAdES-BES": "firma PDF base",
            "PAdES-B": "firma PDF base",
            "PAdES-T": "PDF con marca temporale",
            "PAdES-LT": "PDF, validazione a lungo termine",
            "PAdES-LTA": "PDF, archiviazione a lungo termine",
            "PAdES document-timestamp": "marca temporale sul documento",
        }.get(sig.level, "")
        llabel = QLabel(f"Livello: {sig.level}" + (f" — {lvl_desc}" if lvl_desc else ""))
        llabel.setStyleSheet(f"color:{_MUTED}; padding:0 0 6px 0; font-weight:600;")
        lay.addWidget(llabel)

        s = sig.signer
        lay.addWidget(_row("Organizzazione", s.organization))
        lay.addWidget(_row("Identificativo", s.fiscal_code))
        if s.email:
            lay.addWidget(_row("Email", s.email))
        lay.addWidget(_row("Certificato emesso da", s.issuer_cn))
        lay.addWidget(_row("Numero di serie", s.serial_number))
        validita = f"{_fmt_dt(s.not_before)}  →  {_fmt_dt(s.not_after)}"
        lay.addWidget(_row("Validità certificato", validita))
        lay.addWidget(_row("Data e ora firma", _fmt_dt(s.signing_time)))
        lay.addWidget(_row("Algoritmi", f"{s.digest_algorithm} / {s.signature_algorithm}"))

        integ_txt, integ_col = (
            ("Integra (hash e firma corrispondono)", _OK)
            if crypto_ok
            else ("Compromessa o non verificabile", _BAD)
        )
        lay.addWidget(_row("Integrità firma", integ_txt, integ_col))

        ttext, tcolor = _TRUST_TEXT[sig.trust_status]
        if sig.trust_anchor_cn:
            ttext = f"{ttext} — {sig.trust_anchor_cn}"
        lay.addWidget(_row("Catena / Trust", ttext, tcolor))
        if sig.revocation_info:
            lay.addWidget(_row("Revoca", sig.revocation_info))

        # marca temporale CAdES-T
        if sig.has_timestamp:
            if sig.timestamp_valid and sig.timestamp_trust is TrustStatus.TRUSTED:
                tstxt, tscol = "valida — TSA accreditata", _OK
            elif sig.timestamp_valid:
                tstxt, tscol = "valida (TSA non accreditata)", _WARN
            else:
                tstxt, tscol = "presente ma non verificata", _BAD
            when = _fmt_dt(sig.timestamp_time)
            tsa = f" · {sig.timestamp_tsa}" if sig.timestamp_tsa else ""
            lay.addWidget(_row("Marca temporale", f"{when} — {tstxt}{tsa}", tscol))
        else:
            lay.addWidget(
                _row("Marca temporale", "assente (CAdES-BES, data auto-dichiarata)",
                     _MUTED)
            )

        # validazione a lungo termine (LT)
        if sig.embedded_certs or sig.embedded_crls or sig.embedded_ocsps:
            lt_txt = (
                f"{sig.embedded_certs} certificati, {sig.embedded_crls} CRL, "
                f"{sig.embedded_ocsps} OCSP incapsulati"
            )
            if sig.ltv_used:
                lt_txt += " — usati per la validazione della revoca"
            lay.addWidget(_row("Materiale LT", lt_txt, _OK if sig.ltv_used else _MUTED))

        # archive-timestamp (LTA)
        if sig.archive_timestamps:
            acol = _OK if sig.archive_valid == sig.archive_timestamps else _WARN
            atxt = f"{sig.archive_valid}/{sig.archive_timestamps} validi"
            if sig.archive_imprint_verified:
                atxt += f" · {sig.archive_imprint_verified} con impronta ricalcolata ✓"
            if sig.archive_time:
                atxt += f" · piu' recente {_fmt_dt(sig.archive_time)}"
            lay.addWidget(_row("Archive-timestamp", atxt, acol))

        for e in sig.errors:
            lay.addWidget(_row("Errore", e, _BAD))
        for w in sig.warnings:
            if w.startswith("Catena valida"):
                continue
            lay.addWidget(_row("Nota", w, _MUTED))


# --------------------------------------------------------------------------- #
# Dialog impostazioni
# --------------------------------------------------------------------------- #
class SettingsDialog(QDialog):
    """Impostazioni con navigazione a sinistra (Verifica / Firma)."""

    def __init__(self, cfg: appconfig.AppConfig, update_callback=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Impostazioni")
        self.setModal(True)
        self.resize(640, 520)
        self._cfg = cfg
        self._update_cb = update_callback
        # copia di lavoro dei profili
        self._profiles: list[appconfig.SignProfile] = [
            appconfig.SignProfile(**vars(p)) for p in cfg.profiles
        ]
        self._logo_path = cfg.sign_logo_path
        self._loading = False

        outer = QVBoxLayout(self)
        body = QHBoxLayout()
        outer.addLayout(body, 1)

        self.nav = QListWidget()
        self.nav.setFixedWidth(150)
        self.nav.addItem(QListWidgetItem("Generali"))
        self.nav.addItem(QListWidgetItem("Verifica"))
        self.nav.addItem(QListWidgetItem("Firma"))
        body.addWidget(self.nav)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_general_page())
        self.stack.addWidget(self._build_verify_page())
        self.stack.addWidget(self._build_sign_page())
        body.addWidget(self.stack, 1)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)

    # ----- pagina Generali ----- #
    def _build_general_page(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)
        self.combo_tz = QComboBox()
        self.combo_tz.setEditable(True)
        try:
            from zoneinfo import available_timezones
            zones = sorted(available_timezones())
        except Exception:  # noqa: BLE001
            zones = ["Europe/Rome", "UTC"]
        self.combo_tz.addItems(zones)
        cur = self._cfg.timezone if self._cfg.timezone in zones else "Europe/Rome"
        self.combo_tz.setCurrentText(cur)
        form.addRow("Fuso orario:", self.combo_tz)
        note = QLabel("Usato per la data/ora della firma.")
        note.setStyleSheet(f"color:{_MUTED};")
        form.addRow(note)

        # aggiornamenti dell'app
        self.chk_app_update = QCheckBox("Controlla aggiornamenti dell'app all'avvio")
        self.chk_app_update.setChecked(self._cfg.auto_update_app)
        form.addRow("Aggiornamenti:", self.chk_app_update)
        urow = QHBoxLayout()
        self.btn_check_update = QPushButton("⭳  Controlla aggiornamenti ora")
        self.btn_check_update.clicked.connect(self._check_update_now)
        urow.addWidget(self.btn_check_update)
        urow.addStretch(1)
        form.addRow("", self._wrap_lay(urow))
        self.lbl_version = QLabel(f"Versione installata: {__version__}")
        self.lbl_version.setStyleSheet(f"color:{_MUTED};")
        form.addRow(self.lbl_version)
        return page

    def _check_update_now(self) -> None:
        # delega alla finestra principale se disponibile (mostra dialog/progresso)
        win = self.parent()
        if hasattr(win, "check_app_update"):
            win.check_app_update(manual=True)
        else:
            QMessageBox.information(self, "Aggiornamenti",
                                    "Controllo aggiornamenti non disponibile qui.")

    # ----- pagina Verifica ----- #
    def _build_verify_page(self) -> QWidget:
        cfg = self._cfg
        page = QWidget()
        lay = QVBoxLayout(page)

        self.chk_trust = QCheckBox("Valida catena (Trusted List)")
        self.chk_trust.setChecked(cfg.check_trust)
        lay.addWidget(self.chk_trust)
        self.chk_revoke = QCheckBox("Controllo revoca online (CRL/OCSP)")
        self.chk_revoke.setChecked(cfg.revocation_online)
        lay.addWidget(self.chk_revoke)
        self.chk_verify = QCheckBox("Verifica autenticità delle liste (firma XAdES)")
        self.chk_verify.setChecked(cfg.verify_signatures)
        lay.addWidget(self.chk_verify)
        self.chk_open_doc = QCheckBox(
            "Apri il documento dopo una verifica valida (solo aprendo un .p7m "
            "con «Apri con»)"
        )
        self.chk_open_doc.setChecked(cfg.open_document_on_verify)
        lay.addWidget(self.chk_open_doc)

        form = QFormLayout()
        self.chk_auto = QCheckBox("all'avvio")
        self.chk_auto.setChecked(cfg.auto_update)
        self.spin_days = QSpinBox()
        self.spin_days.setRange(1, 365)
        self.spin_days.setValue(cfg.interval_days)
        self.spin_days.setSuffix(" giorni")
        arow = QHBoxLayout()
        arow.addWidget(self.chk_auto)
        arow.addWidget(QLabel("ogni"))
        arow.addWidget(self.spin_days)
        arow.addStretch(1)
        form.addRow("Aggiorna automaticamente:", self._wrap_lay(arow))
        self.combo_terr = QComboBox()
        self.combo_terr.addItem("Solo Italia (AgID)", ["IT"])
        self.combo_terr.addItem("Tutta l'Unione Europea", ["*"])
        self.combo_terr.setCurrentIndex(1 if cfg.territories == ["*"] else 0)
        form.addRow("Ambito:", self.combo_terr)
        lay.addLayout(form)

        self.btn_update_now = QPushButton("🔄  Aggiorna Trusted List ora")
        self.btn_update_now.clicked.connect(self._do_update_now)
        lay.addWidget(self.btn_update_now)
        lay.addStretch(1)
        return page

    def _do_update_now(self) -> None:
        if self._update_cb:
            self._update_cb(self.combo_terr.currentData())

    # ----- pagina Firma ----- #
    def _build_sign_page(self) -> QWidget:
        cfg = self._cfg
        page = QWidget()
        lay = QVBoxLayout(page)

        # aspetto grafico PAdES
        grp_app = QGroupBox("Aspetto firma grafica (PAdES)")
        af = QVBoxLayout(grp_app)
        self.chk_show_dt = QCheckBox("Mostra data e ora")
        self.chk_show_dt.setChecked(cfg.sign_show_datetime)
        af.addWidget(self.chk_show_dt)
        self.chk_ask_reason = QCheckBox("Chiedi la motivazione al momento della firma")
        self.chk_ask_reason.setChecked(cfg.sign_ask_reason)
        af.addWidget(self.chk_ask_reason)
        self.chk_ask_location = QCheckBox("Chiedi il luogo al momento della firma")
        self.chk_ask_location.setChecked(cfg.sign_ask_location)
        af.addWidget(self.chk_ask_location)
        # selettore immagine della firma grafica
        af.addWidget(QLabel("Immagine della firma:"))
        self.rb_img_default = QRadioButton("Immagine di default")
        self.rb_img_none = QRadioButton("Nessuna immagine")
        self.rb_img_custom = QRadioButton("Immagine personalizzata")
        # i tre radio come figli diretti dello stesso layout: stesso allineamento
        af.addWidget(self.rb_img_default)
        af.addWidget(self.rb_img_none)
        af.addWidget(self.rb_img_custom)
        # riga del file (Scegli… + nome), indentata sotto il radio «personalizzata»
        crow = QHBoxLayout()
        crow.setContentsMargins(22, 0, 0, 0)
        crow.setSpacing(8)
        self.btn_logo = QPushButton("🖼  Scegli…")
        self.btn_logo.clicked.connect(self._pick_logo)
        crow.addWidget(self.btn_logo)
        self.logo_label = QLabel(Path(self._logo_path).name if self._logo_path else "nessun file")
        self.logo_label.setStyleSheet(f"color:{_MUTED};")
        crow.addWidget(self.logo_label, 1)
        af.addLayout(crow)

        mode = getattr(cfg, "sign_image_mode", "default")
        self._img_ready = False
        {"none": self.rb_img_none, "custom": self.rb_img_custom}.get(
            mode, self.rb_img_default).setChecked(True)
        for rb in (self.rb_img_default, self.rb_img_none, self.rb_img_custom):
            rb.toggled.connect(self._img_mode_changed)
        self._img_mode_changed()
        self._img_ready = True

        self.set_image_only = QCheckBox("Solo immagine (senza testo)")
        self.set_image_only.setChecked(cfg.sign_image_only)
        af.addWidget(self.set_image_only)
        lay.addWidget(grp_app)

        # profili utenti remoti
        grp_u = QGroupBox("Utenti firma remota")
        ug = QHBoxLayout(grp_u)
        left = QVBoxLayout()
        self.prof_list = QListWidget()
        self.prof_list.currentRowChanged.connect(self._load_profile)
        left.addWidget(self.prof_list)
        prow = QHBoxLayout()
        b_add = QPushButton("+ Aggiungi")
        b_add.clicked.connect(self._add_profile)
        b_del = QPushButton("− Rimuovi")
        b_del.clicked.connect(self._del_profile)
        prow.addWidget(b_add)
        prow.addWidget(b_del)
        left.addLayout(prow)
        ug.addLayout(left, 1)

        pf = QFormLayout()
        self.p_name = QLineEdit()
        self.p_user = QLineEdit()
        self.p_domain = QComboBox()
        self.p_domain.addItems(appconfig.SIGN_DOMAINS)
        self.p_cert = QLineEdit()
        self.p_hsm = QLineEdit()
        self.p_demo = QCheckBox("Endpoint demo")
        for w in (self.p_name, self.p_user, self.p_cert, self.p_hsm):
            w.textChanged.connect(self._profile_edited)
        self.p_domain.currentTextChanged.connect(self._profile_edited)
        self.p_demo.stateChanged.connect(self._profile_edited)
        self.p_name.setPlaceholderText("etichetta del profilo (es. Lavoro)")
        pf.addRow("Nome profilo:", self.p_name)
        pf.addRow("Utente:", self.p_user)
        pf.addRow("Dominio:", self.p_domain)
        pf.addRow("certID:", self.p_cert)
        pf.addRow("HSM:", self.p_hsm)
        pf.addRow(self.p_demo)
        ug.addLayout(pf, 1)
        lay.addWidget(grp_u, 1)

        self._refresh_profile_list()
        if self._profiles:
            self.prof_list.setCurrentRow(0)
        else:
            self._set_profile_form_enabled(False)
        return page

    def _wrap_lay(self, layout) -> QWidget:
        w = QWidget()
        w.setLayout(layout)
        return w

    def _img_mode_changed(self) -> None:
        """Abilita il selettore file solo con «Immagine personalizzata»."""
        custom = self.rb_img_custom.isChecked()
        self.btn_logo.setEnabled(custom)
        self.logo_label.setEnabled(custom)
        if custom and self._img_ready and not self._logo_path:
            self._pick_logo()

    def _image_mode(self) -> str:
        if self.rb_img_none.isChecked():
            return "none"
        if self.rb_img_custom.isChecked():
            return "custom"
        return "default"

    def _pick_logo(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Immagine firma", "", "Immagini (*.png *.jpg *.jpeg *.bmp)")
        if path:
            self._logo_path = path
            self.logo_label.setText(Path(path).name)
            self.logo_label.setStyleSheet("color:#24292f;")

    # ----- gestione profili ----- #
    def _refresh_profile_list(self) -> None:
        self.prof_list.clear()
        for p in self._profiles:
            self.prof_list.addItem(p.label())

    def _set_profile_form_enabled(self, on: bool) -> None:
        for w in (self.p_name, self.p_user, self.p_domain, self.p_cert,
                  self.p_hsm, self.p_demo):
            w.setEnabled(on)

    def _load_profile(self, row: int) -> None:
        if row < 0 or row >= len(self._profiles):
            self._set_profile_form_enabled(False)
            return
        self._set_profile_form_enabled(True)
        p = self._profiles[row]
        self._loading = True
        self.p_name.setText(p.name)
        self.p_user.setText(p.user)
        self._set_domain(p.domain)
        self.p_cert.setText(p.cert_id)
        self.p_hsm.setText(p.hsm)
        self.p_demo.setChecked(p.demo)
        self._loading = False

    def _set_domain(self, domain: str) -> None:
        """Seleziona il dominio nel dropdown; se ignoto (profilo vecchio) lo aggiunge."""
        domain = domain or appconfig.DEFAULT_SIGN_DOMAIN
        idx = self.p_domain.findText(domain)
        if idx < 0:
            self.p_domain.addItem(domain)
            idx = self.p_domain.findText(domain)
        self.p_domain.setCurrentIndex(idx)

    def _profile_edited(self) -> None:
        if self._loading:
            return
        row = self.prof_list.currentRow()
        if row < 0 or row >= len(self._profiles):
            return
        p = self._profiles[row]
        p.name = self.p_name.text()
        p.user = self.p_user.text()
        p.domain = self.p_domain.currentText()
        p.cert_id = self.p_cert.text() or "AS0"
        p.hsm = self.p_hsm.text() or "COSIGN"
        p.demo = self.p_demo.isChecked()
        self.prof_list.item(row).setText(p.label())

    def _add_profile(self) -> None:
        self._profiles.append(appconfig.SignProfile(
            name="Nuovo profilo", domain=appconfig.DEFAULT_SIGN_DOMAIN,
            cert_id="AS0", hsm="COSIGN"))
        self._refresh_profile_list()
        self.prof_list.setCurrentRow(len(self._profiles) - 1)
        self.p_name.setFocus()

    def _del_profile(self) -> None:
        row = self.prof_list.currentRow()
        if 0 <= row < len(self._profiles):
            del self._profiles[row]
            self._refresh_profile_list()
            if self._profiles:
                self.prof_list.setCurrentRow(min(row, len(self._profiles) - 1))
            else:
                self._set_profile_form_enabled(False)

    def result_config(self) -> appconfig.AppConfig:
        c = self._cfg
        c.timezone = self.combo_tz.currentText().strip() or "Europe/Rome"
        c.auto_update_app = self.chk_app_update.isChecked()
        c.check_trust = self.chk_trust.isChecked()
        c.revocation_online = self.chk_revoke.isChecked()
        c.open_document_on_verify = self.chk_open_doc.isChecked()
        c.verify_signatures = self.chk_verify.isChecked()
        c.auto_update = self.chk_auto.isChecked()
        c.interval_days = self.spin_days.value()
        c.territories = self.combo_terr.currentData()
        c.sign_ask_reason = self.chk_ask_reason.isChecked()
        c.sign_ask_location = self.chk_ask_location.isChecked()
        c.sign_show_datetime = self.chk_show_dt.isChecked()
        c.sign_image_mode = self._image_mode()
        c.sign_logo_path = self._logo_path
        c.sign_image_only = self.set_image_only.isChecked()
        c.profiles = self._profiles
        return c.clamp()


# --------------------------------------------------------------------------- #
# Firma: anteprima PDF con riquadro trascinabile + dialog credenziali
# --------------------------------------------------------------------------- #
class PdfSignaturePreview(QWidget):
    """Mostra una pagina PDF e permette di tracciare il riquadro della firma.

    Espone il riquadro in punti PDF (origine in basso a sinistra) via ``pdf_rect``.
    """

    def __init__(self):
        super().__init__()
        self._doc = QPdfDocument(self) if _HAS_QTPDF else None
        self._page = 0
        self._img = None            # QImage della pagina renderizzata
        self._img_off = QPoint(0, 0)  # offset di disegno dell'immagine
        self._sel = None            # QRect selezione in px immagine
        self._drag_start = None
        self._logo = None           # QImage del logo da mostrare nel riquadro
        self._text = "Nome Cognome"  # testo di anteprima nel riquadro
        self._image_only = False
        self.setMinimumHeight(380)
        self.setStyleSheet(
            "background:#eef1f4; border:1px solid #d0d7de; border-radius:6px;"
        )

    def has_pdf(self) -> bool:
        return self._img is not None

    def set_logo(self, data: bytes) -> None:
        """Imposta (o rimuove) il logo mostrato nel riquadro della firma."""
        if data:
            img = QImage()
            self._logo = img if img.loadFromData(data) else None
        else:
            self._logo = None
        self.update()

    def set_preview(self, text: str, image_only: bool) -> None:
        """Testo (nome) e modalità solo-immagine per l'anteprima del riquadro."""
        self._text = text or ""
        self._image_only = image_only
        self.update()

    def page_count(self) -> int:
        return self._doc.pageCount() if self._doc else 0

    def load(self, path: str) -> bool:
        if not self._doc:
            return False
        self._doc.load(path)
        self._page = 0
        self._sel = None
        self._render()
        return self.page_count() > 0

    def set_page(self, page_index: int) -> None:
        if self._doc and 0 <= page_index < self.page_count():
            self._page = page_index
            self._sel = None
            self._render()

    def _page_points(self):
        size = self._doc.pagePointSize(self._page)
        return float(size.width()), float(size.height())

    def _render(self) -> None:
        self._img = None
        if not self._doc or self.page_count() == 0:
            self.update()
            return
        wp, hp = self._page_points()
        if wp <= 0 or hp <= 0:
            self.update()
            return
        avail_w = max(50, self.width() - 24)
        avail_h = max(50, self.height() - 24)
        scale = min(avail_w / wp, avail_h / hp)
        px_w, px_h = int(wp * scale), int(hp * scale)
        try:
            self._img = self._doc.render(self._page, QSize(px_w, px_h))
        except Exception:  # noqa: BLE001
            self._img = None
        # riquadro predefinito: in basso a sinistra
        if self._img is not None and self._sel is None:
            iw, ih = self._img.width(), self._img.height()
            self._sel = QRect(int(iw * 0.08), int(ih * 0.80),
                              int(iw * 0.42), int(ih * 0.12))
        self.update()

    def resizeEvent(self, event):  # noqa: N802
        self._render()

    def paintEvent(self, event):  # noqa: N802
        p = QPainter(self)
        if self._img is None:
            p.setPen(QColor("#8a94a0"))
            p.drawText(self.rect(), Qt.AlignCenter,
                       "Anteprima PDF\n(seleziona un PDF e attiva la firma visibile)")
            return
        iw, ih = self._img.width(), self._img.height()
        self._img_off = QPoint((self.width() - iw) // 2, (self.height() - ih) // 2)
        # foglio bianco con bordo, così i margini della pagina si distinguono dal grigio
        page_rect = QRect(self._img_off, QSize(iw, ih))
        p.fillRect(page_rect, QColor(255, 255, 255))
        p.drawImage(self._img_off, self._img)
        p.setPen(QPen(QColor("#c4ccd4"), 1))
        p.drawRect(page_rect.adjusted(0, 0, -1, -1))
        if self._sel is not None:
            r = self._sel.translated(self._img_off)
            p.fillRect(r, QColor(255, 255, 255, 210))  # sfondo chiaro tipo timbro
            inner = r.adjusted(4, 4, -4, -4)
            self._paint_signature(p, inner)
            p.setPen(QPen(QColor("#1a7f37"), 2))
            p.drawRect(r)

    def _paint_signature(self, p: QPainter, inner) -> None:
        if inner.width() < 8 or inner.height() < 8:
            return
        has_logo = self._logo is not None
        show_text = bool(self._text) and not self._image_only

        def _fit(img, rect):
            s = img.scaled(rect.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
            return QPoint(rect.x() + (rect.width() - s.width()) // 2,
                          rect.y() + (rect.height() - s.height()) // 2), s

        if has_logo and not show_text:
            pt, s = _fit(self._logo, inner)
            p.drawImage(pt, s)
            return
        text_rect = inner
        if has_logo and show_text:
            lw = min(inner.height(), inner.width() // 2)
            logo_rect = QRect(inner.x(), inner.y(), lw, inner.height())
            pt, s = _fit(self._logo, logo_rect)
            p.drawImage(pt, s)
            text_rect = QRect(inner.x() + lw + 4, inner.y(),
                              inner.width() - lw - 4, inner.height())
        if show_text:
            nlines = self._text.count("\n") + 1
            font = QFont()
            font.setPointSizeF(max(6.0, min(text_rect.height() / (2.2 * nlines), 13.0)))
            p.setFont(font)
            p.setPen(QColor("#111418"))
            p.drawText(text_rect, Qt.AlignLeft | Qt.AlignVCenter | Qt.TextWordWrap, self._text)

    # -- disegno del riquadro con trascinamento -- #
    def mousePressEvent(self, event):  # noqa: N802
        if self._img is None:
            return
        self._drag_start = event.position().toPoint() - self._img_off
        self._sel = QRect(self._drag_start, self._drag_start)
        self.update()

    def mouseMoveEvent(self, event):  # noqa: N802
        if self._drag_start is None or self._img is None:
            return
        cur = event.position().toPoint() - self._img_off
        self._sel = QRect(self._drag_start, cur).normalized()
        self.update()

    def mouseReleaseEvent(self, event):  # noqa: N802
        self._drag_start = None

    def pdf_rect(self):
        """Riquadro in punti PDF: (leftx, lefty, rightx, righty) o None."""
        if self._img is None or self._sel is None:
            return None
        iw, ih = self._img.width(), self._img.height()
        wp, hp = self._page_points()
        r = self._sel.normalized()
        sx, sy = wp / iw, hp / ih
        leftx = r.left() * sx
        rightx = r.right() * sx
        righty = hp - r.top() * sy       # bordo superiore (y maggiore)
        lefty = hp - r.bottom() * sy      # bordo inferiore (y minore)
        return int(leftx), int(lefty), int(rightx), int(righty)


class CredentialsDialog(QDialog):
    """Chiede password di firma e OTP (mai salvate); opzionalmente motivo/luogo."""

    def __init__(self, user: str, ask_reason: bool = False,
                 ask_location: bool = False, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Firma remota Aruba")
        self.setModal(True)
        form = QFormLayout(self)
        form.addRow(QLabel(f"Utente: <b>{user}</b>"))
        self.pwd = QLineEdit()
        self.pwd.setEchoMode(QLineEdit.Password)
        form.addRow("Password di firma:", self.pwd)
        self.otp = QLineEdit()
        self.otp.setMaxLength(12)
        form.addRow("Codice OTP:", self.otp)
        self.reason = QLineEdit() if ask_reason else None
        if self.reason is not None:
            form.addRow("Motivazione:", self.reason)
        self.location = QLineEdit() if ask_location else None
        if self.location is not None:
            form.addRow("Luogo:", self.location)
        note = QLabel("Password e OTP: digita senza correggere con Backspace.")
        note.setStyleSheet(f"color:{_MUTED};")
        form.addRow(note)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.button(QDialogButtonBox.Ok).setText("Firma")
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        form.addRow(bb)
        self.pwd.setFocus()

    def values(self) -> tuple[str, str]:
        return self.pwd.text(), self.otp.text()

    def reason_text(self) -> str:
        return self.reason.text() if self.reason is not None else ""

    def location_text(self) -> str:
        return self.location.text() if self.location is not None else ""


# --------------------------------------------------------------------------- #
# Finestra principale
# --------------------------------------------------------------------------- #
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{__app_name__} {__version__}")
        self.setWindowIcon(app_icon())
        self.resize(760, 720)
        self.setAcceptDrops(True)

        self._config = appconfig.load_config()
        self._store = trust.load_trust_store()
        self._result: P7MResult | None = None
        self._is_pades_result = False
        # True solo per un .p7m aperto con "Apri con": a verifica verde apre da
        # solo il documento incapsulato (vedi analyze/_on_analyzed).
        self._auto_open_document = False
        self._worker: AnalyzeWorker | None = None
        self._trust_worker: TrustWorker | None = None
        self._trust_silent = False
        self._sign_worker: SignWorker | None = None
        self._sign_src: str | None = None
        self._signed_bytes: bytes = b""
        self._upd_check: UpdateCheckWorker | None = None
        self._upd_dl: UpdateDownloadWorker | None = None

        self._build_ui()
        # velo modale mostrato durante la verifica (copre l'intera finestra)
        self._overlay = BusyOverlay(self, "Verifica in corso…")
        self._refresh_trust_status()
        # aggiornamento automatico ricorrente all'avvio
        QTimer.singleShot(400, self._maybe_auto_update)
        # controllo aggiornamenti dell'app all'avvio (in background, silenzioso)
        if self._config.auto_update_app:
            QTimer.singleShot(1200, lambda: self.check_app_update(manual=False))

    def resizeEvent(self, event):  # noqa: N802
        super().resizeEvent(event)
        if getattr(self, "_overlay", None) is not None and self._overlay.isVisible():
            self._overlay.setGeometry(self.rect())

    # -- costruzione UI --------------------------------------------------- #
    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # barra superiore con il pulsante Impostazioni (sempre visibile)
        topbar = QHBoxLayout()
        topbar.setContentsMargins(16, 10, 16, 0)
        topbar.addStretch(1)
        self.btn_settings = QPushButton("⚙  Impostazioni")
        self.btn_settings.clicked.connect(self.open_settings)
        self.btn_settings.setMinimumHeight(38)
        topbar.addWidget(self.btn_settings)
        outer.addLayout(topbar)

        self.tabs = QTabWidget()
        outer.addWidget(self.tabs)

        # ===== TAB VERIFICA ===== #
        verify_tab = QWidget()
        root = QVBoxLayout(verify_tab)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(10)

        # barra superiore
        top = QHBoxLayout()
        self.btn_open = QPushButton("📂  Apri file firmato")
        self.btn_open.clicked.connect(self.open_dialog)
        self.btn_open.setMinimumHeight(38)
        self.btn_extract = QPushButton("💾  Estrai documento")
        self.btn_extract.clicked.connect(self.extract)
        self.btn_extract.setEnabled(False)
        self.btn_extract.setMinimumHeight(38)
        self.btn_open_doc = QPushButton("👁  Apri documento")
        self.btn_open_doc.clicked.connect(self.open_document)
        self.btn_open_doc.setEnabled(False)
        self.btn_open_doc.setMinimumHeight(38)
        top.addWidget(self.btn_open)
        top.addWidget(self.btn_extract)
        top.addWidget(self.btn_open_doc)
        top.addStretch(1)
        root.addLayout(top)

        # intestazione file + esito globale
        self.header = QLabel("Trascina qui un file .p7m o un PDF firmato, "
                             "oppure premi «Apri file».")
        self.header.setStyleSheet(
            "background:#f6f8fa; border:1px dashed #d0d7de; border-radius:8px;"
            "padding:22px; color:#57606a;"
        )
        self.header.setAlignment(Qt.AlignCenter)
        self.header.setWordWrap(True)
        root.addWidget(self.header)

        self.summary = QLabel("")
        self.summary.setAlignment(Qt.AlignCenter)
        self.summary.setWordWrap(True)
        sf = QFont()
        sf.setPointSize(14)
        sf.setBold(True)
        self.summary.setFont(sf)
        self.summary.setVisible(False)
        root.addWidget(self.summary)

        # area schede firme
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.cards_host = QWidget()
        self.cards_layout = QVBoxLayout(self.cards_host)
        self.cards_layout.setContentsMargins(0, 0, 0, 0)
        self.cards_layout.setSpacing(10)
        self.cards_layout.addStretch(1)
        self.scroll.setWidget(self.cards_host)
        root.addWidget(self.scroll, 1)
        self.tabs.addTab(verify_tab, "Verifica")

        # ===== TAB FIRMA ===== #
        self.tabs.addTab(self._build_sign_tab(), "Firma")

        self.status = self.statusBar()

        # menu
        m = self.menuBar().addMenu("File")
        a_open = QAction("Apri…", self)
        a_open.triggered.connect(self.open_dialog)
        m.addAction(a_open)
        a_set = QAction("Impostazioni…", self)
        a_set.triggered.connect(self.open_settings)
        self.menuBar().addAction(a_set)

    # -- trust status ----------------------------------------------------- #
    def _refresh_trust_status(self) -> None:
        n = len(self._store)
        if n == 0:
            self.status.showMessage(
                "⚠ Nessuna Trusted List caricata — premi «Aggiorna Trusted List» "
                "per la validazione legale."
            )
        else:
            when = (
                datetime.fromtimestamp(self._store.updated_at).strftime("%d/%m/%Y %H:%M")
                if self._store.updated_at
                else "?"
            )
            terr = ", ".join(self._store.territories) or "?"
            if self._store.verify_attempted:
                auth = "✓ autentiche" if self._store.authentic else "⚠ non autenticate"
            else:
                auth = "autenticità non verificata"
            ntsa = len(self._store.tsa_certificates)
            self.status.showMessage(
                f"Trusted List: {n} CA, {ntsa} TSA ({terr}) · {auth} · "
                f"aggiornata il {when}"
            )

    # -- apertura / drag&drop -------------------------------------------- #
    def dragEnterEvent(self, event) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:  # noqa: N802
        urls = event.mimeData().urls()
        if urls:
            self.analyze(urls[0].toLocalFile())

    def open_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Apri file firmato", "",
            "File firmati (*.p7m *.pdf);;CAdES (*.p7m);;PDF firmati (*.pdf);;"
            "Tutti i file (*)",
        )
        if path:
            self.analyze(path)

    # -- analisi ---------------------------------------------------------- #
    def analyze(self, path: str, auto_open_document: bool = False) -> None:
        if not path or not Path(path).is_file():
            return
        # se richiesto (solo "Apri con" di un .p7m), a verifica verde apriremo
        # da soli il documento incapsulato in _on_analyzed
        self._auto_open_document = auto_open_document
        if self._config.check_trust and len(self._store) == 0:
            QMessageBox.information(
                self,
                "Trusted List assente",
                "Per la validazione legale serve la Trusted List.\n"
                "Aggiornala da «Impostazioni ▸ Verifica» oppure la firma sarà "
                "verificata solo dal punto di vista crittografico.",
            )
        self._set_busy(True)
        self._overlay.show_over("Verifica in corso…")
        options = verifier.VerifyOptions(
            check_trust=self._config.check_trust,
            revocation_mode=RevocationMode.SOFT_FAIL,
            allow_fetching=self._config.revocation_online,
        )
        self._worker = AnalyzeWorker(
            path, self._store.certificates, options, self._store.tsa_certificates
        )
        self._worker.done.connect(self._on_analyzed)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_failed(self, msg: str) -> None:
        self._auto_open_document = False
        self._overlay.hide()
        self._set_busy(False)
        QMessageBox.critical(self, "Errore", msg)

    def _on_analyzed(self, res: P7MResult) -> None:
        self._overlay.hide()
        self._set_busy(False)
        self._result = res
        # consuma il flag "apri con" (vale solo per questa analisi)
        auto_open = self._auto_open_document
        self._auto_open_document = False
        self._clear_cards()

        if res.parse_errors:
            self.header.setText("❌  " + "\n".join(res.parse_errors))
            self.header.setStyleSheet(
                f"background:#fff0f0; border:1px solid {_BAD}; border-radius:8px;"
                f"padding:18px; color:{_BAD};"
            )
            self.summary.setVisible(False)
            self.btn_extract.setEnabled(False)
            self.btn_open_doc.setEnabled(False)
            return

        name = Path(res.source_path).name
        extra = f" · {res.nested_levels} livelli annidati" if res.nested_levels > 1 else ""
        self.header.setText(
            f"📄  {name}\nContenuto: {res.content_filename} "
            f"({len(res.content):,} byte){extra}".replace(",", ".")
        )
        self.header.setStyleSheet(
            "background:#f6f8fa; border:1px solid #d0d7de; border-radius:8px;"
            "padding:14px; color:#24292f;"
        )

        if res.all_valid:
            txt, col = f"✓ Tutte le {len(res.signatures)} firme sono valide", _OK
        elif res.any_crypto_valid:
            txt, col = "! Firme integre ma non pienamente validate", _WARN
        else:
            txt, col = "✗ Firma non valida", _BAD
        self.summary.setText(txt)
        self.summary.setStyleSheet(f"color:{col};")
        self.summary.setVisible(True)

        for i, sig in enumerate(res.signatures, 1):
            self.cards_layout.insertWidget(self.cards_layout.count() - 1, SignatureCard(i, sig))

        # per un PDF firmato PAdES il "documento" è il PDF stesso: estrarlo è
        # inutile (ma resta utile aprirlo). Per un .p7m — anche se racchiude un
        # PDF — l'estrazione ha senso. Si distingue dal livello di firma PAdES,
        # non dal contenuto (un p7m può contenere un PDF).
        self._is_pades_result = any(
            s.level.startswith("PAdES") for s in res.signatures
        )
        self.btn_extract.setEnabled(bool(res.content) and not self._is_pades_result)
        self.btn_open_doc.setEnabled(bool(res.content))

        # "Apri con" di un .p7m + verifica verde: apri subito il documento
        # incapsulato, come se si premesse "Apri documento" (disattivabile da
        # Impostazioni ▸ Verifica).
        if (auto_open and self._config.open_document_on_verify
                and res.all_valid and res.content and not self._is_pades_result):
            self.open_document()

    # -- estrazione ------------------------------------------------------- #
    def extract(self) -> None:
        if not self._result or not self._result.content:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Salva documento estratto", self._result.content_filename
        )
        if not path:
            return
        try:
            Path(path).write_bytes(self._result.content)
        except OSError as exc:
            QMessageBox.critical(self, "Errore", f"Impossibile salvare: {exc}")
            return
        self.status.showMessage(f"Documento estratto in: {path}", 8000)
        QMessageBox.information(self, "Fatto", f"Documento salvato:\n{path}")

    # -- apertura diretta ------------------------------------------------- #
    def open_document(self) -> None:
        """Apre il documento contenuto nel file firmato con l'app di sistema."""
        if not self._result or not self._result.content:
            return
        import tempfile

        name = self._result.content_filename or "documento"
        try:
            tmp_dir = Path(tempfile.mkdtemp(prefix="corianosign_"))
            out = tmp_dir / name
            out.write_bytes(self._result.content)
        except OSError as exc:
            QMessageBox.critical(self, "Errore", f"Impossibile aprire il documento: {exc}")
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(out))):
            QMessageBox.warning(
                self, "Attenzione",
                "Impossibile aprire il documento con un'applicazione di sistema.\n"
                f"Il file è comunque disponibile in:\n{out}",
            )
            return
        self.status.showMessage(f"Documento aperto: {out}", 8000)

    # -- aggiornamento trust --------------------------------------------- #
    def update_trust(self, territories, silent: bool = False) -> None:
        if self._trust_worker is not None and self._trust_worker.isRunning():
            return
        self._trust_silent = silent
        if not silent:
            self._set_busy(True, "Aggiornamento Trusted List…")
        else:
            self.status.showMessage("Controllo aggiornamenti Trusted List…")
        self._trust_worker = TrustWorker(
            territories, verify_signatures=self._config.verify_signatures
        )
        self._trust_worker.progress.connect(lambda m: self.status.showMessage(m))
        self._trust_worker.done.connect(self._on_trust_done)
        self._trust_worker.failed.connect(self._on_trust_failed)
        self._trust_worker.start()

    def _on_trust_failed(self, msg: str) -> None:
        self._set_busy(False)
        if self._trust_silent:
            self.status.showMessage(f"Aggiornamento automatico non riuscito: {msg}", 8000)
        else:
            QMessageBox.critical(self, "Errore aggiornamento", msg)

    def _on_trust_done(self, store) -> None:
        self._store = store
        self._set_busy(False)
        self._refresh_trust_status()
        if not self._trust_silent:
            auth = "autentiche ✓" if store.authentic else "NON pienamente autenticate ⚠"
            QMessageBox.information(
                self, "Trusted List aggiornata",
                f"Caricate {len(store)} CA accreditate ({', '.join(store.territories)}).\n"
                f"Liste {auth}.",
            )
        self._trust_silent = False

    def _maybe_auto_update(self) -> None:
        """Aggiornamento automatico ricorrente in base alla configurazione."""
        if not self._config.auto_update:
            return
        if trust.needs_update(self._store, self._config.interval_days):
            age = trust.store_age_days(self._store)
            motivo = "cache assente" if age is None else f"cache di {age:.0f} giorni"
            self.status.showMessage(
                f"Aggiornamento automatico Trusted List ({motivo})…"
            )
            self.update_trust(self._config.territories, silent=True)

    # -- aggiornamento dell'app ------------------------------------------- #
    def check_app_update(self, manual: bool = False) -> None:
        """Controlla in background se c'è una nuova versione dell'app."""
        from . import updater

        if self._upd_check is not None and self._upd_check.isRunning():
            return
        if not updater.can_auto_update():
            if manual:
                QMessageBox.information(
                    self, "Aggiornamenti",
                    "L'auto-aggiornamento è disponibile solo nell'app installata "
                    "(build macOS/Windows), non durante l'esecuzione da sorgente.")
            return
        self._upd_manual = manual
        if manual:
            self.status.showMessage("Controllo aggiornamenti…")
        self._upd_check = UpdateCheckWorker()
        self._upd_check.found.connect(self._on_update_found)
        self._upd_check.none.connect(self._on_update_none)
        self._upd_check.failed.connect(self._on_update_check_failed)
        self._upd_check.start()

    def _on_update_none(self) -> None:
        if getattr(self, "_upd_manual", False):
            QMessageBox.information(
                self, "Aggiornamenti",
                f"Nessun aggiornamento disponibile.\nVersione installata: {__version__}.")
        self.status.clearMessage()

    def _on_update_check_failed(self, msg: str) -> None:
        if getattr(self, "_upd_manual", False):
            QMessageBox.warning(self, "Aggiornamenti", msg)
        else:
            self.status.showMessage(msg, 6000)

    def _on_update_found(self, info) -> None:
        notes = (info.notes or "").strip()
        if len(notes) > 800:
            notes = notes[:800] + "…"
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Information)
        box.setWindowTitle("Aggiornamento disponibile")
        box.setText(f"È disponibile CorianoSign {info.version} "
                    f"(installata: {__version__}).")
        if notes:
            box.setInformativeText(notes)
        btn_now = box.addButton("Aggiorna ora", QMessageBox.AcceptRole)
        box.addButton("Più tardi", QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is btn_now:
            self._start_update_download(info)

    def _start_update_download(self, info) -> None:
        self._overlay.show_over(f"Scaricamento aggiornamento {info.version}…")
        self._upd_dl = UpdateDownloadWorker(info)
        self._upd_dl.progress.connect(self._on_update_progress)
        self._upd_dl.ready.connect(self._on_update_ready)
        self._upd_dl.failed.connect(self._on_update_dl_failed)
        self._upd_dl.start()

    def _on_update_progress(self, done: int, total: int) -> None:
        if total > 0:
            pct = int(done * 100 / total)
            self._overlay.set_text(f"Scaricamento aggiornamento… {pct}%")

    def _on_update_dl_failed(self, msg: str) -> None:
        self._overlay.hide()
        QMessageBox.critical(self, "Aggiornamento non riuscito", msg)

    def _on_update_ready(self, archive_path: str) -> None:
        self._overlay.set_text("Installazione e riavvio…")
        ret = QMessageBox.question(
            self, "Pronto all'installazione",
            "L'aggiornamento è stato scaricato e verificato.\n"
            "L'app verrà chiusa, aggiornata e riavviata automaticamente.\n\nProcedere?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes,
        )
        if ret != QMessageBox.Yes:
            self._overlay.hide()
            return
        from . import updater
        try:
            updater.apply_update(Path(archive_path))  # non ritorna: termina il processo
        except Exception as exc:  # noqa: BLE001
            self._overlay.hide()
            QMessageBox.critical(self, "Aggiornamento non riuscito", str(exc))

    # -- impostazioni ----------------------------------------------------- #
    def open_settings(self) -> None:
        dlg = SettingsDialog(self._config, update_callback=self.update_trust, parent=self)
        if dlg.exec() == QDialog.Accepted:
            self._config = dlg.result_config()
            appconfig.save_config(self._config)
            self._refresh_trust_status()
            self._refresh_sign_profiles()
            self._apply_sign_appearance()
            self.status.showMessage("Impostazioni salvate.", 5000)

    # ==================================================================== #
    # TAB FIRMA (firma remota Aruba)
    # ==================================================================== #
    def _build_sign_tab(self) -> QWidget:
        cfg = self._config
        tab = QWidget()
        lay = QVBoxLayout(tab)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(10)

        # riga file
        frow = QHBoxLayout()
        self.btn_sign_open = QPushButton("📄  Scegli documento…")
        self.btn_sign_open.clicked.connect(self._sign_pick_file)
        self.sign_path = QLabel("Nessun documento selezionato")
        self.sign_path.setStyleSheet(f"color:{_MUTED};")
        frow.addWidget(self.btn_sign_open)
        frow.addWidget(self.sign_path, 1)
        lay.addLayout(frow)

        # formato + livello
        orow = QHBoxLayout()
        self.rb_pades = QRadioButton("PAdES (PDF)")
        self.rb_pades.setChecked(True)
        self.rb_pades.toggled.connect(self._sign_format_changed)
        self.rb_cades = QRadioButton("CAdES (.p7m)")
        orow.addWidget(self.rb_pades)
        orow.addWidget(self.rb_cades)
        orow.addSpacing(20)
        orow.addWidget(QLabel("Livello:"))
        self.sign_level = QComboBox()
        for label, val in [("Predefinito", ""), ("B", "B"), ("T", "T"),
                           ("LT", "LT"), ("LTA", "LTA")]:
            self.sign_level.addItem(label, val)
        orow.addWidget(self.sign_level)
        orow.addStretch(1)
        lay.addLayout(orow)

        # gruppo firma visibile (PAdES)
        self.grp_visible = QGroupBox("Firma visibile (PAdES)")
        self.grp_visible.setCheckable(True)
        self.grp_visible.setChecked(True)
        gv = QVBoxLayout(self.grp_visible)

        prow = QHBoxLayout()
        prow.addStretch(1)
        self.btn_page_prev = QPushButton("←")
        self.btn_page_prev.setFixedWidth(40)
        self.btn_page_prev.clicked.connect(
            lambda: self.sign_page.setValue(self.sign_page.value() - 1)
        )
        prow.addWidget(self.btn_page_prev)

        self.sign_page = QSpinBox()
        self.sign_page.setMinimum(1)
        self.sign_page.setMaximum(1)
        self.sign_page.setButtonSymbols(QAbstractSpinBox.NoButtons)
        self.sign_page.setAlignment(Qt.AlignCenter)
        self.sign_page.setFixedWidth(56)
        self.sign_page.valueChanged.connect(self._on_sign_page_changed)
        prow.addWidget(self.sign_page)

        self.sign_page_total = QLabel("/ 1")
        prow.addWidget(self.sign_page_total)

        self.btn_page_next = QPushButton("→")
        self.btn_page_next.setFixedWidth(40)
        self.btn_page_next.clicked.connect(
            lambda: self.sign_page.setValue(self.sign_page.value() + 1)
        )
        prow.addWidget(self.btn_page_next)
        prow.addStretch(1)
        gv.addLayout(prow)
        self._update_page_nav()

        if _HAS_QTPDF:
            self.preview = PdfSignaturePreview()
            gv.addWidget(self.preview, 1)
        else:
            self.preview = None
            gv.addWidget(QLabel("Anteprima non disponibile: posizione predefinita."))
        hint = QLabel("Trascina sul PDF per posizionare il riquadro.")
        hint.setStyleSheet(f"color:{_MUTED};")
        gv.addWidget(hint)
        lay.addWidget(self.grp_visible, 1)

        # selettore profilo utente (dai profili salvati in Impostazioni)
        prow2 = QHBoxLayout()
        prow2.addWidget(QLabel("Firma come:"))
        self.sign_profile = QComboBox()
        self.sign_profile.currentIndexChanged.connect(self._apply_sign_appearance)
        prow2.addWidget(self.sign_profile, 1)
        lay.addLayout(prow2)

        # azione
        arow = QHBoxLayout()
        self.btn_sign = QPushButton("🖊  Firma con Aruba (OTP)")
        self.btn_sign.setMinimumHeight(40)
        self.btn_sign.setEnabled(False)
        self.btn_sign.clicked.connect(self.do_sign)
        arow.addWidget(self.btn_sign)
        self.sign_result = QLabel("")
        self.sign_result.setWordWrap(True)
        arow.addWidget(self.sign_result, 1)
        lay.addLayout(arow)

        self._refresh_sign_profiles()
        self._apply_sign_appearance()
        return tab

    def _refresh_sign_profiles(self) -> None:
        """Ricarica il menu a tendina dei profili utente dai settaggi."""
        if not hasattr(self, "sign_profile"):
            return
        self.sign_profile.clear()
        for i, p in enumerate(self._config.profiles):
            self.sign_profile.addItem(p.label(), i)
        if self._config.profiles:
            self.sign_profile.setEnabled(True)
        else:
            self.sign_profile.addItem("(nessun utente — aggiungine in Impostazioni)", -1)
            self.sign_profile.setEnabled(False)

    def _load_logo_bytes(self) -> bytes:
        return _signature_bytes(self._config)

    def _preview_text(self) -> str:
        """Anteprima: NOME COGNOME (segnaposto, il vero nome è dal certificato) + data."""
        lines = _sig_text_lines("Nome Cognome", self._config.timezone,
                                self._config.sign_show_datetime)
        return "\n".join(lines) if lines else "NOME COGNOME"

    def _on_sign_page_changed(self, value: int) -> None:
        if _HAS_QTPDF and self.preview:
            self.preview.set_page(value - 1)
        self._update_page_nav()

    def _update_page_nav(self) -> None:
        """Abilita ← / → in base alla pagina corrente e al totale."""
        cur = self.sign_page.value()
        total = self.sign_page.maximum()
        self.btn_page_prev.setEnabled(cur > 1)
        self.btn_page_next.setEnabled(cur < total)

    def _apply_sign_appearance(self) -> None:
        """Aggiorna l'anteprima del riquadro (logo + nome/data + solo-immagine)."""
        if self.preview and _HAS_QTPDF:
            self.preview.set_logo(self._load_logo_bytes())
            self.preview.set_preview(self._preview_text(), self._config.sign_image_only)

    @staticmethod
    def _wrap(layout) -> QWidget:
        w = QWidget()
        w.setLayout(layout)
        return w

    def _sign_pick_file(self) -> None:
        flt = ("PDF (*.pdf)" if self.rb_pades.isChecked()
               else "Tutti i file (*)")
        path, _ = QFileDialog.getOpenFileName(self, "Documento da firmare", "", flt)
        if not path:
            return
        self._sign_src = path
        self.sign_path.setText(Path(path).name)
        self.sign_path.setStyleSheet("color:#24292f;")
        self.btn_sign.setEnabled(True)
        self.sign_result.setText("")
        if _HAS_QTPDF and self.rb_pades.isChecked() and path.lower().endswith(".pdf"):
            if self.preview and self.preview.load(path):
                total = max(1, self.preview.page_count())
                self.sign_page.setMaximum(total)
                self.sign_page_total.setText(f"/ {total}")
                self.sign_page.setValue(1)
                self._update_page_nav()
                self._apply_sign_appearance()

    def _sign_format_changed(self) -> None:
        is_pdf = self.rb_pades.isChecked()
        self.grp_visible.setVisible(is_pdf)

    def do_sign(self) -> None:
        if not self._sign_src:
            return
        # profilo utente selezionato
        idx = self.sign_profile.currentData()
        if idx is None or idx < 0 or idx >= len(self._config.profiles):
            QMessageBox.warning(
                self, "Nessun utente",
                "Aggiungi almeno un utente di firma remota in «Impostazioni ▸ Firma».")
            return
        prof = self._config.profiles[idx]
        if not prof.user or not prof.domain:
            QMessageBox.warning(self, "Profilo incompleto",
                                "Il profilo selezionato non ha utente e dominio.")
            return

        cfg = self._config
        cades = self.rb_cades.isChecked()
        want_visible = (not cades) and self.grp_visible.isChecked()
        dlg = CredentialsDialog(
            prof.user,
            ask_reason=want_visible and cfg.sign_ask_reason,
            ask_location=want_visible and cfg.sign_ask_location,
            parent=self)
        if dlg.exec() != QDialog.Accepted:
            return
        pwd, otp = dlg.values()
        if not pwd or not otp:
            QMessageBox.warning(self, "Dati mancanti", "Password e OTP sono richiesti.")
            return

        from . import aruba
        rect = self.preview.pdf_rect() if (self.preview and _HAS_QTPDF) else None
        lx, ly, rx, ry = rect if rect else (50, 50, 300, 130)
        # data/ora su righe separate (il NOME lo recupera il worker dal certificato)
        date_lines = []
        if want_visible and cfg.sign_show_datetime:
            now = _now_in_tz(cfg.timezone)
            date_lines = [now.strftime("%d/%m/%Y"), now.strftime("%H:%M:%S")]
        params = dict(
            data=Path(self._sign_src).read_bytes(),
            cades=cades,
            level=self.sign_level.currentData(),
            # NON inviamo signingTime: Aruba usa l'ora esatta del server (UTC).
            # Inviare l'ora locale la farebbe interpretare come UTC -> "data futura".
            # Il fuso serve solo alla data MOSTRATA nel riquadro (testo grafico).
            signing_time=None,
            user=prof.user, pwd=pwd, otp=otp, otp_type=prof.domain,
            cert_id=prof.cert_id, hsm=prof.hsm,
            wsdl=(aruba.WSDL_DEMO if prof.demo else aruba.WSDL_PROD),
            want_visible=want_visible,
            page=self.sign_page.value(),
            rect=(lx, ly, rx, ry),
            reason=dlg.reason_text(), location=dlg.location_text(),
            image_bin=self._load_logo_bytes(),
            image_only=cfg.sign_image_only,
            date_lines=date_lines,
            profile_name=prof.name,
        )
        self.btn_sign.setEnabled(False)
        self.sign_result.setStyleSheet(f"color:{_MUTED};")
        self.sign_result.setText("Firma in corso… (invio ad Aruba)")
        QGuiApplication.setOverrideCursor(Qt.WaitCursor)
        self._sign_worker = SignWorker(params)
        self._sign_worker.done.connect(lambda b, c=cades: self._on_signed(b, c))
        self._sign_worker.failed.connect(self._on_sign_failed)
        self._sign_worker.start()

    def _on_sign_failed(self, msg: str) -> None:
        QGuiApplication.restoreOverrideCursor()
        self.btn_sign.setEnabled(True)
        self.sign_result.setStyleSheet(f"color:{_BAD};")
        self.sign_result.setText("Firma non riuscita.")
        QMessageBox.critical(self, "Firma non riuscita", msg)

    def _on_signed(self, signed: bytes, cades: bool) -> None:
        QGuiApplication.restoreOverrideCursor()
        self.btn_sign.setEnabled(True)
        src = Path(self._sign_src)
        default = (src.with_suffix(src.suffix + ".p7m").name if cades
                   else src.with_name(src.stem + "-firmato.pdf").name)
        out, _ = QFileDialog.getSaveFileName(self, "Salva documento firmato", default)
        if not out:
            self.sign_result.setText("Firma completata (non salvata).")
            return
        try:
            Path(out).write_bytes(signed)
        except OSError as exc:
            QMessageBox.critical(self, "Errore", f"Impossibile salvare: {exc}")
            return
        self.sign_result.setStyleSheet(f"color:{_OK};")
        self.sign_result.setText(f"✓ Firmato: {Path(out).name} ({len(signed):,} byte)".replace(",", "."))

        if cades:
            # ri-verifica col nostro motore
            res = verifier.analyze_file(
                out, self._store.certificates,
                verifier.VerifyOptions(check_trust=bool(len(self._store)), allow_fetching=False),
                self._store.tsa_certificates)
            if res.signatures:
                s = res.signatures[0]
                QMessageBox.information(
                    self, "Firmato e verificato",
                    f"Firmatario: {s.signer.display_name}\nLivello: {s.level}\n"
                    f"Integrità: {'OK' if s.crypto_valid and s.digest_match else 'NO'}")
        else:
            QMessageBox.information(
                self, "Firmato",
                f"PDF firmato salvato:\n{out}\n\nPuoi aprirlo in un lettore PDF per "
                "vedere la firma visibile.")

    # -- util ------------------------------------------------------------- #
    def _set_busy(self, busy: bool, msg: str = "") -> None:
        for b in (self.btn_open, self.btn_extract, self.btn_open_doc):
            b.setEnabled(not busy)
        if busy:
            self.status.showMessage(msg)
            QGuiApplication.setOverrideCursor(Qt.WaitCursor)
        else:
            QGuiApplication.restoreOverrideCursor()
            if self._result and self._result.content:
                self.btn_extract.setEnabled(not self._is_pades_result)
                self.btn_open_doc.setEnabled(True)

    def _clear_cards(self) -> None:
        while self.cards_layout.count() > 1:
            item = self.cards_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()


class CorianoApp(QApplication):
    """QApplication che gestisce l'apertura di un .p7m via doppio clic.

    Su macOS il file arriva come ``QFileOpenEvent`` (anche ad app gia' avviata);
    su Windows/Linux come argomento a riga di comando.
    """

    def __init__(self, argv):
        super().__init__(argv)
        self._window: MainWindow | None = None
        self._pending: str | None = None
        self._instance_server = None  # QLocalServer del lock a istanza singola

    def event(self, e):  # noqa: N802
        if e.type() == QEvent.FileOpen:
            path = e.file()
            if path:
                self.open_path(path)
            return True
        return super().event(e)

    def attach_window(self, win: "MainWindow") -> None:
        self._window = win
        if self._pending:
            path, self._pending = self._pending, None
            self.open_path(path)

    def activate(self) -> None:
        """Porta in primo piano la finestra esistente (senza aprire file)."""
        if self._window is None:
            return
        win = self._window
        if win.isMinimized():
            win.showNormal()
        win.show()
        win.raise_()
        win.activateWindow()

    def open_path(self, path: str) -> None:
        if self._window is None:
            self._pending = path
            return
        self.activate()
        win = self._window
        # "Apri con": solo per i .p7m, a verifica verde apri il documento
        # incapsulato (non per i PDF PAdES, il cui contenuto è il PDF stesso).
        auto_open = path.lower().endswith(".p7m")
        QTimer.singleShot(0, lambda: win.analyze(path, auto_open_document=auto_open))


def _file_from_argv(argv) -> str | None:
    """Primo argomento che sia un file .p7m/.pdf esistente (Windows/Linux)."""
    for arg in argv[1:]:
        if arg.lower().endswith((".p7m", ".pdf")) and os.path.isfile(arg):
            return arg
    return None


def _instance_key() -> str:
    """Nome del lock, PER-UTENTE (istanze di utenti diversi non si disturbano)."""
    import getpass
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = "u"
    return f"CorianoSign-{user}"


def _forward_to_running(name: str, payload: str, timeout_ms: int = 400) -> bool:
    """Se esiste già un'istanza in ascolto, le invia ``payload`` e ritorna True.

    ``payload`` = percorso file da aprire, oppure "" per la sola attivazione.
    Ritorna False se non c'è alcuna istanza (o QtNetwork non è disponibile).
    """
    try:
        from PySide6.QtNetwork import QLocalSocket
    except Exception:  # noqa: BLE001
        return False
    sock = QLocalSocket()
    sock.connectToServer(name)
    if not sock.waitForConnected(timeout_ms):
        return False
    sock.write(payload.encode("utf-8"))
    sock.flush()
    sock.waitForBytesWritten(timeout_ms)
    sock.disconnectFromServer()
    if sock.state() != QLocalSocket.LocalSocketState.UnconnectedState:
        sock.waitForDisconnected(timeout_ms)
    return True


def _start_instance_server(app: "CorianoApp", name: str) -> None:
    """Mette in ascolto il server del lock: gestisce le seconde aperture."""
    try:
        from PySide6.QtNetwork import QLocalServer
    except Exception:  # noqa: BLE001
        return
    server = QLocalServer()
    # rimuove un eventuale socket stantio lasciato da un crash precedente
    QLocalServer.removeServer(name)
    if not server.listen(name):
        return  # non bloccante: senza lock l'app funziona comunque

    def _on_connection() -> None:
        conn = server.nextPendingConnection()
        if conn is None:
            return
        payload = ""
        if conn.waitForReadyRead(500):
            payload = bytes(conn.readAll()).decode("utf-8", "ignore").strip()
        conn.disconnectFromServer()
        if payload:
            app.open_path(payload)
        else:
            app.activate()

    server.newConnection.connect(_on_connection)
    app._instance_server = server  # trattieni il riferimento


def run() -> int:
    file_arg = _file_from_argv(sys.argv)

    existing = QApplication.instance()
    app = existing or CorianoApp(sys.argv)
    app.setApplicationName(__app_name__)
    app.setApplicationDisplayName(__app_name__)
    app.setWindowIcon(app_icon())

    # Istanza singola: se ce n'è già una attiva, passale il file (o la sola
    # attivazione) ed esci senza aprire una seconda finestra.
    lock_name = _instance_key()
    if isinstance(app, CorianoApp) and _forward_to_running(lock_name, file_arg or ""):
        return 0

    win = MainWindow()
    win.show()

    if isinstance(app, CorianoApp):
        app.attach_window(win)
        _start_instance_server(app, lock_name)
        # file passato come argomento (Windows/Linux o riga di comando)
        if file_arg:
            app.open_path(file_arg)

    return app.exec()
