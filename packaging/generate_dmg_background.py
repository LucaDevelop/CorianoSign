"""Genera lo sfondo della finestra DMG (freccia + "Trascina in Applicazioni").

    python packaging/generate_dmg_background.py

Produce packaging/dmg_background.png (640x400) e dmg_background@2x.png
(1280x800). La finestra del DMG e' 640x400, icona app centrata a (160,200) e
cartella Applicazioni a (480,200): la freccia sta nel mezzo.
"""
from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

W, H = 640, 400
# posizioni (centro) delle icone, coerenti con make_dmg_macos.sh
APP_X, DROP_X, ICON_Y = 160, 480, 200

BLUE = (30, 111, 217)          # blu accento (icona/app)
INK = (43, 58, 74)             # testo scuro
GREY = (120, 133, 148)         # testo secondario
TOP = (238, 243, 249)          # gradiente alto
BOTTOM = (255, 255, 255)       # gradiente basso

_FONTS = [
    "/System/Library/Fonts/Helvetica.ttc",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/SFNS.ttf",
]


def _font(size: int, bold: bool = False):
    paths = _FONTS[:]
    if bold:
        paths = ["/System/Library/Fonts/Supplemental/Arial Bold.ttf"] + paths
    for p in paths:
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size)
            except Exception:  # noqa: BLE001
                continue
    return ImageFont.load_default()


def _center_text(d, xy, text, font, fill):
    x, y = xy
    l, t, r, b = d.textbbox((0, 0), text, font=font)
    d.text((x - (r - l) / 2, y - (b - t) / 2), text, font=font, fill=fill)


def _draw(scale: int) -> Image.Image:
    """Disegna a risoluzione supersample e ridimensiona per l'antialiasing."""
    ss = 4  # supersampling
    w, h = W * scale * ss, H * scale * ss
    k = scale * ss

    img = Image.new("RGB", (w, h), BOTTOM)
    d = ImageDraw.Draw(img)

    # gradiente verticale morbido
    for y in range(h):
        f = y / h
        r = int(TOP[0] + (BOTTOM[0] - TOP[0]) * f)
        g = int(TOP[1] + (BOTTOM[1] - TOP[1]) * f)
        b = int(TOP[2] + (BOTTOM[2] - TOP[2]) * f)
        d.line([(0, y), (w, y)], fill=(r, g, b))

    # titolo in alto
    _center_text(d, (W * k / 2, 46 * k), "Installazione di CorianoSign",
                 _font(24 * k, bold=True), INK)

    # freccia orizzontale tra le due icone (all'altezza dei centri icona)
    y = ICON_Y * k
    x0 = (APP_X + 52) * k      # dopo l'icona app
    x1 = (DROP_X - 58) * k     # prima della cartella Applicazioni
    shaft = 9 * k
    d.line([(x0, y), (x1 - 10 * k, y)], fill=BLUE, width=shaft)
    # punta della freccia
    head = 26 * k
    d.polygon([(x1, y), (x1 - head, y - head * 0.7),
               (x1 - head, y + head * 0.7)], fill=BLUE)

    # "Trascina" sopra la freccia
    _center_text(d, ((x0 + x1) / 2, y - 34 * k), "Trascina",
                 _font(20 * k, bold=True), BLUE)

    # didascalia in basso
    _center_text(d, (W * k / 2, 344 * k),
                 "Trascina l'icona di CorianoSign nella cartella Applicazioni",
                 _font(15 * k), GREY)

    return img.resize((W * scale, H * scale), Image.LANCZOS)


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    _draw(1).save(os.path.join(here, "dmg_background.png"))
    _draw(2).save(os.path.join(here, "dmg_background@2x.png"))
    print("Creati: packaging/dmg_background.png e dmg_background@2x.png")


if __name__ == "__main__":
    main()
