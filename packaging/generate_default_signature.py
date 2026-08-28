"""Genera l'immagine di firma grafica predefinita (PAdES).

Un emblema/sigillo professionale "FIRMA DIGITALE": doppio anello, un pennino
stilizzato e uno svolazzo, testo curvo. Sfondo trasparente così si integra sul
timbro bianco della firma. Rende un PNG ad alta risoluzione.

    python packaging/generate_default_signature.py
"""
from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent / "assets" / "default_signature.png"

SIZE = 1024
INK = (26, 58, 95, 255)        # blu istituzionale
INK_SOFT = (26, 58, 95, 90)


def _font(size: int) -> ImageFont.FreeTypeFont:
    for name in (
        "/System/Library/Fonts/Supplemental/Georgia Bold.ttf",
        "/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf",
        "/Library/Fonts/Arial Bold.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
    ):
        if Path(name).is_file():
            try:
                return ImageFont.truetype(name, size)
            except OSError:
                continue
    return ImageFont.load_default()


def _arc_text(draw, center, radius, text, font, color, top=True):
    """Dispone il testo lungo un arco di cerchio."""
    cx, cy = center
    # larghezza totale approssimata in angolo
    widths = [draw.textlength(ch, font=font) for ch in text]
    total = sum(widths)
    ang_span = total / radius  # radianti
    start = -math.pi / 2 - ang_span / 2 if top else math.pi / 2 + ang_span / 2
    direction = 1 if top else -1
    acc = 0.0
    for ch, w in zip(text, widths):
        a = start + direction * (acc + w / 2) / radius
        x = cx + radius * math.cos(a)
        y = cy + radius * math.sin(a)
        rot = math.degrees(a) + (90 if top else -90)
        ch_img = Image.new("RGBA", (font.size * 2, font.size * 2), (0, 0, 0, 0))
        d2 = ImageDraw.Draw(ch_img)
        d2.text((font.size, font.size), ch, font=font, fill=color, anchor="mm")
        ch_img = ch_img.rotate(-rot, resample=Image.BICUBIC, center=(font.size, font.size))
        draw._image.paste(ch_img, (int(x - font.size), int(y - font.size)), ch_img)
        acc += w


def main() -> None:
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d._image = img  # per _arc_text

    c = SIZE / 2
    r_out = SIZE * 0.46
    r_in = SIZE * 0.36

    # doppio anello
    d.ellipse([c - r_out, c - r_out, c + r_out, c + r_out], outline=INK, width=int(SIZE * 0.018))
    d.ellipse([c - r_in, c - r_in, c + r_in, c + r_in], outline=INK, width=int(SIZE * 0.010))

    # testo curvo
    f_top = _font(int(SIZE * 0.072))
    f_bot = _font(int(SIZE * 0.060))
    _arc_text(d, (c, c), (r_out + r_in) / 2, "FIRMA  DIGITALE", f_top, INK, top=True)
    _arc_text(d, (c, c), (r_out + r_in) / 2, "documento  firmato", f_bot, INK, top=False)

    # piccoli rombi ai lati
    for side in (-1, 1):
        sx = c + side * (r_out + r_in) / 2
        s = SIZE * 0.020
        d.polygon([(sx, c - s), (sx + s, c), (sx, c + s), (sx - s, c)], fill=INK)

    # pennino stilizzato al centro
    pen_len = SIZE * 0.30
    pw = SIZE * 0.075
    top_x, top_y = c + pen_len * 0.42, c - pen_len * 0.55
    tip_x, tip_y = c - pen_len * 0.42, c + pen_len * 0.55
    dx, dy = tip_x - top_x, tip_y - top_y
    ln = math.hypot(dx, dy)
    ux, uy = dx / ln, dy / ln
    px, py = -uy, ux  # perpendicolare
    # corpo del pennino (trapezio che si assottiglia verso la punta)
    body = [
        (top_x + px * pw / 2, top_y + py * pw / 2),
        (top_x - px * pw / 2, top_y - py * pw / 2),
        (tip_x - px * pw * 0.06, tip_y - py * pw * 0.06),
        (tip_x + px * pw * 0.06, tip_y + py * pw * 0.06),
    ]
    d.polygon(body, fill=INK)
    # fenditura centrale del pennino
    d.line([(top_x, top_y), (tip_x, tip_y)], fill=(255, 255, 255, 255), width=int(SIZE * 0.008))
    # punta scritta
    d.ellipse([tip_x - SIZE * 0.012, tip_y - SIZE * 0.012,
               tip_x + SIZE * 0.012, tip_y + SIZE * 0.012], fill=INK)

    # svolazzo della firma sotto il pennino
    flourish = []
    for t in range(0, 101):
        tt = t / 100
        x = c - pen_len * 0.55 + tt * pen_len * 1.15
        y = c + pen_len * 0.62 + math.sin(tt * math.pi * 2.2) * SIZE * 0.045
        flourish.append((x, y))
    d.line(flourish, fill=INK_SOFT, width=int(SIZE * 0.012), joint="curve")

    img.save(OUT)
    print("scritta:", OUT, img.size)


if __name__ == "__main__":
    main()
