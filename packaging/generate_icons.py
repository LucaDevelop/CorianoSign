"""Genera le icone dell'app da packaging/icon.svg.

Produce:
    packaging/icons/  (PNG a varie dimensioni)
    packaging/CorianoSign.ico   (Windows)
    packaging/CorianoSign.icns  (macOS, solo se lanciato su macOS con iconutil)
    docs/icon.png               (anteprima 256px)

Uso:
    python packaging/generate_icons.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

ROOT = Path(__file__).resolve().parent.parent
SVG = ROOT / "packaging" / "icon.svg"
ICONS_DIR = ROOT / "packaging" / "icons"
SIZES = [16, 32, 64, 128, 256, 512, 1024]


def render_png(renderer: QSvgRenderer, size: int, out: Path) -> None:
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    painter = QPainter(img)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
    renderer.render(painter)
    painter.end()
    img.save(str(out))


def build_ico(png_paths: list[Path], out: Path) -> None:
    from PIL import Image

    imgs = [Image.open(p).convert("RGBA") for p in png_paths]
    base = imgs[-1]  # 256
    base.save(out, format="ICO",
              sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print(f"  -> {out.relative_to(ROOT)}")


def build_icns(iconset_pngs: dict[int, Path], out: Path) -> None:
    """Crea .icns con iconutil (solo macOS)."""
    if sys.platform != "darwin":
        print("  (.icns saltato: non su macOS)")
        return
    iconset = ROOT / "packaging" / "CorianoSign.iconset"
    iconset.mkdir(exist_ok=True)
    # mappa dimensioni -> nomi richiesti da iconutil
    mapping = {
        16: ["icon_16x16.png"],
        32: ["icon_16x16@2x.png", "icon_32x32.png"],
        64: ["icon_32x32@2x.png"],
        128: ["icon_128x128.png"],
        256: ["icon_128x128@2x.png", "icon_256x256.png"],
        512: ["icon_256x256@2x.png", "icon_512x512.png"],
        1024: ["icon_512x512@2x.png"],
    }
    import shutil

    for size, names in mapping.items():
        for name in names:
            shutil.copy(iconset_pngs[size], iconset / name)
    subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(out)], check=True)
    shutil.rmtree(iconset)
    print(f"  -> {out.relative_to(ROOT)}")


def main() -> int:
    _app = QGuiApplication.instance() or QGuiApplication(sys.argv)
    data = QByteArray(SVG.read_bytes())
    renderer = QSvgRenderer(data)
    if not renderer.isValid():
        print("SVG non valido:", SVG)
        return 1

    ICONS_DIR.mkdir(parents=True, exist_ok=True)
    pngs: dict[int, Path] = {}
    print("Render PNG:")
    for s in SIZES:
        out = ICONS_DIR / f"icon_{s}.png"
        render_png(renderer, s, out)
        pngs[s] = out
        print(f"  {s}x{s}")

    print("Genero .ico:")
    build_ico([pngs[s] for s in (16, 32, 64, 128, 256)], ROOT / "packaging" / "CorianoSign.ico")

    print("Genero .icns:")
    build_icns(pngs, ROOT / "packaging" / "CorianoSign.icns")

    (ROOT / "docs").mkdir(exist_ok=True)
    import shutil

    shutil.copy(pngs[256], ROOT / "docs" / "icon.png")
    print("  -> docs/icon.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
