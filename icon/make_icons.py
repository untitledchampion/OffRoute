"""Turn QuickLook renders (white background) into icons: app icon with transparent rounded corners, menu bar
template (black silhouette on transparent), and AppIcon.icns."""
import struct
import subprocess
import zlib
from pathlib import Path

from AppKit import NSBitmapImageRep

D = Path(__file__).resolve().parent


def read(p):
    r = NSBitmapImageRep.imageRepWithContentsOfFile_(str(p))
    w, h, bpp, bpr = r.pixelsWide(), r.pixelsHigh(), r.bitsPerPixel() // 8, r.bytesPerRow()
    data = bytes(r.bitmapData()[: bpr * h])
    return w, h, bpp, bpr, data


def write_png(p, w, h, rgba):
    raw = b"".join(b"\x00" + rgba[y * w * 4:(y + 1) * w * 4] for y in range(h))
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)) \
        + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    Path(p).write_bytes(png)


def template():
    w, h, bpp, bpr, d = read(D / "out/tpl.svg.png")
    out = bytearray(w * h * 4)
    for y in range(h):
        for x in range(w):
            i = y * bpr + x * bpp
            lum = (d[i] + d[i + 1] + d[i + 2]) // 3
            out[(y * w + x) * 4 + 3] = 255 - lum  # black silhouette, background transparent
    write_png(D / "menubar.png", w, h, bytes(out))
    subprocess.run(["sips", "-z", "36", "36", str(D / "menubar.png"), "--out", str(D / "menubarTemplate.png")], capture_output=True)
    subprocess.run(["sips", "-z", "72", "72", str(D / "menubar.png"), "--out", str(D / "menubarTemplate@2x.png")], capture_output=True)


def app():
    w, h, bpp, bpr, d = read(D / "out/app.svg.png")
    rad = 230 * w / 1024
    out = bytearray(w * h * 4)
    for y in range(h):
        for x in range(w):
            i = y * bpr + x * bpp
            o = (y * w + x) * 4
            cx = min(max(x + 0.5, rad), w - rad)
            cy = min(max(y + 0.5, rad), h - rad)
            inside = (x + 0.5 - cx) ** 2 + (y + 0.5 - cy) ** 2 <= rad * rad
            out[o:o + 3] = d[i:i + 3]
            out[o + 3] = 255 if inside else 0
    write_png(D / "app.png", w, h, bytes(out))
    iconset = D / "AppIcon.iconset"
    iconset.mkdir(exist_ok=True)
    for s in (16, 32, 128, 256, 512):
        for k, suffix in ((1, ""), (2, "@2x")):
            subprocess.run(["sips", "-z", str(s * k), str(s * k), str(D / "app.png"),
                            "--out", str(iconset / f"icon_{s}x{s}{suffix}.png")], capture_output=True)
    subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(D / "AppIcon.icns")], check=True)


def from_source(src):
    """A square picture (white helmet on black) -> app.png (rounded corners), AppIcon.icns, menu bar template
    (solid helmet silhouette: everything not connected to the black background through dark pixels)."""
    out = D / "out"
    out.mkdir(exist_ok=True)
    subprocess.run(["sips", "-s", "format", "png", "-c", "904", "904", str(src), "--out", str(out / "crop.png")], capture_output=True, check=True)
    subprocess.run(["sips", "-z", "1024", "1024", str(out / "crop.png"), "--out", str(out / "app.svg.png")], capture_output=True, check=True)
    app()
    subprocess.run(["sips", "-z", "256", "256", str(out / "crop.png"), "--out", str(out / "small.png")], capture_output=True, check=True)
    w, h, bpp, bpr, d = read(out / "small.png")
    dark = [[(d[y * bpr + x * bpp] + d[y * bpr + x * bpp + 1] + d[y * bpr + x * bpp + 2]) < 3 * 90 for x in range(w)] for y in range(h)]
    bg = [[False] * w for _ in range(h)]
    stack = [(0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)]
    while stack:
        x, y = stack.pop()
        if 0 <= x < w and 0 <= y < h and not bg[y][x] and dark[y][x]:
            bg[y][x] = True
            stack += [(x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)]
    # cut out the biggest dark area inside the helmet (the goggle lens) so the silhouette reads as a helmet
    seen = [[False] * w for _ in range(h)]
    best = []
    for sy in range(h):
        for sx in range(w):
            if dark[sy][sx] and not bg[sy][sx] and not seen[sy][sx]:
                comp, st = [], [(sx, sy)]
                while st:
                    x, y = st.pop()
                    if 0 <= x < w and 0 <= y < h and dark[y][x] and not bg[y][x] and not seen[y][x]:
                        seen[y][x] = True
                        comp.append((x, y))
                        st += [(x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)]
                if len(comp) > len(best):
                    best = comp
    hole = set(best)
    rgba = bytearray(w * h * 4)
    for y in range(h):
        for x in range(w):
            rgba[(y * w + x) * 4 + 3] = 0 if bg[y][x] or (x, y) in hole else 255
    write_png(D / "menubar.png", w, h, bytes(rgba))
    for size, name in ((36, "menubarTemplate.png"), (72, "menubarTemplate@2x.png")):
        subprocess.run(["sips", "-z", str(size), str(size), str(D / "menubar.png"), "--out", str(D / name)], capture_output=True)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        from_source(Path(sys.argv[1]))
    else:
        template()
        app()
    print("ok")
