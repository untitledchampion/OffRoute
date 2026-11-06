"""icon/source.jpg (white helmet on black) -> icon/helmet.png: the helmet with a transparent background, for the window."""
import subprocess
from pathlib import Path
from make_icons import read, write_png, D

out = D / "out"
out.mkdir(exist_ok=True)
subprocess.run(["sips", "-s", "format", "png", "-c", "860", "860", str(D / "source.jpg"), "--out", str(out / "h.png")], capture_output=True, check=True)
subprocess.run(["sips", "-z", "512", "512", str(out / "h.png"), "--out", str(out / "h512.png")], capture_output=True, check=True)
w, h, bpp, bpr, d = read(out / "h512.png")
dark = [[sum(d[y * bpr + x * bpp + i] for i in range(3)) < 3 * 70 for x in range(w)] for y in range(h)]
bg = [[False] * w for _ in range(h)]
stack = [(0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)]
while stack:
    x, y = stack.pop()
    if 0 <= x < w and 0 <= y < h and not bg[y][x] and dark[y][x]:
        bg[y][x] = True
        stack += [(x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)]
rgba = bytearray(w * h * 4)
for y in range(h):
    for x in range(w):
        i, o = y * bpr + x * bpp, (y * w + x) * 4
        rgba[o:o + 3] = d[i:i + 3]
        rgba[o + 3] = 0 if bg[y][x] else 255
write_png(D / "helmet.png", w, h, bytes(rgba))
print("ok")
