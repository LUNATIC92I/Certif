"""Génère les ressources graphiques du guide (motif de couverture) sans dépendance externe autre que Pillow."""
import math
import random
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

HERE = Path(__file__).resolve().parent
RED = (227, 0, 27)


def cover_pattern(path=HERE / "cover_pattern.png", w=1240, h=1754, seed=7):
    """Réseau de nœuds et de liens évoquant la télémétrie corrélée, sur fond noir profond."""
    rng = random.Random(seed)
    img = Image.new("RGB", (w, h), (11, 12, 16))
    glow = Image.new("RGB", (w, h), (0, 0, 0))
    d = ImageDraw.Draw(img)
    g = ImageDraw.Draw(glow)
    nodes = []
    for _ in range(140):
        x = rng.uniform(w * 0.38, w * 1.05)
        y = rng.uniform(-40, h * 0.62)
        nodes.append((x, y))
    for i, (x1, y1) in enumerate(nodes):
        near = sorted(nodes, key=lambda p: (p[0] - x1) ** 2 + (p[1] - y1) ** 2)[1:4]
        for (x2, y2) in near:
            dist = math.hypot(x2 - x1, y2 - y1)
            if dist < 210:
                fade = max(0, 1 - (w - x1) / w) * 0.6 + 0.15
                c = int(70 * fade)
                d.line([(x1, y1), (x2, y2)], fill=(c + 18, c + 20, c + 26), width=2)
    for (x, y) in nodes:
        r = rng.choice([2, 3, 3, 4, 6])
        hot = rng.random() < 0.16
        col = RED if hot else (120, 124, 134)
        d.ellipse([x - r, y - r, x + r, y + r], fill=col)
        if hot:
            g.ellipse([x - 14, y - 14, x + 14, y + 14], fill=(150, 0, 18))
    glow = glow.filter(ImageFilter.GaussianBlur(10))
    img = Image.blend(img, Image.composite(glow, img, glow.convert("L")), 0.55)
    # dégradé vers le bas pour la zone de texte
    shade = Image.new("L", (w, h), 0)
    sd = ImageDraw.Draw(shade)
    for yy in range(h):
        sd.line([(0, yy), (w, yy)], fill=int(min(255, max(0, (yy - h * 0.35) / (h * 0.4) * 255))))
    img = Image.composite(Image.new("RGB", (w, h), (11, 12, 16)), img, shade)
    img.save(path, optimize=True)
    return path


if __name__ == "__main__":
    print(cover_pattern())
