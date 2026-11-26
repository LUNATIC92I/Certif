"""Génère l'icône de l'application (resources/app.ico et app.png) : bouclier stylisé, sans marque tierce."""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parents[1] / "src" / "ai_soc_analyst" / "resources"


def draw(size: int = 256) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size / 256
    shield = [(128 * s, 14 * s), (226 * s, 50 * s), (220 * s, 140 * s), (128 * s, 244 * s), (36 * s, 140 * s), (30 * s, 50 * s)]
    d.polygon(shield, fill=(11, 17, 24, 255), outline=(0, 194, 184, 255), width=max(2, int(10 * s)))
    inner = [(128 * s, 40 * s), (202 * s, 66 * s), (198 * s, 136 * s), (128 * s, 214 * s), (58 * s, 136 * s), (54 * s, 66 * s)]
    d.polygon(inner, outline=(30, 144, 255, 255), width=max(1, int(4 * s)))
    font_path = OUT / "fonts" / "DejaVuSans-Bold.ttf"
    font = ImageFont.truetype(str(font_path), int(78 * s))
    d.text((128 * s, 128 * s), "AI", font=font, fill=(230, 237, 243, 255), anchor="mm")
    return img


if __name__ == "__main__":
    big = draw(256)
    big.save(OUT / "app.png")
    big.save(OUT / "app.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("Icône écrite dans", OUT)
