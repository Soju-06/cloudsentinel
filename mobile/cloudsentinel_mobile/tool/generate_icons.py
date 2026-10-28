"""Generate CloudSentinel launcher icons (legacy + adaptive).

Run from the Flutter project root:

    python tool/generate_icons.py

Requires Pillow. Outputs PNGs into android/app/src/main/res/mipmap-*.
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "android" / "app" / "src" / "main" / "res"

DENSITIES = {
    "mdpi": 1.0,
    "hdpi": 1.5,
    "xhdpi": 2.0,
    "xxhdpi": 3.0,
    "xxxhdpi": 4.0,
}

LEGACY_BASE = 48
FOREGROUND_BASE = 108
SUPERSAMPLE = 4

CYAN = (0, 229, 255)
CYAN_SOFT = (0, 229, 255, 90)
VIOLET = (124, 77, 255)
DARK_TOP = (7, 12, 24)
DARK_BOTTOM = (12, 24, 42)
SHIELD_FILL = (9, 19, 34)


def _shield_points(cx: float, cy: float, w: float, h: float) -> list[tuple[float, float]]:
    """Smooth shield outline with straight shoulders and a curved point."""

    left, right = cx - w / 2, cx + w / 2
    top = cy - h / 2
    shoulder = cy + h * 0.06
    bottom = cy + h / 2

    points: list[tuple[float, float]] = [(left, top), (right, top), (right, shoulder)]

    def quadratic(p0, p1, p2, steps=40):
        for index in range(1, steps + 1):
            t = index / steps
            x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t**2 * p2[0]
            y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t**2 * p2[1]
            points.append((x, y))

    quadratic(
        (right, shoulder),
        (right, bottom - h * 0.26),
        (cx, bottom),
    )
    quadratic(
        (cx, bottom),
        (left, bottom - h * 0.26),
        (left, shoulder),
    )
    return points


def _inset(points, cx, cy, factor):
    return [(cx + (x - cx) * factor, cy + (y - cy) * factor) for x, y in points]


def render(size: int, background: bool, content: float) -> Image.Image:
    scale = size / 1024 * SUPERSAMPLE
    big = size * SUPERSAMPLE
    image = Image.new("RGBA", (big, big), (0, 0, 0, 0))

    if background:
        gradient = Image.new("RGBA", (big, big))
        pixels = gradient.load()
        for y in range(big):
            ratio = y / max(1, big - 1)
            eased = ratio**0.85
            color = tuple(
                int(DARK_TOP[i] + (DARK_BOTTOM[i] - DARK_TOP[i]) * eased)
                for i in range(3)
            )
            for x in range(big):
                pixels[x, y] = color + (255,)

        glow = Image.new("RGBA", (big, big), (0, 0, 0, 0))
        glow_draw = ImageDraw.Draw(glow)
        glow_draw.ellipse(
            [-big * 0.30, big * 0.42, big * 0.72, big * 1.30],
            fill=(0, 180, 235, 70),
        )
        glow_draw.ellipse(
            [big * 0.46, -big * 0.30, big * 1.20, big * 0.48],
            fill=(105, 62, 255, 55),
        )
        glow = glow.filter(ImageFilter.GaussianBlur(big * 0.08))
        gradient.alpha_composite(glow)
        image.alpha_composite(gradient)

    draw = ImageDraw.Draw(image)
    cx, cy = big / 2, big / 2
    shield_w = big * 0.50 * content
    shield_h = big * 0.60 * content
    points = _shield_points(cx, cy, shield_w, shield_h)

    # Outer glow.
    halo = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    halo_draw = ImageDraw.Draw(halo)
    halo_draw.polygon(points, fill=CYAN + (120,))
    halo = halo.filter(ImageFilter.GaussianBlur(big * 0.030))
    image.alpha_composite(halo)

    draw = ImageDraw.Draw(image)
    border = max(2, int(big * 0.012))
    draw.polygon(points, fill=CYAN + (255,))
    inner = _inset(points, cx, cy, 1 - (border * 2) / shield_w)
    draw.polygon(inner, fill=SHIELD_FILL + (255,))

    # Radar inside the shield.
    radar_cy = cy + shield_h * 0.02
    radius = shield_w * 0.30
    sweep_layer = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    sweep_draw = ImageDraw.Draw(sweep_layer)
    sweep_draw.pieslice(
        [cx - radius, radar_cy - radius, cx + radius, radar_cy + radius],
        start=248,
        end=308,
        fill=CYAN + (60,),
    )
    sweep_layer = sweep_layer.filter(ImageFilter.GaussianBlur(big * 0.006))
    image.alpha_composite(sweep_layer)

    draw = ImageDraw.Draw(image)
    for index, fraction in enumerate((1.0, 0.66, 0.32)):
        width = max(2, int(big * (0.0045 if index else 0.0055)))
        draw.arc(
            [
                cx - radius * fraction,
                radar_cy - radius * fraction,
                cx + radius * fraction,
                radar_cy + radius * fraction,
            ],
            start=195,
            end=345,
            fill=CYAN + (220 if index == 0 else 140,),
            width=width,
        )

    # Sweep needle.
    angle = math.radians(300)
    draw.line(
        [
            (cx, radar_cy),
            (cx + radius * 0.95 * math.cos(angle), radar_cy + radius * 0.95 * math.sin(angle)),
        ],
        fill=CYAN + (235,),
        width=max(2, int(big * 0.006)),
    )

    # Contact dot.
    dot_r = max(3, int(big * 0.014))
    dot_x = cx + radius * 0.55 * math.cos(math.radians(312))
    dot_y = radar_cy + radius * 0.55 * math.sin(math.radians(312))
    draw.ellipse(
        [dot_x - dot_r, dot_y - dot_r, dot_x + dot_r, dot_y + dot_r],
        fill=VIOLET + (255,),
    )
    # Centre pivot.
    draw.ellipse(
        [cx - dot_r * 0.7, radar_cy - dot_r * 0.7, cx + dot_r * 0.7, radar_cy + dot_r * 0.7],
        fill=CYAN + (255,),
    )

    return image.resize((size, size), Image.LANCZOS)


def main() -> None:
    for density, factor in DENSITIES.items():
        folder = RES / f"mipmap-{density}"
        folder.mkdir(parents=True, exist_ok=True)

        legacy_px = round(LEGACY_BASE * factor)
        render(legacy_px, background=True, content=1.0).save(
            folder / "ic_launcher.png"
        )

        foreground_px = round(FOREGROUND_BASE * factor)
        render(foreground_px, background=False, content=1.25).save(
            folder / "ic_launcher_foreground.png"
        )

    adaptive = RES / "mipmap-anydpi-v26"
    adaptive.mkdir(parents=True, exist_ok=True)
    (adaptive / "ic_launcher.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
        '    <background android:drawable="@color/ic_launcher_background" />\n'
        '    <foreground android:drawable="@mipmap/ic_launcher_foreground" />\n'
        '    <monochrome android:drawable="@mipmap/ic_launcher_foreground" />\n'
        '</adaptive-icon>\n',
        encoding="utf-8",
    )

    values = RES / "values"
    values.mkdir(parents=True, exist_ok=True)
    (values / "colors.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<resources>\n"
        '    <color name="ic_launcher_background">#070C18</color>\n'
        "</resources>\n",
        encoding="utf-8",
    )
    print("icons written to", RES)


if __name__ == "__main__":
    main()
