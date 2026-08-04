#!/usr/bin/env python3
"""
make-splash.py - render a boot splash at a panel's exact native resolution.

Centres artwork on a solid background, scaled to a fraction of the screen
width. Output is intended to be fed straight to build-logo.py.

Usage:
    ./make-splash.py --width 480 --height 640 --src my-logo.png \
                     -o splash_480x640.png [--fraction 0.78] [--bg 000000]
"""
import argparse

from PIL import Image


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--width", type=int, required=True)
    ap.add_argument("--height", type=int, required=True)
    ap.add_argument("--src", required=True, help="artwork, ideally with alpha")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--fraction", type=float, default=0.78,
                    help="logo width as a fraction of screen width (default 0.78)")
    ap.add_argument("--bg", default="000000", help="background as RRGGBB (default black)")
    args = ap.parse_args()

    bg = tuple(int(args.bg[i:i + 2], 16) for i in (0, 2, 4)) + (255,)

    logo = Image.open(args.src).convert("RGBA")
    # Crop to the artwork's real ink so padding in the source doesn't skew centring.
    box = logo.getbbox()
    if box:
        logo = logo.crop(box)

    tw = int(args.width * args.fraction)
    th = max(1, round(logo.height * tw / logo.width))
    if th > args.height:  # very wide panels: fit to height instead
        th = int(args.height * args.fraction)
        tw = max(1, round(logo.width * th / logo.height))
    logo = logo.resize((tw, th), Image.LANCZOS)

    canvas = Image.new("RGBA", (args.width, args.height), bg)
    canvas.alpha_composite(logo, ((args.width - tw) // 2, (args.height - th) // 2))
    canvas.save(args.output)

    print(f"wrote {args.output}  ({args.width}x{args.height}, logo {tw}x{th} centred)")


if __name__ == "__main__":
    main()
