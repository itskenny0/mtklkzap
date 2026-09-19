#!/usr/bin/env python3
"""
make-splash.py - render a boot splash at a panel's exact native resolution.

Centres artwork on a solid background, scaled to a fraction of the screen
width. Output is intended to be fed straight to build-logo.py.

Usage:
    ./make-splash.py --width 480 --height 640 --src my-logo.png \
                     -o splash_480x640.png [--fraction 0.78] [--bg 000000]

Some panels (a lot of smartwatches) are mounted rotated relative to the logo
buffer, so a normally-composed splash shows up sideways. --rotate DEGREES turns
the logo clockwise before it's placed, keeping the canvas the panel's size, so it
reads upright on the physical screen.
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
    ap.add_argument("--rotate", type=float, default=0,
                    help="rotate the logo this many degrees clockwise before placing "
                         "it (for panels mounted rotated, e.g. many smartwatches)")
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

    if args.rotate:
        # PIL rotates counter-clockwise for positive angles; negate for clockwise.
        logo = logo.rotate(-args.rotate, expand=True, resample=Image.BICUBIC)

    canvas = Image.new("RGBA", (args.width, args.height), bg)
    pw, ph = logo.size
    canvas.alpha_composite(logo, ((args.width - pw) // 2, (args.height - ph) // 2))
    canvas.save(args.output)

    rot = f", rotated {args.rotate:g} deg CW" if args.rotate else ""
    print(f"wrote {args.output}  ({args.width}x{args.height}, logo {pw}x{ph} centred{rot})")


if __name__ == "__main__":
    main()
