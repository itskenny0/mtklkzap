#!/usr/bin/env python3
"""
build-logo.py - replace boot-splash slots in an MTK `logo.bin` and verify it.

Wraps the mtklogo unpack/repack round-trip with the safety steps that matter:

  * every slot you are NOT replacing is carried through as raw `.z`, so it
    repacks byte-identically (no decode/re-encode loss);
  * the STOCK 0x200 MTK header is preserved and only its payload-length field
    is rewritten, instead of letting mtklogo emit its own header (which renames
    the image to `LOGO` and drops the secondary 0x89168958 block);
  * the result is re-unpacked and diffed slot-by-slot against the original, so
    the tool proves it changed exactly what you asked for and nothing else;
  * the output is checked to fit the partition.

Usage:
    ./build-logo.py --logo logo.bin.orig --profile profiles/mt6765-480x640.yaml \
                    --name mt6765-480x640 --image splash.png --slots 0,38 \
                    --partition-size 11534336 -o logo.bin.new

The image must already be the panel's exact pixel size; this does not rescale.

Requires the `mtklogo` binary (https://github.com/arlept/mtklogo) on PATH, in
$MTKLOGO, or passed via --mtklogo.
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import yaml
from PIL import Image

MTK_MAGIC = bytes.fromhex("88168858")
HDR = 0x200


def die(msg):
    sys.exit(f"error: {msg}")


def resolve_mtklogo(explicit):
    """Find the mtklogo binary: explicit arg, then $MTKLOGO, then a local build,
    then whatever is on PATH. Returns a path string or None."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    if os.environ.get("MTKLOGO"):
        candidates.append(os.environ["MTKLOGO"])
    candidates.append(str(Path(__file__).parent / "mtklogo/cli/target/release/mtklogo"))
    for c in candidates:
        if Path(c).exists():
            return c
    return shutil.which("mtklogo")


def run(mtk, *args):
    r = subprocess.run([mtk, *map(str, args)], capture_output=True, text=True)
    if r.returncode:
        die(f"mtklogo {args[0]} failed:\n{r.stdout}\n{r.stderr}")
    return r.stdout


def unpack_raw(mtk, logo, profile, name, outdir):
    """Extract every slot as raw .z into outdir -> {index: bytes}."""
    run(mtk, "unpack", logo, "-c", profile, "-p", name, "-z", "-o", outdir)
    return {p.name.split("_")[1]: p.read_bytes() for p in Path(outdir).glob("logo_*")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logo", required=True, help="stock logo.bin to base on")
    ap.add_argument("--profile", required=True, help="mtklogo device profile YAML")
    ap.add_argument("--name", required=True, help="profile name inside the YAML")
    ap.add_argument("--image", required=True, help="replacement PNG, exact panel size")
    ap.add_argument("--slots", required=True, help="comma-separated slot indices, e.g. 0,38")
    ap.add_argument("--partition-size", type=int, required=True)
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--mtklogo", default=None,
                    help="path to the mtklogo binary (default: $MTKLOGO, then a "
                         "local ./mtklogo build, then 'mtklogo' on PATH)")
    args = ap.parse_args()

    mtk = resolve_mtklogo(args.mtklogo)
    if mtk is None:
        die("mtklogo binary not found. Build it from https://github.com/arlept/mtklogo "
            "and either put it on PATH, set $MTKLOGO, or pass --mtklogo. "
            "(e.g. git clone .../mtklogo && cd mtklogo/cli && cargo build --release)")

    prof = next((p for p in yaml.safe_load(open(args.profile))["profiles"]
                 if p["name"] == args.name), None)
    if prof is None:
        die(f"profile '{args.name}' not in {args.profile}")
    color = prof["color_model"]

    orig = Path(args.logo).read_bytes()
    if orig[:4] != MTK_MAGIC:
        die(f"{args.logo} does not start with the MTK header magic")

    # The replacement must match one of the profile's declared formats, or the
    # bootloader will blit it at the wrong stride.
    img = Image.open(args.image)
    dims = {(f["w"], f["h"]) for f in prof["formats"]}
    if img.size not in dims:
        die(f"{args.image} is {img.size}, which is not one of the profile's "
            f"formats {sorted(dims)} -- resize it first")

    slots = [f"{int(s):03d}" for s in args.slots.split(",")]

    # mtklogo splits the WHOLE path on '_' to find the slot index, so no
    # component of the working path may contain an underscore. Python's mkdtemp
    # picks its random suffix from a set that includes '_', so build the name
    # here instead of letting tempfile choose it.
    base = Path(tempfile.gettempdir())
    if "_" in str(base):
        die(f"temp base {base} contains '_'; set TMPDIR to a path without one")
    td = base / f"mtklogobuild{uuid.uuid4().hex}"
    td.mkdir()
    try:
        src, ref, chk = td / "src", td / "ref", td / "chk"
        for d in (src, ref, chk):
            d.mkdir()

        before = unpack_raw(mtk, args.logo, args.profile, args.name, ref)
        shutil.copytree(ref, src, dirs_exist_ok=True)

        for s in slots:
            if s not in before:
                die(f"slot {s} does not exist in {args.logo} (has {len(before)} slots)")
            (src / f"logo_{s}_raw.z").unlink()
            shutil.copy(args.image, src / f"logo_{s}_{color}.png")

        run(mtk, "repack", "-o", td / "payload.bin", *sorted(src.glob("logo_*")))

        payload = (td / "payload.bin").read_bytes()[HDR:]
        hdr = bytearray(orig[:HDR])
        struct.pack_into("<I", hdr, 4, len(payload))
        out = bytes(hdr) + payload

        if len(out) > args.partition_size:
            die(f"result is {len(out)} bytes, larger than the {args.partition_size}-byte partition")

        Path(args.output).write_bytes(out)

        # ---- prove it: re-unpack and diff every slot --------------------------
        after = unpack_raw(mtk, args.output, args.profile, args.name, chk)
    finally:
        shutil.rmtree(td, ignore_errors=True)

    if set(after) != set(before):
        die("slot index set changed between original and result")
    changed = sorted(k for k in before if before[k] != after[k])
    if changed != sorted(slots):
        die(f"expected exactly slots {sorted(slots)} to change, but {changed} did")

    pct = len(out) / args.partition_size * 100
    print(f"wrote {args.output}")
    print(f"  {len(out)} bytes ({pct:.1f}% of the {args.partition_size}-byte partition)")
    print(f"  header: stock, name={bytes(hdr[8:12]).decode(errors='replace')!r}, "
          f"secondary block {'kept' if hdr[0x30:0x34] == bytes.fromhex('89168958') else 'absent'}")
    print(f"  slots: {len(before)} total, changed exactly {changed}, "
          f"{len(before) - len(changed)} byte-identical to stock")


if __name__ == "__main__":
    main()
