#!/usr/bin/env python3
"""
patch_lk_orangestate.py

Patch a MediaTek LK (Little Kernel / bootloader) image to:
  (a) blank the "Orange State" unlocked-bootloader warning text, and/or
  (b) remove the ~5 second boot delay that accompanies that warning.

This was written for and tested on an MT6739 device whose stock firmware was
Android 10. It performs strict, in-place, same-length edits only: the output
file is always the exact same size as the input, and every change is verified
before it is written.

    !!!  READ THIS  !!!
    You are editing a BOOTLOADER. A wrong write here can HARD-BRICK the device
    so that it will not even reach fastboot. Recovery then requires a low-level
    flash tool (e.g. mtkclient over the SoC's BROM/preloader mode) and a known
    good backup. Do NOT flash the output of this script unless you:
      - have a verified full backup of the original lk / lk2 partition, and
      - understand how to recover via BROM if it goes wrong.

    This script only edits a FILE on your computer. It never touches a device.
    Flashing is a separate, deliberate step you perform yourself.

Usage:
    ./patch_lk_orangestate.py <lk.bin> [-o OUT] [--mode text|delay|both]
                              [--android-below-10] [--force] [--dry-run]

Examples:
    # Blank the warning text only, write lk.patched.bin next to the input:
    ./patch_lk_orangestate.py lk.bin --mode text

    # Blank text AND remove the 5s delay:
    ./patch_lk_orangestate.py lk.bin --mode both -o lk.new.bin

    # Just show what WOULD change, write nothing:
    ./patch_lk_orangestate.py lk.bin --mode both --dry-run

Exit codes: 0 = success (or clean dry-run), non-zero = nothing was written.
"""

import argparse
import shutil
import sys

# ----------------------------------------------------------------------------
# Patch definitions
# ----------------------------------------------------------------------------
#
# TEXT BLANKING
# -------------
# The orange-state screen prints three consecutive C strings. We overwrite each
# with 0x00 bytes for its FULL length, so it renders as an empty string. We find
# them by exact byte content (not fixed offsets), so this adapts to any LK where
# these exact strings exist. Only these three are touched; the yellow/red-state
# strings are deliberately left alone.
TEXT_STRINGS = [
    b"Orange State",
    b"Your device has been unlocked and can't be trusted",
    b"Your device will boot in 5 seconds",
]

# 5-SECOND DELAY REMOVAL
# ----------------------
# This is the well-known MTK "boot delay" patch. The delay lives in a small
# Thumb function. We locate it by an instruction signature and rewrite the two
# instructions right after the function's `push` so the function returns
# immediately (movs r0,#0 ; pop {r3,pc}), skipping any wait.
#
# The signature and its preceding `push {r3, lr}` (0x08B5) uniquely identify the
# function. Two variants exist depending on the Android version the LK is from:
#
#   window (12 bytes) = 08B5 <2 bytes> 7B44 1B68 1B68 <CMP>
#     where <CMP> is 022B for Android 10+, or 012B for below Android 10.
#
# We replace bytes [2:6] of that window (the two instructions after the push):
#     <2 bytes> 7B44   ->   0020 08BD      (movs r0,#0 ; pop {r3,pc})
# The trailing bytes are left intact but become unreachable.
DELAY_PREFIX = bytes.fromhex("08B5")           # push {r3, lr}
DELAY_TAIL_A10 = bytes.fromhex("7B441B681B68022B")   # Android 10 and above
DELAY_TAIL_OLD = bytes.fromhex("7B441B681B68012B")   # below Android 10
DELAY_REPLACE_MID = bytes.fromhex("002008BD")  # movs r0,#0 ; pop {r3,pc}


def eprint(*a):
    print(*a, file=sys.stderr)


def find_all(haystack: bytes, needle: bytes):
    out, start = [], 0
    while True:
        i = haystack.find(needle, start)
        if i < 0:
            return out
        out.append(i)
        start = i + 1


def plan_text_patches(data: bytes):
    """Return (patches, notes). patches = list of (offset, original, new)."""
    patches, notes = [], []
    for s in TEXT_STRINGS:
        hits = find_all(data, s)
        if not hits:
            notes.append(f"  - NOT FOUND (skipped): {s!r}")
            continue
        if len(hits) > 1:
            notes.append(f"  - found {len(hits)} copies, patching all: {s!r}")
        for off in hits:
            patches.append((off, s, b"\x00" * len(s)))
            notes.append(f"  - blank {len(s):3d} bytes @ 0x{off:x}: {s!r}")
    return patches, notes


def plan_delay_patch(data: bytes, android_below_10: bool):
    """Return (patches, notes). Fails safe: refuses if not exactly one match."""
    tail = DELAY_TAIL_OLD if android_below_10 else DELAY_TAIL_A10
    variant = "below Android 10 (...012B)" if android_below_10 else "Android 10+ (...022B)"
    notes = [f"  variant: {variant}"]

    sig_hits = find_all(data, tail)
    # Keep only matches that are preceded by the push {r3,lr} at window start.
    good = []
    for h in sig_hits:
        entry = h - 4  # window = push(2) + mid(2) + tail(8); tail starts at +4
        if entry >= 0 and data[entry:entry + 2] == DELAY_PREFIX:
            good.append(entry)

    if len(good) == 0:
        other = DELAY_TAIL_OLD if not android_below_10 else DELAY_TAIL_A10
        hint = ""
        if find_all(data, other):
            hint = ("\n    NOTE: the OTHER Android-version signature DID match. "
                    "Re-run with the correct --android-below-10 setting "
                    "(or remove it).")
        return None, [f"  ERROR: delay signature not found for {variant}."
                      f" Refusing to patch the delay.{hint}"]
    if len(good) > 1:
        locs = ", ".join(f"0x{g:x}" for g in good)
        return None, [f"  ERROR: delay signature matched {len(good)} times "
                      f"({locs}). Ambiguous - refusing to guess which is the "
                      f"real delay function. Patch aborted."]

    entry = good[0]
    window = data[entry:entry + 12]
    mid_off = entry + 2                       # the two instructions after push
    original = data[mid_off:mid_off + 4]
    patches = [(mid_off, original, DELAY_REPLACE_MID)]
    notes += [
        f"  function entry @ 0x{entry:x} (push {{r3, lr}})",
        f"  12-byte window: {window.hex()}",
        f"  rewrite 4 bytes @ 0x{mid_off:x}: {original.hex()} -> "
        f"{DELAY_REPLACE_MID.hex()}  (movs r0,#0 ; pop {{r3,pc}})",
    ]
    return patches, notes


def apply_patches(data: bytearray, patches):
    """Apply verified patches in place. Every original is re-checked first."""
    # Detect overlaps (defensive; text vs delay live in different regions).
    spans = sorted((off, off + len(orig)) for off, orig, _ in patches)
    for (a0, a1), (b0, b1) in zip(spans, spans[1:]):
        if b0 < a1:
            raise RuntimeError(f"internal error: overlapping patches "
                               f"[{a0:#x},{a1:#x}) and [{b0:#x},{b1:#x})")
    for off, original, new in patches:
        assert len(original) == len(new), "length mismatch (would resize image)"
        if bytes(data[off:off + len(original)]) != original:
            raise RuntimeError(f"verify failed @ 0x{off:x}: expected "
                               f"{original.hex()}, refusing to write")
        data[off:off + len(new)] = new


def main():
    ap = argparse.ArgumentParser(
        description="Safely patch an MTK LK image: blank the orange-state "
                    "warning and/or remove its 5-second boot delay.")
    ap.add_argument("input", help="path to the LK image (e.g. lk.bin)")
    ap.add_argument("-o", "--output",
                    help="output path (default: <input>.patched)")
    ap.add_argument("--mode", choices=["text", "delay", "both"], default="text",
                    help="what to patch (default: text)")
    ap.add_argument("--android-below-10", action="store_true",
                    help="use the pre-Android-10 delay signature (...012B)")
    ap.add_argument("--force", action="store_true",
                    help="overwrite the output file if it already exists")
    ap.add_argument("--dry-run", action="store_true",
                    help="show planned changes but write nothing")
    args = ap.parse_args()

    # ---- warnings, shown every run -----------------------------------------
    eprint("=" * 72)
    eprint(" WARNING: this edits a BOOTLOADER image. Flashing a bad LK can")
    eprint(" HARD-BRICK your device (no fastboot). Only flash the result if you")
    eprint(" have a verified backup and a BROM recovery path (e.g. mtkclient).")
    eprint(" The 5s-delay patch is a community pattern, not guaranteed for every")
    eprint(" LK build; always keep the original and test a reboot after flashing.")
    eprint(" This script edits a file only - it never touches your device.")
    eprint("=" * 72)

    # ---- read input ---------------------------------------------------------
    try:
        with open(args.input, "rb") as f:
            data = bytearray(f.read())
    except OSError as e:
        eprint(f"error: cannot read input: {e}")
        return 2
    if not data:
        eprint("error: input file is empty")
        return 2

    # Light sanity check: MTK images start with magic 0x88168858 (big-endian).
    if data[0:4] != bytes.fromhex("88168858"):
        eprint("note: input does not start with the MTK header magic "
               "(0x88168858). Continuing anyway - content search still applies, "
               "but double-check this is really an LK image.")

    orig_len = len(data)

    # ---- build the patch plan ----------------------------------------------
    all_patches = []
    print(f"\ninput : {args.input}  ({orig_len} bytes)")
    print(f"mode  : {args.mode}\n")

    if args.mode in ("text", "both"):
        tp, notes = plan_text_patches(data)
        print("TEXT blanking:")
        print("\n".join(notes) if notes else "  (nothing)")
        if not tp:
            eprint("\nerror: none of the orange-state strings were found; "
                   "nothing to do for 'text'. Aborting to avoid a no-op that "
                   "looks like success.")
            return 3
        all_patches += tp
        print()

    if args.mode in ("delay", "both"):
        dp, notes = plan_delay_patch(data, args.android_below_10)
        print("DELAY removal:")
        print("\n".join(notes))
        if dp is None:
            eprint("\nerror: delay patch could not be applied safely (see "
                   "above). Aborting; no file written.")
            return 4
        all_patches += dp
        print()

    # ---- apply to a COPY, verify, report ------------------------------------
    patched = bytearray(data)
    try:
        apply_patches(patched, all_patches)
    except RuntimeError as e:
        eprint(f"error: {e}")
        return 5

    assert len(patched) == orig_len, "size changed - this must never happen"
    changed = sum(1 for a, b in zip(data, patched) if a != b)
    print(f"total bytes changed: {changed}  (file size unchanged: {orig_len})")

    if args.dry_run:
        print("\ndry-run: no file written.")
        return 0

    # ---- write output safely ------------------------------------------------
    out = args.output or (args.input + ".patched")
    import os
    if os.path.abspath(out) == os.path.abspath(args.input):
        eprint("error: refusing to overwrite the input file in place. "
               "Choose a different -o/--output path.")
        return 6
    if os.path.exists(out) and not args.force:
        eprint(f"error: output '{out}' already exists (use --force to "
               f"overwrite).")
        return 6
    tmp = out + ".tmp"
    with open(tmp, "wb") as f:
        f.write(patched)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, out)
    print(f"\nwrote: {out}")
    print("Keep your ORIGINAL LK backup. To flash (only if you accept the "
          "risk):")
    print(f"    fastboot flash lk  {out}")
    print(f"    fastboot flash lk2 {out}   # if your device has a redundant "
          f"lk2 copy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
