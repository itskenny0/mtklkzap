#!/usr/bin/env python3
"""
patch_lk_dmverity.py

Suppress the MediaTek LK "dm-verity corruption" warning screen that reads

    dm-verity corruption
    Your device is corrupt.
    It can't be trusted and may not work properly.
    Press power button to continue.
    phone will continue boot up after 5s...

and then blocks boot waiting on a key (or a 5-second timeout).

HOW IT WORKS
------------
The screen is drawn by a single function (call it `corrupt_screen`). Near its
top it decides whether to show anything:

    cmp   r4, #2            ; r4 = mode
    it    eq
    orreq r3, r3, #1
    cbnz  r3, draw          ; r3 != 0  -> draw the screen and wait
    add   sp, #0xc          ; r3 == 0  -> nothing to warn about, return
    pop   {r4, r5, pc}

We change the `cbnz r3, draw` into a `nop`, so control always falls through to
the function's own `add sp,#0xc; pop {r4,r5,pc}` epilogue. The function then
returns immediately without drawing or waiting - identical to the path it
already takes on a normal, non-corrupt boot. The single caller ignores the
return value (it does `mov r0, r5` right after the call), so nothing downstream
is affected.

This is an in-place, same-length, 2-byte edit. Like the orange-state patch it is
anchored on an instruction signature, not a fixed offset, and it refuses to run
unless that signature is present exactly once AND the enclosing image really does
contain the corruption strings (so it can't fire on an unrelated image).

    !!!  This edits a BOOTLOADER. A bad write can hard-brick the device. Keep a
         verified backup and a BROM recovery path (mtkclient). This script only
         edits a file; flashing is a separate, deliberate step.

Usage:
    ./patch_lk_dmverity.py lk_a.bin.orig -o lk_a.bin.patched [--force] [--dry-run]
"""
import argparse
import os
import sys

# cmp r4,#2 ; it eq ; orreq r3,r3,#1 ; cbnz r3,#+4 ; add sp,#0xc ; pop {r4,r5,pc}
ANCHOR = bytes.fromhex("022c08bf43f001030bb903b030bd")
CBNZ_OFFSET_IN_ANCHOR = 8            # the 'cbnz r3' halfword sits here
CBNZ = bytes.fromhex("0bb9")
NOP = bytes.fromhex("00bf")

# Must also be present, so we never touch an image that isn't this screen.
REQUIRED_STRINGS = [
    b"dm-verity corruption",
    b"Your device is corrupt.",
    b"Press power button to continue.",
]


def eprint(*a):
    print(*a, file=sys.stderr)


def find_all(hay, needle):
    out, i = [], hay.find(needle)
    while i >= 0:
        out.append(i)
        i = hay.find(needle, i + 1)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("-o", "--output")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    eprint("=" * 72)
    eprint(" WARNING: editing a BOOTLOADER image. Flashing a bad LK can hard-brick")
    eprint(" the device. Keep a verified backup and a BROM recovery path.")
    eprint("=" * 72)

    with open(args.input, "rb") as f:
        data = bytearray(f.read())

    if data[0:4] != bytes.fromhex("88168858"):
        eprint("note: input lacks the MTK header magic - double-check this is an LK image.")

    missing = [s for s in REQUIRED_STRINGS if s not in data]
    if missing:
        eprint(f"error: this image does not contain the dm-verity corruption screen "
               f"(missing {missing[0]!r}). Nothing to do; refusing to guess.")
        return 3

    hits = find_all(data, ANCHOR)
    if len(hits) != 1:
        eprint(f"error: decision-point signature matched {len(hits)} times "
               f"(expected exactly 1). Refusing to patch.")
        return 4

    cbnz_off = hits[0] + CBNZ_OFFSET_IN_ANCHOR
    if bytes(data[cbnz_off:cbnz_off + 2]) != CBNZ:
        eprint(f"error: expected cbnz {CBNZ.hex()} at 0x{cbnz_off:x}, "
               f"found {bytes(data[cbnz_off:cbnz_off+2]).hex()}. Refusing.")
        return 5

    print(f"\ninput : {args.input}  ({len(data)} bytes)")
    print(f"dm-verity corruption screen suppressed:")
    print(f"  nop the 'cbnz r3' decision @ 0x{cbnz_off:x} "
          f"({CBNZ.hex()} -> {NOP.hex()})  -> function returns before drawing")

    patched = bytearray(data)
    patched[cbnz_off:cbnz_off + 2] = NOP

    changed = sum(1 for a, b in zip(data, patched) if a != b)
    assert len(patched) == len(data)
    print(f"total bytes changed: {changed}  (size unchanged: {len(data)})")

    if args.dry_run:
        print("\ndry-run: no file written.")
        return 0

    out = args.output or (args.input + ".patched")
    if os.path.abspath(out) == os.path.abspath(args.input):
        eprint("error: refusing to overwrite the input in place; choose -o.")
        return 6
    if os.path.exists(out) and not args.force:
        eprint(f"error: {out} exists (use --force).")
        return 6
    tmp = out + ".tmp"
    with open(tmp, "wb") as f:
        f.write(patched)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, out)
    print(f"\nwrote: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
