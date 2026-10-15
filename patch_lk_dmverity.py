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

SKIPPING THE VENDOR_BOOT READ
-----------------------------
The same AVB boot path appends "vendor_boot" to libavb's requested partitions
whenever that partition exists:

    ldr   r0, =vendor_boot  ; add r0, pc
    bl    partition_lookup
    cbnz  r0, skip          ; lookup failed -> don't request it
    ...                     ; requested[0 or 1] = "vendor_boot"
  skip:

With verification disabled in vbmeta, libavb then reads every requested
partition in full, so a boot image with header v2 or older, which has no
vendor_boot, still costs a whole (64 MiB on the r1) partition read. We change
the cbnz into an unconditional b to the same target. The site is found by
resolving the pc-relative load of the "vendor_boot" string and must be
followed by a bl and a cbnz r0; it is optional, and skipped when absent.
Don't use this on a device that boots a header v3/v4 boot image.

REPORTING A VERIFIED BOOT (--report-locked, opt-in)
---------------------------------------------------
LK tells Android how it booted on the kernel command line. By default this
image reports androidboot.verifiedbootstate=orange,
androidboot.vbmeta.device_state=unlocked and, with dm-verity off in vbmeta,
androidboot.veritymode=disabled. With --report-locked the command line says
green, locked and enforcing instead; what LK actually verifies and boots is
unchanged. This is the device owner choosing what their own bootloader reports.

  * the boot state picks its string through `tbb [pc, rN]` over four cases.
    The yellow and orange table entries are pointed at the green case; red
    (a failed verification) is left alone.
  * libavb's options pick "locked"/"unlocked" with `cbnz rN, unlocked` right
    before loading "locked"; the cbnz becomes a nop, so it always takes locked.
  * the hashtree-disabled branch loads "disabled"; that pc-relative literal,
    used by that one load, is repointed at the "enforcing" string the same
    function already carries.

Each site is re-derived from its string references and must match exactly once.
Android's first-stage init accepts a locked device_state with dm-verity off in
vbmeta; anything that reads the real lock state (fastboot getvar, the seccfg
partition) still sees the device as it physically is.

The default edits are in-place, same-length, 2-byte edits. Like the orange-state patch it is
anchored on an instruction signature, not a fixed offset, and it refuses to run
unless that signature is present exactly once AND the enclosing image really does
contain the corruption strings (so it can't fire on an unrelated image).

    !!!  This edits a BOOTLOADER. A bad write can hard-brick the device. Keep a
         verified backup and a BROM recovery path (mtkclient). This script only
         edits a file; flashing is a separate, deliberate step.

Usage:
    ./patch_lk_dmverity.py lk_a.bin.orig -o lk_a.bin.patched [--report-locked] [--force] [--dry-run]
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


def h16(data, off):
    return data[off] | data[off + 1] << 8


def pc_loads(data, target):
    """Offsets just past each 'ldr rN,[pc,#x]; ... add rN,pc' pair that
    yields `target`. Pc-relative, so file offsets work as addresses."""
    out = []
    for o in range(0, len(data) - 4, 2):
        x = h16(data, o)
        if x >> 11 == 0b01001:                       # ldr rN,[pc,#imm8*4]
            rn, lit = (x >> 8) & 7, ((o + 4) & ~3) + (x & 0xFF) * 4
        elif x == 0xF8DF and h16(data, o + 2) >> 12 < 8:   # ldr.w rN,[pc,#imm12]
            y = h16(data, o + 2)
            rn, lit = y >> 12, ((o + 4) & ~3) + (y & 0xFFF)
        else:
            continue
        if lit + 4 > len(data):
            continue
        val = int.from_bytes(data[lit:lit + 4], "little")
        for k in range(2, 24, 2):
            if h16(data, o + k) == 0x4478 + rn:      # add rN,pc
                if (val + o + k + 4) & 0xFFFFFFFF == target:
                    out.append(o + k + 2)
                break
    return out


def find_vendor_boot_request(data):
    """File offset of the 'cbnz r0' that guards requesting vendor_boot, or
    None when the image has no such site. Raises if ambiguous."""
    name = data.find(b"\0vendor_boot\0")
    if name < 0:
        return None
    sites = []
    for after in pc_loads(data, name + 1):
        # at most one more 16-bit instruction (the paired add), then bl
        for o in range(after, after + 6, 2):
            hi, lo = h16(data, o), h16(data, o + 2)
            if hi >> 11 == 0b11110 and lo >> 14 == 0b11 and lo & 0x1000:
                cb = h16(data, o + 4)
                if cb & 0xFD07 == 0xB900:            # cbnz r0
                    sites.append(o + 4)
                break
    if len(sites) > 1:
        raise ValueError(f"vendor_boot request matched {len(sites)} sites")
    return sites[0] if sites else None


def cstring(data, text):
    """File offset of the NUL-delimited string `text`; raises unless unique."""
    hits = find_all(data, b"\0" + text.encode() + b"\0")
    if len(hits) != 1:
        raise ValueError(f"string {text!r} found {len(hits)} times")
    return hits[0] + 1


def load_start(data, after):
    """Start of the ldr whose paired 'add rN,pc' ends at `after`."""
    for o in range(after - 4, max(after - 26, 0), -2):
        x = h16(data, o)
        if x >> 11 == 0b01001 or (x == 0xF8DF and h16(data, o + 2) >> 12 < 8):
            return o
    raise ValueError(f"no ldr before 0x{after:x}")


def literal_of(data, ldr):
    x = h16(data, ldr)
    if x >> 11 == 0b01001:
        return ((ldr + 4) & ~3) + (x & 0xFF) * 4
    return ((ldr + 4) & ~3) + (h16(data, ldr + 2) & 0xFFF)


def find_bootstate_table(data):
    """(table offset, {case: colour}) for the tbb choosing verifiedbootstate."""
    names = {c: cstring(data, f"androidboot.verifiedbootstate={c}")
             for c in ("green", "yellow", "orange", "red")}
    sites = {}
    for colour, name in names.items():
        loads = pc_loads(data, name)
        if len(loads) != 1:
            raise ValueError(f"verifiedbootstate={colour} loaded {len(loads)} times")
        sites[load_start(data, loads[0])] = colour
    first = min(sites)
    tbbs = [o for o in range(first - 0x20, first, 2)
            if data[o:o + 4] == b"\xdf\xe8\x03\xf0"]          # tbb [pc, r3]
    if len(tbbs) != 1:
        raise ValueError(f"boot state tbb matched {len(tbbs)} times")
    table = tbbs[0] + 4
    cases = {n: sites.get(table + 2 * data[table + n]) for n in range(4)}
    if sorted(c for c in cases.values() if c) != sorted(sites.values()):
        raise ValueError(f"boot state table does not select the four strings: {cases}")
    return table, cases


def find_device_state(data):
    """Offset of the 'cbnz rN' that selects "unlocked" for vbmeta.device_state."""
    sites = []
    for after in pc_loads(data, cstring(data, "locked")):
        cb = load_start(data, after) - 2
        x = h16(data, cb)
        if x & 0xFD00 != 0xB900:                     # cbnz rN (forward)
            continue
        target = cb + 4 + (((x >> 9) & 1) << 6 | ((x >> 3) & 0x1F) << 1)
        if target + 4 in pc_loads(data, cstring(data, "unlocked")):
            sites.append(cb)
    if len(sites) != 1:
        raise ValueError(f"device_state choice matched {len(sites)} times")
    return sites[0]


def find_veritymode_disabled(data):
    """(literal offset, new little-endian value) that repoints the "disabled"
    veritymode load at the "enforcing" string."""
    option = pc_loads(data, cstring(data, "androidboot.veritymode"))
    enforcing_str = cstring(data, "enforcing")
    enforcing = pc_loads(data, enforcing_str)
    # The linker may merge "disabled" into the tail of a longer string.
    disabled = find_all(data, b"disabled\0")
    sites = []
    for after in [a for o in disabled for a in pc_loads(data, o)]:
        if not any(abs(after - a) < 0x200 for a in option):
            continue
        if not any(abs(after - a) < 0x200 for a in enforcing):
            continue
        sites.append(after)
    if len(sites) != 1:
        raise ValueError(f"veritymode=disabled load matched {len(sites)} times")
    ldr = load_start(data, sites[0])
    lit = literal_of(data, ldr)
    users = [o for o in range(0, len(data) - 4, 2)
             if (h16(data, o) >> 11 == 0b01001
                 or (h16(data, o) == 0xF8DF and h16(data, o + 2) >> 12 < 8))
             and literal_of(data, o) == lit]
    if users != [ldr]:
        raise ValueError(f"veritymode literal at 0x{lit:x} is shared by {len(users)} loads")
    # The string address is literal + (add_rN,pc PC + 4), not the ldr's PC.
    # pc_loads returns the halfword past the add, so add_PC + 4 == sites[0] + 2.
    delta = (enforcing_str - (sites[0] + 2)) & 0xFFFFFFFF
    return lit, delta


def cbnz_to_b(cbnz):
    """Same-target unconditional b (T1 encoding) for a forward cbnz."""
    imm = ((cbnz >> 9) & 1) << 5 | (cbnz >> 3) & 0x1F
    return (0xE000 | imm).to_bytes(2, "little")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("-o", "--output")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report-locked", action="store_true",
                    help="report the boot as green, locked and verity-enforcing")
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

    try:
        vb_off = find_vendor_boot_request(data)
    except ValueError as e:
        eprint(f"error: {e}. Refusing to patch.")
        return 7
    if vb_off is None:
        print("vendor_boot request: not present, left alone")
    else:
        branch = cbnz_to_b(h16(data, vb_off))
        print(f"vendor_boot request skipped:")
        print(f"  'cbnz r0' @ 0x{vb_off:x} -> 'b' to the same target "
              f"({bytes(data[vb_off:vb_off+2]).hex()} -> {branch.hex()})")
        patched[vb_off:vb_off + 2] = branch

    if args.report_locked:
        try:
            table, cases = find_bootstate_table(data)
            state_cb = find_device_state(data)
            lit, value = find_veritymode_disabled(data)
        except ValueError as e:
            eprint(f"error: {e}. Refusing to patch.")
            return 8
        green = next(n for n, c in cases.items() if c == "green")
        print("boot reported as verified:")
        for n, colour in cases.items():
            if colour in ("yellow", "orange"):
                print(f"  boot state case {n} ({colour}) @ 0x{table + n:x} -> green")
                patched[table + n] = data[table + green]
        print(f"  device_state 'cbnz' @ 0x{state_cb:x} -> nop (always \"locked\")")
        patched[state_cb:state_cb + 2] = NOP
        print(f"  veritymode literal @ 0x{lit:x} -> \"enforcing\"")
        patched[lit:lit + 4] = value.to_bytes(4, "little")

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
