#!/usr/bin/env python3
"""
Independent verification of an LK image patched by patch_lk_orangestate.py.

Deliberately does NOT trust the patcher: it re-derives every target from the
image content (string search, then the dispatcher's own tail-call) and checks
the result by disassembly.

Usage:
    ./verify-lk.py <orig.bin> <patched.bin> [<orig2.bin> <patched2.bin> ...]

Exit code 0 only if every check on every pair passes.
"""
import struct
import sys

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

STRINGS = [
    b"Orange State",
    b"Your device has been unlocked and can't be trusted",
    b"Your device will boot in 5 seconds",
]

# push {r3,lr} ; movs r0,#0 ; pop {r3,pc} ; then the original dead tail.
# The final CMP differs by Android version: 022B on 10+, 012B below 10 (which
# also means the orange boot state is 2 there and 1 here).
PATCHED_SIGS = {
    "Android 10+ (...022B)": bytes.fromhex("08b5002008bd1b681b68022b"),
    "below Android 10 (...012B)": bytes.fromhex("08b5002008bd1b681b68012b"),
}

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def dis(data, addr, n):
    return list(md.disasm(data[addr:addr + n], addr))


# dm-verity screen anchor: cmp r4,#2 ; it eq ; orreq r3,r3,#1 ; cbnz r3,#+4 ;
# add sp,#0xc ; pop {r4,r5,pc}. The patch nops the cbnz (halfword at +8).
DMV_ANCHOR = bytes.fromhex("022c08bf43f001030bb903b030bd")
DMV_CBNZ_AT = 8


def detect_dmverity(orig, patched):
    """If the dm-verity screen patch is present (cbnz -> nop at the anchor),
    return the file offset of the nop; else None."""
    at = orig.find(DMV_ANCHOR)
    if at < 0:
        return None
    off = at + DMV_CBNZ_AT
    if orig[off:off + 2] == bytes.fromhex("0bb9") and patched[off:off + 2] == bytes.fromhex("00bf"):
        return off
    return None


def detect_vendor_boot(orig, patched, skip):
    """If a cbnz was turned into a b to the same target (the vendor_boot
    request patch), return its file offset; else None. `skip` holds offsets
    already accounted for."""
    for i in range(0, len(orig) - 1, 2):
        if i in skip or orig[i:i + 2] == patched[i:i + 2]:
            continue
        a, b = dis(orig, i, 2), dis(patched, i, 2)
        if a and b and a[0].mnemonic == "cbnz" and b[0].mnemonic == "b" \
                and a[0].op_str.split("#")[-1] == b[0].op_str.split("#")[-1]:
            return i
    return None


def loads_string(data, start, end, target):
    """True if an ldr rN,[pc,#x]; add rN,pc pair in [start, end) yields target."""
    for a in dis(data, start, end - start):
        if a.mnemonic != "ldr" or "[pc," not in a.op_str.replace(" ", ""):
            continue
        for nxt in dis(data, a.address + a.size, 12):
            if nxt.mnemonic == "add" and nxt.op_str == a.op_str.split(",")[0] + ", pc":
                imm = int(a.op_str.split("#")[1].rstrip("]"), 0)
                lit = ((a.address + 4) & ~3) + imm
                val = int.from_bytes(data[lit:lit + 4], "little")
                if (val + nxt.address + 4) & 0xFFFFFFFF == target:
                    return True
                break
    return False


class Checker:
    def __init__(self):
        self.ok = True

    def __call__(self, name, cond):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        self.ok &= bool(cond)
        return cond


def verify(orig_path, patched_path):
    o = open(orig_path, "rb").read()
    p = open(patched_path, "rb").read()
    print(f"\n=== {patched_path} vs {orig_path} ===")
    check = Checker()

    check(f"size unchanged ({len(p)} bytes)", len(o) == len(p))
    check("MTK header (0x200) untouched", o[:0x200] == p[:0x200])
    check("MTK magic intact", p[:4] == bytes.fromhex("88168858"))

    payload_len = struct.unpack_from("<I", p, 4)[0]
    check(f"declared payload length {payload_len} fits the image",
          0 < payload_len <= len(p) - 0x200)

    # The orange-state patch changes exactly 100 bytes. The optional dm-verity
    # patch adds 2 more (a single cbnz -> nop), so account for it if present.
    dmv_off = detect_dmverity(o, p)
    vb_off = detect_vendor_boot(o, p, {dmv_off})
    expected = 100 + (2 if dmv_off is not None else 0) + (2 if vb_off is not None else 0)
    diffs = [i for i in range(len(o)) if o[i] != p[i]]
    label = f"{expected} bytes changed (orange" + (" + dm-verity" if dmv_off is not None else "") \
        + (" + vendor_boot" if vb_off is not None else "") + ")"
    check(f"exactly {label} (got {len(diffs)})", len(diffs) == expected)

    # --- text blanking -------------------------------------------------------
    blanked = 0
    for s in STRINGS:
        at = o.find(s)
        if at < 0:
            check(f"string present in original: {s[:24]!r}", False)
            continue
        check(f"blanked @0x{at:x} ({len(s):2d}B) {s[:30]!r}",
              p[at:at + len(s)] == b"\x00" * len(s))
        blanked += len(s)
    check(f"96 string bytes blanked (got {blanked})", blanked == 96)

    # --- the dispatcher ------------------------------------------------------
    hits = {v: p.find(s) for v, s in PATCHED_SIGS.items() if p.find(s) >= 0}
    if not check(f"patched dispatcher signature found ({', '.join(hits) or 'none'})", len(hits) == 1):
        return check.ok
    variant, entry = next(iter(hits.items()))
    check("dispatcher signature is unique", p.find(PATCHED_SIGS[variant], entry + 1) < 0)

    ins = dis(p, entry, 6)
    print(f"    dispatcher @0x{entry:x} now:")
    for i in ins[:3]:
        print(f"      0x{i.address:05x}: {i.bytes.hex():<8} {i.mnemonic} {i.op_str}")
    seq = [(i.mnemonic, i.op_str) for i in ins[:3]]
    check("push {r3, lr}", seq[0] == ("push", "{r3, lr}"))
    check("movs r0, #0  (returns 0 = 'nothing to warn about')", seq[1] == ("movs", "r0, #0"))
    check("pop {r3, pc} (balances the push)", seq[2] == ("pop", "{r3, pc}"))
    check("returns at instruction 3, before any branch",
          next((n for n, i in enumerate(dis(p, entry, 12)) if i.mnemonic == "pop"), None) == 2)

    # --- the orange routine it used to reach ---------------------------------
    # Resolve it from the dispatcher's own tail-call rather than scanning the
    # file, since movw r0,#0x1388 appears elsewhere too.
    tailpop = o.find(bytes.fromhex("bde80840"), entry, entry + 0x40)  # pop.w {r3, lr}
    if not check("dispatcher's tail-call to the orange routine located", tailpop > 0):
        return check.ok
    branch = dis(o, tailpop + 4, 4)[0]
    check("tail-call is an unconditional b.w", branch.mnemonic.startswith("b"))
    orange = int(branch.op_str.lstrip("#"), 0)
    print(f"    orange-state routine @0x{orange:x}")

    # It must be the routine that prints the warning strings: check that all
    # three string offsets are reached from inside it via ldr/add pc pairs.
    printed = 0
    for s in STRINGS:
        at = o.find(s)
        for a in dis(o, orange, 0x60):
            if a.mnemonic != "ldr" or "[pc," not in a.op_str.replace(" ", ""):
                continue
            nxt = dis(o, a.address + a.size, 4)
            if not nxt or nxt[0].mnemonic != "add" or not nxt[0].op_str.endswith("pc"):
                continue
            imm = int(a.op_str.split("#")[1].rstrip("]"), 0)
            lit = ((a.address + 4) & ~3) + imm
            val = int.from_bytes(o[lit:lit + 4], "little")
            if (val + nxt[0].address + 4) & 0xFFFFFFFF == at:
                printed += 1
                break
    check(f"all 3 warning strings are printed by that routine (found {printed})", printed == 3)

    body = o[orange:orange + 0x60]
    at = body.find(bytes.fromhex("41f28830"))  # movw r0, #0x1388  (5000)
    if check(f"5000ms delay found inside it @0x{orange + at:x}", at >= 0):
        pair = dis(o, orange + at, 8)
        for i in pair[:2]:
            print(f"      0x{i.address:05x}: {i.bytes.hex():<10} {i.mnemonic} {i.op_str}")
        check("delay is movw r0,#0x1388 followed by bl (mdelay(5000))",
              pair[0].op_str.endswith("#0x1388") and pair[1].mnemonic == "bl")
        check("routine left byte-identical (now unreachable dead code)",
              o[orange:orange + 0x60] == p[orange:orange + 0x60])

    # --- optional dm-verity screen patch -------------------------------------
    if dmv_off is not None:
        print(f"    dm-verity screen patch present @0x{dmv_off:x}")
        ins = dis(p, dmv_off, 6)
        seq = [(i.mnemonic, i.op_str) for i in ins[:3]]
        check("dm-verity: cbnz replaced by nop", seq[0] == ("nop", ""))
        check("dm-verity: falls through to add sp,#0xc",
              seq[1] == ("add", "sp, #0xc"))
        check("dm-verity: then pop {r4, r5, pc}", seq[2] == ("pop", "{r4, r5, pc}"))
        check("dm-verity: warning strings still present (removed by control flow)",
              b"Your device is corrupt." in p)

    # --- optional vendor_boot request patch ----------------------------------
    if vb_off is not None:
        print(f"    vendor_boot request patch present @0x{vb_off:x}")
        was, now = dis(o, vb_off, 2)[0], dis(p, vb_off, 2)[0]
        print(f"      0x{vb_off:05x}: {was.bytes.hex()} {was.mnemonic} {was.op_str} -> "
              f"{now.bytes.hex()} {now.mnemonic} {now.op_str}")
        check("vendor_boot: cbnz r0 became b to the same target",
              was.op_str.startswith("r0,") and now.size == 2)
        name = o.find(b"\0vendor_boot\0") + 1
        check("vendor_boot: the guarded code loads the vendor_boot name",
              name > 0 and loads_string(o, vb_off - 16, vb_off, name))
        check("vendor_boot: a bl immediately precedes the cbnz",
              dis(o, vb_off - 4, 4)[0].mnemonic == "bl")
    return check.ok


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) < 2 or len(args) % 2:
        sys.exit(__doc__)
    allok = True
    for i in range(0, len(args), 2):
        allok &= verify(args[i], args[i + 1])
    print("\n" + ("ALL CHECKS PASSED" if allok else "SOME CHECKS FAILED"))
    sys.exit(0 if allok else 1)
