# mtklkzap

Small tools for cleaning up the boot experience on unlocked MediaTek phones and
tablets. Three things:

1. Replace the boot logo with your own image. Only the boot splash changes; every
   other image in the `logo` partition stays byte for byte identical.
2. Get rid of the "Orange State" unlocked bootloader warning and the 5 second
   pause that comes with it.
3. On devices that show a dm-verity "Your device is corrupt / Press power button
   to continue" screen on every boot, make that go away too.

The bootloader edits are tiny (a handful of bytes, same length in and out) and
each one is checked by disassembling the result before you flash anything. The
patchers find what they need by searching for code and instruction patterns
rather than hard coded offsets, so the same scripts have a decent chance of
working across LK builds they've never seen.

## Which devices have actually been tested

Eight devices, across seven SoCs: **MT6739**, **MT6755**, **MT6761**, **MT6762**
(two of them, different panels), **MT6765**, **MT6833**, and **MT8768** (a
tablet). Full details, panels, and quirks are in
[docs/DEVICES.md](docs/DEVICES.md).

That is the entire tested set. If your device is not one of those exact
SoC-plus-panel combinations, nobody has ever run this on hardware like yours, and
you are the test. Even within that set, a different LK build or firmware revision
on the same chip can lay things out differently. The tools are built to fail loud
and refuse rather than write on a bad match, but "it refused" is a much better
outcome than "it flashed something wrong", and only one of those is guaranteed.
Treat every new device as unproven and check each step.

## Please read this before you flash anything

Your warranty is now void.

The maintainer is not responsible for bricked devices, dead SD cards,
thermonuclear war, or you getting fired because the alarm app failed. This is
free software given away for nothing, with no warranty of any kind (see
[LICENSE](LICENSE)). Please do some research if you have any concerns about what
these tools do before you use them. YOU are choosing to make these
modifications, and if you point the finger at the maintainer for messing up your
device, you will be laughed at.

With that out of the way: `lk` is the bootloader. Write a bad one and the phone
may not even reach fastboot, at which point you are recovering over BROM with a
tool like [mtkclient](https://github.com/bkerler/mtkclient) and a full backup.
Only do this on an unlocked device, keep a verified backup, and know how you
would recover before you start. The scripts here only ever edit files on your
computer; flashing is a separate step you run yourself.

The `logo` partition is harmless by comparison. It is not needed to boot, so a
bad logo is a cosmetic problem at worst.

## What it actually does

An MTK `lk` (Little Kernel) bootloader draws the verified boot warning screens
from small routines. A dispatcher looks at the boot state (green, orange, yellow,
red) and calls into the right one. The warning text and the `mdelay(5000)` that
holds it on screen live in the same routine, so blanking the text alone would
still leave the pause. Instead, the patch rewrites the two instructions at the
top of the routine so it returns straight away, which is the same thing the
firmware already does on a clean boot. The verifier then disassembles the result
and confirms the routine returns before drawing or waiting, that the old code is
now unreachable, and that the stack stays balanced.

The `logo` partition is a table of zlib compressed images ("slots") behind a
0x200 byte MTK header. The build tool swaps only the boot splash slots, carries
every other slot through as its original compressed blob so they repack
identically, keeps the stock header, and then unpacks its own output again to
prove exactly the slots you asked for changed and nothing else.

There is more detail in [docs/PORTING.md](docs/PORTING.md).

## What you need

Python 3.8 or newer, plus a few packages:

```bash
pip install capstone pyyaml pillow
```

`capstone` is for the disassembly in the verifier; `pyyaml` and `pillow` are for
the logo side.

You also need `mtklogo`, the logo (un)packer, built from
[arlept/mtklogo](https://github.com/arlept/mtklogo):

```bash
git clone https://github.com/arlept/mtklogo
cd mtklogo/cli && cargo build --release
```

Put the resulting binary on your `PATH`, point `$MTKLOGO` at it, or pass
`--mtklogo /path/to/mtklogo` to `build-logo.py`.

Finally, `adb` and `fastboot` from Android platform-tools. You need root on the
device to dump its stock partitions (or another way to read `lk`/`logo`, such as
BROM). Flashing needs an unlocked bootloader.

## A full run, start to finish

Nothing below touches the phone until the last step.

```bash
# 0. Back up the partitions you are about to touch and check the dumps.
adb root                 # or however you get root; e.g. adb shell su -c ...
for p in lk_a lk_b logo; do
  adb exec-out "su -c 'dd if=/dev/block/by-name/$p'" > $p.bin.orig
  adb shell "su -c 'md5sum /dev/block/by-name/$p'"; md5sum $p.bin.orig   # compare
done

# 1. Make a splash at the panel's exact size.
./make-splash.py --width 720 --height 1640 --src examples/lineage-logo.png -o splash.png

# 2. Swap the boot splash slots. On every device so far these are 0 and 38.
#    build-logo.py unpacks its own result and proves only those changed.
./build-logo.py --logo logo.bin.orig --profile profiles/mt6833-720x1640.yaml \
                --name mt6833-720x1640 --image splash.png --slots 0,38 \
                --partition-size 12058624 -o logo.bin.new

# 3. Patch the bootloader: blank the orange warning and drop the 5s pause.
#    Add --android-below-10 on Android 9 and older. If you pick the wrong one the
#    script tells you and refuses rather than guessing.
./patch_lk_orangestate.py lk_a.bin.orig --mode both -o lk_a.bin.patched

# 3b. Optional: also kill the dm-verity "device is corrupt" screen.
#     Safe no-op if the device doesn't have it.
./patch_lk_dmverity.py lk_a.bin.patched -o lk_a.tmp && mv lk_a.tmp lk_a.bin.patched

# 4. Check the LK edits by disassembly. Should print ALL CHECKS PASSED.
./verify-lk.py lk_a.bin.orig lk_a.bin.patched

# 5. Flash. Put the phone in the bootloader first. The script rechecks sizes,
#    confirms the bootloader exposes each partition, and skips empty slots.
adb reboot bootloader
./flash-logo-lk.sh .
```

`flash-logo-lk.sh` looks in the target directory for the built logo
(`logo.bin.new`), the stock LK dumps (`lk*.bin.orig`), and the matching
`lk*.bin.patched`. Name your files that way and it picks them up. Pass
`--logo-only` or `--lk-only` to do just one side, and `-n` to see the commands
without running them.

## The tools

`make-splash.py` renders your artwork centered on a background at a panel's exact
resolution. It sizes the logo to a fraction of the panel width (`--fraction`,
default 0.78). On a physically large panel that default can look huge, so drop it;
one tablet here used 0.63 to sit a little under the stock OEM logo. If you want to
match or undercut the OEM logo specifically, decode its splash slot and measure
the ink width first.

`build-logo.py` swaps boot splash slots in a `logo.bin` and proves it only
touched those slots, by unpacking the result and diffing every slot against the
original. It keeps the stock MTK header.

`patch_lk_orangestate.py` blanks the orange warning strings and/or removes the 5
second delay. `--mode text|delay|both`. It finds its targets by content, not
offset.

`patch_lk_dmverity.py` suppresses the dm-verity "device is corrupt / press power"
screen with a two byte instruction patch, anchored on a unique code signature. It
no-ops if the device doesn't have that screen.

`verify-lk.py` re-derives every target from the image and checks the patches by
disassembly. It knows both the Android 9 and Android 10+ variants, and it also
validates the dm-verity patch when present.

`flash-logo-lk.sh` is the flasher, with preflight checks. It reads sizes from the
dumps and from the bootloader itself, skips all-zero (unprovisioned) LK slots, and
has `--restore`, `--logo-only`, `--lk-only`, and `-n`.

Every script takes `--help`, and all of them would rather stop than write on an
ambiguous match.

## Things that tripped us up, so you don't have to

The boot splash is a pair of duplicated slots, usually 0 and 38, but one device
used 0 and 90 instead. Render a contact sheet and look rather than trusting the
usual pair. The slot count varies too (42 to 94).

The delay signature follows the LK build, not the Android version you see in
`getprop`. One device was running an Android 12 GSI on a 2019 bootloader and
needed `--android-below-10`. Let the patcher's detection decide.

The color model has been `bgrabe` (BGRA, big endian) every single time. Work it
out by decoding a colored slot, not a white on black splash, which can't tell
`rgbabe` from `bgrabe`. Slot 1 is usually the stock battery image and makes a good
reference: in `bgrabe` it's a teal glow with an orange battery cap.

Keep the stock MTK header. `mtklogo repack` writes its own (it renames the image
to `LOGO` and drops a secondary block). `build-logo.py` splices the original
header back and only fixes the payload length field.

No underscores anywhere in your working path. `mtklogo` splits the whole path on
`_` to find the slot index. `build-logo.py` handles this for you with a safe temp
directory.

The Android version changes both the LK signature and the boot state number.
Android 10+ has orange as state 2; Android 9 and older have it as state 1. Use
`--android-below-10` for the older ones.

Layout follows the Android era more than the SoC. Newer phones are A/B
(`lk_a`/`lk_b`), usually different builds, so patch each from its own dump. Older
ones have `lk` + `lk2`, usually identical, so patch once and copy. An inactive
slot can be completely blank (all zeros); the flasher notices and skips it.

Not every `mdelay(5000)` in the LK is the boot delay. There are others for
red state, modem auth failure, and fastboot `oem` commands. The verifier points
at the right one.

On a custom ROM, don't trust `ro.boot.*` for the lock state; it can be faked so
apps behave. Cross check `/proc/cmdline`, keymaster's `vbmeta_state`, the `seccfg`
partition, and `fastboot getvar unlocked`.

## If something goes wrong

Reflash the stock images you backed up:

```bash
./flash-logo-lk.sh --restore .
```

If the phone won't reach fastboot at all, recover over BROM with
[mtkclient](https://github.com/bkerler/mtkclient) and your backup. And don't
re-lock the bootloader while it's running modified partitions.

## Credits and license

Logo packing and unpacking is done by
[arlept/mtklogo](https://github.com/arlept/mtklogo). The boot delay LK patch is an
old community trick; what this repo adds is content based location, the dm-verity
screen patch, and disassembly level verification. mtklkzap is released into the
public domain under the Unlicense; see [LICENSE](LICENSE). Do whatever you want
with it.
