# Porting to a new device

The scripts are content driven, so most devices only need a new logo profile and
the right flags. This is the whole checklist, with the techniques used to bring up
the devices in [DEVICES.md](DEVICES.md). Everything here works on files you dumped
from the device; flashing is the last step and is separate.

## 0. Make sure it's really unlocked

On a custom ROM, `ro.boot.verifiedbootstate` and `ro.boot.flash.locked` can be
faked so apps behave. Trust these instead:

* `/proc/cmdline`, which the bootloader writes: look for
  `androidboot.verifiedbootstate`
* a `ro.boot.*` value that appears twice in `getprop` output, which is the sign of
  a resetprop style override
* `ro.keymaster.*.vbmeta_state`, since keymaster reads the real hardware state
* the `seccfg` partition: magic `MMMM`, then a `lock_state` word where
  1 is DEFAULT, 2 MP_DEFAULT, 3 UNLOCK, 4 LOCK, 5 VERIFIED, 6 CUSTOM
* `fastboot getvar unlocked`

This also tells you whether there is anything to remove. The orange warning and
its 5 second pause only happen in orange state.

## 1. Back up first, and check the dumps

Dump `lk*`, `logo`, and ideally the whole boot chain, then compare each dump's md5
against `md5sum` run on the block device itself:

```bash
adb exec-out "su -c 'dd if=/dev/block/by-name/lk_a'" > lk_a.bin.orig
adb shell "su -c 'md5sum /dev/block/by-name/lk_a'"; md5sum lk_a.bin.orig
```

Use `su` if it's there; `adb root` works on a userdebug build. No root at all?
Read the partitions over BROM with mtkclient instead.

Some devices (certain phh-su GSIs) corrupt binary data over `adb exec-out`,
turning every `0x0a` byte into `0x0d0a`. You'll see the dump come out a few
kilobytes too large and the md5 won't match. If that happens, dump to a file on
the device and pull it, which transfers raw:

```bash
adb shell "su -c 'dd if=/dev/block/by-name/lk_a of=/data/local/tmp/lk_a.img'"
adb pull /data/local/tmp/lk_a.img lk_a.bin.orig
adb shell "rm /data/local/tmp/lk_a.img"
```

## 2. Find the panel size and slot layout

Full screen slots decompress to `w * h * 4` bytes:

```bash
mtklogo explore logo.bin.orig --width <panel-width> -o /tmp/explore
```

Copy an existing profile and list every distinct slot size. Only the product
`w * h` per size has to be right, since mtklogo matches by byte size. Small glyphs
are the easy thing to get wrong: rendering at twice or four times the real width
shows two or four squashed copies side by side, so if you see repeats, halve the
width.

## 3. Work out the color model by decoding, not guessing

Find a colored slot (slot 1 is usually the stock battery image) and see which
model gives sane colors. A white on black splash can't tell `rgbabe` from
`bgrabe`. Every device so far has been `bgrabe`, where slot 1 comes out as a teal
glow with an orange battery cap.

## 4. Find the boot splash slot

Render a contact sheet of the full screen slots and look for the splash. It has
been slots 0 and 38, duplicated, every time. Confirm it; the slot count changes.

## 5. Build the logo

```bash
./make-splash.py --width W --height H --src my-logo.png -o splash.png
./build-logo.py --logo logo.bin.orig --profile profiles/<dev>.yaml --name <dev> \
                --image splash.png --slots 0,38 --partition-size <N> -o logo.bin.new
```

`build-logo.py` unpacks its own output and asserts that exactly slots 0 and 38
changed. If it prints anything else, stop.

## 6. Patch the bootloader

```bash
# Android 10+; add --android-below-10 for Android 9 and older.
./patch_lk_orangestate.py lk_a.bin.orig --mode both -o lk_a.bin.patched
./verify-lk.py lk_a.bin.orig lk_a.bin.patched     # must say ALL CHECKS PASSED
```

If the device shows the dm-verity "device is corrupt / press power to continue"
screen, chain the second patch. It's a safe no-op when the strings aren't there:

```bash
./patch_lk_dmverity.py lk_a.bin.patched -o lk_a.tmp && mv lk_a.tmp lk_a.bin.patched
```

On A/B devices, repeat for `lk_b` from its own dump if it is a real (non-zero)
bootloader. On `lk`/`lk2` devices the two are usually identical, so patch `lk` and
copy it to `lk2.bin.patched`.

### Finding the dm-verity screen by hand

If `patch_lk_dmverity.py` doesn't match, because it's a different build, find it
the way it was found the first time:

1. `strings lk_a.bin.orig | grep -iE 'corrupt|press|dm.?verity|continue'`
2. Resolve the PC relative `ldr rX,[pc,#imm]; add rX,pc` string loads to confirm
   which single function prints all of them.
3. That function has a small "should I draw this?" branch near the top, something
   like `cmp/it/orreq; cbnz r3, draw;` followed by the return. Nop the `cbnz` so it
   always falls through to its own return, which is the path it takes on a clean
   boot anyway.
4. Check that the caller ignores the return value. On ours it did `mov r0, r5`
   right after the call.

## 7. Flash

```bash
adb reboot bootloader
./flash-logo-lk.sh .          # try -n first if you want to see the commands
```

Reboot, confirm the splash and the missing screens, and for peace of mind read the
partitions back and compare md5 against the patched files.

## Contributing a device

A profile in `profiles/` and a row in [DEVICES.md](DEVICES.md) is the whole thing.
Please don't commit firmware dumps.
