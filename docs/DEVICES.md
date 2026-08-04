# Tested devices

Seven devices across six SoCs have been through these tools. All were unlocked
and all used the `bgrabe` color model. The boot splash was slots 0 and 38 on all
but one, so treat even that as something to confirm rather than assume. The point
of listing them is to show what varies, so you know what to check on something
new.

| SoC | Panel | Android | LK layout | Slots | Splash | Delay variant | Profile |
|---|---|---|---|---|---|---|---|
| MT6739 | 396x880 | 10 | lk + lk2 (identical) | 42 | 0, 38 | A10+ (022B) | mt6739-396x880 |
| MT6755 | 480x800 | 9 | lk + lk2 (identical) | 42 | 0, 38 | pre-10 (012B) | mt6755-480x800 |
| MT6761 | 600x1280 | 12 (GSI) | lk + lk2 (identical) | 94 | 0, 90 | pre-10 (012B) | mt6761-600x1280 |
| MT6762 | 480x800 | 14 | lk_a + lk_b (b empty) | 42 | 0, 38 | A10+ (022B) | mt6762-480x800 |
| MT6762 | 1080x1920 | 13 | lk_a + lk_b (b empty) | 60 | 0, 38 | A10+ (022B) | mt6762-1080x1920 |
| MT6765 | 480x640 | 14 | lk_a + lk_b (different) | 60 | 0, 38 | A10+ (022B) | mt6765-480x640 |
| MT6833 | 720x1640 | 14 | lk_a + lk_b (different) | 42 | 0, 38 | A10+ (022B) | mt6833-720x1640 |

What actually varied between them:

The slot count was 42, 60, or 94. Never assume it; render a contact sheet. The
splash pair was usually 0 and 38, but the MT6761 used 0 and 90, so confirm it
visually rather than trusting the pattern. That device also mixed two fullscreen
sizes in one partition (600x1280 and 720x1280), which is fine: you only replace
the ones that hold the splash.

The delay signature follows the LK build, not the running OS. The MT6761 above
was booting an Android 12 GSI on a bootloader built in 2019, and it needed the
pre-10 (`012B`) signature to match that old LK. So go by what the patcher detects,
not by the Android version in `getprop`.

The LK layout tracks the Android era, not the chip. Newer devices are A/B
(`lk_a`/`lk_b`), older ones have `lk` + `lk2`. On the A/B devices the two slots
were sometimes different builds (patch each from its own dump) and sometimes the
inactive one was completely unprovisioned, a megabyte of zeros. The flasher skips
all-zero slots on its own.

The two delay signatures: the Android 10+ LKs use `022B` with orange as boot
state 2, older ones use `012B` with orange as state 1. Pass `--android-below-10`
for the older shape. If you get it wrong the patcher refuses and tells you which
one matched, so let that decide rather than guessing from the OS version (see the
MT6761 note above).

The dm-verity "device is corrupt / press power" screen showed up on the MT6762
1080x1920 device and was removed there with `patch_lk_dmverity.py`. It is a
separate LK routine from the orange warning, and it is drawn as text rather than
pulled from the logo partition. Not every device has it.

The small slot geometry (digits, glyphs, charge bar) differed by panel, but you
never need it exactly right. `mtklogo` maps slots by their decompressed byte size,
and the slots you aren't replacing pass through untouched, so the digit and glyph
dimensions in a profile never affect the output.

Adding a device is a profile in `profiles/` and a row in this table. Please don't
commit firmware dumps.
