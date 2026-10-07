# Block accidental relocking

Never relock while patched LK or other custom firmware remains installed.
Restore the **complete stock firmware package**, including every LK slot and
all other modified verified partitions, before considering relocking. Restoring
only a stock boot image is insufficient: signature enforcement can reject the
patched LK and leave the device unable to boot. Relocking can also erase data.

`patch_lk_relock.py` adds a guard against an accidental Fastboot lock command.
It changes the lock handler to return:

```text
FAILRelock blocked: restore complete stock firmware first
```

It returns before confirmation, factory reset or any lock-state update. It
neither unlocks the device nor changes its current lock state. Other loaders,
direct writes to `seccfg`, and low-level tools such as mtkclient remain outside
this protection. On an A/B device the other LK slot is also outside the guard
unless it has been patched separately using a supported stock image.

## Supported firmware

Initially, only the exact RabbitOS v0.8.293 rabbit r1 LK is supported, identified
by its full SHA256 in `profiles/lk/rabbit-r1-v0.8.293.json`. It has passed offline
instruction and emulation checks; it has **not** been tested on hardware.
Unknown, truncated and already modified images are rejected. `--force` only
permits replacing an output file; it never overrides firmware identification.
Unlike the warning patchers, this feature requires a reviewed firmware profile.

Run this patch **first**, on pristine LK. The verifier checks this step alone:

```sh
python3 patch_lk_relock.py lk.bin.orig -o lk.guard.bin
python3 verify_lk_relock.py lk.bin.orig lk.guard.bin
```

Then apply the optional warning patches and verify their diff against the guarded
image. This keeps both verifiers strict about changes outside their own patches:

```sh
python3 patch_lk_orangestate.py lk.guard.bin --mode both -o lk.orange.bin
python3 patch_lk_dmverity.py lk.orange.bin -o lk.bin.patched
python3 verify-lk.py lk.guard.bin lk.bin.patched
```

`--dry-run` performs identification and verification without writing a file.
No command above accesses a device. See the main README for backup and flashing
steps. A same-size output and passing offline checks do not prove bootability.

## Implementation and evidence

The r1 profile identifies the Fastboot `flashing lock` registration at file
offset `0x1f02c`. Its GOT entry at `0xb767c` points to the Thumb handler at
`0x28788`. The patch replaces its first 64 bytes with:

1. `adr r0, message`
2. `b.w fastboot_fail`
3. Unreachable padding and the NUL-terminated error message.

The handler starts on a four-byte boundary; the message is at entry + 8. The
tail-call preserves the original caller's LR and stack. `fastboot_fail` at
`0x1e6fc` passes the message and `FAIL` to the unchanged Fastboot response routine
at `0x1e5ec`. The rest of the image, including header, command registration,
unlock handler, persistent lock state and security policy code, is untouched.

The separate verifier resolves the ADR and branch with Capstone, checks the
message length against Fastboot's response limit, confirms the `FAIL` wrapper,
and rejects any changes outside the refusal stub. Tests use Unicorn to execute
the stub and existing failure wrapper while modeling only the final response
transport. They check the response, return address, stack, callee-saved registers
and absence of memory writes. An optional stock-image test also executes the
actual command registration to prove it selects the patched handler.

```sh
python3 -m pip install capstone==5.0.7 unicorn==2.1.4
python3 tests/test_relock.py -v
MTKLKZAP_TEST_LK=/path/to/stock/lk.img python3 tests/test_relock.py -v
```

Tests use a synthetic fixture when stock firmware is unavailable; the real-image
test is then explicitly skipped. Firmware dumps are not committed. Add further
profiles only after tracing their registered lock handlers and response paths,
and testing them against the actual images. Offsets from one LK must not be
reused for another firmware merely because the SoC matches.
