#!/usr/bin/env python3
"""Block the Fastboot relock handler in a reviewed stock LK. Files only, no USB."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

MESSAGE = b'Relock blocked: restore complete stock firmware first'
PROFILE_DIR = Path(__file__).resolve().parent/'profiles/lk'


def select_profile(data):
    digest = hashlib.sha256(data).hexdigest()
    matches = [p for path in sorted(PROFILE_DIR.glob('*.json'))
               if (p := json.loads(path.read_text()))['sha256'] == digest]
    if len(matches) != 1:
        raise ValueError('Unsupported LK: requires an exact reviewed stock image; run relock patching first')
    return matches[0]


def branch_w(address, target):
    delta = target-address-4
    if address & 1 or target & 1 or not -(1 << 24) <= delta < (1 << 24):
        raise ValueError('Invalid Thumb branch target')
    value = delta & 0x1ffffff
    s, i1, i2 = (value >> 24)&1, (value >> 23)&1, (value >> 22)&1
    j1, j2 = 1 ^ i1 ^ s, 1 ^ i2 ^ s
    return struct.pack('<HH', 0xf000 | (s << 10) | ((value >> 12)&0x3ff),
                       0x9000 | (j1 << 13) | (j2 << 11) | ((value >> 1)&0x7ff))


def make_patch(data, profile):
    if hashlib.sha256(data).hexdigest() != profile['sha256'] or len(data) != profile['bytes']:
        raise ValueError('Profile does not match input')
    entry, end, fail = profile['handler'], profile['handler_end'], profile['fastboot_fail']
    if entry % 4 or not 512 <= entry < end <= len(data) or not 512 <= fail < len(data)-16:
        raise ValueError('Invalid profile bounds/alignment')
    # ADR r0, entry+8; tail-call fastboot_fail; unreachable NOP, then message.
    # No prologue: the original caller's LR and stack stay intact.
    payload = bytes.fromhex('01a0') + branch_w(entry+2, fail) + bytes.fromhex('00bf') + MESSAGE + b'\0'
    payload += bytes((-len(payload)) % 4)
    if len(payload) > end-entry:
        raise ValueError('Refusal stub exceeds original handler')
    return data[:entry]+payload+data[entry+len(payload):]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='pristine stock LK; patch relock before warning removal')
    parser.add_argument('-o','--output', type=Path)
    parser.add_argument('--force', action='store_true', help='overwrite output; never bypass input validation')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    data = args.input.read_bytes()
    profile = select_profile(data)
    output = make_patch(data, profile)
    # Separate verifier resolves the instructions and validates the full diff.
    from verify_lk_relock import verify
    verify(data, output, profile)
    print(f"Profile: {profile['name']}; hardware tested: {profile['hardware_tested']}")
    print('Fastboot FAIL: '+MESSAGE.decode())
    print('Restore the complete stock firmware, including all LK slots, before relocking.')
    print('Other loaders and direct seccfg writes are outside this protection.')
    if args.dry_run:
        print('Dry run: no file written')
        return
    path = args.output or args.input.with_name(args.input.name+'.relock-blocked')
    if path.resolve() == args.input.resolve():
        raise ValueError('Refusing to overwrite input')
    if path.exists() and not args.force:
        raise ValueError('Output exists; use --force to replace it')
    # The output has already passed the verifier; input remains untouched.
    path.write_bytes(output)
    print(f'Wrote {path} ({len(output)} bytes)')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(str(error))
