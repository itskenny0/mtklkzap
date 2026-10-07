#!/usr/bin/env python3
"""Verify a relock-only patch by disassembly, target resolution and exact diff."""
import argparse
import hashlib
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_REG_R0


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(original, patched, profile):
    require(hashlib.sha256(original).hexdigest() == profile['sha256'], 'Wrong stock reference')
    require(len(original) == len(patched) == profile['bytes'], 'LK length changed')
    entry, fail = profile['handler'], profile['fastboot_fail']
    md = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    md.detail = True
    ins = list(md.disasm(patched[entry:entry+6],entry))
    require(len(ins) == 2, 'Expected two refusal instructions')
    adr, branch = ins
    require(adr.mnemonic == 'adr' and adr.size == 2 and adr.operands[0].reg == ARM_REG_R0
            and adr.operands[1].type == ARM_OP_IMM, 'Expected ADR r0')
    message_at = ((entry+4)&~3)+adr.operands[1].imm
    require(message_at == entry+8, 'Wrong message address')
    require(branch.mnemonic == 'b.w' and branch.operands[0].imm == fail,
            'Expected a tail-call to fastboot_fail')
    end = patched.find(b'\0',message_at,min(message_at+61,len(patched)))
    require(end > message_at, 'Missing bounded Fastboot error message')
    require(patched[message_at:end] == b'Relock blocked: restore complete stock firmware first',
            'Wrong refusal message')
    patch_end = (end+1+3)&~3
    require(patch_end <= profile['handler_end'], 'Patch leaves original handler')
    require(patched[entry+6:entry+8] == bytes.fromhex('00bf') and not any(patched[end+1:patch_end]),
            'Unexpected stub padding')
    require(patched[:entry] == original[:entry] and patched[patch_end:] == original[patch_end:],
            'Changes outside relock handler')
    # Resolve the untouched FAIL wrapper's literal and final response routine.
    ins = list(md.disasm(patched[fail:fail+10],fail))
    require([(i.mnemonic,i.op_str) for i in ins[:3]] ==
            [('mov','r1, r0'),('ldr','r0, [pc, #8]'),('add','r0, pc')],
            'Unexpected fastboot_fail wrapper')
    literal = ((ins[1].address+4)&~3)+8
    label = (struct.unpack_from('<I',patched,literal)[0]+ins[2].address+4)&0xffffffff
    require(patched[label:label+5] == b'FAIL\0', 'Wrapper does not send FAIL')
    require(ins[3].mnemonic == 'b.w' and ins[3].operands[0].imm == profile['fastboot_ack'],
            'Wrong Fastboot response target')
    return {'handler': entry, 'patch_bytes': patch_end-entry, 'message': patched[message_at:end].decode()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original',type=Path)
    parser.add_argument('patched',type=Path)
    args = parser.parse_args()
    from patch_lk_relock import select_profile
    original = args.original.read_bytes()
    result = verify(original,args.patched.read_bytes(),select_profile(original))
    print('PASS: relock rejected through Fastboot FAIL; stack untouched; exact handler-only diff')
    print(result)


if __name__ == '__main__':
    try:
        main()
    except (OSError,ValueError) as error:
        raise SystemExit(str(error))
