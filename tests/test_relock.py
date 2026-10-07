#!/usr/bin/env python3
"""Relock regression checks; optionally set MTKLKZAP_TEST_LK to a stock r1 LK."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from patch_lk_relock import MESSAGE, branch_w, make_patch, select_profile
from verify_lk_relock import verify
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import *


def emulate(data, profile, bias=0x100000, argument=0):
    uc = Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    start = bias & ~4095
    length = (len(data)+bias-start+4095)&~4095
    uc.mem_map(start,length)
    uc.mem_write(bias,data)
    uc.mem_map(0x20000000,0x20000)
    stack, stop = 0x20008000,0x20010000
    uc.reg_write(UC_ARM_REG_SP,stack)
    uc.reg_write(UC_ARM_REG_LR,stop|1)
    uc.reg_write(UC_ARM_REG_R0,argument)
    saved = [UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,
             UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11]
    for n,reg in enumerate(saved):
        uc.reg_write(reg,0x12340000+n)
    replies, writes = [],[]
    def cstring(address):
        return bytes(uc.mem_read(address,61)).split(b'\0')[0]
    def code(uc,address,size,_):
        offset = address-bias
        if offset == profile['fastboot_ack']:
            replies.append((cstring(uc.reg_read(UC_ARM_REG_R0)),cstring(uc.reg_read(UC_ARM_REG_R1))))
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        elif not (profile['handler'] <= offset < profile['handler']+6 or
                  profile['fastboot_fail'] <= offset < profile['fastboot_fail']+10):
            raise AssertionError(f'Unexpected code reached: {offset:#x}')
    uc.hook_add(UC_HOOK_CODE,code)
    uc.hook_add(UC_HOOK_MEM_WRITE,lambda uc,access,address,size,value,user: writes.append(address))
    uc.emu_start((bias+profile['handler'])|1,stop,count=30)
    assert uc.reg_read(UC_ARM_REG_PC) == stop
    assert replies == [(b'FAIL',MESSAGE)]
    assert not writes, 'Refusal must not change memory, storage or lock state'
    assert uc.reg_read(UC_ARM_REG_SP) == stack
    assert all(uc.reg_read(reg)==0x12340000+n for n,reg in enumerate(saved))


class RelockTests(unittest.TestCase):
    def run_tool(self, name, *args, success=True):
        result = subprocess.run([sys.executable, str(ROOT/name), *map(str,args)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout+result.stderr)
        return result

    def setUp(self):
        blob = bytearray(4096)
        entry,fail,ack,label = 0x500,0x800,0x780,0x900
        blob[entry:entry+64] = bytes(range(64))
        wrapper = bytes.fromhex('014602487844')+branch_w(fail+6,ack)+bytes.fromhex('00bf')
        wrapper += struct.pack('<I',label-(fail+8))
        blob[fail:fail+len(wrapper)] = wrapper
        blob[label:label+5] = b'FAIL\0'
        self.original = bytes(blob)
        self.profile = {'sha256':hashlib.sha256(blob).hexdigest(),'bytes':len(blob),
                        'handler':entry,'handler_end':entry+128,'fastboot_fail':fail,'fastboot_ack':ack}

    def test_refusal(self):
        patched = make_patch(self.original,self.profile)
        self.assertEqual(verify(self.original,patched,self.profile)['patch_bytes'],64)
        for bias in [0x100000,0x48000000,0x47fffe00]:
            for argument in [0,1,0xffffffff]:
                emulate(patched,self.profile,bias,argument)

    def test_bad_inputs(self):
        with self.assertRaises(ValueError):
            select_profile(self.original)
        with self.assertRaises(ValueError):
            make_patch(self.original[:-1],self.profile)
        with self.assertRaises(ValueError):
            make_patch(make_patch(self.original,self.profile),self.profile)
        for key,value in [('handler',0x502),('handler_end',0x510),('fastboot_fail',5000)]:
            with self.assertRaises(ValueError):
                make_patch(self.original,dict(self.profile,**{key:value}))

    def test_tampering(self):
        good = make_patch(self.original,self.profile)
        for offset in [0,0x501,0x503,0x506,0x510,0x53f,0x540,0x801,4095]:
            bad = bytearray(good)
            bad[offset] ^= 1
            with self.assertRaises(ValueError,msg=hex(offset)):
                verify(self.original,bytes(bad),self.profile)

    @unittest.skipUnless(os.environ.get('MTKLKZAP_TEST_LK'),'stock LK not supplied')
    def test_rabbit_stock(self):
        original = Path(os.environ['MTKLKZAP_TEST_LK']).read_bytes()
        profile = select_profile(original)
        patched = make_patch(original,profile)
        verify(original,patched,profile)
        # Execute the real command-registration instructions and resolve its GOT entry.
        bias = profile['file_address_bias']
        uc = Uc(UC_ARCH_ARM,UC_MODE_THUMB)
        base = bias & ~4095
        uc.mem_map(base,(len(original)+bias-base+4095)&~4095)
        uc.mem_write(bias,original)
        uc.reg_write(UC_ARM_REG_R7,bias+profile['got'])
        uc.emu_start((bias+profile['registration'])|1,bias+profile['fastboot_register'],count=20)
        self.assertEqual(uc.reg_read(UC_ARM_REG_PC),bias+profile['fastboot_register'])
        self.assertEqual(bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R0),14)),b'flashing lock\0')
        self.assertEqual(uc.reg_read(UC_ARM_REG_R1),(bias+profile['handler'])|1)
        self.assertEqual(struct.unpack_from('<I',original,profile['handler_pointer'])[0],
                         (bias+profile['handler'])|1)
        for argument in [0,1,0xffffffff]:
            emulate(patched,profile,bias,argument)

    @unittest.skipUnless(os.environ.get('MTKLKZAP_TEST_LK'),'stock LK not supplied')
    def test_rabbit_cli(self):
        original = Path(os.environ['MTKLKZAP_TEST_LK']).read_bytes()
        profile = select_profile(original)
        expected = make_patch(original,profile)
        with tempfile.TemporaryDirectory(prefix='mtklkzap-test-') as directory:
            source = Path(directory)/'lk.img'
            output = Path(directory)/'lk.img.relock-blocked'
            source.write_bytes(original)
            self.run_tool('patch_lk_relock.py',source,'--dry-run')
            self.assertEqual(list(Path(directory).iterdir()),[source])
            self.run_tool('patch_lk_relock.py',source)
            self.assertEqual(output.read_bytes(),expected)
            self.run_tool('verify_lk_relock.py',source,output)

            output.write_bytes(b'existing output')
            result = self.run_tool('patch_lk_relock.py',source,success=False)
            self.assertIn('Output exists',result.stderr)
            self.assertEqual(output.read_bytes(),b'existing output')
            self.run_tool('patch_lk_relock.py',source,'--force')
            self.assertEqual(output.read_bytes(),expected)
            result = self.run_tool('patch_lk_relock.py',source,'-o',source,'--force',success=False)
            self.assertIn('Refusing to overwrite input',result.stderr)
            self.assertEqual(source.read_bytes(),original)

            # --force must not accept a modified image or clobber its output.
            source.write_bytes(expected)
            output.write_bytes(b'keep this output')
            result = self.run_tool('patch_lk_relock.py',source,'--force',success=False)
            self.assertIn('Unsupported LK',result.stderr)
            self.assertEqual(source.read_bytes(),expected)
            self.assertEqual(output.read_bytes(),b'keep this output')

    @unittest.skipUnless(os.environ.get('MTKLKZAP_TEST_LK'),'stock LK not supplied')
    def test_rabbit_input_aliases(self):
        original = Path(os.environ['MTKLKZAP_TEST_LK']).read_bytes()
        with tempfile.TemporaryDirectory(prefix='mtklkzap-test-') as directory:
            source = Path(directory)/'stock.img'
            source.write_bytes(original)
            for link in [os.link,os.symlink]:
                with self.subTest(link=link.__name__):
                    alias = Path(directory)/(link.__name__+'.img')
                    link(source,alias)
                    result = self.run_tool('patch_lk_relock.py',source,'-o',alias,
                                           '--force',success=False)
                    self.assertIn('Refusing to overwrite input',result.stderr)
                    self.assertEqual(source.read_bytes(),original)

    @unittest.skipUnless(os.environ.get('MTKLKZAP_TEST_LK'),'stock LK not supplied')
    def test_rabbit_warning_patches(self):
        original = Path(os.environ['MTKLKZAP_TEST_LK']).read_bytes()
        profile = select_profile(original)
        with tempfile.TemporaryDirectory(prefix='mtklkzap-test-') as directory:
            stock,guard,orange,final = [Path(directory)/name for name in
                                       ['stock.img','guard.bin','orange.bin','final.bin']]
            stock.write_bytes(original)
            self.run_tool('patch_lk_relock.py',stock,'-o',guard)
            self.run_tool('verify_lk_relock.py',stock,guard)
            self.run_tool('patch_lk_orangestate.py',guard,'--mode','both','-o',orange)
            self.run_tool('patch_lk_dmverity.py',orange,'-o',final)
            self.run_tool('verify-lk.py',guard,final)
            guarded,patched = guard.read_bytes(),final.read_bytes()
            self.assertEqual(len(patched),len(original))
            self.assertEqual(patched[profile['handler']:profile['handler_end']],
                             guarded[profile['handler']:profile['handler_end']])
            self.assertEqual(patched[profile['fastboot_fail']:profile['fastboot_fail']+16],
                             original[profile['fastboot_fail']:profile['fastboot_fail']+16])
            emulate(patched,profile,profile['file_address_bias'])


if __name__ == '__main__':
    unittest.main()
