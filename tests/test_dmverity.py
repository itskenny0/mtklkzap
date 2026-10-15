#!/usr/bin/env python3
"""dm-verity screen / vendor_boot / report-locked checks.

The byte-level assertions need a real stock r1 LK in MTKLKZAP_TEST_LK; the
refusal checks run without one.
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import patch_lk_dmverity as dmv

_spec = importlib.util.spec_from_file_location("verify_lk", ROOT / "verify-lk.py")
verify_lk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_lk)

STOCK = os.environ.get("MTKLKZAP_TEST_LK")


def run(*args):
    return subprocess.run([sys.executable, *map(str, args)], capture_output=True, text=True)


class RefusalTests(unittest.TestCase):
    def test_refuses_unrelated_image(self):
        with tempfile.TemporaryDirectory() as d:
            junk = Path(d) / "junk.bin"
            junk.write_bytes(bytes(0x40000))
            r = run(ROOT / "patch_lk_dmverity.py", junk, "--report-locked",
                    "-o", Path(d) / "out.bin")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("does not contain the dm-verity corruption screen", r.stderr)


@unittest.skipUnless(STOCK, "stock LK not supplied (set MTKLKZAP_TEST_LK)")
class StockReportLockedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        cls.relock = d / "relock.bin"
        cls.orange = d / "orange.bin"
        # relock -> orange, the inputs the dm-verity patch expects downstream.
        run(ROOT / "patch_lk_relock.py", STOCK, "-o", cls.relock, "--force")
        run(ROOT / "patch_lk_orangestate.py", cls.relock, "--mode", "both",
            "-o", cls.orange, "--force")
        cls.out = d / "warnings.bin"
        cls.r = run(ROOT / "patch_lk_dmverity.py", cls.orange, "--report-locked",
                    "-o", cls.out, "--force")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_patch_succeeds_and_verifies(self):
        self.assertEqual(self.r.returncode, 0, self.r.stderr)
        # verify-lk compares against the pre-orange image, as build-lk.py does.
        self.assertTrue(verify_lk.verify(str(self.relock), str(self.out)))

    def test_sites(self):
        o = self.orange.read_bytes()
        p = self.out.read_bytes()
        rl = dmv_detect = verify_lk.detect_report_locked(o, p)
        self.assertIsNotNone(rl)
        # device_state cbnz is now a nop
        self.assertEqual(verify_lk.dis(p, rl["ds"], 2)[0].mnemonic, "nop")
        # yellow/orange boot-state cases select the green case, red is untouched
        for n, c in rl["case_of"].items():
            if c in ("yellow", "orange"):
                self.assertEqual(p[rl["table"] + n], o[rl["table"] + rl["green"]])
            if c == "red":
                self.assertEqual(p[rl["table"] + n], o[rl["table"] + n])
        # veritymode load now resolves to "enforcing"
        tgt = verify_lk.pc_targets(p, rl["vl"], rl["vl"] + 8)[rl["vl"]]
        self.assertEqual(p[tgt:tgt + 10], b"enforcing\0")

    def test_default_run_does_not_report_locked(self):
        d = Path(self.tmp.name)
        plain = d / "plain.bin"
        r = run(ROOT / "patch_lk_dmverity.py", self.orange, "-o", plain, "--force")
        self.assertEqual(r.returncode, 0, r.stderr)
        # The sites still resolve, but a plain build applies none of their edits.
        o, pbytes = self.orange.read_bytes(), plain.read_bytes()
        rl = verify_lk.detect_report_locked(o, pbytes)
        self.assertFalse(all(pbytes[k] == v for k, v in rl["edits"].items()))

    def test_refuses_to_repatch(self):
        # Re-running report-locked on an already-reported image must refuse:
        # the boot-state table no longer maps to four distinct colours.
        d = Path(self.tmp.name)
        again = d / "again.bin"
        r = run(ROOT / "patch_lk_dmverity.py", self.out, "--report-locked",
                "-o", again, "--force")
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
