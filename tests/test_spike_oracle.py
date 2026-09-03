#!/usr/bin/env python3
"""Spike 胶水的静态约定：不启动 spike，只锁 ISA 串和对照用例。

合法读 (v)stimecmp 必须带 zicntr，否则 host SIGSEGV 会被误写成 ISA 结论。
阳性对照走 M 态，避免 HS+STCE=1 还要配 mcounteren.TM。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from csrformal.spike_oracle import (
    _ASM_TEMPLATE, _SPIKE_ISAS, _is_host_crash, _mcause_to_verdict,
    case_workdir, classify, control_cases,
)


class TestSpikeIsa(unittest.TestCase):
    def test_preferred_isa_has_zicntr_and_sstc(self):
        self.assertTrue(_SPIKE_ISAS[0].startswith("rv64gch"))
        self.assertIn("zicntr", _SPIKE_ISAS[0])
        self.assertIn("sstc", _SPIKE_ISAS[0])

    def test_old_isa_without_zicntr_is_only_fallback(self):
        self.assertIn("rv64gch_zicsr_sstc", _SPIKE_ISAS)
        self.assertNotEqual(_SPIKE_ISAS[0], "rv64gch_zicsr_sstc")


class TestHarnessTemplate(unittest.TestCase):
    def test_htif_and_menvcfg_numeric(self):
        self.assertIn("tohost", _ASM_TEMPLATE)
        self.assertIn("fromhost", _ASM_TEMPLATE)
        self.assertIn("0x30A", _ASM_TEMPLATE)
        self.assertIn("mret", _ASM_TEMPLATE)
        self.assertIn("{csr_line}", _ASM_TEMPLATE)
        self.assertNotIn("{csr_insn}", _ASM_TEMPLATE)

    def test_success_path_writes_tohost_one(self):
        # t0=0 → (0<<1)|1 = 1，fesvr 当成退出码 0 / NONE
        self.assertIn("li   t0, 0", _ASM_TEMPLATE)
        self.assertIn("j    _exit", _ASM_TEMPLATE)


class TestControls(unittest.TestCase):
    def test_legal_is_m_mode_vstimecmp(self):
        legal = next(c for c in control_cases() if c.pid.startswith("ctrl/legal"))
        self.assertEqual(legal.addr, 0x24D)
        self.assertEqual(legal.prvm, 3)
        self.assertFalse(legal.v)
        self.assertEqual(legal.spec, "NONE")

    def test_illegal_stimecmp_hs_stce0(self):
        ill = next(c for c in control_cases() if c.pid.startswith("ctrl/illegal"))
        self.assertEqual(ill.addr, 0x14D)
        self.assertEqual(ill.prvm, 1)
        self.assertFalse(ill.v)
        self.assertFalse(ill.menvcfg_stce)
        self.assertEqual(ill.spec, "II")

    def test_case_dirs_do_not_clobber(self):
        a = case_workdir("CSRPermit/S3")
        b = case_workdir("ctrl/legal-M-vstimecmp")
        self.assertNotEqual(a, b)
        self.assertTrue(a.endswith("CSRPermit_S3"))
        self.assertTrue(b.endswith("ctrl_legal-M-vstimecmp"))


class TestVerdict(unittest.TestCase):
    def test_mcause_codes(self):
        self.assertEqual(_mcause_to_verdict(0), "NONE")
        self.assertEqual(_mcause_to_verdict(2), "II")
        self.assertEqual(_mcause_to_verdict(22), "VI")

    def test_host_sigsegv_is_not_mcause(self):
        self.assertTrue(_is_host_crash(-11))
        self.assertFalse(_is_host_crash(0))
        self.assertFalse(_is_host_crash(2))

    def test_classify_rtl_bug(self):
        self.assertIn("RTL bug", classify("NONE", "II", "II"))


if __name__ == "__main__":
    unittest.main()
