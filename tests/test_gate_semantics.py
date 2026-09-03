#!/usr/bin/env python3
"""门禁语义：UNKNOWN 计失败、空 --review 不得静默通过、变异对照不认 UNKNOWN。

不精化、不读香山树。"""
import json
import os
import sys
import tempfile
import unittest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from csrformal import runner
from csrformal.cli import (
    check_failed, expect_key_matches, main, select_expect_props, selftest_ok,
)
from csrformal.props import Property, SpecRef


class TestCheckExit(unittest.TestCase):
    def test_holds_only_passes(self):
        s = {runner.HOLDS: 3, runner.VIOLATED: 0, runner.VACUOUS: 0,
             runner.UNKNOWN: 0, runner.ERROR: 0}
        self.assertFalse(check_failed(s))

    def test_unknown_is_failure(self):
        s = {runner.HOLDS: 2, runner.VIOLATED: 0, runner.VACUOUS: 0,
             runner.UNKNOWN: 1, runner.ERROR: 0}
        self.assertTrue(check_failed(s))

    def test_violated_vacuous_error_still_fail(self):
        for key in (runner.VIOLATED, runner.VACUOUS, runner.ERROR):
            s = {runner.HOLDS: 1, runner.VIOLATED: 0, runner.VACUOUS: 0,
                 runner.UNKNOWN: 0, runner.ERROR: 0}
            s[key] = 1
            self.assertTrue(check_failed(s), key)


def _prop(pid):
    return Property(pid=pid, title=pid, module="T", assumes=[], prove="true",
                    ref=SpecRef("norm:x", "t.adoc"))


class TestExpectKeyMatch(unittest.TestCase):
    """EQ-tval 不得 startswith 误伤 EQ-tval-data；族名仍吃 D2[...]。"""

    def test_eq_tval_does_not_eat_eq_tval_data(self):
        self.assertTrue(expect_key_matches("TrapEntryM/EQ-tval", "EQ-tval"))
        self.assertFalse(expect_key_matches("TrapEntryM/EQ-tval-data", "EQ-tval"))
        self.assertTrue(expect_key_matches("TrapEntryM/EQ-tval-data", "EQ-tval-data"))
        self.assertFalse(expect_key_matches("TrapEntryM/EQ-tval", "EQ-tval-data"))

    def test_eq_permit_is_exact(self):
        self.assertTrue(expect_key_matches("CSRPermit/EQ-permit", "EQ-permit"))
        self.assertFalse(expect_key_matches("CSRPermit/EQ-permit", "EQ"))
        self.assertFalse(expect_key_matches("TrapEntryM/EQ-tval", "EQ"))

    def test_family_bracket_still_matches(self):
        self.assertTrue(expect_key_matches("TrapHandle/D2[e=8,HS]", "D2"))
        self.assertTrue(expect_key_matches("CSRPermit/C2[cycle]", "C2"))
        self.assertTrue(expect_key_matches("CSRPermit/E3[0]", "E3"))
        self.assertFalse(expect_key_matches("CSRPermit/E3u[0]", "E3"))
        self.assertFalse(expect_key_matches("CSRPermit/S3b", "S3"))

    def test_te1_te2_select_disjoint(self):
        props = [
            _prop("TrapEntryM/EQ-next"),
            _prop("TrapEntryM/EQ-tval"),
            _prop("TrapEntryM/EQ-tval-data"),
        ]
        te1 = [p.pid for p in select_expect_props(props, ["EQ-tval"])]
        te2 = [p.pid for p in select_expect_props(props, ["EQ-tval-data"])]
        self.assertEqual(te1, ["TrapEntryM/EQ-tval"])
        self.assertEqual(te2, ["TrapEntryM/EQ-tval-data"])


class TestSelftestVerdict(unittest.TestCase):
    def test_fix_unknown_is_not_fixed(self):
        self.assertFalse(selftest_ok("fix", [runner.HOLDS, runner.UNKNOWN]))
        self.assertTrue(selftest_ok("fix", [runner.HOLDS, runner.HOLDS]))

    def test_defect_unknown_is_not_killed(self):
        self.assertFalse(selftest_ok("defect", [runner.UNKNOWN]))
        self.assertFalse(selftest_ok("defect", [runner.HOLDS, runner.UNKNOWN]))
        self.assertTrue(selftest_ok("defect", [runner.HOLDS, runner.VIOLATED]))

    def test_vacuous_and_error_inconclusive(self):
        self.assertFalse(selftest_ok("fix", [runner.VACUOUS]))
        self.assertFalse(selftest_ok("defect", [runner.ERROR, runner.VIOLATED]))


class TestEmptyReview(unittest.TestCase):
    def test_review_zero_match_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            drift = os.path.join(td, "drift.json")
            with open(drift, "w", encoding="utf-8") as f:
                json.dump({"affected_properties": ["NoSuchModule/NoSuchPid"]}, f)
            # 匹配不到任何已注册 pid：必须在精化之前以非 0 退出。
            rc = main(["check", "CSRPermitModule", "--review", drift])
            self.assertEqual(rc, 1)

    def test_review_empty_list_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            drift = os.path.join(td, "empty.json")
            with open(drift, "w", encoding="utf-8") as f:
                json.dump({"affected_properties": []}, f)
            rc = main(["check", "all", "--review", drift])
            self.assertEqual(rc, 1)


class TestEmptyOnly(unittest.TestCase):
    def test_only_typo_exits_nonzero(self):
        # 拼错 / 匹配 0 条必须在精化之前以非 0 退出，不能当成功。
        rc = main(["check", "CSRPermitModule", "--only", "NoSuchPidTyPoXYZ"])
        self.assertEqual(rc, 1)

    def test_selftest_only_typo_exits_nonzero(self):
        rc = main(["self-test", "--only", "no_such_mutant_xyz"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
