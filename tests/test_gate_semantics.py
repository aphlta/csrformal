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
from csrformal.cli import check_failed, main, selftest_ok


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


if __name__ == "__main__":
    unittest.main()
