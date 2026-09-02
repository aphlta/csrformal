#!/usr/bin/env python3
"""CSRFORMAL_YOSYS 必须在 import 之后仍能覆盖；旧名 YOSYS 无效。"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from csrformal import config, smt


class TestYosysEnv(unittest.TestCase):
    def setUp(self):
        self._old = os.environ.get("CSRFORMAL_YOSYS")

    def tearDown(self):
        if self._old is None:
            os.environ.pop("CSRFORMAL_YOSYS", None)
        else:
            os.environ["CSRFORMAL_YOSYS"] = self._old

    def test_csrformal_yosys_overrides_config(self):
        os.environ["CSRFORMAL_YOSYS"] = "/tmp/stub-yosys-for-test"
        self.assertEqual(smt.yosys_bin(), "/tmp/stub-yosys-for-test")
        # config.YOSYS 是 import 时定型的；覆盖不得依赖改这个全局量。
        self.assertNotEqual(config.YOSYS, "/tmp/stub-yosys-for-test")

    def test_old_yosys_env_is_ignored(self):
        os.environ.pop("CSRFORMAL_YOSYS", None)
        os.environ["YOSYS"] = "/tmp/old-name-must-not-win"
        try:
            self.assertNotEqual(smt.yosys_bin(), "/tmp/old-name-must-not-win")
        finally:
            os.environ.pop("YOSYS", None)


if __name__ == "__main__":
    unittest.main()
