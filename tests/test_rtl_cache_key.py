#!/usr/bin/env python3
"""精化缓存键必须含 RTL 树身份。不精化、不调 firtool。"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from csrformal import config, elaborate


class TestRtlIdentity(unittest.TestCase):
    def setUp(self):
        self._tree = config.XS_TREE
        self._commit = config.XS_COMMIT
        self._out = config.OUT_DIR
        self._hsrc = config.HARNESS_SRC

    def tearDown(self):
        config.XS_TREE = self._tree
        config.XS_COMMIT = self._commit
        config.OUT_DIR = self._out
        config.HARNESS_SRC = self._hsrc

    def test_tree_and_commit_change_key(self):
        config.XS_TREE = "/tmp/xs-tree-a"
        config.XS_COMMIT = "aaaa1111"
        a = elaborate.rtl_identity("CSRPermitModule")
        config.XS_TREE = "/tmp/xs-tree-b"
        b = elaborate.rtl_identity("CSRPermitModule")
        self.assertNotEqual(a, b, "换 CSRFORMAL_XS_TREE 必须换缓存键")
        config.XS_TREE = "/tmp/xs-tree-a"
        config.XS_COMMIT = "bbbb2222"
        c = elaborate.rtl_identity("CSRPermitModule")
        self.assertNotEqual(a, c, "换 XS_COMMIT 必须换缓存键")

    def test_source_hash_change_key(self):
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "M.scala")
            with open(src, "w") as f:
                f.write("object A\n")
            k1 = elaborate.rtl_identity("M", source_files=[src])
            with open(src, "w") as f:
                f.write("object B  // 变异体源\n")
            k2 = elaborate.rtl_identity("M", source_files=[src])
            self.assertNotEqual(k1, k2)

    def test_cache_hit_does_not_reuse_other_commit(self):
        with tempfile.TemporaryDirectory() as td:
            config.OUT_DIR = td
            config.XS_TREE = ""
            config.XS_COMMIT = "oldc0mm1t"
            src = os.path.join(td, "M.scala")
            with open(src, "w") as f:
                f.write("object A\n")
            d = elaborate.cache_dir("base_M", "M", source_files=[src])
            os.makedirs(d, exist_ok=True)
            sv = os.path.join(d, "m.sv")
            with open(sv, "w") as f:
                f.write("// old sv\n")
            key = elaborate.rtl_identity("M", source_files=[src])
            with open(os.path.join(d, ".rtl_id"), "w") as f:
                f.write(key + "\n")
            self.assertEqual(
                elaborate.cache_hit("M", "base_M", source_files=[src]), sv)

            # 换 commit：旧目录对不上新键，不得命中。
            config.XS_COMMIT = "newc0mm1t"
            self.assertIsNone(
                elaborate.cache_hit("M", "base_M", source_files=[src]))
            new_d = elaborate.cache_dir("base_M", "M", source_files=[src])
            self.assertNotEqual(d, new_d)

    def test_harness_identity_includes_elab2(self):
        """改 Elab2.scala 必须换 rtl_identity("harness")，否则静默复用旧 class。"""
        with tempfile.TemporaryDirectory() as td:
            eq = os.path.join(td, "eqcheck")
            os.makedirs(eq)
            src = os.path.join(eq, "Elab2.scala")
            with open(src, "w") as f:
                f.write("object Elab2\n")
            config.HARNESS_SRC = td
            config.XS_TREE = ""
            config.XS_COMMIT = "samecommit"
            k1 = elaborate.rtl_identity("harness")
            with open(src, "w") as f:
                f.write("object Elab2 { /* 改了精化 top */ }\n")
            k2 = elaborate.rtl_identity("harness")
            self.assertNotEqual(k1, k2, "Elab2 内容变必须换 harness 缓存键")

    def test_force_misses_existing_cache(self):
        """force=True（--rebuild）不得命中旧 SV / 旧 harness 目录。"""
        with tempfile.TemporaryDirectory() as td:
            config.OUT_DIR = td
            config.XS_TREE = ""
            config.XS_COMMIT = "c0mm1t"
            src = os.path.join(td, "M.scala")
            with open(src, "w") as f:
                f.write("object A\n")
            d = elaborate.cache_dir("base_M", "M", source_files=[src])
            os.makedirs(d, exist_ok=True)
            sv = os.path.join(d, "m.sv")
            with open(sv, "w") as f:
                f.write("// cached sv\n")
            key = elaborate.rtl_identity("M", source_files=[src])
            with open(os.path.join(d, ".rtl_id"), "w") as f:
                f.write(key + "\n")
            self.assertEqual(
                elaborate.cache_hit("M", "base_M", source_files=[src]), sv)
            self.assertIsNone(
                elaborate.cache_hit("M", "base_M", source_files=[src], force=True),
                "force=True 必须跳过旧缓存")


if __name__ == "__main__":
    unittest.main()
