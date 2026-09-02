#!/usr/bin/env python3
"""行内锚点正文含 # 不得静默截断。不读香山树。"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from csrformal.specdb import extract_rules_from_text


class TestInlineHash(unittest.TestCase):
    def test_hash_in_body_is_kept(self):
        # 旧实现 src.find("#") 会得到 "Access CSR "，后半段漂移会漏报。
        src = "[#norm:hash_in_body]#Access CSR #0x14D when STCE=0.#\n"
        rules = extract_rules_from_text(src, "t.adoc")
        self.assertIn("norm:hash_in_body", rules)
        self.assertEqual(rules["norm:hash_in_body"].text,
                         "Access CSR #0x14D when STCE=0.")

    def test_normal_inline_still_works(self):
        src = "[#norm:plain]#When STCE is 0, access is illegal.# next sentence\n"
        rules = extract_rules_from_text(src, "t.adoc")
        self.assertEqual(rules["norm:plain"].text,
                         "When STCE is 0, access is illegal.")

    def test_escaped_hash(self):
        src = "[#norm:esc]#foo \\# bar#\n"
        rules = extract_rules_from_text(src, "t.adoc")
        self.assertEqual(rules["norm:esc"].text, "foo \\# bar")

    def test_unclosed_interior_hash_fails(self):
        src = "[#norm:bad]#Access CSR #0x14D with no closer\n"
        with self.assertRaises(ValueError) as ctx:
            extract_rules_from_text(src, "t.adoc")
        self.assertIn("拒绝截断", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
