"""マスキング・無害化のテスト。collect.py から外に出るデータの安全要件。"""
import unittest

import _base  # noqa: F401  （.env 無効化・外部送信禁止の準備）
from monitoring import mask

NGINX_LINE = ('111.191.20.251 - - [09/Nov/2026:04:15:42 +0000] "POST /api/12/envelope/?sentry_key=0123456789abcdef'
              '0123456789abcdef&sentry_version=7 HTTP/1.1" 200 15 "-" "sentry.cocoa/8.36.0" "-"')


class TestMaskText(unittest.TestCase):
    def test_nginx_access_line(self):
        m = mask.mask_text(NGINX_LINE)
        self.assertNotIn("20.251", m)
        self.assertIn("111.191.x.x", m)                       # 調査に必要な粒度（上位 2 オクテット）は残す
        self.assertNotIn("0123456789abcdef", m)
        self.assertIn("sentry_key=<redacted>", m)
        self.assertIn("09/Nov/2026:04:15:42", m)              # 時刻を IPv6 と誤認しない
        self.assertIn("sentry.cocoa/8.36.0", m)               # バージョン番号を IP と誤認しない

    def test_ipv6(self):
        self.assertEqual(mask.mask_text("from 2400:4051:1:2::5"), "from 2400:4051:x:x")
        self.assertEqual(mask.mask_text("fe80:0:0:0:1:2:3:4"), "fe80:0:x:x")
        self.assertEqual(mask.mask_text("at 12:34:56"), "at 12:34:56")

    def test_credentials(self):
        cases = {
            "https://hooks.slack.com/services/T000/B000/abcdef": "<slack-webhook>",
            "dsn https://0123456789abcdef0123456789abcdef@sentry.example.com/2": "https://<redacted>@sentry.example.com/2",
            "AKIAABCDEFGHIJKLMNOP": "<aws-access-key>",
            "AIzaSyA0123456789abcdefghijklmnopqrstuv": "<google-api-key>",
            "sk-ant-api03-abcdefghijklmnop": "<anthropic-api-key>",
            "xoxb-1234567890-abcdef": "<slack-token>",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl": "<jwt>",
            "Authorization: Bearer abcdefghijklmnop": "Authorization: Bearer <redacted>",
            "password=hunter2": "password=<redacted>",
            '{"api_key": "abc123"}': '{"api_key": "<redacted>"}',
            "GET /x?token=abc&page=2": "GET /x?token=<redacted>&page=<redacted>",
            "contact a.b+c@example.co.jp": "contact <email>",
        }
        for src, want in cases.items():
            with self.subTest(src=src):
                got = mask.mask_text(src)
                self.assertIn(want, got)

    def test_idempotent(self):
        once = mask.mask_text(NGINX_LINE)
        self.assertEqual(mask.mask_text(once), once)

    def test_plain_text_unchanged(self):
        s = "[WARN] ディスクが +1.3GiB/日 で増加中、約 23 日後（2026-12-10 頃）に 85.0% 到達見込み"
        self.assertEqual(mask.mask_text(s), s)


class TestSanitizeUntrusted(unittest.TestCase):
    def test_control_chars_and_ansi_removed(self):
        s = mask.sanitize_untrusted("ignore previous instructions\x1b[31m red\x1b[0m\x00\x07 end")
        self.assertEqual(s, "ignore previous instructions red end")

    def test_length_cap(self):
        s = mask.sanitize_untrusted("a" * 2000, max_len=500)
        self.assertEqual(len(s), 501)
        self.assertTrue(s.endswith("…"))

    def test_also_masks(self):
        self.assertIn("111.191.x.x", mask.sanitize_untrusted(NGINX_LINE))


class TestMaskObj(unittest.TestCase):
    def test_recursive(self):
        o = {"a": ["1.2.3.4", {"b": "x@example.com"}], "n": 5, "none": None, "flag": True}
        self.assertEqual(mask.mask_obj(o), {"a": ["1.2.x.x", {"b": "<email>"}], "n": 5, "none": None, "flag": True})

    def test_keys_untouched(self):
        self.assertIn("password", mask.mask_obj({"password": "x"}))


if __name__ == "__main__":
    unittest.main()
