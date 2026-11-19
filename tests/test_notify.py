"""Slack 通知（状態変化時のみ）のテスト。実際の送信は行わない。"""
import io
import contextlib
import unittest
from unittest import mock

from _base import h

WARN_DISK = "[WARN] ディスクが +1.3GiB/日 で増加中、約 23 日後（2026-12-10 頃）に 85.0% 到達見込み"
WARN_DISK_NEXT_DAY = "[WARN] ディスクが +1.4GiB/日 で増加中、約 22 日後（2026-12-09 頃）に 85.0% 到達見込み"
CRIT_WEB = "[CRIT] Web Sentry の疎通失敗：HTTP 502"
INFO_RESTART = "[INFO] コンテナ x が前回巡検以降に再起動された"


def state(alerts):
    """前回「通知に成功した」状態。"""
    cur = {h._alert_key(a): a for a in alerts if a.startswith(("[WARN]", "[CRIT]"))}
    return {"v": h.NOTIFY_STATE_VERSION, "status": h._overall(alerts), "keys": cur}


class TestNotify(unittest.TestCase):
    def setUp(self):
        self.sent = []
        p1 = mock.patch.object(h, "_send_slack", side_effect=lambda *a: self.sent.append(a))
        p2 = mock.patch.object(h, "SLACK_WEBHOOK_URL", "https://example.invalid/webhook")
        p1.start(), p2.start()
        self.addCleanup(mock.patch.stopall)

    def run_notify(self, alerts, prev, ai_text=""):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return h.notify_on_change(alerts, prev, ai_text, "2026-11-19 00:00:00 UTC")

    def test_no_change_no_message(self):
        new = self.run_notify([WARN_DISK], state([WARN_DISK]))
        self.assertEqual(self.sent, [])
        self.assertEqual(new["status"], "注意")

    def test_first_run_all_normal_is_silent(self):
        self.run_notify([], {})
        self.run_notify([INFO_RESTART], {})
        self.assertEqual(self.sent, [])

    def test_new_warning(self):
        new = self.run_notify([WARN_DISK], state([]), ai_text="1) 総合ステータス: 注意")
        self.assertEqual(len(self.sent), 1)
        title, text = self.sent[0][0], self.sent[0][1]
        self.assertIn("正常 → 注意", title)
        self.assertIn("*新規*", text)
        self.assertIn("AI 診断", text)
        self.assertEqual(new["status"], "注意")

    def test_only_numbers_changed_is_not_a_change(self):
        # 毎日 ETA が 1 日ずつ近づいても、同じ問題なので再通知しない
        self.run_notify([WARN_DISK_NEXT_DAY], state([WARN_DISK]))
        self.assertEqual(self.sent, [])

    def test_resolved(self):
        self.run_notify([], state([WARN_DISK]))
        self.assertEqual(len(self.sent), 1)
        self.assertIn("注意 → 正常", self.sent[0][0])
        self.assertIn("*解消*", self.sent[0][1])

    def test_content_change_with_same_status(self):
        self.run_notify([CRIT_WEB, WARN_DISK], state([CRIT_WEB]))
        self.assertEqual(len(self.sent), 1)
        self.assertIn("内容に変化あり", self.sent[0][0])

    def test_info_changes_are_not_notified(self):
        self.run_notify([WARN_DISK, INFO_RESTART], state([WARN_DISK]))
        self.assertEqual(self.sent, [])

    def test_send_failure_keeps_previous_state(self):
        # 送信失敗 → 通知済みにしない（次回の実行で再送される）
        prev = state([])
        with mock.patch.object(h, "_send_slack", side_effect=RuntimeError("HTTP 500")):
            new = self.run_notify([WARN_DISK], prev)
        self.assertIs(new, prev)

    def test_no_webhook_keeps_previous_state(self):
        prev = state([])
        with mock.patch.object(h, "SLACK_WEBHOOK_URL", ""):
            new = self.run_notify([WARN_DISK], prev)
        self.assertIs(new, prev)
        self.assertEqual(self.sent, [])

    def test_old_state_version_compares_status_only(self):
        # 文言変更前の state：個別アラートは比較できないため、総合ステータスが同じなら通知しない
        old = {"v": h.NOTIFY_STATE_VERSION - 1, "status": "注意", "keys": {"旧文言": "[WARN] 旧文言"}}
        new = self.run_notify([WARN_DISK], old)
        self.assertEqual(self.sent, [])
        self.assertEqual(new["v"], h.NOTIFY_STATE_VERSION)


class TestAlertKey(unittest.TestCase):
    def test_digits_are_normalized(self):
        self.assertEqual(h._alert_key(WARN_DISK), h._alert_key(WARN_DISK_NEXT_DAY))

    def test_different_problems_differ(self):
        self.assertNotEqual(h._alert_key(WARN_DISK), h._alert_key(CRIT_WEB))


if __name__ == "__main__":
    unittest.main()
