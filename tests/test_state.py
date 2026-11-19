"""前回巡検との比較（再起動の増分・swap 換ページ速度・ディスク増加予測）のテスト。"""
import unittest
from unittest import mock

from _base import container
from monitoring import state, system

DAY = 86400.0


class TestRestartDelta(unittest.TestCase):
    def prev(self, restarts, started_at):
        return {"containers": {"c": {"restarts": restarts, "started_at": started_at}}}

    def test_delta(self):
        cs = [container("c", restarts=55, started_at="T2")]
        state.apply_restart_delta(cs, self.prev(52, "T1"))
        self.assertEqual(cs[0]["restarts_delta"], 3)
        self.assertTrue(cs[0]["restarted_since_last"])

    def test_unchanged(self):
        cs = [container("c", restarts=52, started_at="T1")]
        state.apply_restart_delta(cs, self.prev(52, "T1"))
        self.assertEqual(cs[0]["restarts_delta"], 0)
        self.assertFalse(cs[0]["restarted_since_last"])

    def test_manual_restart_keeps_count(self):
        # docker restart / cron による restart は RestartCount を増やさない → 起動時刻の変化で検出
        cs = [container("c", restarts=52, started_at="T2")]
        state.apply_restart_delta(cs, self.prev(52, "T1"))
        self.assertEqual(cs[0]["restarts_delta"], 0)
        self.assertTrue(cs[0]["restarted_since_last"])

    def test_recreated_container_counter_reset(self):
        cs = [container("c", restarts=0, started_at="T2")]
        state.apply_restart_delta(cs, self.prev(52, "T1"))
        self.assertIsNone(cs[0]["restarts_delta"])

    def test_no_history(self):
        cs = [container("new", restarts=5)]
        state.apply_restart_delta(cs, {})
        self.assertIsNone(cs[0]["restarts_delta"])
        self.assertFalse(cs[0]["restarted_since_last"])


class TestSwapRate(unittest.TestCase):
    def test_rate(self):
        with mock.patch.object(system, "PAGE_KB", 4):
            r = system._swap_rate({"pswpin": 0, "pswpout": 0}, {"pswpin": 250, "pswpout": 500}, 10)
        self.assertEqual(r, {"in_kbps": 100.0, "out_kbps": 200.0})

    def test_counter_reset_after_reboot(self):
        self.assertIsNone(system._swap_rate({"pswpin": 1000, "pswpout": 0}, {"pswpin": 10, "pswpout": 0}, 10))

    def test_missing_data(self):
        self.assertIsNone(system._swap_rate({}, {"pswpin": 1}, 10))
        self.assertIsNone(system._swap_rate({"pswpin": 1}, {"pswpin": 2}, 0))


class TestDiskTrend(unittest.TestCase):
    # 容量 1000 GiB、空き 200 GiB（Use% 80%）、1 日 2 GiB ずつ減る
    DISK = {"used_gib": 800.0, "avail_gib": 200.0}

    def hist(self, days, per_day=2.0, start=1_700_000_000.0):
        return [[start + i * DAY, 200.0 + (days - 1 - i) * per_day] for i in range(days)]

    def test_growth_and_eta(self):
        t = system.disk_trend(self.hist(10), self.DISK)
        self.assertAlmostEqual(t["gib_per_day"], 2.0)
        # 85% 到達 = 空き 150 GiB → 残り 50 GiB / 2 GiB/日 = 25 日
        self.assertEqual(t["days_to_warn"], 25)
        # 95% 到達 = 空き 50 GiB → 150 / 2 = 75 日
        self.assertEqual(t["days_to_crit"], 75)
        self.assertRegex(t["eta_warn"], r"^\d{4}-\d{2}-\d{2}$")

    def test_short_span_is_not_forecast(self):
        start = 1_700_000_000.0
        hist = [[start, 210.0], [start + 6 * 3600, 200.0]]   # 6 時間ではノイズが大きい
        self.assertIsNone(system.disk_trend(hist, self.DISK))

    def test_shrinking_usage_has_no_eta(self):
        t = system.disk_trend(self.hist(10, per_day=-2.0), self.DISK)
        self.assertLess(t["gib_per_day"], 0)
        self.assertNotIn("days_to_warn", t)

    def test_history_window(self):
        now = 1_700_000_000.0 + 30 * DAY
        prev = {"disk_avail_history": [[now - 20 * DAY, 300.0], [now - 5 * DAY, 210.0]]}
        hist = system.update_disk_history(prev, {"avail_gib": 200.0}, now)
        self.assertEqual(hist, [[now - 5 * DAY, 210.0], [now, 200.0]])   # 14 日より古いサンプルは捨てる


if __name__ == "__main__":
    unittest.main()
