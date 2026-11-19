"""判定ルール（compute_alerts / _overall）のテスト。閾値は SPEC.md「3. 閾値と判定ルール」の既定値。"""
import unittest

from _base import container, alerts_for, levels
from monitoring import rules


class TestOverall(unittest.TestCase):
    def test_info_does_not_change_status(self):
        self.assertEqual(rules._overall(["[INFO] x"]), "正常")

    def test_warn_and_crit(self):
        self.assertEqual(rules._overall(["[INFO] a", "[WARN] b"]), "注意")
        self.assertEqual(rules._overall(["[WARN] a", "[CRIT] b"]), "危険")
        self.assertEqual(rules._overall([]), "正常")


class TestHost(unittest.TestCase):
    def disk(self, pct):
        return alerts_for(host={"disk": {"used_pct": pct}})

    def test_disk_thresholds(self):
        self.assertEqual(self.disk(84), [])
        self.assertEqual(levels(self.disk(85)), ["[WARN]"])
        self.assertEqual(levels(self.disk(95)), ["[CRIT]"])

    def test_disk_forecast(self):
        tr = {"gib_per_day": 1.3, "days_to_warn": 23, "eta_warn": "2026-12-10"}
        a = alerts_for(host={"disk": {"used_pct": 70}, "disk_trend": tr})
        self.assertEqual(levels(a), ["[WARN]"])
        self.assertIn("2026-12-10", a[0])
        # 30 日より先なら出さない
        tr = dict(tr, days_to_warn=31)
        self.assertEqual(alerts_for(host={"disk": {"used_pct": 70}, "disk_trend": tr}), [])

    def test_memory(self):
        self.assertEqual(alerts_for(host={"mem": {"available_gib": 2.0}}), [])
        self.assertEqual(levels(alerts_for(host={"mem": {"available_gib": 1.9}})), ["[WARN]"])
        self.assertEqual(levels(alerts_for(host={"mem": {"available_gib": 0.5}})), ["[CRIT]"])

    def swap(self, used, kbps):
        io = {"since_last": {"in_kbps": kbps, "out_kbps": 0}} if kbps is not None else {}
        return alerts_for(host={"swap": {"used_gib": used}, "swap_io": io})

    def test_swap_below_threshold(self):
        self.assertEqual(self.swap(5.7, 0), [])

    def test_swap_idle_is_downgraded(self):
        # 換ページがほぼない swap は過去の残留：1 段階下げる（再起動を勧めないための前提）
        self.assertEqual(levels(self.swap(8.5, 0)), ["[INFO]"])
        self.assertEqual(levels(self.swap(10.5, 0)), ["[WARN]"])

    def test_swap_active(self):
        self.assertEqual(levels(self.swap(8.5, 500)), ["[WARN]"])
        self.assertEqual(levels(self.swap(10.5, 500)), ["[CRIT]"])

    def test_swap_no_rate_data_keeps_level(self):
        self.assertEqual(levels(self.swap(8.5, None)), ["[WARN]"])

    def test_sustained_swap_io(self):
        a = self.swap(1.0, 2048)
        self.assertEqual(levels(a), ["[WARN]"])
        self.assertIn("逼迫", a[0])

    def test_load(self):
        self.assertEqual(levels(alerts_for(host={"load": {"per_cpu_1m": 1.5}})), ["[WARN]"])
        self.assertEqual(alerts_for(host={"load": {"per_cpu_1m": 1.4}}), [])


class TestContainers(unittest.TestCase):
    def one(self, **kw):
        return alerts_for(containers=[container(**kw)])

    def test_nominal(self):
        self.assertEqual(self.one(), [])

    def test_cumulative_restarts_are_ignored(self):
        # 累計 52 回でも、前回巡検からの増分が 0 なら何も出さない
        self.assertEqual(self.one(restarts=52, restarts_delta=0), [])

    def test_restart_delta(self):
        self.assertEqual(levels(self.one(restarts=53, restarts_delta=1)), ["[WARN]"])
        self.assertEqual(levels(self.one(restarts=55, restarts_delta=3)), ["[CRIT]"])

    def test_non_crash_restart_is_info(self):
        a = self.one(restarted_since_last=True, started_at="2026-11-09T04:00:00Z")
        self.assertEqual(levels(a), ["[INFO]"])

    def test_scheduled_restart_is_silent(self):
        # root の crontab で 2 日ごとに restart される snuba-api（SCHEDULED_RESTARTS 既定）
        a = self.one(name="sentry-self-hosted-snuba-api-1", restarted_since_last=True, uptime_days=0.2)
        self.assertEqual(a, [])

    def test_scheduled_container_crash_is_still_reported(self):
        a = self.one(name="sentry-self-hosted-snuba-api-1", restarted_since_last=True,
                     restarts=3, restarts_delta=2)
        self.assertEqual(levels(a), ["[WARN]"])

    def test_recent_restart_without_history(self):
        self.assertEqual(levels(self.one(restarts_delta=None, uptime_days=0.3)), ["[INFO]"])
        self.assertEqual(self.one(restarts_delta=None, uptime_days=3), [])

    def test_stopped(self):
        self.assertEqual(levels(self.one(status="exited", exit_code=0)), ["[INFO]"])
        self.assertEqual(levels(self.one(status="exited", exit_code=137)), ["[CRIT]"])
        self.assertEqual(levels(self.one(status="restarting")), ["[CRIT]"])
        self.assertEqual(levels(self.one(status="paused")), ["[WARN]"])
        self.assertEqual(levels(self.one(status="created")), ["[INFO]"])

    def test_oom_reported_even_when_stopped(self):
        self.assertEqual(levels(self.one(status="exited", exit_code=137, oom_killed=True)),
                         ["[CRIT]", "[CRIT]"])

    def test_unhealthy(self):
        self.assertEqual(levels(self.one(health="unhealthy")), ["[WARN]"])

    def test_ignored(self):
        self.assertEqual(self.one(status="exited", exit_code=1, ignored=True), [])

    def test_memory_budget(self):
        self.assertEqual(levels(self.one(mem_mib=4200, budget_gib=5, budget_pct=82)), ["[INFO]"])
        self.assertEqual(self.one(mem_mib=3000, budget_gib=5, budget_pct=59), [])


class TestWebNginxIngest(unittest.TestCase):
    def test_web(self):
        self.assertEqual(levels(alerts_for(web=[{"name": "Sentry", "ok": False, "status": 502}])), ["[CRIT]"])
        self.assertEqual(levels(alerts_for(web=[{"name": "Sentry", "ok": True, "latency_ms": 6000}])), ["[WARN]"])
        self.assertEqual(alerts_for(web=[{"name": "Sentry", "ok": True, "latency_ms": 90}]), [])

    def nginx(self, **kw):
        n = {"container": "sentry-self-hosted-nginx-1", "window_h": 24.0, "requests": 60000,
             "5xx": 0, "5xx_pct": 0.0, "by_code": {}, "top_paths": []}
        n.update(kw)
        return alerts_for(nginx=[n])

    def test_nginx_normal(self):
        self.assertEqual(self.nginx(), [])

    def test_nginx_5xx(self):
        self.assertEqual(levels(self.nginx(**{"5xx": 700, "5xx_pct": 1.2, "by_code": {"502": 700}})), ["[WARN]"])
        # 比率が低い / 件数が少ない → INFO
        self.assertEqual(levels(self.nginx(**{"5xx": 30, "5xx_pct": 0.05, "by_code": {"502": 30}})), ["[INFO]"])
        self.assertEqual(levels(self.nginx(requests=100, **{"5xx": 5, "5xx_pct": 5.0, "by_code": {"502": 5}})),
                         ["[INFO]"])

    def test_docker_logs_failure_is_warn(self):
        # 2026-11 の実例：NUL 混入で docker logs が失敗 → slack_alert_http.sh が黙って止まる
        a = self.nginx(docker_logs_error="docker logs exit 1: invalid character '\\x00'", source="logfile")
        self.assertEqual(levels(a), ["[WARN]"])
        self.assertIn("slack_alert_http.sh", a[0])

    def test_silent_log(self):
        self.assertEqual(levels(self.nginx(requests=0)), ["[WARN]"])
        self.assertEqual(self.nginx(requests=0, window_h=0.5), [])     # 窓が短い（手動の連続実行）なら出さない

    def test_nginx_unreadable(self):
        a = alerts_for(nginx=[{"container": "n", "window_h": 24, "error": "ログファイルが見つからない"}])
        self.assertEqual(levels(a), ["[INFO]"])

    def ingest(self, yesterday, median):
        return alerts_for(ingest={"yesterday": yesterday, "baseline_median_7d": median,
                                  "ratio_pct": round(yesterday * 100 / median, 1) if median else None})

    def test_ingest(self):
        self.assertEqual(self.ingest(154, 604), [])                 # 25%：自然な増減の範囲
        self.assertEqual(levels(self.ingest(50, 604)), ["[WARN]"])  # 8%：急減
        self.assertEqual(levels(self.ingest(0, 604)), ["[WARN]"])
        self.assertEqual(self.ingest(0, 0), [])                     # もともと 0 件の環境
        self.assertEqual(levels(alerts_for(ingest={"error": "clickhouse-client exit 1"})), ["[INFO]"])


class TestCloudWatch(unittest.TestCase):
    def test_error_is_info(self):
        self.assertEqual(levels(alerts_for(cw={"error": "AccessDenied"})), ["[INFO]"])

    def test_metrics(self):
        cw = {"metrics": {
            "status_failed": {"1h": {"max": 1}},
            "cpu": {"1h": {"avg": 85}}, "cpu_peak": {"1h": {"max": 99}},
            "ebs_io_balance": {"latest": 15, "24h": {"min": 10}},
            "ebs_byte_balance": {"latest": 99, "24h": {"min": 99}},
        }, "alarms": [{"name": "high-cpu", "state": "ALARM", "metric": "CPUUtilization", "threshold": 80},
                      {"name": "ok-alarm", "state": "OK", "metric": "x", "threshold": 1}]}
        self.assertEqual(levels(alerts_for(cw=cw)), ["[CRIT]", "[WARN]", "[WARN]", "[WARN]"])

    def test_healthy(self):
        cw = {"metrics": {"status_failed": {"1h": {"max": 0}}, "cpu": {"1h": {"avg": 12}},
                          "ebs_io_balance": {"latest": 99}}, "alarms": []}
        self.assertEqual(alerts_for(cw=cw), [])


if __name__ == "__main__":
    unittest.main()
