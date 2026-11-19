"""収集処理のうち外部コマンドに依存しない部分のテスト（docker / clickhouse はモック）。
nginx パスのマスキングは「AI に送るデータに認証情報を残さない」ための安全要件。"""
import datetime as dt
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import subprocess
import _base  # noqa: F401  （.env 無効化・外部送信禁止の準備）
from monitoring import config as cfg, docker, nginx_log, sentry, util


def access_line(path="/api/12/envelope/?sentry_key=abc123", code=200, method="POST"):
    return f'1.2.3.4 - - [19/Nov/2026:03:00:00 +0000] "{method} {path} HTTP/1.1" {code} 0 "-" "sentry.cocoa/8" "-"\n'


class TestPathMasking(unittest.TestCase):
    def test_query_is_removed(self):
        p = nginx_log._norm_path("/api/12/envelope/?sentry_key=0123456789abcdef&sentry_version=7")
        self.assertNotIn("sentry_key", p)
        self.assertNotIn("0123456789abcdef", p)

    def test_ids_are_normalized(self):
        self.assertEqual(nginx_log._norm_path("/api/12/envelope/"), "/api/{n}/envelope/")
        self.assertEqual(nginx_log._norm_path("/organizations/x/issues/123456/"), "/organizations/x/issues/{n}/")
        self.assertEqual(nginx_log._norm_path("/api/0/events/0123456789abcdef0123456789abcdef/"), "/api/{n}/events/{id}/")

    def test_length_is_capped(self):
        self.assertLessEqual(len(nginx_log._norm_path("/" + "a" * 500)), 80)


class TestCounter(unittest.TestCase):
    def test_counts(self):
        c = nginx_log._Counter()
        for line in [access_line(code=200), access_line(code=502), access_line(code=502),
                     access_line("/batch", code=503), "nginx: [warn] not an access log\n"]:
            c.feed(line)
        r = c.result()
        self.assertEqual((r["requests"], r["5xx"], r["5xx_pct"]), (4, 3, 75.0))
        self.assertEqual(r["by_code"], {"502": 2, "503": 1})
        self.assertEqual(r["top_paths"][0], ("POST /api/{n}/envelope/", 2))
        self.assertNotIn("sentry_key", json.dumps(r))


class TestReverseLines(unittest.TestCase):
    def test_reverse_across_blocks(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = os.path.join(d, "x.log")
        lines = [f"line-{i:03d}" for i in range(100)]
        with open(p, "w") as f:
            f.write("\n".join(lines) + "\n")
        got = [b.decode() for b in nginx_log._reverse_lines(p, block=7) if b]   # ブロック境界をまたぐよう小さくする
        self.assertEqual(got, list(reversed(lines)))


class TestNginxLogFileFallback(unittest.TestCase):
    """docker logs が NUL 混入で失敗したときの代替経路（json-file を直接読む）。"""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = os.path.join(self.dir, "c-json.log")

    def write_log(self, entries, nul_prefix=0):
        with open(self.path, "wb") as f:
            f.write(b"\x00" * nul_prefix)   # 外部から truncate された後の先頭の穴
            for ago_min, code in entries:
                t = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=ago_min)).strftime("%Y-%m-%dT%H:%M:%S.%f000Z")
                f.write((json.dumps({"log": access_line(code=code), "stream": "stdout", "time": t}) + "\n").encode())

    def inspect_ok(self):
        r = mock.Mock(returncode=0, stdout=self.path + "\n")
        return mock.patch.object(subprocess, "run", return_value=r)

    def test_counts_only_window_and_skips_nul(self):
        # 3 時間前・1 時間前・10 分前。窓は 2 時間 → 2 件。先頭の NUL は 1 行ぶんの壊れた行になる
        self.write_log([(180, 502), (60, 502), (10, 200)], nul_prefix=4096)
        cnt, rec = nginx_log._Counter(), {}
        with self.inspect_ok():
            nginx_log._nginx_via_file("nginx", 2 * 3600, cnt, rec)
        r = cnt.result()
        self.assertEqual((r["requests"], r["5xx"]), (2, 1))
        self.assertEqual(rec["source"], "logfile")
        self.assertNotIn("partial_window", rec)   # 窓より古い行まで届いた

    def test_nul_prefixed_line_is_recovered(self):
        # 切り詰め後の最初の 1 行は「NUL の穴 + JSON」が同じ行になる。NUL を除けば読めるので数える
        self.write_log([(10, 200)], nul_prefix=1024)
        cnt, rec = nginx_log._Counter(), {}
        with self.inspect_ok():
            nginx_log._nginx_via_file("nginx", 24 * 3600, cnt, rec)
        self.assertEqual(cnt.total, 1)
        self.assertEqual(rec["corrupt_lines"], 0)
        self.assertTrue(rec["partial_window"])    # ファイルの先頭まで窓内（切り詰め・ローテーション直後）

    def test_broken_line_is_skipped_and_counted(self):
        self.write_log([(30, 502)])
        with open(self.path, "ab") as f:
            f.write(b'{"log":"half written\n')    # 書き込み途中で壊れた行
        self.write_log_append([(5, 200)])
        cnt, rec = nginx_log._Counter(), {}
        with self.inspect_ok():
            nginx_log._nginx_via_file("nginx", 3600, cnt, rec)
        self.assertEqual((cnt.total, cnt.n5, rec["corrupt_lines"]), (2, 1, 1))

    def write_log_append(self, entries):
        with open(self.path, "ab") as f:
            for ago_min, code in entries:
                t = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=ago_min)).strftime("%Y-%m-%dT%H:%M:%S.%f000Z")
                f.write((json.dumps({"log": access_line(code=code), "stream": "stdout", "time": t}) + "\n").encode())

    def test_missing_file(self):
        cnt, rec = nginx_log._Counter(), {}
        r = mock.Mock(returncode=0, stdout="/nonexistent/x-json.log\n")
        with mock.patch.object(subprocess, "run", return_value=r):
            with self.assertRaises(RuntimeError):
                nginx_log._nginx_via_file("nginx", 3600, cnt, rec)

    def test_collect_nginx_falls_back(self):
        def docker_fails(name, window_s, cnt, rec):
            return False, "docker logs exit 1: invalid character '\\x00'"

        def from_file(name, window_s, cnt, rec):
            cnt.feed(access_line(code=200))
            rec["source"] = "logfile"

        with mock.patch.object(cfg, "NGINX_CONTAINERS", ["nginx"]), \
                mock.patch.object(nginx_log, "_nginx_via_docker", side_effect=docker_fails), \
                mock.patch.object(nginx_log, "_nginx_via_file", side_effect=from_file):
            [rec] = nginx_log.collect_nginx(3600)
        self.assertIn("x00", rec["docker_logs_error"])
        self.assertEqual((rec["requests"], rec["source"]), (1, "logfile"))
        self.assertNotIn("error", rec)


class TestSentryIngest(unittest.TestCase):
    def run_ingest(self, counts_by_days_ago, returncode=0):
        today = dt.datetime.now(dt.timezone.utc).date()
        out = "\n".join(f"{(today - dt.timedelta(days=d)).isoformat()}\t{n}" for d, n in counts_by_days_ago.items())
        r = mock.Mock(returncode=returncode, stdout=out, stderr="DB::Exception")
        with mock.patch.object(cfg, "SENTRY_CLICKHOUSE", "ch"), mock.patch.object(subprocess, "run", return_value=r):
            return sentry.collect_sentry_ingest()

    def test_median_and_ratio(self):
        # 8〜2 日前の中央値は 600。昨日 150 → 25%
        ig = self.run_ingest({8: 590, 7: 600, 6: 610, 5: 620, 4: 580, 3: 605, 2: 595, 1: 150, 0: 40})
        self.assertEqual((ig["yesterday"], ig["baseline_median_7d"], ig["ratio_pct"]), (150, 600, 25.0))
        self.assertEqual(len(ig["by_day"]), 9)

    def test_missing_days_count_as_zero(self):
        ig = self.run_ingest({8: 100, 2: 100})
        self.assertEqual(ig["yesterday"], 0)
        self.assertEqual(ig["baseline_median_7d"], 0)   # 7 日中 5 日が 0 件
        self.assertIsNone(ig["ratio_pct"])

    def test_error(self):
        ig = self.run_ingest({}, returncode=1)
        self.assertIn("clickhouse-client exit 1", ig["error"])

    def test_disabled(self):
        with mock.patch.object(cfg, "SENTRY_CLICKHOUSE", "0"):
            self.assertIsNone(sentry.collect_sentry_ingest())


class TestHelpers(unittest.TestCase):
    def test_parse_size(self):
        self.assertEqual(docker._parse_size("1.5GiB"), 1.5 * 1024 ** 3)
        self.assertEqual(docker._parse_size("512MiB"), 512 * 1024 ** 2)
        self.assertEqual(docker._parse_size("1kB"), 1000)

    def test_uptime_days(self):
        t = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")
        self.assertEqual(util._uptime_days(t), 3.0)   # docker のナノ秒表記
        self.assertIsNone(util._uptime_days("broken"))

    def test_short(self):
        self.assertEqual(util._short("a\n  b"), "a b")
        self.assertTrue(util._short("x" * 500).endswith("…"))

    def test_scheduled_restart_matching(self):
        base = {"status": "running", "restarts_delta": 0}
        self.assertTrue(docker._scheduled_restart(dict(base, name="sentry-self-hosted-snuba-api-1")))
        self.assertFalse(docker._scheduled_restart(dict(base, name="sentry-self-hosted-web-1")))
        self.assertFalse(docker._scheduled_restart(dict(base, name="sentry-self-hosted-snuba-api-1", restarts_delta=1)))


class TestDotenv(unittest.TestCase):
    def test_parsing(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = os.path.join(d, ".env")
        with open(p, "w", encoding="utf-8") as f:
            f.write("# comment\nPH_T_A=1   # 行末コメント\nPH_T_B=\"quoted\"\nPH_T_EMPTY=\nPH_T_KEEP=from_file\nbroken line\n")
        keys = ("PH_T_A", "PH_T_B", "PH_T_EMPTY", "PH_T_KEEP")
        with mock.patch.dict(os.environ, {"PH_T_KEEP": "from_env"}):
            cfg._load_dotenv(p)
            got = {k: os.environ.get(k) for k in keys}
            for k in keys[:3]:
                os.environ.pop(k, None)
        self.assertEqual(got, {"PH_T_A": "1", "PH_T_B": "quoted", "PH_T_EMPTY": None,   # 空 = 未設定（既定値を使う）
                               "PH_T_KEEP": "from_env"})                                # 既存の環境変数が優先


if __name__ == "__main__":
    unittest.main()
