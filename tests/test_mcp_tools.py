"""MCP サーバーのテスト：接続先の固定・引数検証・マスキング・上限・監査・読み取り専用の宣言。

tools.py（標準ライブラリのみ）は常に検証する。server.py（MCP SDK が必要）は mcp が入っている環境でだけ検証する。
"""
import asyncio
import datetime as dt
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import _base  # noqa: F401  （.env 無効化・外部送信禁止の準備）
from monitoring import cloudwatch
from mcp_server import tools

ENV = {"MCP_AWS_PROFILE": "mcp-readonly", "MCP_INSTANCE_ID": "i-08ba45b5cffc2313e", "MCP_REGION": "ap-northeast-1"}
ST = tools.Settings("mcp-readonly", "i-08ba45b5cffc2313e", "ap-northeast-1")
NOW = dt.datetime(2026, 11, 20, 3, 0, tzinfo=dt.timezone.utc)


class Base(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        p = mock.patch.object(tools, "AUDIT_FILE", os.path.join(d, "mcp_audit.log"))
        p.start()
        self.addCleanup(p.stop)

    def audit(self):
        with open(tools.AUDIT_FILE, encoding="utf-8") as f:
            return [json.loads(l) for l in f]


class TestSettings(unittest.TestCase):
    def test_ok(self):
        st = tools.load_settings(dict(ENV))
        self.assertEqual((st.profile, st.instance_id, st.region), ("mcp-readonly", "i-08ba45b5cffc2313e", "ap-northeast-1"))

    def test_rejected(self):
        bad = [{"MCP_AWS_PROFILE": ""}, {"MCP_AWS_PROFILE": "x y"}, {"MCP_AWS_PROFILE": "default"},
               {"MCP_INSTANCE_ID": "i-xyz"}, {"MCP_INSTANCE_ID": "i-08ba45b5cffc2313e; id"},
               {"MCP_REGION": "ap-northeast-1 --debug"}, {"MCP_REGION": ""}]
        for patch in bad:
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                tools.load_settings({**ENV, **patch})

    def test_default_profile_needs_explicit_opt_in(self):
        st = tools.load_settings({**ENV, "MCP_AWS_PROFILE": "default", "MCP_ALLOW_DEFAULT_PROFILE": "1"})
        self.assertEqual(st.profile, "default")

    def test_scrub_credentials_env(self):
        env = {"AWS_ACCESS_KEY_ID": "AKIA...", "AWS_SECRET_ACCESS_KEY": "s", "AWS_PROFILE": "admin", "PATH": "/bin"}
        removed = tools.scrub_credentials_env(env)
        self.assertEqual(env, {"PATH": "/bin"})
        self.assertEqual(set(removed), {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"})


class TestArgs(unittest.TestCase):
    def test_end(self):
        self.assertEqual(tools._end(None, NOW), NOW)
        self.assertEqual(tools._end("2026-11-08T06:00Z", NOW), dt.datetime(2026, 11, 8, 6, tzinfo=dt.timezone.utc))
        self.assertEqual(tools._end("2026-11-08T06:00", NOW), dt.datetime(2026, 11, 8, 6, tzinfo=dt.timezone.utc))
        self.assertEqual(tools._end("2026-11-08T15:00+09:00", NOW), dt.datetime(2026, 11, 8, 6, tzinfo=dt.timezone.utc))
        for bad in ("2026-11-21T00:00Z", "2026-09-01T00:00Z", "yesterday", "2026-11-08T06:00Z; id", 123, "x" * 40):
            with self.subTest(bad=bad), self.assertRaises(tools.ToolInputError):
                tools._end(bad, NOW)

    def test_int(self):
        for bad in (0, 73, -1, "6", 6.0, True, None):
            with self.subTest(bad=bad), self.assertRaises(tools.ToolInputError):
                tools._int(bad, 1, 72, "hours")

    def test_series_period_caps_points(self):
        for hours in (1, 6, 24, 48, 168):
            with self.subTest(hours=hours):
                p = tools._series_period(hours)
                self.assertEqual(p % 300, 0)
                self.assertLessEqual(hours * 3600 / p, tools.MAX_SERIES_POINTS)
        self.assertEqual(tools._series_period(6), 300)


class TestCall(Base):
    def test_unknown_metric_and_tool(self):
        ok, out = tools.call(ST, "ec2_metric_series", metric="rm -rf /", hours=6)
        self.assertFalse(ok)
        self.assertIn("引数エラー", out["error"])
        ok, out = tools.call(ST, "run_shell", cmd="id")
        self.assertFalse(ok)
        self.assertIn("未知のツール", out["error"])

    def test_target_cannot_be_overridden(self):
        """接続先（インスタンス ID・プロファイル）はツール引数で変えられない。"""
        with mock.patch.object(cloudwatch, "fetch_alarms", return_value=[]) as f:
            ok, out = tools.call(ST, "cloudwatch_alarms", instance_id="i-0000000000000000")
        self.assertFalse(ok)
        f.assert_not_called()

    def test_profile_and_window_are_passed(self):
        with mock.patch.object(cloudwatch, "_aws", return_value={"MetricDataResults": []}) as aws:
            ok, out = tools.call(ST, "ec2_metrics_summary", hours=6, end="2026-11-08T06:00Z")
        self.assertTrue(ok, out)
        args, kw = aws.call_args
        self.assertEqual(kw["profile"], "mcp-readonly")
        self.assertIn("2026-11-08T00:00:00+00:00", args[0])
        self.assertEqual(out["window"], {"start": "2026-11-08T00:00Z", "end": "2026-11-08T06:00Z", "hours": 6})

    def test_aws_cli_gets_profile_flag(self):
        r = mock.Mock(returncode=0, stdout="{}", stderr="")
        with mock.patch.object(cloudwatch.subprocess, "run", return_value=r) as run:
            cloudwatch._aws(["cloudwatch", "describe-alarms"], "ap-northeast-1", profile="mcp-readonly")
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[-2:], ["--profile", "mcp-readonly"])

    def test_output_is_masked(self):
        alarms = [{"name": "a", "state": "ALARM", "reason": "from 10.20.30.40 token=abc123"}]
        with mock.patch.object(cloudwatch, "fetch_alarms", return_value=alarms):
            ok, out = tools.call(ST, "cloudwatch_alarms")
        text = json.dumps(out)
        self.assertNotIn("30.40", text)
        self.assertNotIn("abc123", text)

    def test_aws_error_is_returned_not_raised(self):
        with mock.patch.object(cloudwatch, "_aws", side_effect=RuntimeError("IAM 権限不足：cloudwatch:GetMetricData")):
            ok, out = tools.call(ST, "ec2_metrics_summary")
        self.assertFalse(ok)
        self.assertIn("IAM 権限不足", out["error"])

    def test_output_size_cap(self):
        with mock.patch.object(cloudwatch, "fetch_alarms", return_value=[{"reason": "x" * 5000}] * 10), \
                mock.patch.object(tools, "MAX_BYTES", 10000):
            ok, out = tools.call(ST, "cloudwatch_alarms")
        self.assertFalse(ok)
        self.assertNotIn("alarms", out)

    def test_audit_records_every_call(self):
        with mock.patch.object(cloudwatch, "fetch_alarms", return_value=[]):
            tools.call(ST, "cloudwatch_alarms")
        tools.call(ST, "ec2_metric_series", metric="nope")
        recs = self.audit()
        self.assertEqual([(r["tool"], r["ok"]) for r in recs], [("cloudwatch_alarms", True), ("ec2_metric_series", False)])
        self.assertEqual(recs[0]["profile"], "mcp-readonly")


try:
    from mcp_server import server
except ImportError:   # MCP SDK のない環境（EC2 の Python 3.9 等）
    server = None


@unittest.skipIf(server is None, "mcp パッケージがない（mcp_server/requirements.txt）")
class TestServer(Base):
    def _run(self, coro_fn):
        from mcp.client.client import Client

        async def go():
            async with Client(server.build(ST)) as c:
                return await coro_fn(c)
        return asyncio.run(go())

    def test_all_tools_are_read_only(self):
        res = self._run(lambda c: c.list_tools())
        self.assertEqual({t.name for t in res.tools}, set(tools.TOOLS))
        for t in res.tools:
            with self.subTest(tool=t.name):
                self.assertTrue(t.annotations.read_only_hint)
                self.assertFalse(t.annotations.destructive_hint)
                self.assertNotIn("instance_id", t.input_schema.get("properties", {}))
                self.assertNotIn("profile", t.input_schema.get("properties", {}))

    def test_call_and_error(self):
        with mock.patch.object(cloudwatch, "fetch_alarms", return_value=[{"reason": "1.2.3.4"}]):
            r = self._run(lambda c: c.call_tool("cloudwatch_alarms", {}))
        self.assertFalse(r.is_error)
        self.assertIn("1.2.x.x", r.content[0].text)
        r = self._run(lambda c: c.call_tool("ec2_metric_series", {"metric": "nope"}))
        self.assertTrue(r.is_error)
        self.assertIn("引数エラー", r.content[0].text)


if __name__ == "__main__":
    unittest.main()
