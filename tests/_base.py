"""テスト共通の準備。

- 実際の .env（API キー・Slack Webhook・閾値の上書き）を読まない：PH_SKIP_DOTENV=1 を import 前に設定する。
  閾値はコードの既定値（= SPEC.md の表）でテストする。
- 外部への通信を禁止する：_post（AI / Slack の HTTP 送信）を呼ぶとテスト失敗にする。
- EC2 の Python 3.9 でも動くよう、3.10 以降の構文は使わない。
"""
import os
import sys

os.environ["PH_SKIP_DOTENV"] = "1"
for _k in list(os.environ):
    # 開発者のシェルに残った設定が閾値を変えないようにする
    if _k in ("SWAP_WARN_GB", "SWAP_CRIT_GB", "DISK_WARN", "DISK_CRIT", "SCHEDULED_RESTARTS",
              "IGNORE_CONTAINERS", "SLACK_WEBHOOK_URL", "SENTRY_CLICKHOUSE", "OUT_DIR"):
        del os.environ[_k]

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monitoring import httpclient, rules  # noqa: E402


def _no_network(*args, **kwargs):
    raise AssertionError("テスト中に外部 HTTP 送信が呼ばれた（httpclient._post はモックすること）")


httpclient._post = _no_network   # AI・Slack はすべて httpclient._post を経由する


def container(name="sentry-self-hosted-web-1", **kw):
    """compute_alerts が期待する形の正常なコンテナ。"""
    c = {"name": name, "status": "running", "health": "healthy", "exit_code": 0, "oom_killed": False,
         "restarts": 0, "restarts_delta": 0, "restarted_since_last": False, "uptime_days": 30.0,
         "started_at": "2026-10-01T00:00:00Z", "ignored": False, "watched": True}
    c.update(kw)
    return c


def alerts_for(**kw):
    """compute_alerts をキーワード引数で呼ぶ（未指定は空）。"""
    return rules.compute_alerts(kw.get("host", {}), kw.get("containers", []), kw.get("web", []),
                            kw.get("cw"), kw.get("nginx"), kw.get("ingest"))


def levels(alerts):
    return [a.split("]", 1)[0] + "]" for a in alerts]
