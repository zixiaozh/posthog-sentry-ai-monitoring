"""MCP ツールの実体（MCP SDK に依存しない部分。標準ライブラリのみ、単体テスト可能）。

server.py はここの関数を MCP のツールとして登録するだけ。安全上の処理はすべてこちらに置く：
  - 接続先（AWS プロファイル・インスタンス ID・リージョン）は起動時の環境変数で固定し、ツール引数では変えられない
  - 引数は型・範囲・形式を検証（指標名は許可リスト、期間は上限あり、過去 60 日まで）
  - 出力はマスキングし、サイズ上限を超えたら返さない
  - すべての呼び出し（失敗・拒否を含む）を監査ログに記録
"""
import datetime as dt
import json
import math
import os
import re
import sys
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from monitoring import audit, cloudwatch, mask  # noqa: E402

AUDIT_FILE = os.path.join(BASE_DIR, "out", "mcp_audit.log")
MAX_BYTES = 256 * 1024
MAX_LOOKBACK_DAYS = 60          # CloudWatch の 5 分粒度データの保持（63 日）より少し短く
MAX_SERIES_POINTS = 288         # 時系列 1 回の点数上限（期間が長いと粒度を粗くする）
METRICS = {m[0]: {"name": m[1], "stat": m[2], "unit": m[4]} for m in cloudwatch.CW_METRICS}

_INSTANCE_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")
_PROFILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
# プロファイル指定を上書きしうる認証情報の環境変数（--profile が優先されるが、念のため子プロセスに渡さない）
_CRED_ENV = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_PROFILE")


class ToolInputError(ValueError):
    """引数の検証エラー（AI に理由を返して出し直させる）。"""


class Settings:
    def __init__(self, profile, instance_id, region):
        self.profile, self.instance_id, self.region = profile, instance_id, region


def load_settings(env=None):
    """環境変数から接続先を読む。不正・未設定なら ValueError（サーバーを起動しない）。

    MCP_AWS_PROFILE は必須。管理者権限を持つことが多い default は、MCP_ALLOW_DEFAULT_PROFILE=1 を
    明示しない限り拒否する（MCP には専用の読み取り専用プロファイルを使う）。"""
    env = os.environ if env is None else env
    profile = env.get("MCP_AWS_PROFILE", "")
    iid = env.get("MCP_INSTANCE_ID", "")
    region = env.get("MCP_REGION", "")
    if not _PROFILE_RE.match(profile):
        raise ValueError("MCP_AWS_PROFILE を設定すること（MCP 専用の読み取り専用プロファイル、例 mcp-readonly）")
    if profile == "default" and env.get("MCP_ALLOW_DEFAULT_PROFILE") != "1":
        raise ValueError("default プロファイルは使わない（管理者権限の可能性）。"
                         "検証目的なら MCP_ALLOW_DEFAULT_PROFILE=1 を明示すること")
    if not _INSTANCE_RE.match(iid):
        raise ValueError("MCP_INSTANCE_ID が不正（例 i-0123456789abcdef0）")
    if not _REGION_RE.match(region):
        raise ValueError("MCP_REGION が不正（例 ap-northeast-1）")
    return Settings(profile, iid, region)


def scrub_credentials_env(env=None):
    """子プロセス（aws CLI）が環境変数の認証情報を使わないよう除去する。除去した変数名を返す。"""
    env = os.environ if env is None else env
    removed = [k for k in _CRED_ENV if k in env]
    for k in removed:
        del env[k]
    return removed


# ---------------------------------------------------------------- 引数検証
def _int(v, lo, hi, name):
    if isinstance(v, bool) or not isinstance(v, int):
        raise ToolInputError(f"{name} は整数で指定する")
    if not lo <= v <= hi:
        raise ToolInputError(f"{name} は {lo}〜{hi} の範囲で指定する")
    return v


def _end(v, now=None):
    """期間の終了時刻。省略時は現在。ISO 8601（UTC。タイムゾーン省略時も UTC とみなす）、過去 60 日以内。"""
    now = now or dt.datetime.now(dt.timezone.utc)
    if v is None or v == "":
        return now.replace(second=0, microsecond=0)
    if not isinstance(v, str) or len(v) > 32:
        raise ToolInputError("end は ISO 8601 の文字列で指定する（例 2026-11-08T06:00Z）")
    try:
        t = dt.datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
    except ValueError:
        raise ToolInputError("end は ISO 8601 の文字列で指定する（例 2026-11-08T06:00Z）") from None
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    t = t.astimezone(dt.timezone.utc).replace(second=0, microsecond=0)
    if t > now + dt.timedelta(minutes=5):
        raise ToolInputError("end に未来の時刻は指定できない")
    if t < now - dt.timedelta(days=MAX_LOOKBACK_DAYS):
        raise ToolInputError(f"end は過去 {MAX_LOOKBACK_DAYS} 日以内で指定する")
    return t


def _series_period(hours):
    """点数が MAX_SERIES_POINTS 以下になる、300 秒の倍数の粒度。"""
    return max(300, math.ceil(hours * 3600 / MAX_SERIES_POINTS / 300) * 300)


def _iso(t):
    return t.strftime("%Y-%m-%dT%H:%MZ")


# ---------------------------------------------------------------- ツール本体
def ec2_metrics_summary(st, hours=24, end=None):
    hours = _int(hours, 1, 72, "hours")
    end = _end(end)
    metrics = cloudwatch.fetch_metrics(st.instance_id, st.region, hours, end, profile=st.profile)
    return {"instance_id": st.instance_id, "region": st.region,
            "window": {"start": _iso(end - dt.timedelta(hours=hours)), "end": _iso(end), "hours": hours},
            "period_s": cloudwatch.CW_PERIOD, "metrics": metrics,
            "note": "各指標は latest と直近 1h・期間全体の avg/min/max（unit の単位に換算済み）。"
                    "データのない指標は省略。時系列で見たい指標は ec2_metric_series を使う。"}


def ec2_metric_series(st, metric, hours=6, end=None):
    if metric not in METRICS:
        raise ToolInputError(f"metric は次のいずれか：{', '.join(METRICS)}")
    hours = _int(hours, 1, 168, "hours")
    end = _end(end)
    period = _series_period(hours)
    points = cloudwatch.fetch_series(st.instance_id, st.region, metric, hours, end, period, profile=st.profile)
    return {"instance_id": st.instance_id, "metric": metric, **METRICS[metric], "period_s": period,
            "window": {"start": _iso(end - dt.timedelta(hours=hours)), "end": _iso(end), "hours": hours},
            "points": points, "count": len(points)}


def cloudwatch_alarms(st):
    alarms = cloudwatch.fetch_alarms(st.instance_id, st.region, profile=st.profile)
    return {"instance_id": st.instance_id, "alarms": alarms,
            "note": "本インスタンス ID をディメンションに持つアラームのみ。空ならアラームが設定されていない。"}


TOOLS = {f.__name__: f for f in (ec2_metrics_summary, ec2_metric_series, cloudwatch_alarms)}


def call(st, tool, **kwargs):
    """ツールを実行し (ok, 出力 dict) を返す。出力はマスキング済み・サイズ上限内。監査ログに記録する。"""
    t0 = time.time()
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "tool": tool, "args": kwargs,
           "profile": st.profile}
    try:
        if tool not in TOOLS:
            raise ToolInputError(f"未知のツール：{tool[:40]}")
        body, ok = TOOLS[tool](st, **kwargs), True
    except ToolInputError as e:
        body, ok = {"error": f"引数エラー：{e}"}, False
    except RuntimeError as e:   # aws CLI の失敗（権限不足・タイムアウト等）
        body, ok = {"error": str(e)[:300]}, False
    except Exception as e:  # noqa  想定外でもスタックトレースは返さない
        body, ok = {"error": f"{type(e).__name__}: {str(e)[:300]}"}, False
    body = mask.mask_obj(body)
    size = len(json.dumps(body, ensure_ascii=False, default=str).encode("utf-8"))
    if size > MAX_BYTES:
        body, ok = {"error": f"出力が上限 {MAX_BYTES} バイトを超えた。期間を絞って再実行すること"}, False
    rec.update(ok=ok, error=body.get("error"), ms=int((time.time() - t0) * 1000), bytes=size)
    audit.append(AUDIT_FILE, rec)
    return ok, body
