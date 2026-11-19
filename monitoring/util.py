"""共通の小さな関数。"""

import datetime as dt


# ----------------------------------------------------------------------------
# 1) コンテナ
# ----------------------------------------------------------------------------
def _uptime_days(started_at):
    """docker の StartedAt（ナノ秒付きの場合あり）を「稼働日数」に変換。解析失敗時は None。"""
    try:
        s = started_at.rstrip("Z")
        if "." in s:
            head, frac = s.split(".", 1)
            s = head + "." + frac[:6]        # strptime が扱えるようナノ秒をマイクロ秒に切り詰める
            fmt = "%Y-%m-%dT%H:%M:%S.%f"
        else:
            fmt = "%Y-%m-%dT%H:%M:%S"
        started = dt.datetime.strptime(s, fmt).replace(tzinfo=dt.timezone.utc)
        return round((dt.datetime.now(dt.timezone.utc) - started).total_seconds() / 86400, 1)
    except Exception:  # noqa
        return None


def _short(text, n=300):
    """エラーメッセージを短く整形する（コマンド全体や大量の出力をレポートに載せないため）。"""
    t = " ".join((text or "").split())
    return t if len(t) <= n else t[:n] + "…"
