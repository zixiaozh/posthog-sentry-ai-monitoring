"""Sentry の取り込み量（ClickHouse の errors_local を日別に集計。件数のみ）。"""

import datetime as dt
import subprocess

from . import config as cfg
from . import util


# ----------------------------------------------------------------------------
# 3c) Sentry の取り込み量：「Web は 200 を返すがイベントが入ってこない」を検出する
#     nginx のログやヘルス端点では分からない（実例：2026-11 に nginx ログが 5 日欠落したが取り込みは継続していた）
# ----------------------------------------------------------------------------
def collect_sentry_ingest():
    if not cfg.SENTRY_CLICKHOUSE or cfg.SENTRY_CLICKHOUSE == "0":
        return None
    q = ("SELECT toDate(timestamp) AS d, count() FROM errors_local "
         "WHERE timestamp >= today() - 8 GROUP BY d ORDER BY d FORMAT TSV")
    try:
        r = subprocess.run(["docker", "exec", cfg.SENTRY_CLICKHOUSE, "clickhouse-client", "-q", q],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"clickhouse-client exit {r.returncode}: {(r.stderr or r.stdout).strip()}")
        by_day = {}
        for line in r.stdout.splitlines():
            d, n = line.split("\t")
            by_day[d] = int(n)
    except Exception as e:  # noqa
        return {"error": util._short(str(e))}
    today = dt.datetime.now(dt.timezone.utc).date()
    days = [(today - dt.timedelta(days=i)).isoformat() for i in range(8, 0, -1)]   # 8 日前〜昨日（完結した日だけ）
    counts = [by_day.get(d, 0) for d in days]
    yesterday, base = counts[-1], sorted(counts[:-1])
    median = base[len(base) // 2] if base else 0
    return {"by_day": {d: by_day.get(d, 0) for d in days + [today.isoformat()]},
            "yesterday": yesterday, "baseline_median_7d": median,
            "ratio_pct": round(yesterday * 100 / median, 1) if median else None,
            "note": "当日分は途中までの件数"}
