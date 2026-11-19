"""Markdown レポートの生成と古い成果物の削除。"""

import os
import time

from . import config as cfg
from . import ai
from . import cloudwatch
from . import rules


def render_markdown(snap, ai_text, generated_at):
    host, containers, web, alerts = snap["host"], snap["containers"], snap["web"], snap["alerts"]
    overall = {"危険": "🔴 危険", "注意": "🟡 注意", "正常": "🟢 正常"}[rules._overall(alerts)]
    L = []
    L.append(f"# プラットフォーム健康レポート（Sentry + PostHog）")
    L.append("")
    L.append(f"- 生成時刻: {generated_at}")
    L.append(f"- 総合ステータス: **{overall}** / 検出アラート: {len(alerts)} 件")
    L.append("")
    if ai_text:
        L.append(f"## AI 診断（{cfg.AI_PROVIDER} / {ai.PROVIDERS.get(cfg.AI_PROVIDER, (None, None, '?'))[2]}）")
        L.append("")
        L.append(ai_text)
        L.append("")
    L.append("## 検出アラート")
    L.append("")
    if alerts:
        for a in alerts:
            L.append(f"- {a}")
    else:
        L.append("- 異常なし")
    L.append("")
    # ホスト
    L.append("## ホストリソース")
    L.append("")
    d, m, s, lo = host.get("disk", {}), host.get("mem", {}), host.get("swap", {}), host.get("load", {})
    L.append(f"- ディスク: {d.get('used_pct')}% 使用 ({d.get('used_gib')}/{d.get('total_gib')} GiB、空き {d.get('avail_gib')} GiB)")
    tr = host.get("disk_trend")
    if tr:
        eta = "".join(f"、{pct}% まで約 {tr[f'days_to_{k}']} 日（{tr[f'eta_{k}']} 頃）"
                      for k, pct in (("warn", cfg.DISK_WARN), ("crit", cfg.DISK_CRIT)) if f"days_to_{k}" in tr)
        L.append(f"- ディスク増加: {tr['gib_per_day']:+} GiB/日（過去 {tr['span_days']} 日・{tr['points']} 点）{eta}")
    L.append(f"- メモリ: {m.get('used_pct')}% 使用 (空き {m.get('available_gib')} GiB / 全 {m.get('total_gib')} GiB)")
    L.append(f"- swap: {s.get('used_pct')}% 使用 ({s.get('used_gib')}/{s.get('total_gib')} GiB)")
    sio = host.get("swap_io", {})
    for key, label in (("now", f"直近 {sio.get('now_window_s')} 秒"), ("since_last", f"前回巡検から {sio.get('since_last_min')} 分")):
        if sio.get(key):
            L.append(f"- swap 換ページ（{label}）: in {sio[key]['in_kbps']} KB/s / out {sio[key]['out_kbps']} KB/s")
    L.append(f"- load: 1m={lo.get('1m')} 5m={lo.get('5m')} 15m={lo.get('15m')} ({lo.get('cpu_count')} コア, コアあたり {lo.get('per_cpu_1m')})")
    L.append("")
    # コンテナ
    L.append("## コンテナ状態")
    L.append("")
    L.append("Restarts は累計（括弧内は前回巡検からの増分、— は比較データなし。🔄 = 前回巡検以降に手動/再作成等で再起動）。")
    L.append("")
    L.append("| Container | Core | Status | Health | Uptime(d) | Restarts | Mem MiB | Swap MiB | OOM |")
    L.append("|-----------|------|--------|--------|-----------|----------|--------|---------|-----|")

    def _v(x):
        return "—" if x is None else x

    for c in containers:
        st = c["status"] + (f" ({c.get('exit_code')})" if c["status"] == "exited" else "")
        mark = "(ignored)" if c.get("ignored") else ("★" if c["watched"] else "")
        rd = c.get("restarts_delta")
        budget = f" ({c['budget_pct']}% of {c['budget_gib']}G)" if c.get("budget_gib") else ""
        rs = f"{c['restarts']} ({'+' + str(rd) if rd else _v(rd)})" + (" 🔄" if c.get("restarted_since_last") else "")
        L.append(f"| {c['name']} | {mark} | {st} | {c['health']} | {_v(c.get('uptime_days'))} | {rs} | "
                 f"{_v(c.get('mem_mib'))}{budget} | {_v(c.get('swap_mib'))} | {'⚠️' if c['oom_killed'] else ''} |")
    L.append("")
    # Web
    if web:
        L.append("## Web 可用性")
        L.append("")
        L.append("| Target | Status | OK | Latency |")
        L.append("|--------|--------|----|---------|")
        for w in web:
            L.append(f"| {w['name']} | {w.get('status')} | {'✅' if w.get('ok') else '❌'} | {w.get('latency_ms')}ms |")
        L.append("")
    ng = snap.get("nginx") or []
    if ng:
        L.append("## nginx アクセスログ")
        L.append("")
        for n in ng:
            if n.get("error"):
                L.append(f"- {n['container']}: 取得失敗 {n['error']}")
                continue
            L.append(f"- {n['container']}（直近 {n['window_h']}h）: リクエスト {n['requests']} 件、5xx {n['5xx']} 件"
                     f"（{n['5xx_pct']}%）{' ※途中打ち切り' if n.get('truncated') else ''}"
                     f"{' ※ログファイル直接読み取り（破損行 ' + str(n.get('corrupt_lines', 0)) + '）' if n.get('source') == 'logfile' else ''}"
                     f"{' ※窓の途中から' if n.get('partial_window') else ''}")
            for path, cnt in n.get("top_paths", []):
                L.append(f"  - {path}: {cnt} 件")
        L.append("")
    ig = snap.get("sentry_ingest")
    if ig:
        L.append("## Sentry 取り込み量（エラーイベント / 日、UTC）")
        L.append("")
        if ig.get("error"):
            L.append(f"- 取得失敗 {ig['error']}")
        else:
            L.append("| " + " | ".join(d[5:] for d in ig["by_day"]) + " |")
            L.append("|" + "---|" * len(ig["by_day"]))
            L.append("| " + " | ".join(str(v) for v in ig["by_day"].values()) + " |")
            L.append("")
            L.append(f"- 昨日 {ig['yesterday']} 件 / 直近 7 日の中央値 {ig['baseline_median_7d']} 件"
                     f"（{ig['ratio_pct']}%）。最終列は当日の途中経過")
        L.append("")
    cw = snap.get("cloudwatch")
    if cw is not None:
        L.append("## CloudWatch（EC2 インスタンス指標）")
        L.append("")
        if cw.get("instance_id"):
            L.append(f"- インスタンス: {cw['instance_id']}（{cw.get('instance_type')}, {cw.get('region')}）")
        if cw.get("error"):
            L.append(f"- ⚠️ 取得失敗: {cw['error']}")
        m = cw.get("metrics", {})
        if m:
            L.append("")
            L.append("| Metric | Unit | Latest | 1h avg | 1h max | 24h avg | 24h min | 24h max |")
            L.append("|--------|------|--------|--------|--------|---------|---------|---------|")
            for qid, name, stat, _, _ in cloudwatch.CW_METRICS:
                v = m.get(qid)
                if not v:
                    continue
                h1, h24 = v.get("1h", {}), v.get("24h", {})
                label = f"{name} ({stat})" if name == "CPUUtilization" else name
                L.append(f"| {label} | {v['unit']} | {v['latest']} | {h1.get('avg', '—')} | {h1.get('max', '—')} | "
                         f"{h24.get('avg', '—')} | {h24.get('min', '—')} | {h24.get('max', '—')} |")
        if "alarms" in cw:
            L.append("")
            if cw["alarms"]:
                for a in cw["alarms"]:
                    L.append(f"- アラーム {a['name']}: **{a['state']}**（{a['metric']} 閾値 {a['threshold']}）")
            else:
                L.append("- 本インスタンスに紐づく CloudWatch アラーム: なし")
        if cw.get("alarms_error"):
            L.append(f"- アラーム取得失敗: {cw['alarms_error']}")
        L.append("")
    return "\n".join(L)


def cleanup_old(out_dir, keep_days):
    if keep_days <= 0:
        return
    cutoff = time.time() - keep_days * 86400
    for name in os.listdir(out_dir):
        p = os.path.join(out_dir, name)
        try:
            if os.path.isfile(p) and os.path.getmtime(p) < cutoff:
                os.remove(p)
        except OSError:
            pass
