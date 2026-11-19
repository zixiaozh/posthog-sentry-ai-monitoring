"""判定ルール：収集結果から WARN / CRIT / INFO を算出する（決定的。AI の焦点にも使う）。"""


from . import config as cfg
from . import docker


# ----------------------------------------------------------------------------
# 「注目ポイント」の算出（決定的なルール。AI の分析の焦点に使う。★リアルタイム通知は slack_alert.sh の担当）
# 本当に意味のある信号だけを拾い、Slack との重複や累計再起動回数のようなノイズを避ける。
# ----------------------------------------------------------------------------
def compute_alerts(host, containers, web, cw=None, nginx=None, ingest=None):
    alerts = []

    d = host.get("disk", {})
    if isinstance(d.get("used_pct"), (int, float)):
        if d["used_pct"] >= cfg.DISK_CRIT:
            alerts.append(f"[CRIT] ディスク使用率 {d['used_pct']}% ≥ {cfg.DISK_CRIT}%")
        elif d["used_pct"] >= cfg.DISK_WARN:
            alerts.append(f"[WARN] ディスク使用率 {d['used_pct']}% ≥ {cfg.DISK_WARN}%")
    tr = host.get("disk_trend") or {}
    if "days_to_warn" in tr and tr["days_to_warn"] <= cfg.DISK_FORECAST_WARN_DAYS:
        alerts.append(f"[WARN] ディスクが +{tr['gib_per_day']}GiB/日 で増加中、約 {tr['days_to_warn']} 日後（{tr['eta_warn']} 頃）"
                      f"に {cfg.DISK_WARN}% 到達見込み")

    m = host.get("mem", {})
    av = m.get("available_gib")
    if isinstance(av, (int, float)):
        if av < cfg.MEM_AVAIL_CRIT_GB:      # slack_alert.sh：floor(GiB) < 閾値 ⇔ GiB < 閾値
            alerts.append(f"[CRIT] 空きメモリ {av}GiB < {cfg.MEM_AVAIL_CRIT_GB}GiB")
        elif av < cfg.MEM_AVAIL_WARN_GB:
            alerts.append(f"[WARN] 空きメモリ {av}GiB < {cfg.MEM_AVAIL_WARN_GB}GiB")

    s = host.get("swap", {})
    sio = host.get("swap_io", {})
    # 「swap 使用量」に換ページ速度を注記する：使用量が多くてもほぼ換ページがなければ過去の残留
    # 「前回巡検以降」の長い窓を優先する（3 秒の瞬間値は巡検自体が引き起こす換入の影響を受けやすい）
    rate = sio.get("since_last") or sio.get("now")
    hint, idle = "", False
    if rate:
        tot = round(rate["in_kbps"] + rate["out_kbps"], 1)
        idle = tot < cfg.SWAP_IO_WARN_KBPS / 10
        hint = (f"（換ページ {tot}KB/s、ほぼ動きなし。過去に換出された残留のため 1 段階下げて表示）" if idle
                else f"（換ページ {tot}KB/s、現在も活発に換ページ中）")
    su = s.get("used_gib")
    if isinstance(su, (int, float)):
        # 動きのない swap は性能に影響しない：1 段階下げる（WARN→INFO、CRIT→WARN）。毎回ノイズとして出るのを防ぐ。
        # Slack の絶対閾値の通知には影響しない。実際のメモリ逼迫は下の「継続的な換ページ」ルールで検出する。
        if su >= cfg.SWAP_CRIT_GB:
            alerts.append(f"[{'WARN' if idle else 'CRIT'}] swap 使用量 {su}GiB ≥ {cfg.SWAP_CRIT_GB}GiB{hint}")
        elif su >= cfg.SWAP_WARN_GB:
            alerts.append(f"[{'INFO' if idle else 'WARN'}] swap 使用量 {su}GiB ≥ {cfg.SWAP_WARN_GB}GiB{hint}")
    sl = sio.get("since_last")
    if sl and sl["in_kbps"] + sl["out_kbps"] >= cfg.SWAP_IO_WARN_KBPS:
        alerts.append(f"[WARN] 前回巡検以降 swap の換ページが継続：換入 {sl['in_kbps']}KB/s / 換出 {sl['out_kbps']}KB/s"
                      f"（≥{cfg.SWAP_IO_WARN_KBPS}KB/s、実際にメモリが逼迫している）")

    l = host.get("load", {})
    if isinstance(l.get("per_cpu_1m"), (int, float)) and l["per_cpu_1m"] >= cfg.LOAD_PER_CPU_WARN:
        alerts.append(f"[WARN] コアあたり load {l['per_cpu_1m']}（1m {l.get('1m')} / {l.get('cpu_count')} コア）")

    for c in containers:
        if c.get("ignored"):
            continue
        tag = "コアコンテナ" if c["watched"] else "コンテナ"
        # OOM は現在の状態に関係なく報告する（停止中のコンテナこそ OOM で落ちた可能性がある）
        if c.get("oom_killed"):
            alerts.append(f"[CRIT] {tag} {c['name']} が OOM kill された（status={c['status']}）")
        st = c["status"]
        if st != "running":
            if st == "exited" and c.get("exit_code") == 0:
                # 正常終了：多くは一回限りのタスク（migration 等）で、障害ではない
                alerts.append(f"[INFO] {tag} {c['name']} は正常終了（exit 0、一回限りのタスクの可能性。"
                              f"想定どおりなら IGNORE_CONTAINERS に追加）")
            elif st == "created":
                alerts.append(f"[INFO] {tag} {c['name']} は作成済みだが未起動（status=created）")
            elif st == "paused":
                alerts.append(f"[WARN] {tag} {c['name']} が一時停止中（status=paused）")
            else:
                # exited≠0 / restarting / dead / removing
                detail = f"、exit {c.get('exit_code')}" if st == "exited" else ""
                alerts.append(f"[CRIT] {tag} {c['name']} が停止中（status={st}{detail}）")
            continue
        if c["health"] not in ("none", "healthy"):
            alerts.append(f"[WARN] {tag} {c['name']} health={c['health']}")
        if c.get("budget_pct") is not None and c["budget_pct"] >= cfg.BUDGET_INFO_PCT:
            alerts.append(f"[INFO] {tag} {c['name']} のメモリ {c['mem_mib']}MiB、Slack 閾値 {c['budget_gib']}GiB の "
                          f"{c['budget_pct']}% に到達（95% 以上が続くと Slack がリアルタイム通知）")
        # 再起動は増分（前回巡検以降）だけを見る。累計回数は意味がないので見ない
        rd = c.get("restarts_delta")
        if rd:
            lv = "CRIT" if rd >= cfg.RESTART_DELTA_CRIT else "WARN"
            why = "、クラッシュの繰り返しの疑い" if lv == "CRIT" else ""
            alerts.append(f"[{lv}] {tag} {c['name']} が前回巡検以降 {rd} 回再起動（累計 {c['restarts']}{why}）")
            continue
        if c.get("restarted_since_last") and docker._scheduled_restart(c):
            continue    # 既知の定期再起動（SCHEDULED_RESTARTS）。異常ではない
        if c.get("restarted_since_last"):
            alerts.append(f"[INFO] {tag} {c['name']} が前回巡検以降に再起動された（RestartCount は増えていない → クラッシュによる自動再起動ではなく、"
                          f"手動 restart / compose 再作成 / 定期ジョブ。起動 {c['started_at'][:16]}Z）")
            continue
        # 増分データがない（初回実行等）場合は「最近再起動した」で代替
        ud = c.get("uptime_days")
        if rd is None and isinstance(ud, (int, float)) and ud < cfg.RECENT_RESTART_DAYS and not docker._scheduled_restart(c):
            alerts.append(f"[INFO] {tag} {c['name']} は最近再起動した（uptime {ud} 日、累計 {c['restarts']} 回）")

    for w in web:
        if not w.get("ok"):
            detail = w.get("error") or f"HTTP {w.get('status')}"
            alerts.append(f"[CRIT] Web {w['name']} の疎通失敗：{detail}")
        elif isinstance(w.get("latency_ms"), int) and w["latency_ms"] >= cfg.WEB_LATENCY_WARN_MS:
            alerts.append(f"[WARN] Web {w['name']} の応答が遅い：{w['latency_ms']}ms（≥{cfg.WEB_LATENCY_WARN_MS}ms、依存先の遅延の疑い）")

    for n in nginx or []:
        if n.get("docker_logs_error"):
            alerts.append(f"[WARN] nginx {n['container']} の docker logs が失敗（{n['docker_logs_error']}）。"
                          f"ログファイル破損の疑いで、docker logs に依存する slack_alert_http.sh の 5xx 監視も機能していない可能性"
                          f"（本スクリプトはログファイルを直接読んで集計）")
        if not n.get("error") and n.get("requests") == 0 and n["window_h"] >= cfg.NGINX_SILENT_MIN_H:
            alerts.append(f"[WARN] nginx {n['container']} 直近 {n['window_h']}h のアクセスログが 0 件"
                          f"（ログの欠落、または通信が届いていない。Sentry の取り込み量と合わせて確認）")
        if n.get("error"):
            alerts.append(f"[INFO] nginx ログ {n['container']} を取得できない：{n['error']}")
        elif n.get("5xx"):
            lv = "WARN" if n["5xx"] >= cfg.NGINX_5XX_WARN_MIN and n["5xx_pct"] >= cfg.NGINX_5XX_WARN_PCT else "INFO"
            codes = ", ".join(f"{k}×{v}" for k, v in sorted(n["by_code"].items()))
            alerts.append(f"[{lv}] nginx {n['container']} 直近 {n['window_h']}h で 5xx {n['5xx']} 件 / {n['requests']} リクエスト"
                          f"（{n['5xx_pct']}%：{codes}）")

    if ingest:
        if ingest.get("error"):
            alerts.append(f"[INFO] Sentry 取り込み量を取得できない：{ingest['error']}")
        elif ingest["yesterday"] == 0 and ingest["baseline_median_7d"] > 0:
            alerts.append(f"[WARN] Sentry の取り込みイベントが昨日 0 件（直近 7 日の中央値 {ingest['baseline_median_7d']} 件/日）")
        elif ingest["ratio_pct"] is not None and ingest["ratio_pct"] < cfg.INGEST_DROP_PCT:
            alerts.append(f"[WARN] Sentry の取り込みイベントが急減：昨日 {ingest['yesterday']} 件、"
                          f"直近 7 日の中央値 {ingest['baseline_median_7d']} 件/日の {ingest['ratio_pct']}%")

    if cw is not None:
        if cw.get("error"):
            # データソースが欠けてもプラットフォームの異常ではなく、ローカル信号は揃っている → INFO（総合ステータスに影響しない）
            alerts.append(f"[INFO] CloudWatch を取得できない：{cw['error']}")
        m = cw.get("metrics", {})
        sf = m.get("status_failed", {}).get("1h", {})
        if sf.get("max", 0) >= 1:
            alerts.append("[CRIT] CloudWatch：直近 1h に EC2 状態チェック失敗（StatusCheckFailed=1、AWS 側のハードウェア/ネットワークまたはインスタンス OS の異常）")
        cpu = m.get("cpu", {}).get("1h", {})
        if cpu.get("avg", 0) >= cfg.CW_CPU_WARN:
            alerts.append(f"[WARN] CloudWatch：直近 1h の CPU 平均 {cpu['avg']}% ≥ {cfg.CW_CPU_WARN}%（ピーク {m.get('cpu_peak', {}).get('1h', {}).get('max')}%）")
        for key, label in (("ebs_io_balance", "EBS IO バースト残高"), ("ebs_byte_balance", "EBS スループットバースト残高")):
            b = m.get(key)
            if b and b["latest"] <= cfg.CW_BALANCE_WARN:
                alerts.append(f"[WARN] CloudWatch：{label} {b['latest']}% ≤ {cfg.CW_BALANCE_WARN}%（枯渇するとディスク IO が制限される。"
                              f"24h 最低 {b.get('24h', {}).get('min')}%）")
        cc = m.get("cpu_credit")
        if cc and cc["latest"] <= cfg.CW_CPU_CREDIT_WARN:
            alerts.append(f"[WARN] CloudWatch：CPU クレジット残高 {cc['latest']} ≤ {cfg.CW_CPU_CREDIT_WARN}（枯渇すると CPU がベースライン性能に制限される）")
        for a in cw.get("alarms", []):
            if a["state"] == "ALARM":
                alerts.append(f"[WARN] CloudWatch アラーム {a['name']} が ALARM 状態（{a['metric']} 閾値 {a['threshold']}）")

    return alerts


# ----------------------------------------------------------------------------
# レポート生成 + 保存 + 古いファイルの削除
# ----------------------------------------------------------------------------
def _overall(alerts):
    # INFO は総合ステータスに影響しない
    if any(a.startswith("[CRIT]") for a in alerts):
        return "危険"
    return "注意" if any(a.startswith("[WARN]") for a in alerts) else "正常"
