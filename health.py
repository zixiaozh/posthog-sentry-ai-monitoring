#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
platform_health.py — 自建 Sentry + PostHog 平台健康巡检（运维视角 · 第一步）

目标：定期检查这台 EC2 上 Sentry / PostHog 平台是否正常运行，异常时由 AI 点出
      可能原因与处理建议。数据全部来自本机，无需 Sentry/PostHog 的 API token。

采集三类信号：
  1) 容器健康：docker 各容器的 status / health / 重启次数 / 是否被 OOM kill
  2) 主机资源：磁盘、内存、swap、load（读 /proc 与 statvfs，零依赖）
  3) 网页可用性：对 Sentry / PostHog 的 URL 做 HTTP 探活（状态码 + 延迟）

设计同样遵循资源受限原则：零第三方依赖、短命进程、产物极小、自动清理。

用法：
  # 只巡检+聚合，不调 LLM（先验证采集正常）
  python3 platform_health.py --dry-run
  # 加 AI 诊断（需要 ANTHROPIC_API_KEY）
  python3 platform_health.py

注意：读取 docker 信息通常需要权限。若你平时用 `sudo docker`，
      则用 `sudo -E python3 platform_health.py`（-E 保留环境变量），
      或把运行用户加入 docker 组。
"""

import os
import sys
import json
import time
import shutil
import argparse
import subprocess
import datetime as dt
import ssl
from urllib import request, error

# ----------------------------------------------------------------------------
# 配置（环境变量）
# ----------------------------------------------------------------------------
# 要重点关注的容器名前缀（用于标记「平台核心容器」）
WATCH_PREFIXES = os.environ.get("WATCH_PREFIXES", "sentry,posthog,clickhouse,kafka,redis,postgres,snuba").split(",")

# 网页探活目标：格式 "名称=URL"，多个用逗号分隔。留空则不做网页检查。
# 例：SENTRY_URL / POSTHOG_URL 单独给也行
WEB_TARGETS = os.environ.get("WEB_TARGETS", "")
SENTRY_URL = os.environ.get("SENTRY_URL", "")
POSTHOG_URL = os.environ.get("POSTHOG_URL", "")

# 关注提示的阈值（★注意：这些不是「告警通道」——实时告警由已有的 slack_alert.sh 负责。
#  这里只是给 AI 的「关注提示」，用于聚焦分析和算总合状态。阈值刻意对齐 slack_alert.sh，
#  避免两套数值漂移。改阈值时请同时改 slack_alert.sh，保持单一心智模型。）
DISK_WARN = float(os.environ.get("DISK_WARN", "85"))          # 磁盘使用率 %（同 Slack DISK_WARN_PCT）
DISK_CRIT = float(os.environ.get("DISK_CRIT", "95"))          # 同 Slack DISK_CRIT_PCT
MEM_AVAIL_WARN_GB = float(os.environ.get("MEM_AVAIL_WARN_GB", "2"))  # 可用内存 < N GB（同 Slack RAM_WARN_GB）
MEM_AVAIL_CRIT_GB = float(os.environ.get("MEM_AVAIL_CRIT_GB", "1"))  # 同 Slack RAM_CRIT_GB
SWAP_WARN_GB = float(os.environ.get("SWAP_WARN_GB", "5"))     # swap 已用 > N GB（同 Slack SWAP_WARN_GB）
SWAP_CRIT_GB = float(os.environ.get("SWAP_CRIT_GB", "10"))    # 同 Slack SWAP_CRIT_GB
LOAD_PER_CPU_WARN = float(os.environ.get("LOAD_PER_CPU_WARN", "1.5"))  # 每核 load
RECENT_RESTART_DAYS = float(os.environ.get("RECENT_RESTART_DAYS", "1"))  # uptime < N 天视为「最近重启」
WEB_LATENCY_WARN_MS = int(os.environ.get("WEB_LATENCY_WARN_MS", "5000"))  # 网页/健康端点响应过慢阈值

# AI
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")
REPORT_LANG = os.environ.get("REPORT_LANG", "ja")

# 产物
OUT_DIR = os.environ.get("OUT_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"))
KEEP_DAYS = int(os.environ.get("KEEP_DAYS", "14"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "10"))
INSECURE = os.environ.get("WEB_INSECURE", "") == "1"


# ----------------------------------------------------------------------------
# 1) 容器健康
# ----------------------------------------------------------------------------
def _uptime_days(started_at):
    """把 docker 的 StartedAt（可能带纳秒）换成「已运行天数」，解析失败返回 None。"""
    try:
        s = started_at.rstrip("Z")
        if "." in s:
            head, frac = s.split(".", 1)
            s = head + "." + frac[:6]        # 纳秒截到微秒，strptime 才认
            fmt = "%Y-%m-%dT%H:%M:%S.%f"
        else:
            fmt = "%Y-%m-%dT%H:%M:%S"
        started = dt.datetime.strptime(s, fmt).replace(tzinfo=dt.timezone.utc)
        return round((dt.datetime.now(dt.timezone.utc) - started).total_seconds() / 86400, 1)
    except Exception:  # noqa
        return None


def collect_containers():
    """用 docker inspect 采集所有容器的关键状态。docker 不可用则返回错误标记。"""
    if shutil.which("docker") is None:
        return {"error": "docker 命令不可用（PATH 中找不到）"}, []
    # 先列出所有容器名（含已停止）
    try:
        names_out = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=20, check=True,
        ).stdout
    except subprocess.CalledProcessError as e:
        return {"error": f"docker ps 失败：{e.stderr.strip() or e}"}, []
    except Exception as e:  # noqa
        return {"error": f"docker ps 异常：{e}"}, []

    names = [n for n in names_out.splitlines() if n.strip()]
    if not names:
        return {"error": None, "note": "未发现任何容器"}, []

    # 一次 inspect 全部，输出可解析的分隔行
    fmt = ("{{.Name}}\t{{.State.Status}}\t"
           "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}\t"
           "{{.RestartCount}}\t{{.State.OOMKilled}}\t{{.State.StartedAt}}")
    try:
        insp = subprocess.run(
            ["docker", "inspect", "--format", fmt] + names,
            capture_output=True, text=True, timeout=30, check=True,
        ).stdout
    except Exception as e:  # noqa
        return {"error": f"docker inspect 异常：{e}"}, []

    containers = []
    for line in insp.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        name = parts[0].lstrip("/")
        watched = any(name.startswith(p.strip()) or (p.strip() in name) for p in WATCH_PREFIXES if p.strip())
        containers.append({
            "name": name,
            "status": parts[1],
            "health": parts[2],
            "restarts": int(parts[3]) if parts[3].isdigit() else parts[3],
            "oom_killed": parts[4].strip().lower() == "true",
            "started_at": parts[5],
            "uptime_days": _uptime_days(parts[5]),
            "watched": watched,
        })
    containers.sort(key=lambda c: (not c["watched"], c["name"]))
    return {"error": None}, containers


# ----------------------------------------------------------------------------
# 2) 主机资源（零依赖：statvfs + /proc）
# ----------------------------------------------------------------------------
def collect_host():
    host = {}
    # 磁盘（根分区）
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = total - free
        host["disk"] = {
            "total_gb": round(total / 1e9, 1),
            "used_gb": round(used / 1e9, 1),
            "used_pct": round(used / total * 100, 1) if total else None,
        }
    except Exception as e:  # noqa
        host["disk"] = {"error": str(e)}

    # 内存 / swap（/proc/meminfo，单位 kB）
    try:
        mi = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mi[k.strip()] = int(v.strip().split()[0])
        mem_total = mi.get("MemTotal", 0)
        mem_avail = mi.get("MemAvailable", 0)
        host["mem"] = {
            "total_gb": round(mem_total / 1e6, 1),
            "available_gb": round(mem_avail / 1e6, 1),
            "used_pct": round((mem_total - mem_avail) / mem_total * 100, 1) if mem_total else None,
        }
        sw_total = mi.get("SwapTotal", 0)
        sw_free = mi.get("SwapFree", 0)
        host["swap"] = {
            "total_gb": round(sw_total / 1e6, 1),
            "used_gb": round((sw_total - sw_free) / 1e6, 1),
            "used_pct": round((sw_total - sw_free) / sw_total * 100, 1) if sw_total else 0,
        }
    except Exception as e:  # noqa
        host["mem"] = {"error": str(e)}

    # load
    try:
        la1, la5, la15 = os.getloadavg()
        cpu = os.cpu_count() or 1
        host["load"] = {"1m": round(la1, 2), "5m": round(la5, 2), "15m": round(la15, 2),
                        "cpu_count": cpu, "per_cpu_1m": round(la1 / cpu, 2)}
    except Exception as e:  # noqa
        host["load"] = {"error": str(e)}
    return host


# ----------------------------------------------------------------------------
# 3) 网页可用性
# ----------------------------------------------------------------------------
def _ssl_ctx():
    if INSECURE:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


def collect_web():
    targets = []
    if SENTRY_URL:
        targets.append(("Sentry", SENTRY_URL))
    if POSTHOG_URL:
        targets.append(("PostHog", POSTHOG_URL))
    for item in WEB_TARGETS.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            n, u = item.split("=", 1)
            targets.append((n.strip(), u.strip()))
        else:
            targets.append((item, item))

    results = []
    for name, url in targets:
        t0 = time.time()
        rec = {"name": name, "url": url}
        try:
            req = request.Request(url, method="GET", headers={"User-Agent": "health-check/0.1"})
            with request.urlopen(req, timeout=HTTP_TIMEOUT, context=_ssl_ctx()) as resp:
                rec["status"] = resp.status
                rec["ok"] = 200 <= resp.status < 400
        except error.HTTPError as e:
            rec["status"] = e.code
            rec["ok"] = 200 <= e.code < 400  # 4xx/5xx 也算「有响应」，但标记 ok=False
            rec["ok"] = False
        except Exception as e:  # noqa
            rec["status"] = None
            rec["ok"] = False
            rec["error"] = str(e)
        rec["latency_ms"] = int((time.time() - t0) * 1000)
        results.append(rec)
    return results


# ----------------------------------------------------------------------------
# 计算「关注提示」（确定性规则，给 AI 聚焦用；★不是告警通道，实时告警归 slack_alert.sh）
# 刻意只标真信号，避免与 Slack 重复，也避免累计重启这类噪音。
# ----------------------------------------------------------------------------
def compute_alerts(host, containers, web):
    alerts = []

    d = host.get("disk", {})
    if isinstance(d.get("used_pct"), (int, float)):
        if d["used_pct"] >= DISK_CRIT:
            alerts.append(f"[CRIT] 磁盘使用率 {d['used_pct']}% ≥ {DISK_CRIT}%")
        elif d["used_pct"] >= DISK_WARN:
            alerts.append(f"[WARN] 磁盘使用率 {d['used_pct']}% ≥ {DISK_WARN}%")

    m = host.get("mem", {})
    av = m.get("available_gb")
    if isinstance(av, (int, float)):
        if av <= MEM_AVAIL_CRIT_GB:
            alerts.append(f"[CRIT] 可用内存仅 {av}GB ≤ {MEM_AVAIL_CRIT_GB}GB")
        elif av <= MEM_AVAIL_WARN_GB:
            alerts.append(f"[WARN] 可用内存 {av}GB ≤ {MEM_AVAIL_WARN_GB}GB")

    s = host.get("swap", {})
    su = s.get("used_gb")
    if isinstance(su, (int, float)):
        if su >= SWAP_CRIT_GB:
            alerts.append(f"[CRIT] swap 已用 {su}GB ≥ {SWAP_CRIT_GB}GB")
        elif su >= SWAP_WARN_GB:
            alerts.append(f"[WARN] swap 已用 {su}GB ≥ {SWAP_WARN_GB}GB")

    l = host.get("load", {})
    if isinstance(l.get("per_cpu_1m"), (int, float)) and l["per_cpu_1m"] >= LOAD_PER_CPU_WARN:
        alerts.append(f"[WARN] 每核 load {l['per_cpu_1m']}（1m {l.get('1m')} / {l.get('cpu_count')} 核）")

    for c in containers:
        tag = "核心容器" if c["watched"] else "容器"
        if c["status"] != "running":
            alerts.append(f"[CRIT] {tag} {c['name']} 状态为 {c['status']}（未运行）")
            continue
        if c["health"] not in ("none", "healthy"):
            alerts.append(f"[WARN] {tag} {c['name']} health={c['health']}")
        if c.get("oom_killed"):
            alerts.append(f"[CRIT] {tag} {c['name']} 曾被 OOM kill")
        # 只标「最近重启过」，不用无意义的累计次数
        ud = c.get("uptime_days")
        if isinstance(ud, (int, float)) and ud < RECENT_RESTART_DAYS:
            alerts.append(f"[INFO] {tag} {c['name']} 最近重启过（uptime {ud} 天，累计 {c['restarts']} 次）")

    for w in web:
        if not w.get("ok"):
            detail = w.get("error") or f"HTTP {w.get('status')}"
            alerts.append(f"[CRIT] 网页 {w['name']} 探活失败：{detail}")
        elif isinstance(w.get("latency_ms"), int) and w["latency_ms"] >= WEB_LATENCY_WARN_MS:
            alerts.append(f"[WARN] 网页 {w['name']} 响应过慢：{w['latency_ms']}ms（≥{WEB_LATENCY_WARN_MS}ms，疑似依赖变慢）")

    return alerts


# ----------------------------------------------------------------------------
# 构建「真正发给 AI 的精简 payload」——本地存全量快照，但只把必要内容喂给 LLM 省 token
# ----------------------------------------------------------------------------
def build_ai_payload(snapshot):
    conts = snapshot["containers"]

    def is_nominal(c):
        ud = c.get("uptime_days")
        recent = isinstance(ud, (int, float)) and ud < RECENT_RESTART_DAYS
        return (c["status"] == "running" and c["health"] in ("healthy", "none")
                and not c.get("oom_killed") and not recent
                and (not isinstance(c["restarts"], int) or c["restarts"] == 0))

    # notable = 有任何非常态特征的容器（未运行/不健康/OOM/最近重启/有重启历史）
    notable = []
    for c in conts:
        if not is_nominal(c):
            notable.append({
                "name": c["name"],
                "status": c["status"],
                "health": c["health"],
                "restarts": c["restarts"],
                "oom_killed": c["oom_killed"],
                "uptime_days": c.get("uptime_days"),
            })

    total = len(conts)
    running = sum(1 for c in conts if c["status"] == "running")
    return {
        "generated_at": snapshot["generated_at"],
        "host": snapshot["host"],
        "containers": {
            "summary": {"total": total, "running": running,
                        "not_running": total - running, "nominal": total - len(notable)},
            "notable": notable,   # 只发值得看的容器，正常的只给计数
        },
        "web": snapshot["web"],
        "flags": snapshot["alerts"],   # 确定性关注提示
        "note_for_ai": "flags 是确定性提示，实时告警另由 Slack 负责；正常容器已折叠为计数。",
    }


# ----------------------------------------------------------------------------
# AI 诊断
# ----------------------------------------------------------------------------
LANG_LABEL = {"ja": "日本語", "zh": "中文", "en": "English"}


def ai_diagnose(snapshot):
    lang = LANG_LABEL.get(REPORT_LANG, "日本語")
    system = (
        "あなたは SRE / インフラ運用のアシスタントです。以下は自前ホストの "
        "Sentry + PostHog プラットフォーム（EC2 上、Docker 運用）の健康チェック結果です。"
        f"{lang} で簡潔な健康レポートを書いてください。与えられたデータのみ使用し、"
        "数値を捏造しないこと。構成: 1) 総合ステータス(正常/注意/危険を1行で) "
        "2) 検出された異常とその影響 3) 想定原因 4) 推奨アクション(具体的に)。"
        "異常が無ければその旨を明記。"
    )
    payload = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": 1500,
        "system": system,
        "messages": [{"role": "user",
                      "content": "健康チェックデータ(JSON):\n" + json.dumps(snapshot, ensure_ascii=False, indent=2)}],
    }
    req = request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json", "x-api-key": ANTHROPIC_API_KEY,
                 "anthropic-version": "2023-06-01"},
        method="POST",
    )
    with request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return "\n".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text").strip()


# ----------------------------------------------------------------------------
# 报告渲染 + 落盘 + 清理
# ----------------------------------------------------------------------------
def render_markdown(snap, ai_text, generated_at):
    host, containers, web, alerts = snap["host"], snap["containers"], snap["web"], snap["alerts"]
    overall = "🔴 危険" if any(a.startswith("[CRIT]") for a in alerts) else ("🟡 注意" if alerts else "🟢 正常")
    L = []
    L.append(f"# プラットフォーム健康レポート（Sentry + PostHog）")
    L.append("")
    L.append(f"- 生成時刻: {generated_at}")
    L.append(f"- 総合ステータス: **{overall}** / 検出アラート: {len(alerts)} 件")
    L.append("")
    if ai_text:
        L.append("## AI 診断")
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
    # 主机
    L.append("## ホストリソース")
    L.append("")
    d, m, s, lo = host.get("disk", {}), host.get("mem", {}), host.get("swap", {}), host.get("load", {})
    L.append(f"- ディスク: {d.get('used_pct')}% 使用 ({d.get('used_gb')}/{d.get('total_gb')} GB)")
    L.append(f"- メモリ: {m.get('used_pct')}% 使用 (空き {m.get('available_gb')} GB / 全 {m.get('total_gb')} GB)")
    L.append(f"- swap: {s.get('used_pct')}% 使用 (全 {s.get('total_gb')} GB)")
    L.append(f"- load: 1m={lo.get('1m')} 5m={lo.get('5m')} 15m={lo.get('15m')} ({lo.get('cpu_count')} 核, 每核 {lo.get('per_cpu_1m')})")
    L.append("")
    # 容器
    L.append("## コンテナ状態")
    L.append("")
    L.append("| Container | Watched | Status | Health | Restarts | OOM |")
    L.append("|-----------|---------|--------|--------|----------|-----|")
    for c in containers:
        L.append(f"| {c['name']} | {'★' if c['watched'] else ''} | {c['status']} | {c['health']} | {c['restarts']} | {'⚠️' if c['oom_killed'] else ''} |")
    L.append("")
    # 网页
    if web:
        L.append("## Web 可用性")
        L.append("")
        L.append("| Target | Status | OK | Latency |")
        L.append("|--------|--------|----|---------|")
        for w in web:
            L.append(f"| {w['name']} | {w.get('status')} | {'✅' if w.get('ok') else '❌'} | {w.get('latency_ms')}ms |")
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


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Sentry+PostHog 平台健康巡检")
    ap.add_argument("--dry-run", action="store_true", help="只采集聚合，不调 LLM")
    ap.add_argument("--stdout", action="store_true", help="报告同时打印到终端")
    ap.add_argument("--show-payload", action="store_true",
                    help="把「原封不动准备发送给 AI 的 JSON」打印到终端（不调 AI）")
    args = ap.parse_args()

    now = dt.datetime.now(dt.timezone.utc)
    generated_at = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    host = collect_host()
    cinfo, containers = collect_containers()
    web = collect_web()
    if cinfo.get("error"):
        print(f"[warn] 容器采集失败: {cinfo['error']}（可能需要 sudo -E 运行）", file=sys.stderr)
    alerts = compute_alerts(host, containers, web)

    snapshot = {
        "generated_at": generated_at,
        "host": host,
        "containers": containers,
        "container_collect_error": cinfo.get("error"),
        "web": web,
        "alerts": alerts,
    }

    ai_payload = build_ai_payload(snapshot)

    # 打印「准备发给 AI 的 payload」并直接结束（--show-payload 隐含不调 AI）
    if args.show_payload:
        print("===== 以下 JSON 就是准备发送给 AI 的内容（--show-payload，已精简）=====")
        print(json.dumps(ai_payload, ensure_ascii=False, indent=2))
        print("===== 结束（未调用 AI，未写文件；完整快照见 out/health_*.json）=====")
        return

    ai_text = ""
    if not args.dry_run:
        if not ANTHROPIC_API_KEY:
            print("[warn] 未设置 ANTHROPIC_API_KEY，跳过 AI 诊断（等同 --dry-run）", file=sys.stderr)
        else:
            try:
                ai_text = ai_diagnose(ai_payload)
            except Exception as e:  # noqa
                print(f"[warn] AI 诊断失败: {e}", file=sys.stderr)

    md = render_markdown(snapshot, ai_text, generated_at)

    os.makedirs(OUT_DIR, exist_ok=True)
    stamp = now.strftime("%Y%m%d_%H%M%S")
    with open(os.path.join(OUT_DIR, f"health_{stamp}.json"), "w", encoding="utf-8") as f:
        json.dump(snapshot, f, ensure_ascii=False, indent=2)
    with open(os.path.join(OUT_DIR, f"health_{stamp}.md"), "w", encoding="utf-8") as f:
        f.write(md)
    with open(os.path.join(OUT_DIR, "health_latest.md"), "w", encoding="utf-8") as f:
        f.write(md)
    cleanup_old(OUT_DIR, KEEP_DAYS)

    n_crit = sum(1 for a in alerts if a.startswith("[CRIT]"))
    print(f"[ok] containers={len(containers)} alerts={len(alerts)} crit={n_crit}")
    if args.stdout or args.dry_run:
        print("\n" + md)


if __name__ == "__main__":
    main()