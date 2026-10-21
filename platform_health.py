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
  # 加 AI 诊断（AI_PROVIDER=gemini 需 GEMINI_API_KEY；=anthropic 需 ANTHROPIC_API_KEY）
  python3 platform_health.py

注意：读取 docker 信息通常需要权限。若你平时用 `sudo docker`，
      则用 `sudo python3 platform_health.py`（.env 由脚本自行读取，无需 -E），
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
import math
import re
import socket
import fcntl
from urllib import request, error


# ----------------------------------------------------------------------------
# 自动加载同目录 .env（已存在的环境变量优先，不覆盖；空值忽略）
# 放在读取配置之前；sudo 会清空环境变量，所以由脚本自己读文件最可靠。
# ----------------------------------------------------------------------------
def _load_dotenv():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.split(" #", 1)[0].strip().strip('"').strip("'")
                if v:  # 空值视为未设置，走代码默认值（如 OUT_DIR=）
                    os.environ.setdefault(k.strip(), v)
    except FileNotFoundError:
        pass


_load_dotenv()

# ----------------------------------------------------------------------------
# 配置（环境变量）
# ----------------------------------------------------------------------------
# 平台核心容器（名称包含即匹配，用于标 ★）。注意别写 sentry/posthog 这种所有容器都含的词，否则 ★ 失去区分意义。
WATCH_PREFIXES = os.environ.get(
    "WATCH_PREFIXES",
    "-web-,-nginx-,-relay-,-postgres-,-db-,-pgbouncer-,-kafka-,-clickhouse-,-redis,"
    "-snuba-api-,-taskworker-,-capture-,-ingestion-",
).split(",")
# 完全不参与判定的容器（逗号分隔，名称包含即匹配），用于已知的一次性/废弃容器
IGNORE_CONTAINERS = [p.strip() for p in os.environ.get("IGNORE_CONTAINERS", "").split(",") if p.strip()]

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
SWAP_WARN_GB = float(os.environ.get("SWAP_WARN_GB", "8"))     # swap 已用 ≥ N GiB（同 Slack SWAP_WARN_GB）
SWAP_CRIT_GB = float(os.environ.get("SWAP_CRIT_GB", "10"))    # 同 Slack SWAP_CRIT_GB
LOAD_PER_CPU_WARN = float(os.environ.get("LOAD_PER_CPU_WARN", "1.5"))  # 每核 load
RECENT_RESTART_DAYS = float(os.environ.get("RECENT_RESTART_DAYS", "1"))  # uptime < N 天视为「最近重启」
WEB_LATENCY_WARN_MS = int(os.environ.get("WEB_LATENCY_WARN_MS", "5000"))  # 网页/健康端点响应过慢阈值
# 以下为本脚本独有（Slack 不管的「趋势/活动」类信号，依赖上次巡检的 state.json）
SWAP_IO_WARN_KBPS = float(os.environ.get("SWAP_IO_WARN_KBPS", "1024"))  # 上次巡检以来 swap 换入+换出平均 KB/s
RESTART_DELTA_CRIT = int(os.environ.get("RESTART_DELTA_CRIT", "3"))  # 上次巡检以来新增重启 ≥N → CRIT（≥1 → WARN）
TOP_MEM_N = int(os.environ.get("TOP_MEM_N", "8"))                     # 发给 AI 的内存占用前 N 名容器
DISK_TREND_DAYS = float(os.environ.get("DISK_TREND_DAYS", "14"))      # 磁盘增速按最近 N 天的样本线性回归
DISK_FORECAST_WARN_DAYS = float(os.environ.get("DISK_FORECAST_WARN_DAYS", "30"))  # 预计 N 天内到达 DISK_WARN → WARN

# AI
AI_PROVIDER = os.environ.get("AI_PROVIDER", "gemini").strip().lower()   # gemini | anthropic
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-pro")
GEMINI_FALLBACK_MODEL = os.environ.get("GEMINI_FALLBACK_MODEL", "gemini-2.5-flash")  # 主模型重试仍失败时改用（空=不降级）
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")
REPORT_LANG = os.environ.get("REPORT_LANG", "ja")

# 产物
OUT_DIR = os.environ.get("OUT_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"))
KEEP_DAYS = int(os.environ.get("KEEP_DAYS", "14"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "10"))
# slack_alert.sh 里给部分容器设的内存阈值（GiB），格式同其 CONTAINERS 数组；改动时两边一起改
CONTAINER_MEM_BUDGETS = os.environ.get(
    "CONTAINER_MEM_BUDGETS",
    "posthog-web-1:5,posthog-clickhouse-1:2,sentry-self-hosted-web-1:1.5,sentry-self-hosted-snuba-api-1:2")
BUDGET_INFO_PCT = float(os.environ.get("BUDGET_INFO_PCT", "80"))   # 占阈值 ≥ N% → INFO（Slack 在 95% 持续时实时报）

# nginx 访问日志的 5xx 统计（窗口 = 上次巡检以来，最长 NGINX_MAX_WINDOW_H 小时）
NGINX_CONTAINERS = [c.strip() for c in os.environ.get("NGINX_CONTAINERS", "sentry-self-hosted-nginx-1").split(",") if c.strip()]
NGINX_MAX_WINDOW_H = float(os.environ.get("NGINX_MAX_WINDOW_H", "24"))
NGINX_5XX_WARN_PCT = float(os.environ.get("NGINX_5XX_WARN_PCT", "1"))    # 5xx 占比 ≥ N% 且
NGINX_5XX_WARN_MIN = int(os.environ.get("NGINX_5XX_WARN_MIN", "20"))     # 件数 ≥ N → WARN；否则有 5xx 只记 INFO

# Slack 通知：只在状态变化时发（WARN/CRIT 新增或消除、总合状态改变）。留空则不发
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

GIB, MIB = 1024 ** 3, 1024 ** 2   # 容量统一用二进制单位（同 docker stats / df -h / slack_alert.sh）
STATE_FILE = os.path.join(OUT_DIR, "state.json")   # 上次巡检的计数器（重启次数 / swap 换页），用于算增量

# CloudWatch（经 aws CLI；需要实例角色有 cloudwatch:GetMetricData / cloudwatch:DescribeAlarms）
CLOUDWATCH = os.environ.get("CLOUDWATCH", "1") != "0"          # 0 = 完全不查 CloudWatch
CW_INSTANCE_ID = os.environ.get("CW_INSTANCE_ID", "")          # 留空则从 IMDS 自动取
CW_REGION = os.environ.get("AWS_REGION", "") or os.environ.get("AWS_DEFAULT_REGION", "")  # 留空则从 IMDS 取
CW_CPU_WARN = float(os.environ.get("CW_CPU_WARN", "80"))        # 近 1h CPU 平均 % ≥ → WARN
CW_BALANCE_WARN = float(os.environ.get("CW_BALANCE_WARN", "20"))  # EBS IO/Byte 突发余额 % ≤ → WARN（将被限速）
CW_CPU_CREDIT_WARN = float(os.environ.get("CW_CPU_CREDIT_WARN", "10"))  # T 系 CPU credit 余额 ≤ → WARN
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


def _short(text, n=300):
    """错误信息只留首尾要点，避免把整条命令/上百行输出塞进报告。"""
    t = " ".join((text or "").split())
    return t if len(t) <= n else t[:n] + "…"


def collect_containers():
    """用 docker inspect 采集所有容器的关键状态。docker 不可用则返回错误标记。"""
    if shutil.which("docker") is None:
        return {"error": "docker 命令不可用（PATH 中找不到）"}, []
    # 先列出所有容器（含已停止）的完整 ID 与名称。ID 从 ps 取：{{.ID}} 是 ps 格式里最通用的写法
    try:
        ps_out = subprocess.run(
            ["docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}"],
            capture_output=True, text=True, timeout=20, check=True,
        ).stdout
    except subprocess.CalledProcessError as e:
        return {"error": f"docker ps 失败：{_short(e.stderr) or e.returncode}"}, []
    except Exception as e:  # noqa
        return {"error": f"docker ps 异常：{e}"}, []

    ids = {}
    for line in ps_out.splitlines():
        if "\t" in line:
            cid, name = line.split("\t", 1)
            ids[name.strip()] = cid.strip()
    names = list(ids)
    if not names:
        return {"error": None, "note": "未发现任何容器"}, []

    # 一次 inspect 全部，输出可解析的分隔行
    fmt = ("{{.Name}}\t{{.State.Status}}\t"
           "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}\t"
           "{{.RestartCount}}\t{{.State.OOMKilled}}\t{{.State.StartedAt}}\t{{.State.ExitCode}}")
    try:
        r = subprocess.run(["docker", "inspect", "--format", fmt] + names,
                           capture_output=True, text=True, timeout=30)
    except Exception as e:  # noqa
        return {"error": f"docker inspect 异常：{e}"}, []
    insp = r.stdout
    # 非 0 退出也先解析已有输出（例如 ps 与 inspect 之间有容器被删掉，只影响那一个）
    inspect_err = f"docker inspect 失败（exit {r.returncode}）：{_short(r.stderr)}" if r.returncode else None

    containers = []
    for line in insp.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 7:
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
            "exit_code": int(parts[6]) if parts[6].lstrip("-").isdigit() else None,
            "watched": watched,
            "ignored": any(p in name for p in IGNORE_CONTAINERS),
            "id": ids.get(name, ""),
        })
    containers.sort(key=lambda c: (not c["watched"], c["name"]))
    if inspect_err and not containers:
        return {"error": inspect_err}, []
    if inspect_err:
        print(f"[warn] {inspect_err}（已解析 {len(containers)}/{len(names)} 个容器）", file=sys.stderr)
    return {"error": None, "partial": inspect_err}, containers


# ----------------------------------------------------------------------------
# 2) 主机资源（零依赖：statvfs + /proc）
# ----------------------------------------------------------------------------
def collect_host():
    host = {}
    # 磁盘（根分区）。口径同 `df`（slack_alert.sh 用的就是 df 的 Use%）：
    #   used = 总块 - 空闲块；Use% = ceil(used / (used + 普通用户可用))，保留块不计入分母
    try:
        st = os.statvfs("/")
        used = (st.f_blocks - st.f_bfree) * st.f_frsize
        avail = st.f_bavail * st.f_frsize
        host["disk"] = {
            "total_gib": round(st.f_blocks * st.f_frsize / GIB, 1),
            "used_gib": round(used / GIB, 1),
            "avail_gib": round(avail / GIB, 1),
            "used_pct": math.ceil(used * 100 / (used + avail)) if used + avail else None,
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
        host["mem"] = {   # /proc/meminfo 为 KiB → GiB（同 slack_alert.sh 的 ÷1048576）
            "total_gib": round(mem_total / 1048576, 1),
            "available_gib": round(mem_avail / 1048576, 2),
            "used_pct": round((mem_total - mem_avail) / mem_total * 100, 1) if mem_total else None,
        }
        sw_total = mi.get("SwapTotal", 0)
        sw_free = mi.get("SwapFree", 0)
        host["swap"] = {
            "total_gib": round(sw_total / 1048576, 1),
            "used_gib": round((sw_total - sw_free) / 1048576, 2),
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
# 1b) 容器内存 / swap（cgroup v2 直读，零开销；读不到时退回 docker stats，仅内存）
# ----------------------------------------------------------------------------
def _read_cg_int(path):
    with open(path) as f:
        v = f.read().strip()
    return None if v == "max" else int(v)


def _cgroup_dir(cid):
    # systemd cgroup driver（Amazon Linux 2023 等默认） / cgroupfs driver
    for d in (f"/sys/fs/cgroup/system.slice/docker-{cid}.scope", f"/sys/fs/cgroup/docker/{cid}"):
        if os.path.isdir(d):
            return d
    return None


_SIZE_UNITS = {"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3}


def _parse_size(text):
    """'1.23GiB' → 字节数。"""
    t = text.strip().lower()
    for u in sorted(_SIZE_UNITS, key=len, reverse=True):
        if t.endswith(u):
            return float(t[: -len(u)]) * _SIZE_UNITS[u]
    return float(t)


def collect_container_mem(containers):
    """给运行中容器补上 mem_mib / swap_mib / mem_limit_mib（口径同 docker stats：memory.current - inactive_file）。"""
    found = 0
    for c in containers:
        if c["status"] != "running" or not c.get("id"):
            continue
        d = _cgroup_dir(c["id"])
        if not d:
            continue
        try:
            cur = _read_cg_int(os.path.join(d, "memory.current"))
            inactive = 0
            with open(os.path.join(d, "memory.stat")) as f:
                for line in f:
                    if line.startswith("inactive_file "):
                        inactive = int(line.split()[1])
                        break
            c["mem_mib"] = round((cur - inactive) / MIB)
            sw = os.path.join(d, "memory.swap.current")
            if os.path.exists(sw):
                c["swap_mib"] = round(_read_cg_int(sw) / MIB)
            lim = _read_cg_int(os.path.join(d, "memory.max"))
            c["mem_limit_mib"] = round(lim / MIB) if lim else None
            found += 1
        except (OSError, ValueError, TypeError):
            continue
    if found or not any(c["status"] == "running" for c in containers):
        return
    # cgroup 读不到（cgroup v1 等）→ docker stats 兜底，约 2 秒
    try:
        out = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.MemUsage}}"],
                             capture_output=True, text=True, timeout=30, check=True).stdout
    except Exception:  # noqa
        return
    by_name = {c["name"]: c for c in containers}
    for line in out.splitlines():
        try:
            name, usage = line.split("\t", 1)
            used, limit = usage.split("/", 1)
            if name in by_name:
                by_name[name]["mem_mib"] = round(_parse_size(used) / MIB)
                by_name[name]["mem_limit_mib"] = round(_parse_size(limit) / MIB)
        except ValueError:
            continue


def apply_mem_budgets(containers):
    budgets = {}
    for item in CONTAINER_MEM_BUDGETS.split(","):
        if ":" in item:
            n, g = item.rsplit(":", 1)
            try:
                budgets[n.strip()] = float(g)
            except ValueError:
                pass
    for c in containers:
        b = budgets.get(c["name"])
        if b and isinstance(c.get("mem_mib"), int):
            c["budget_gib"] = b
            c["budget_pct"] = round(c["mem_mib"] * MIB * 100 / (b * GIB))


# ----------------------------------------------------------------------------
# 1c) swap 换入/换出活动（/proc/vmstat 的累计页数 → 速率）
#     「swap 已用量」只说明曾经换出过；「换页速率」才说明现在是否有内存压力。
# ----------------------------------------------------------------------------
PAGE_KB = os.sysconf("SC_PAGE_SIZE") / 1024 if hasattr(os, "sysconf") else 4


def read_vmstat():
    r = {}
    try:
        with open("/proc/vmstat") as f:
            for line in f:
                k, v = line.split()
                if k in ("pswpin", "pswpout"):
                    r[k] = int(v)
    except (OSError, ValueError):
        pass
    return r


def _swap_rate(v0, v1, seconds):
    if seconds <= 0 or not v0 or not v1:
        return None
    din, dout = v1.get("pswpin", 0) - v0.get("pswpin", 0), v1.get("pswpout", 0) - v0.get("pswpout", 0)
    if din < 0 or dout < 0:      # 重启过主机，计数器归零
        return None
    return {"in_kbps": round(din * PAGE_KB / seconds, 1), "out_kbps": round(dout * PAGE_KB / seconds, 1)}


# ----------------------------------------------------------------------------
# 1d) 上次巡检的状态（重启次数 / swap 计数器），用于算「增量」而不是看累计值
# ----------------------------------------------------------------------------
def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(prev, containers, collect_ok, vmstat, ts, disk_history, notify):
    state = {"ts": ts, "vmstat": vmstat, "disk_avail_history": disk_history, "notify": notify,
             # 容器采集失败时沿用上次的容器计数，避免下次算出错误增量
             "containers": ({c["name"]: {"restarts": c["restarts"], "started_at": c["started_at"]}
                             for c in containers} if collect_ok else prev.get("containers", {}))}
    os.makedirs(OUT_DIR, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def apply_restart_delta(containers, prev):
    """restarts_delta = 上次巡检以来新增的重启次数。无上次记录 / 容器被重建（计数归零）时为 None。
    restarted_since_last = 启动时间变了。RestartCount 只统计 restart policy 触发的重启，
    `docker restart`、compose 重建、定时任务重启都不会让它增加，只能靠启动时间发现。"""
    pc = prev.get("containers", {})
    for c in containers:
        p = pc.get(c["name"])
        if p and isinstance(c["restarts"], int) and isinstance(p.get("restarts"), int):
            d = c["restarts"] - p["restarts"]
            c["restarts_delta"] = d if d >= 0 else None
        else:
            c["restarts_delta"] = None
        c["restarted_since_last"] = bool(p and p.get("started_at") and c["status"] == "running"
                                         and p["started_at"] != c["started_at"])


# ----------------------------------------------------------------------------
# 1e) 磁盘增速与到达阈值的预测（样本存 state.json；首次时从 out/ 里的历史快照补种）
# ----------------------------------------------------------------------------
def _seed_disk_history():
    """从 out/ 的历史快照补种「可用空间 GiB」样本。兼容旧格式（十进制 GB 的 total_gb/used_gb）。"""
    hist = []
    try:
        names = sorted(n for n in os.listdir(OUT_DIR) if n.startswith("health_2") and n.endswith(".json"))
    except OSError:
        return hist
    for n in names:
        try:
            ts = dt.datetime.strptime(n[7:22], "%Y%m%d_%H%M%S").replace(tzinfo=dt.timezone.utc).timestamp()
            with open(os.path.join(OUT_DIR, n), encoding="utf-8") as f:
                d = json.load(f)["host"]["disk"]
            avail = d["avail_gib"] if "avail_gib" in d else (d["total_gb"] - d["used_gb"]) * 1e9 / GIB
            hist.append([ts, round(avail, 2)])
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return hist


def update_disk_history(prev, disk, ts):
    # 记录「可用空间」而不是「已用量」：不受口径（是否计保留块）和单位变化影响，曲线不会断
    hist = prev.get("disk_avail_history") or _seed_disk_history()
    if isinstance(disk.get("avail_gib"), (int, float)):
        hist.append([ts, disk["avail_gib"]])
    cutoff = ts - DISK_TREND_DAYS * 86400
    return [h for h in hist if h[0] >= cutoff]


def disk_trend(hist, disk):
    """最小二乘求每天消耗的 GiB，并预测 Use%（df 口径）到达 DISK_WARN / DISK_CRIT 的天数。样本跨度不足 12 小时则不算。"""
    used, avail = disk.get("used_gib"), disk.get("avail_gib")
    if len(hist) < 2 or used is None or avail is None or hist[-1][0] - hist[0][0] < 12 * 3600:
        return None
    xs = [(t - hist[0][0]) / 86400 for t, _ in hist]
    ys = [a for _, a in hist]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    var = sum((x - mx) ** 2 for x in xs)
    growth = -sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / var   # 可用空间减少速度 = 增长速度
    out = {"gib_per_day": round(growth, 2), "span_days": round(xs[-1], 1), "points": len(hist)}
    cap = used + avail     # df 的 Use% 分母
    for key, pct in (("warn", DISK_WARN), ("crit", DISK_CRIT)):
        remain = avail - cap * (1 - pct / 100)
        if growth > 0.01 and remain > 0:
            days = remain / growth
            out[f"days_to_{key}"] = round(days)
            out[f"eta_{key}"] = (dt.datetime.fromtimestamp(hist[-1][0], dt.timezone.utc)
                                 + dt.timedelta(days=days)).strftime("%Y-%m-%d")
    return out


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
            rec["ok"] = False  # 4xx/5xx 也算「有响应」，但标记 ok=False
        except Exception as e:  # noqa
            rec["status"] = None
            rec["ok"] = False
            rec["error"] = str(e)
        rec["latency_ms"] = int((time.time() - t0) * 1000)
        results.append(rec)
    return results


# ----------------------------------------------------------------------------
# 3b) nginx 访问日志：窗口内请求数与 5xx（流式计数，内存有界）
#     路径去掉 query（Sentry 的上报 URL 带 sentry_key），数字段归一为 {n} 便于聚合
# ----------------------------------------------------------------------------
_ACCESS_RE = re.compile(r'"([A-Z]+) (\S+) [^"]*" (\d{3}) ')


def _norm_path(path):
    path = path.split("?", 1)[0]
    return re.sub(r"/[0-9a-f]{16,}|/\d+", lambda m: "/{id}" if len(m.group()) > 12 else "/{n}", path)[:80]


def collect_nginx(window_s):
    out = []
    for name in NGINX_CONTAINERS:
        rec = {"container": name, "window_h": round(window_s / 3600, 1)}
        try:
            proc = subprocess.Popen(["docker", "logs", "--since", f"{int(window_s)}s", name],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
            total = n5 = 0
            codes, paths = {}, {}
            deadline = time.time() + 60
            for line in proc.stdout:
                m = _ACCESS_RE.search(line)
                if not m:
                    continue
                total += 1
                if m.group(3).startswith("5"):
                    n5 += 1
                    codes[m.group(3)] = codes.get(m.group(3), 0) + 1
                    key = f"{m.group(1)} {_norm_path(m.group(2))}"
                    if key in paths or len(paths) < 200:
                        paths[key] = paths.get(key, 0) + 1
                if time.time() > deadline:
                    proc.kill()
                    rec["truncated"] = True
                    break
            proc.wait(timeout=10)
            if proc.returncode not in (0, None, -9) and total == 0:
                raise RuntimeError(f"docker logs exit {proc.returncode}")
            rec.update({"requests": total, "5xx": n5,
                        "5xx_pct": round(n5 * 100 / total, 2) if total else 0.0,
                        "by_code": codes,
                        "top_paths": sorted(paths.items(), key=lambda kv: -kv[1])[:5]})
        except Exception as e:  # noqa
            rec["error"] = _short(str(e))
        out.append(rec)
    return out


# ----------------------------------------------------------------------------
# 4) CloudWatch：AWS 侧看到的 EC2 实例指标 + 与本实例相关的 CloudWatch 告警
#    经 aws CLI 调用（Amazon Linux 自带），保持零第三方依赖。
#    本机信号看「容器/进程内部」，CloudWatch 看「实例外部」（网络、EBS 限速、状态检查、CPU credit）。
# ----------------------------------------------------------------------------
CW_PERIOD = 300   # EC2 基础监控为 5 分钟粒度
CW_METRICS = [
    # (query id, MetricName, Stat, 换算, 单位)  换算：None=原值 / "kbps"=Sum 字节÷周期÷1024 / "rate"=Sum÷周期
    ("cpu", "CPUUtilization", "Average", None, "%"),
    ("cpu_peak", "CPUUtilization", "Maximum", None, "%"),
    ("net_in", "NetworkIn", "Sum", "kbps", "KB/s"),
    ("net_out", "NetworkOut", "Sum", "kbps", "KB/s"),
    ("ebs_read", "EBSReadBytes", "Sum", "kbps", "KB/s"),
    ("ebs_write", "EBSWriteBytes", "Sum", "kbps", "KB/s"),
    ("ebs_read_iops", "EBSReadOps", "Sum", "rate", "IOPS"),
    ("ebs_write_iops", "EBSWriteOps", "Sum", "rate", "IOPS"),
    ("ebs_io_balance", "EBSIOBalance%", "Minimum", None, "%"),      # 突发型 EBS 带宽余额（Nitro 小规格）
    ("ebs_byte_balance", "EBSByteBalance%", "Minimum", None, "%"),
    ("cpu_credit", "CPUCreditBalance", "Minimum", None, "credits"),  # 仅 T 系实例有
    ("status_failed", "StatusCheckFailed", "Maximum", None, ""),     # 1 = 系统/实例状态检查失败
]


def _imds(path, token, timeout=2):
    req = request.Request(f"http://169.254.169.254/latest/{path}", headers={"X-aws-ec2-metadata-token": token})
    with request.urlopen(req, timeout=timeout) as r:
        return r.read().decode().strip()


def _instance_identity():
    """(instance_id, region, instance_type)。环境变量优先，其余从 IMDSv2 取；不在 EC2 上则抛异常。"""
    iid, region, itype = CW_INSTANCE_ID, CW_REGION, None
    try:
        tok_req = request.Request("http://169.254.169.254/latest/api/token", method="PUT",
                                  headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        with request.urlopen(tok_req, timeout=2) as r:
            token = r.read().decode()
        iid = iid or _imds("meta-data/instance-id", token)
        region = region or _imds("meta-data/placement/region", token)
        itype = _imds("meta-data/instance-type", token)
    except Exception as e:  # noqa
        if not (iid and region):
            raise RuntimeError(f"无法从 IMDS 取得实例信息（不在 EC2 上？）：{e}")
    return iid, region, itype


def _aws(args, region, timeout=40):
    try:
        r = subprocess.run(["aws"] + args + ["--region", region, "--output", "json"],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"aws {args[1]} 超时（{timeout}s）") from None
    if r.returncode:
        err = r.stderr
        if "AccessDenied" in err or "not authorized" in err:
            raise RuntimeError(f"IAM 权限不足：实例角色缺少 cloudwatch:{_CW_ACTION.get(args[1], args[1])}")
        raise RuntimeError(f"aws {args[1]} 失败：{_short(err)}")
    return json.loads(r.stdout or "{}")


_CW_ACTION = {"get-metric-data": "GetMetricData", "describe-alarms": "DescribeAlarms"}


def _summarize(points, conv):
    """points: [(ts, value)] 新→旧。返回 latest + 近 1h / 24h 的 avg/min/max（已换算单位）。"""
    if not points:
        return None
    f = (lambda v: v / CW_PERIOD / 1024) if conv == "kbps" else (lambda v: v / CW_PERIOD) if conv == "rate" else (lambda v: v)
    newest = points[0][0]
    out = {"latest": round(f(points[0][1]), 1)}
    for label, hours in (("1h", 1), ("24h", 24)):
        vals = [f(v) for ts, v in points if (newest - ts).total_seconds() < hours * 3600]
        if vals:
            out[label] = {"avg": round(sum(vals) / len(vals), 1), "min": round(min(vals), 1), "max": round(max(vals), 1)}
    return out


def _parse_cw_ts(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def collect_cloudwatch():
    """返回 None（已用 CLOUDWATCH=0 关闭）或 dict。失败不抛异常，写进 error 字段，其余巡检照常。"""
    if not CLOUDWATCH:
        return None
    cw = {"error": None}
    if shutil.which("aws") is None:
        cw["error"] = "aws CLI 不可用（PATH 中找不到）"
        return cw
    try:
        iid, region, itype = _instance_identity()
    except RuntimeError as e:
        cw["error"] = str(e)
        return cw
    cw.update({"instance_id": iid, "region": region, "instance_type": itype, "period_s": CW_PERIOD})

    # --- 指标：一次 GetMetricData 取 24h 全部（12 指标 × 288 点，远低于单次上限）
    end = dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0)
    queries = [{"Id": qid, "ReturnData": True,
                "MetricStat": {"Metric": {"Namespace": "AWS/EC2", "MetricName": name,
                                          "Dimensions": [{"Name": "InstanceId", "Value": iid}]},
                               "Period": CW_PERIOD, "Stat": stat}}
               for qid, name, stat, _, _ in CW_METRICS]
    try:
        data = _aws(["cloudwatch", "get-metric-data",
                     "--metric-data-queries", json.dumps(queries),
                     "--start-time", (end - dt.timedelta(hours=24)).isoformat(),
                     "--end-time", end.isoformat(),
                     "--scan-by", "TimestampDescending"], region)
        meta = {q[0]: q for q in CW_METRICS}
        metrics = {}
        for res in data.get("MetricDataResults", []):
            qid = res.get("Id")
            pts = list(zip(map(_parse_cw_ts, res.get("Timestamps", [])), res.get("Values", [])))
            summ = _summarize(pts, meta[qid][3]) if qid in meta else None
            if summ:   # 没有数据的指标（如非 T 系没有 CPUCreditBalance）直接省略
                summ["unit"] = meta[qid][4]
                metrics[qid] = summ
        cw["metrics"] = metrics
    except RuntimeError as e:
        cw["error"] = str(e)
        return cw

    # --- 与本实例相关的 CloudWatch 告警（维度含本实例 ID）
    try:
        alarms = _aws(["cloudwatch", "describe-alarms"], region).get("MetricAlarms", [])
        mine = [a for a in alarms if any(d.get("Value") == iid for d in a.get("Dimensions", []))]
        cw["alarms"] = [{"name": a.get("AlarmName"), "state": a.get("StateValue"),
                         "metric": a.get("MetricName"), "threshold": a.get("Threshold"),
                         "reason": _short(a.get("StateReason"), 160)} for a in mine]
    except RuntimeError as e:
        cw["alarms_error"] = str(e)   # 告警查不到不影响指标
    return cw


# ----------------------------------------------------------------------------
# 计算「关注提示」（确定性规则，给 AI 聚焦用；★不是告警通道，实时告警归 slack_alert.sh）
# 刻意只标真信号，避免与 Slack 重复，也避免累计重启这类噪音。
# ----------------------------------------------------------------------------
def compute_alerts(host, containers, web, cw=None, nginx=None):
    alerts = []

    d = host.get("disk", {})
    if isinstance(d.get("used_pct"), (int, float)):
        if d["used_pct"] >= DISK_CRIT:
            alerts.append(f"[CRIT] 磁盘使用率 {d['used_pct']}% ≥ {DISK_CRIT}%")
        elif d["used_pct"] >= DISK_WARN:
            alerts.append(f"[WARN] 磁盘使用率 {d['used_pct']}% ≥ {DISK_WARN}%")
    tr = host.get("disk_trend") or {}
    if "days_to_warn" in tr and tr["days_to_warn"] <= DISK_FORECAST_WARN_DAYS:
        alerts.append(f"[WARN] 磁盘按 +{tr['gib_per_day']}GiB/天 增长，约 {tr['days_to_warn']} 天后（{tr['eta_warn']} 前后）"
                      f"达到 {DISK_WARN}%")

    m = host.get("mem", {})
    av = m.get("available_gib")
    if isinstance(av, (int, float)):
        if av < MEM_AVAIL_CRIT_GB:      # slack_alert.sh：floor(GiB) < 阈值 ⇔ GiB < 阈值
            alerts.append(f"[CRIT] 可用内存仅 {av}GiB < {MEM_AVAIL_CRIT_GB}GiB")
        elif av < MEM_AVAIL_WARN_GB:
            alerts.append(f"[WARN] 可用内存 {av}GiB < {MEM_AVAIL_WARN_GB}GiB")

    s = host.get("swap", {})
    sio = host.get("swap_io", {})
    # 用换页速率给「swap 已用量」加注：已用多但几乎不换页 → 多为历史残留
    # 优先用「上次巡检以来」的长窗口；3 秒的瞬时值易被本次巡检自身触发的换入干扰
    rate = sio.get("since_last") or sio.get("now")
    hint, idle = "", False
    if rate:
        tot = round(rate["in_kbps"] + rate["out_kbps"], 1)
        idle = tot < SWAP_IO_WARN_KBPS / 10
        hint = (f"（换页 {tot}KB/s，几乎无活动，多为历史换出的残留，已降级）" if idle
                else f"（换页 {tot}KB/s，仍在活跃换页）")
    su = s.get("used_gib")
    if isinstance(su, (int, float)):
        # 闲置的 swap 不影响性能：降一级（WARN→INFO、CRIT→WARN），避免每次都报成噪音。
        # Slack 的绝对阈值告警不受影响；真正的内存压力由下面的「持续换页」规则负责。
        if su >= SWAP_CRIT_GB:
            alerts.append(f"[{'WARN' if idle else 'CRIT'}] swap 已用 {su}GiB ≥ {SWAP_CRIT_GB}GiB{hint}")
        elif su >= SWAP_WARN_GB:
            alerts.append(f"[{'INFO' if idle else 'WARN'}] swap 已用 {su}GiB ≥ {SWAP_WARN_GB}GiB{hint}")
    sl = sio.get("since_last")
    if sl and sl["in_kbps"] + sl["out_kbps"] >= SWAP_IO_WARN_KBPS:
        alerts.append(f"[WARN] 上次巡检以来 swap 持续换页：换入 {sl['in_kbps']}KB/s / 换出 {sl['out_kbps']}KB/s"
                      f"（≥{SWAP_IO_WARN_KBPS}KB/s，存在实际内存压力）")

    l = host.get("load", {})
    if isinstance(l.get("per_cpu_1m"), (int, float)) and l["per_cpu_1m"] >= LOAD_PER_CPU_WARN:
        alerts.append(f"[WARN] 每核 load {l['per_cpu_1m']}（1m {l.get('1m')} / {l.get('cpu_count')} 核）")

    for c in containers:
        if c.get("ignored"):
            continue
        tag = "核心容器" if c["watched"] else "容器"
        # OOM 不论当前状态都要报（停掉的容器恰恰可能是被 OOM 杀的）
        if c.get("oom_killed"):
            alerts.append(f"[CRIT] {tag} {c['name']} 曾被 OOM kill（status={c['status']}）")
        st = c["status"]
        if st != "running":
            if st == "exited" and c.get("exit_code") == 0:
                # 正常结束：多为一次性任务（migration 等），不算故障
                alerts.append(f"[INFO] {tag} {c['name']} 已正常退出（exit 0，可能是一次性任务；"
                              f"如属预期可加入 IGNORE_CONTAINERS）")
            elif st == "created":
                alerts.append(f"[INFO] {tag} {c['name']} 已创建但从未启动（status=created）")
            elif st == "paused":
                alerts.append(f"[WARN] {tag} {c['name']} 被暂停（status=paused）")
            else:
                # exited≠0 / restarting / dead / removing
                detail = f"，exit {c.get('exit_code')}" if st == "exited" else ""
                alerts.append(f"[CRIT] {tag} {c['name']} 未运行（status={st}{detail}）")
            continue
        if c["health"] not in ("none", "healthy"):
            alerts.append(f"[WARN] {tag} {c['name']} health={c['health']}")
        if c.get("budget_pct") is not None and c["budget_pct"] >= BUDGET_INFO_PCT:
            alerts.append(f"[INFO] {tag} {c['name']} 内存 {c['mem_mib']}MiB，已达 Slack 阈值 {c['budget_gib']}GiB 的 "
                          f"{c['budget_pct']}%（≥95% 持续时 Slack 实时报警）")
        # 重启只看增量（上次巡检以来），不看无意义的累计次数
        rd = c.get("restarts_delta")
        if rd:
            lv = "CRIT" if rd >= RESTART_DELTA_CRIT else "WARN"
            why = "，疑似反复崩溃" if lv == "CRIT" else ""
            alerts.append(f"[{lv}] {tag} {c['name']} 上次巡检以来重启 {rd} 次（累计 {c['restarts']}{why}）")
            continue
        if c.get("restarted_since_last"):
            alerts.append(f"[INFO] {tag} {c['name']} 上次巡检以来被重新启动（RestartCount 未增加 → 非崩溃自愈，"
                          f"而是手动 restart / compose 重建 / 定时任务；启动于 {c['started_at'][:16]}Z）")
            continue
        # 无增量数据（首次运行等）时，退而标「最近重启过」
        ud = c.get("uptime_days")
        if rd is None and isinstance(ud, (int, float)) and ud < RECENT_RESTART_DAYS:
            alerts.append(f"[INFO] {tag} {c['name']} 最近重启过（uptime {ud} 天，累计 {c['restarts']} 次）")

    for w in web:
        if not w.get("ok"):
            detail = w.get("error") or f"HTTP {w.get('status')}"
            alerts.append(f"[CRIT] 网页 {w['name']} 探活失败：{detail}")
        elif isinstance(w.get("latency_ms"), int) and w["latency_ms"] >= WEB_LATENCY_WARN_MS:
            alerts.append(f"[WARN] 网页 {w['name']} 响应过慢：{w['latency_ms']}ms（≥{WEB_LATENCY_WARN_MS}ms，疑似依赖变慢）")

    for n in nginx or []:
        if n.get("error"):
            alerts.append(f"[INFO] nginx 日志 {n['container']} 未取得：{n['error']}")
        elif n.get("5xx"):
            lv = "WARN" if n["5xx"] >= NGINX_5XX_WARN_MIN and n["5xx_pct"] >= NGINX_5XX_WARN_PCT else "INFO"
            codes = ", ".join(f"{k}×{v}" for k, v in sorted(n["by_code"].items()))
            alerts.append(f"[{lv}] nginx {n['container']} 近 {n['window_h']}h 5xx {n['5xx']} 件 / {n['requests']} 请求"
                          f"（{n['5xx_pct']}%：{codes}）")

    if cw is not None:
        if cw.get("error"):
            # 数据源缺失不等于平台有问题，本机信号仍完整 → INFO，不影响总合状态
            alerts.append(f"[INFO] CloudWatch 未取得：{cw['error']}")
        m = cw.get("metrics", {})
        sf = m.get("status_failed", {}).get("1h", {})
        if sf.get("max", 0) >= 1:
            alerts.append("[CRIT] CloudWatch：近 1h EC2 状态检查失败（StatusCheckFailed=1，AWS 侧硬件/网络或实例 OS 异常）")
        cpu = m.get("cpu", {}).get("1h", {})
        if cpu.get("avg", 0) >= CW_CPU_WARN:
            alerts.append(f"[WARN] CloudWatch：近 1h CPU 平均 {cpu['avg']}% ≥ {CW_CPU_WARN}%（峰值 {m.get('cpu_peak', {}).get('1h', {}).get('max')}%）")
        for key, label in (("ebs_io_balance", "EBS IO 突发余额"), ("ebs_byte_balance", "EBS 吞吐突发余额")):
            b = m.get(key)
            if b and b["latest"] <= CW_BALANCE_WARN:
                alerts.append(f"[WARN] CloudWatch：{label} {b['latest']}% ≤ {CW_BALANCE_WARN}%（耗尽后磁盘 IO 被限速，"
                              f"24h 最低 {b.get('24h', {}).get('min')}%）")
        cc = m.get("cpu_credit")
        if cc and cc["latest"] <= CW_CPU_CREDIT_WARN:
            alerts.append(f"[WARN] CloudWatch：CPU credit 余额 {cc['latest']} ≤ {CW_CPU_CREDIT_WARN}（耗尽后 CPU 被限速到基准性能）")
        for a in cw.get("alarms", []):
            if a["state"] == "ALARM":
                alerts.append(f"[WARN] CloudWatch 告警 {a['name']} 处于 ALARM（{a['metric']} 阈值 {a['threshold']}）")

    return alerts


# ----------------------------------------------------------------------------
# 构建「真正发给 AI 的精简 payload」——本地存全量快照，但只把必要内容喂给 LLM 省 token
# ----------------------------------------------------------------------------
def build_ai_payload(snapshot):
    conts = [c for c in snapshot["containers"] if not c.get("ignored")]
    n_ignored = len(snapshot["containers"]) - len(conts)

    def is_nominal(c):
        # 累计重启次数不参与判定（长期累积是常态、属噪音）；只看当前状态与「最近重启」
        ud = c.get("uptime_days")
        recent = isinstance(ud, (int, float)) and ud < RECENT_RESTART_DAYS
        return (c["status"] == "running" and c["health"] in ("healthy", "none")
                and not c.get("oom_killed") and not recent and not c.get("restarts_delta")
                and not c.get("restarted_since_last"))

    # notable = 有非常态特征的容器（未运行/不健康/OOM/最近重启/上次巡检以来有新重启）
    notable = []
    for c in conts:
        if not is_nominal(c):
            notable.append({
                "name": c["name"],
                "status": c["status"],
                "exit_code": c.get("exit_code") if c["status"] == "exited" else None,
                "health": c["health"],
                "restarts": c["restarts"],
                "oom_killed": c["oom_killed"],
                "uptime_days": c.get("uptime_days"),
                "restarts_delta": c.get("restarts_delta"),
                "restarted_since_last": c.get("restarted_since_last"),
                "started_at": c.get("started_at"),
                "mem_mib": c.get("mem_mib"),
                "swap_mib": c.get("swap_mib"),
            })

    # 内存占用前 N 名（无论是否异常都发），让 AI 能把内存/swap 问题落到具体容器
    top_mem = sorted((c for c in conts if isinstance(c.get("mem_mib"), int)),
                     key=lambda c: c["mem_mib"], reverse=True)[:TOP_MEM_N]
    top_memory = [{k: c.get(k) for k in ("name", "mem_mib", "swap_mib", "budget_gib", "budget_pct")}
                  for c in top_mem]
    top_swap = sorted((c for c in conts if c.get("swap_mib")), key=lambda c: c["swap_mib"], reverse=True)[:TOP_MEM_N]
    # slack_alert.sh 盯着的容器：用量相对其阈值的余量（无论是否在前 N 名都发）
    budgets = [{k: c.get(k) for k in ("name", "mem_mib", "budget_gib", "budget_pct")}
               for c in conts if c.get("budget_gib")]

    total = len(conts)
    running = sum(1 for c in conts if c["status"] == "running")
    return {
        "generated_at": snapshot["generated_at"],
        "host": snapshot["host"],
        "containers": {
            "summary": {"total": total, "running": running,
                        "not_running": total - running, "nominal": total - len(notable),
                        "ignored": n_ignored},
            "notable": notable,   # 只发值得看的容器，正常的只给计数
            "top_memory": top_memory,
            "top_swap": [{"name": c["name"], "swap_mib": c["swap_mib"]} for c in top_swap],
            "slack_mem_budgets": budgets,
        },
        "web": snapshot["web"],
        "cloudwatch": snapshot.get("cloudwatch"),
        "nginx": snapshot.get("nginx"),
        "flags": snapshot["alerts"],   # 确定性关注提示
        "rule_status": _overall(snapshot["alerts"]),
        "note_for_ai": ("flags 是确定性提示，实时告警另由 Slack 负责；正常容器已折叠为计数，IGNORE_CONTAINERS 中的容器已排除。"
                        "exit 0 退出的容器多为一次性任务。restarts 是累计值（长期累积属常态），restarts_delta 才是"
                        "上次巡检以来的新增重启。host.swap_io 是换页速率：swap 已用量高但换页速率≈0 表示历史残留，"
                        "不等于当前内存压力。mem_mib/swap_mib 为各容器 cgroup 实测值（MiB），容量单位均为二进制（GiB/MiB）。"
                        "slack_mem_budgets 是现有实时告警 slack_alert.sh 为部分容器设的内存阈值（GiB）及当前占比，"
                        "≥95% 持续 15 分钟时 Slack 会实时报警。"
                        "nginx 是反向代理访问日志的统计（窗口内请求数、5xx 数与比例、按状态码/路径分布）。"
                        "restarted_since_last=true 且 restarts_delta=0 表示非崩溃的重启（手动/重建/定时任务）。"
                        "host.disk_trend 是磁盘增速（GB/天，线性回归）及到达 WARN/CRIT 阈值的预计天数与日期。"
                        "cloudwatch 是 AWS 侧看到的本 EC2 实例指标（5 分钟粒度，latest 与近 1h/24h 的 avg/min/max，"
                        "单位见 unit），用于和本机信号交叉印证；cloudwatch 为 null 表示未启用。"),
    }


# ----------------------------------------------------------------------------
# AI 诊断
# ----------------------------------------------------------------------------
LANG_LABEL = {"ja": "日本語", "zh": "中文", "en": "English"}


def _system_prompt():
    lang = LANG_LABEL.get(REPORT_LANG, "日本語")
    return (
        "あなたは SRE / インフラ運用のアシスタントです。以下は自前ホストの "
        "Sentry + PostHog プラットフォーム（EC2 上、Docker 運用）の健康チェック結果です。"
        "ローカル信号（コンテナ・ホスト）と CloudWatch のインスタンス指標を突き合わせ、"
        "両者の関連（例: EBS 限速とディスク IO、ネットワークと Web 応答）があれば言及すること。"
        f"{lang} で簡潔な健康レポートを書いてください。与えられたデータのみ使用し、"
        "数値を捏造しないこと。構成: 1) 総合ステータス(正常/注意/危険を1行で) "
        "2) 検出された異常とその影響 3) 想定原因 4) 推奨アクション(具体的に)。"
        "異常が無ければその旨を明記。前置き・挨拶は不要、1) から書き始めること。"
        "総合ステータスは rule_status（ルール判定）を基準とし、異なる判断をする場合は根拠を1行で示すこと。"
        "コンテナ再起動・設定変更などサービスに影響する操作は、持続的な換ページ・メモリ上限への接近・"
        "サービス異常など具体的な根拠がある場合に限り推奨し、その根拠を明記すること。"
        "スワップ使用量だけを理由に再起動を推奨しないこと。"
        "disk_trend がある場合は、容量到達の見込み時期と、それまでに取るべき対策（データ保持期間の見直し等）に触れること。"
    )


def _user_content(snapshot):
    return "健康チェックデータ(JSON):\n" + json.dumps(snapshot, ensure_ascii=False, indent=2)


RETRY_STATUS = (429, 500, 502, 503, 504)


def _post(url, payload, headers, timeout, retries=3, backoff=(5, 20)):
    """POST JSON，返回响应文本。限流 / 5xx / 网络错误时退避重试，其余错误立即抛出。"""
    data = json.dumps(payload).encode("utf-8")
    for attempt in range(retries):
        req = request.Request(url, data=data, headers={"content-type": "application/json", **headers}, method="POST")
        try:
            with request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8")
        except error.HTTPError as e:
            msg = f"HTTP {e.code} {e.reason}: {_short(e.read().decode('utf-8', 'replace'), 200)}"
            if e.code not in RETRY_STATUS or attempt == retries - 1:
                raise RuntimeError(msg) from None
        except (error.URLError, TimeoutError, OSError) as e:
            msg = f"网络错误：{e}"
            if attempt == retries - 1:
                raise RuntimeError(msg) from None
        wait = backoff[min(attempt, len(backoff) - 1)]
        print(f"[warn] {msg} → {wait}s 后重试（{attempt + 2}/{retries}）", file=sys.stderr)
        time.sleep(wait)


def _post_json(url, payload, headers, timeout):
    return json.loads(_post(url, payload, headers, timeout))


def _diagnose_gemini(snapshot):
    models = [GEMINI_MODEL] + ([GEMINI_FALLBACK_MODEL] if GEMINI_FALLBACK_MODEL and GEMINI_FALLBACK_MODEL != GEMINI_MODEL else [])
    for i, model in enumerate(models):
        try:
            text = _diagnose_gemini_model(snapshot, model)
            return text + (f"\n\n（※ {GEMINI_MODEL} が失敗したため {model} で生成）" if i else "")
        except RuntimeError as e:
            if i == len(models) - 1:
                raise
            print(f"[warn] {model} 失败：{e} → 改用 {models[i + 1]}", file=sys.stderr)


def _diagnose_gemini_model(snapshot, model):
    payload = {
        "systemInstruction": {"parts": [{"text": _system_prompt()}]},
        "contents": [{"role": "user", "parts": [{"text": _user_content(snapshot)}]}],
        # 2.5 系的思考 token 也计入 maxOutputTokens，留足余量以免正文被截断
        "generationConfig": {"maxOutputTokens": 8192},
    }
    data = _post_json(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        payload, {"x-goog-api-key": GEMINI_API_KEY}, timeout=180,
    )
    cands = data.get("candidates", [])
    if not cands:
        raise RuntimeError(f"Gemini 无候选回复：{json.dumps(data, ensure_ascii=False)[:300]}")
    parts = cands[0].get("content", {}).get("parts", [])
    text = "".join(p.get("text", "") for p in parts if not p.get("thought")).strip()
    if cands[0].get("finishReason") == "MAX_TOKENS":
        text += "\n\n（※ 出力が上限に達したため途中で切れている可能性あり）"
    return text


def _diagnose_anthropic(snapshot):
    payload = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": 4096,
        "system": _system_prompt(),
        "messages": [{"role": "user", "content": _user_content(snapshot)}],
    }
    data = _post_json("https://api.anthropic.com/v1/messages", payload,
                      {"x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01"}, timeout=120)
    return "\n".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text").strip()


PROVIDERS = {
    # name: (诊断函数, 所需 key 的变量名, 模型名)
    "gemini": (_diagnose_gemini, "GEMINI_API_KEY", GEMINI_MODEL),
    "anthropic": (_diagnose_anthropic, "ANTHROPIC_API_KEY", ANTHROPIC_MODEL),
}


# ----------------------------------------------------------------------------
# 报告渲染 + 落盘 + 清理
# ----------------------------------------------------------------------------
def _overall(alerts):
    # INFO 不影响总合状态
    if any(a.startswith("[CRIT]") for a in alerts):
        return "危険"
    return "注意" if any(a.startswith("[WARN]") for a in alerts) else "正常"


def render_markdown(snap, ai_text, generated_at):
    host, containers, web, alerts = snap["host"], snap["containers"], snap["web"], snap["alerts"]
    overall = {"危険": "🔴 危険", "注意": "🟡 注意", "正常": "🟢 正常"}[_overall(alerts)]
    L = []
    L.append(f"# プラットフォーム健康レポート（Sentry + PostHog）")
    L.append("")
    L.append(f"- 生成時刻: {generated_at}")
    L.append(f"- 総合ステータス: **{overall}** / 検出アラート: {len(alerts)} 件")
    L.append("")
    if ai_text:
        L.append(f"## AI 診断（{AI_PROVIDER} / {PROVIDERS.get(AI_PROVIDER, (None, None, '?'))[2]}）")
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
    L.append(f"- ディスク: {d.get('used_pct')}% 使用 ({d.get('used_gib')}/{d.get('total_gib')} GiB、空き {d.get('avail_gib')} GiB)")
    tr = host.get("disk_trend")
    if tr:
        eta = "".join(f"、{pct}% まで約 {tr[f'days_to_{k}']} 日（{tr[f'eta_{k}']} 頃）"
                      for k, pct in (("warn", DISK_WARN), ("crit", DISK_CRIT)) if f"days_to_{k}" in tr)
        L.append(f"- ディスク増加: {tr['gib_per_day']:+} GiB/日（過去 {tr['span_days']} 日・{tr['points']} 点）{eta}")
    L.append(f"- メモリ: {m.get('used_pct')}% 使用 (空き {m.get('available_gib')} GiB / 全 {m.get('total_gib')} GiB)")
    L.append(f"- swap: {s.get('used_pct')}% 使用 ({s.get('used_gib')}/{s.get('total_gib')} GiB)")
    sio = host.get("swap_io", {})
    for key, label in (("now", f"直近 {sio.get('now_window_s')} 秒"), ("since_last", f"前回巡検から {sio.get('since_last_min')} 分")):
        if sio.get(key):
            L.append(f"- swap 換ページ（{label}）: in {sio[key]['in_kbps']} KB/s / out {sio[key]['out_kbps']} KB/s")
    L.append(f"- load: 1m={lo.get('1m')} 5m={lo.get('5m')} 15m={lo.get('15m')} ({lo.get('cpu_count')} 核, 每核 {lo.get('per_cpu_1m')})")
    L.append("")
    # 容器
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
    # 网页
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
                     f"（{n['5xx_pct']}%）{' ※途中打ち切り' if n.get('truncated') else ''}")
            for path, cnt in n.get("top_paths", []):
                L.append(f"  - {path}: {cnt} 件")
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
            for qid, name, stat, _, _ in CW_METRICS:
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
                    L.append(f"- 告警 {a['name']}: **{a['state']}**（{a['metric']} 閾値 {a['threshold']}）")
            else:
                L.append("- 本インスタンスに紐づく CloudWatch 告警: なし")
        if cw.get("alarms_error"):
            L.append(f"- 告警取得失敗: {cw['alarms_error']}")
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
# Slack 通知：只在状态变化时发。比较对象是上次「已成功通知」的状态（存 state.json），
# 发送失败则不更新，下次运行会再尝试。INFO 不参与。
# ----------------------------------------------------------------------------
_COLOR = {"危険": "danger", "注意": "warning", "正常": "good"}
_EMOJI = {"危険": ":red_circle:", "注意": ":large_yellow_circle:", "正常": ":white_check_mark:"}


def _alert_key(a):
    # 去掉数字：同一问题只是数值变了（swap 5.7→5.8GiB）不算变化
    return re.sub(r"\d+(?:\.\d+)?", "#", a)


def _send_slack(title, text, color, footer):
    payload = {"attachments": [{"color": color, "title": title, "text": text[:3500],
                                "footer": footer, "mrkdwn_in": ["text"]}]}
    _post(SLACK_WEBHOOK_URL, payload, {}, timeout=15, backoff=(3, 10))


def notify_on_change(alerts, prev_notify, ai_text, generated_at):
    """返回应写回 state 的 notify 状态。"""
    overall = _overall(alerts)
    cur = {_alert_key(a): a for a in alerts if a.startswith(("[WARN]", "[CRIT]"))}
    prev_keys = prev_notify.get("keys", {})
    prev_status = prev_notify.get("status", "正常")
    new = [cur[k] for k in cur if k not in prev_keys]
    resolved = [prev_keys[k] for k in prev_keys if k not in cur]
    new_state = {"status": overall, "keys": cur}
    if overall == prev_status and not new and not resolved:
        print("[ok] 状态无变化，不发 Slack")
        return new_state
    if not SLACK_WEBHOOK_URL:
        print("[warn] 状态有变化，但未设置 SLACK_WEBHOOK_URL，跳过通知", file=sys.stderr)
        return prev_notify     # 不记为已通知：配置后首次运行会补发
    host = socket.gethostname()
    title = (f"{_EMOJI[overall]} プラットフォーム巡検: {prev_status} → {overall}" if overall != prev_status
             else f"{_EMOJI[overall]} プラットフォーム巡検: {overall}（内容に変化あり）")
    parts = []
    if new:
        parts.append("*新規*\n" + "\n".join(f"• {a}" for a in new))
    if resolved:
        parts.append("*解消*\n" + "\n".join(f"• {a}" for a in resolved))
    if ai_text:
        summary = "\n".join(ai_text.strip().splitlines()[:15])
        parts.append("*AI 診断（抜粋）*\n" + _short_lines(summary, 1500))
    try:
        _send_slack(title, "\n\n".join(parts), _COLOR[overall],
                    f"{host} | {generated_at} | 詳細: {os.path.join(OUT_DIR, 'health_latest.md')}")
        print("[ok] 已发送 Slack 通知")
        return new_state
    except RuntimeError as e:
        print(f"[warn] Slack 通知失败（下次运行重试）：{e}", file=sys.stderr)
        return prev_notify


def _short_lines(text, n):
    return text if len(text) <= n else text[:n] + "…"


def _acquire_lock():
    """防止两次巡检重叠（例如上一次卡在 docker / AI 上）。拿不到锁就直接退出。"""
    os.makedirs(OUT_DIR, exist_ok=True)
    fh = open(os.path.join(OUT_DIR, ".lock"), "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("[warn] 另一次巡检仍在运行，本次跳过", file=sys.stderr)
        sys.exit(0)
    return fh


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Sentry+PostHog 平台健康巡检")
    ap.add_argument("--dry-run", action="store_true", help="只采集聚合，不调 LLM")
    ap.add_argument("--stdout", action="store_true", help="报告同时打印到终端")
    ap.add_argument("--show-payload", action="store_true",
                    help="把「原封不动准备发送给 AI 的 JSON」打印到终端（不调 AI）")
    ap.add_argument("--no-notify", action="store_true", help="不发 Slack 通知（--dry-run 时也不发）")
    ap.add_argument("--notify-test", action="store_true", help="向 SLACK_WEBHOOK_URL 发一条测试消息后退出")
    args = ap.parse_args()

    if args.notify_test:
        if not SLACK_WEBHOOK_URL:
            sys.exit("未设置 SLACK_WEBHOOK_URL")
        _send_slack(":test_tube: プラットフォーム巡検: 通知テスト", "platform_health.py からのテスト送信です。",
                    "#439FE0", socket.gethostname())
        print("[ok] 测试消息已发送")
        return
    _lock = _acquire_lock()  # noqa: F841  进程结束自动释放

    now = dt.datetime.now(dt.timezone.utc)
    generated_at = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    t0, vm0 = time.time(), read_vmstat()
    prev = load_state()

    host = collect_host()
    disk_hist = update_disk_history(prev, host.get("disk", {}), t0)
    host["disk_trend"] = disk_trend(disk_hist, host.get("disk", {}))
    cinfo, containers = collect_containers()
    collect_container_mem(containers)
    apply_restart_delta(containers, prev)
    apply_mem_budgets(containers)
    web = collect_web()
    nginx_window = min(time.time() - prev["ts"], NGINX_MAX_WINDOW_H * 3600) if prev.get("ts") else NGINX_MAX_WINDOW_H * 3600
    nginx = collect_nginx(nginx_window) if not cinfo.get("error") else []

    # swap 换页速率：本次运行期间（至少 3 秒窗口）+ 上次巡检以来的平均
    elapsed = time.time() - t0
    if elapsed < 3:
        time.sleep(3 - elapsed)
    t1, vm1 = time.time(), read_vmstat()
    host["swap_io"] = {"now": _swap_rate(vm0, vm1, t1 - t0), "now_window_s": round(t1 - t0, 1)}
    if prev.get("ts") and prev.get("vmstat"):
        host["swap_io"]["since_last"] = _swap_rate(prev["vmstat"], vm1, t1 - prev["ts"])
        host["swap_io"]["since_last_min"] = round((t1 - prev["ts"]) / 60)
    if cinfo.get("error"):
        print(f"[warn] 容器采集失败: {cinfo['error']}", file=sys.stderr)
    cw = collect_cloudwatch()
    alerts = compute_alerts(host, containers, web, cw, nginx)
    if cinfo.get("error"):
        # 采集不到≠没问题：不能让总合状态显示为 🟢
        alerts.insert(0, f"[WARN] 容器状态采集失败，本次结果不完整：{cinfo['error']}")
    elif cinfo.get("partial"):
        alerts.insert(0, f"[WARN] 部分容器状态采集失败：{cinfo['partial']}")

    snapshot = {
        "generated_at": generated_at,
        "host": host,
        "containers": containers,
        "container_collect_error": cinfo.get("error"),
        "web": web,
        "cloudwatch": cw,
        "nginx": nginx,
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
        prov = PROVIDERS.get(AI_PROVIDER)
        if prov is None:
            print(f"[warn] 未知 AI_PROVIDER={AI_PROVIDER}（可选 {'/'.join(PROVIDERS)}），跳过 AI 诊断", file=sys.stderr)
        elif not globals()[prov[1]]:
            print(f"[warn] 未设置 {prov[1]}，跳过 AI 诊断（等同 --dry-run）", file=sys.stderr)
        else:
            try:
                ai_text = prov[0](ai_payload)
            except Exception as e:  # noqa
                print(f"[warn] AI 诊断失败: {e}", file=sys.stderr)

    md = render_markdown(snapshot, ai_text, generated_at)

    os.makedirs(OUT_DIR, exist_ok=True)
    stamp = now.strftime("%Y%m%d_%H%M%S")
    with open(os.path.join(OUT_DIR, f"health_{stamp}.json"), "w", encoding="utf-8") as f:
        json.dump(snapshot, f, ensure_ascii=False, indent=2)
    notify = prev.get("notify", {})
    if not (args.dry_run or args.no_notify):
        notify = notify_on_change(alerts, notify, ai_text, generated_at)
    save_state(prev, containers, not cinfo.get("error"), vm1, t1, disk_hist, notify)
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