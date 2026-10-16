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
SWAP_WARN_GB = float(os.environ.get("SWAP_WARN_GB", "5"))     # swap 已用 > N GB（同 Slack SWAP_WARN_GB）
SWAP_CRIT_GB = float(os.environ.get("SWAP_CRIT_GB", "10"))    # 同 Slack SWAP_CRIT_GB
LOAD_PER_CPU_WARN = float(os.environ.get("LOAD_PER_CPU_WARN", "1.5"))  # 每核 load
RECENT_RESTART_DAYS = float(os.environ.get("RECENT_RESTART_DAYS", "1"))  # uptime < N 天视为「最近重启」
WEB_LATENCY_WARN_MS = int(os.environ.get("WEB_LATENCY_WARN_MS", "5000"))  # 网页/健康端点响应过慢阈值
# 以下为本脚本独有（Slack 不管的「趋势/活动」类信号，依赖上次巡检的 state.json）
SWAP_IO_WARN_KBPS = float(os.environ.get("SWAP_IO_WARN_KBPS", "1024"))  # 上次巡检以来 swap 换入+换出平均 KB/s
RESTART_DELTA_CRIT = int(os.environ.get("RESTART_DELTA_CRIT", "3"))  # 上次巡检以来新增重启 ≥N → CRIT（≥1 → WARN）
TOP_MEM_N = int(os.environ.get("TOP_MEM_N", "8"))                     # 发给 AI 的内存占用前 N 名容器

# AI
AI_PROVIDER = os.environ.get("AI_PROVIDER", "gemini").strip().lower()   # gemini | anthropic
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-pro")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")
REPORT_LANG = os.environ.get("REPORT_LANG", "ja")

# 产物
OUT_DIR = os.environ.get("OUT_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"))
KEEP_DAYS = int(os.environ.get("KEEP_DAYS", "14"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "10"))
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
    """给运行中容器补上 mem_mb / swap_mb / mem_limit_mb（口径同 docker stats：memory.current - inactive_file）。"""
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
            c["mem_mb"] = round((cur - inactive) / 1e6)
            sw = os.path.join(d, "memory.swap.current")
            if os.path.exists(sw):
                c["swap_mb"] = round(_read_cg_int(sw) / 1e6)
            lim = _read_cg_int(os.path.join(d, "memory.max"))
            c["mem_limit_mb"] = round(lim / 1e6) if lim else None
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
                by_name[name]["mem_mb"] = round(_parse_size(used) / 1e6)
                by_name[name]["mem_limit_mb"] = round(_parse_size(limit) / 1e6)
        except ValueError:
            continue


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


def save_state(prev, containers, collect_ok, vmstat, ts):
    state = {"ts": ts, "vmstat": vmstat,
             # 容器采集失败时沿用上次的容器计数，避免下次算出错误增量
             "containers": ({c["name"]: {"restarts": c["restarts"], "started_at": c["started_at"]}
                             for c in containers} if collect_ok else prev.get("containers", {}))}
    os.makedirs(OUT_DIR, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def apply_restart_delta(containers, prev):
    """restarts_delta = 上次巡检以来新增的重启次数。无上次记录 / 容器被重建（计数归零）时为 None。"""
    pc = prev.get("containers", {})
    for c in containers:
        p = pc.get(c["name"])
        if p and isinstance(c["restarts"], int) and isinstance(p.get("restarts"), int):
            d = c["restarts"] - p["restarts"]
            c["restarts_delta"] = d if d >= 0 else None
        else:
            c["restarts_delta"] = None


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
def compute_alerts(host, containers, web, cw=None):
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
    sio = host.get("swap_io", {})
    # 用换页速率给「swap 已用量」加注：已用多但几乎不换页 → 多为历史残留
    rate = sio.get("since_last") or sio.get("now")
    hint = ""
    if rate:
        tot = rate["in_kbps"] + rate["out_kbps"]
        hint = (f"（换页 {tot}KB/s，几乎无活动，多为历史换出的残留）" if tot < SWAP_IO_WARN_KBPS / 10
                else f"（换页 {tot}KB/s，仍在活跃换页）")
    su = s.get("used_gb")
    if isinstance(su, (int, float)):
        if su >= SWAP_CRIT_GB:
            alerts.append(f"[CRIT] swap 已用 {su}GB ≥ {SWAP_CRIT_GB}GB{hint}")
        elif su >= SWAP_WARN_GB:
            alerts.append(f"[WARN] swap 已用 {su}GB ≥ {SWAP_WARN_GB}GB{hint}")
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
        # 重启只看增量（上次巡检以来），不看无意义的累计次数
        rd = c.get("restarts_delta")
        if rd:
            lv = "CRIT" if rd >= RESTART_DELTA_CRIT else "WARN"
            why = "，疑似反复崩溃" if lv == "CRIT" else ""
            alerts.append(f"[{lv}] {tag} {c['name']} 上次巡检以来重启 {rd} 次（累计 {c['restarts']}{why}）")
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
                and not c.get("oom_killed") and not recent and not c.get("restarts_delta"))

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
                "mem_mb": c.get("mem_mb"),
                "swap_mb": c.get("swap_mb"),
            })

    # 内存占用前 N 名（无论是否异常都发），让 AI 能把内存/swap 问题落到具体容器
    top_mem = sorted((c for c in conts if isinstance(c.get("mem_mb"), int)),
                     key=lambda c: c["mem_mb"], reverse=True)[:TOP_MEM_N]
    top_memory = [{k: c.get(k) for k in ("name", "mem_mb", "swap_mb", "mem_limit_mb")} for c in top_mem]
    top_swap = sorted((c for c in conts if c.get("swap_mb")), key=lambda c: c["swap_mb"], reverse=True)[:TOP_MEM_N]

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
            "top_swap": [{"name": c["name"], "swap_mb": c["swap_mb"]} for c in top_swap],
        },
        "web": snapshot["web"],
        "cloudwatch": snapshot.get("cloudwatch"),
        "flags": snapshot["alerts"],   # 确定性关注提示
        "rule_status": _overall(snapshot["alerts"]),
        "note_for_ai": ("flags 是确定性提示，实时告警另由 Slack 负责；正常容器已折叠为计数，IGNORE_CONTAINERS 中的容器已排除。"
                        "exit 0 退出的容器多为一次性任务。restarts 是累计值（长期累积属常态），restarts_delta 才是"
                        "上次巡检以来的新增重启。host.swap_io 是换页速率：swap 已用量高但换页速率≈0 表示历史残留，"
                        "不等于当前内存压力。mem_mb/swap_mb 为各容器 cgroup 实测值（MB）。"
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
    )


def _user_content(snapshot):
    return "健康チェックデータ(JSON):\n" + json.dumps(snapshot, ensure_ascii=False, indent=2)


def _post_json(url, payload, headers, timeout):
    req = request.Request(url, data=json.dumps(payload).encode("utf-8"),
                          headers={"content-type": "application/json", **headers}, method="POST")
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"HTTP {e.code} {e.reason}: {body}") from None


def _diagnose_gemini(snapshot):
    payload = {
        "systemInstruction": {"parts": [{"text": _system_prompt()}]},
        "contents": [{"role": "user", "parts": [{"text": _user_content(snapshot)}]}],
        # 2.5 系的思考 token 也计入 maxOutputTokens，留足余量以免正文被截断
        "generationConfig": {"maxOutputTokens": 8192},
    }
    data = _post_json(
        f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent",
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
    L.append(f"- ディスク: {d.get('used_pct')}% 使用 ({d.get('used_gb')}/{d.get('total_gb')} GB)")
    L.append(f"- メモリ: {m.get('used_pct')}% 使用 (空き {m.get('available_gb')} GB / 全 {m.get('total_gb')} GB)")
    L.append(f"- swap: {s.get('used_pct')}% 使用 ({s.get('used_gb')}/{s.get('total_gb')} GB)")
    sio = host.get("swap_io", {})
    for key, label in (("now", f"直近 {sio.get('now_window_s')} 秒"), ("since_last", f"前回巡検から {sio.get('since_last_min')} 分")):
        if sio.get(key):
            L.append(f"- swap 換ページ（{label}）: in {sio[key]['in_kbps']} KB/s / out {sio[key]['out_kbps']} KB/s")
    L.append(f"- load: 1m={lo.get('1m')} 5m={lo.get('5m')} 15m={lo.get('15m')} ({lo.get('cpu_count')} 核, 每核 {lo.get('per_cpu_1m')})")
    L.append("")
    # 容器
    L.append("## コンテナ状態")
    L.append("")
    L.append("Restarts は累計（括弧内は前回巡検からの増分、— は比較データなし）。")
    L.append("")
    L.append("| Container | Core | Status | Health | Uptime(d) | Restarts | Mem MB | Swap MB | OOM |")
    L.append("|-----------|------|--------|--------|-----------|----------|--------|---------|-----|")

    def _v(x):
        return "—" if x is None else x

    for c in containers:
        st = c["status"] + (f" ({c.get('exit_code')})" if c["status"] == "exited" else "")
        mark = "(ignored)" if c.get("ignored") else ("★" if c["watched"] else "")
        rd = c.get("restarts_delta")
        rs = f"{c['restarts']} ({'+' + str(rd) if rd else _v(rd)})"
        L.append(f"| {c['name']} | {mark} | {st} | {c['health']} | {_v(c.get('uptime_days'))} | {rs} | "
                 f"{_v(c.get('mem_mb'))} | {_v(c.get('swap_mb'))} | {'⚠️' if c['oom_killed'] else ''} |")
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
    t0, vm0 = time.time(), read_vmstat()
    prev = load_state()

    host = collect_host()
    cinfo, containers = collect_containers()
    collect_container_mem(containers)
    apply_restart_delta(containers, prev)
    web = collect_web()

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
    alerts = compute_alerts(host, containers, web, cw)
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
    save_state(prev, containers, not cinfo.get("error"), vm1, t1)
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