#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
platform_health.py — 自前ホストの Sentry + PostHog プラットフォーム健康巡検

目的：この EC2 上の Sentry / PostHog が正常に稼働しているかを定期的に点検し、
      異常があれば AI が想定原因と対処案を示す。

収集する信号：
  1) コンテナ：status / health / 再起動（増分・非クラッシュ再起動）/ OOM / メモリ・swap 使用量
  2) ホスト：ディスク（増加速度と閾値到達予測）、メモリ、swap（使用量と換ページ速度）、load
  3) Web：Sentry / PostHog の /_health 疎通（ステータスコード + レイテンシ）
  4) nginx アクセスログ：前回巡検以降のリクエスト数と 5xx
  5) CloudWatch：EC2 インスタンス指標と本インスタンスのアラーム

設計方針：外部依存ゼロ（標準ライブラリ + aws CLI）、短命プロセス、成果物は極小で自動削除。

使い方：
  # 収集とルール判定のみ（LLM を呼ばない。まず収集の確認に）
  python3 platform_health.py --dry-run
  # AI 診断あり（AI_PROVIDER=gemini は GEMINI_API_KEY、=anthropic は ANTHROPIC_API_KEY が必要）
  python3 platform_health.py

注意：docker 情報の取得には権限が必要。普段 `sudo docker` を使っているなら
      `sudo python3 platform_health.py` で実行する（.env はスクリプト自身が読むので -E は不要）。
      または実行ユーザーを docker グループに追加する。
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
# 同じディレクトリの .env を自動で読み込む（既存の環境変数が優先、空の値は無視）
# 設定を読む前に実行する。sudo は環境変数を消すため、スクリプト自身がファイルを読むのが確実。
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
                if v:  # 空の値は未設定とみなし、コードの既定値を使う（例：OUT_DIR=）
                    os.environ.setdefault(k.strip(), v)
    except FileNotFoundError:
        pass


_load_dotenv()

# ----------------------------------------------------------------------------
# 設定（環境変数）
# ----------------------------------------------------------------------------
# コアコンテナ（名前に含まれていれば一致、★ を付ける）。sentry / posthog のように全コンテナが含む語は書かないこと（★ の意味がなくなる）。
WATCH_PREFIXES = os.environ.get(
    "WATCH_PREFIXES",
    "-web-,-nginx-,-relay-,-postgres-,-db-,-pgbouncer-,-kafka-,-clickhouse-,-redis,"
    "-snuba-api-,-taskworker-,-capture-,-ingestion-",
).split(",")
# 判定から完全に除外するコンテナ（カンマ区切り、名前に含まれていれば一致）。既知の一回限り・廃止済みコンテナ用
IGNORE_CONTAINERS = [p.strip() for p in os.environ.get("IGNORE_CONTAINERS", "").split(",") if p.strip()]

# Web 疎通の対象：「名前=URL」をカンマ区切りで。空なら Web チェックなし。
# SENTRY_URL / POSTHOG_URL を個別に指定してもよい
WEB_TARGETS = os.environ.get("WEB_TARGETS", "")
SENTRY_URL = os.environ.get("SENTRY_URL", "")
POSTHOG_URL = os.environ.get("POSTHOG_URL", "")

# 注目ポイントの閾値（★これは「リアルタイム通知」ではない。リアルタイム通知は既存の slack_alert.sh が担当。
#  ここでは AI への注目ポイントと総合ステータスの算出に使う。数値は slack_alert.sh と意図的に揃えており、
#  閾値を変えるときは slack_alert.sh も同時に変えること。）
DISK_WARN = float(os.environ.get("DISK_WARN", "85"))          # ディスク使用率 %（Slack の DISK_WARN_PCT と同じ）
DISK_CRIT = float(os.environ.get("DISK_CRIT", "95"))          # Slack の DISK_CRIT_PCT と同じ
MEM_AVAIL_WARN_GB = float(os.environ.get("MEM_AVAIL_WARN_GB", "2"))  # 空きメモリ < N GiB（Slack の RAM_WARN_GB と同じ）
MEM_AVAIL_CRIT_GB = float(os.environ.get("MEM_AVAIL_CRIT_GB", "1"))  # Slack の RAM_CRIT_GB と同じ
SWAP_WARN_GB = float(os.environ.get("SWAP_WARN_GB", "8"))     # swap 使用量 ≥ N GiB（Slack の SWAP_WARN_GB と同じ）
SWAP_CRIT_GB = float(os.environ.get("SWAP_CRIT_GB", "10"))    # Slack の SWAP_CRIT_GB と同じ
LOAD_PER_CPU_WARN = float(os.environ.get("LOAD_PER_CPU_WARN", "1.5"))  # コアあたり load
RECENT_RESTART_DAYS = float(os.environ.get("RECENT_RESTART_DAYS", "1"))  # uptime < N 日を「最近再起動」とみなす
WEB_LATENCY_WARN_MS = int(os.environ.get("WEB_LATENCY_WARN_MS", "5000"))  # Web / ヘルス端点の応答遅延の閾値
# 以下は本スクリプト独自（Slack が扱わない「傾向・活動」系の信号。前回巡検の state.json に依存）
SWAP_IO_WARN_KBPS = float(os.environ.get("SWAP_IO_WARN_KBPS", "1024"))  # 前回巡検以降の swap 換入+換出の平均 KB/s
RESTART_DELTA_CRIT = int(os.environ.get("RESTART_DELTA_CRIT", "3"))  # 前回巡検以降の再起動増分 ≥N → CRIT（≥1 → WARN）
TOP_MEM_N = int(os.environ.get("TOP_MEM_N", "8"))                     # AI に渡すメモリ使用量上位 N コンテナ
DISK_TREND_DAYS = float(os.environ.get("DISK_TREND_DAYS", "14"))      # ディスク増加速度は直近 N 日のサンプルで線形回帰
DISK_FORECAST_WARN_DAYS = float(os.environ.get("DISK_FORECAST_WARN_DAYS", "30"))  # N 日以内に DISK_WARN 到達見込み → WARN

# AI
AI_PROVIDER = os.environ.get("AI_PROVIDER", "gemini").strip().lower()   # gemini | anthropic
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-pro")
GEMINI_FALLBACK_MODEL = os.environ.get("GEMINI_FALLBACK_MODEL", "gemini-2.5-flash")  # 主モデルが再試行後も失敗したときに使う（空 = 降格しない）
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")
REPORT_LANG = os.environ.get("REPORT_LANG", "ja")

# 成果物
OUT_DIR = os.environ.get("OUT_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"))
KEEP_DAYS = int(os.environ.get("KEEP_DAYS", "14"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "10"))
# slack_alert.sh が一部コンテナに設定しているメモリ閾値（GiB）。形式は同スクリプトの CONTAINERS 配列と同じ。変更時は両方を直す
CONTAINER_MEM_BUDGETS = os.environ.get(
    "CONTAINER_MEM_BUDGETS",
    "posthog-web-1:5,posthog-clickhouse-1:2,sentry-self-hosted-web-1:1.5,sentry-self-hosted-snuba-api-1:2")
BUDGET_INFO_PCT = float(os.environ.get("BUDGET_INFO_PCT", "80"))   # 閾値の N% 以上 → INFO（Slack は 95% 継続でリアルタイム通知）

# nginx アクセスログの 5xx 集計（窓 = 前回巡検以降、最長 NGINX_MAX_WINDOW_H 時間）
NGINX_CONTAINERS = [c.strip() for c in os.environ.get("NGINX_CONTAINERS", "sentry-self-hosted-nginx-1").split(",") if c.strip()]
NGINX_MAX_WINDOW_H = float(os.environ.get("NGINX_MAX_WINDOW_H", "24"))
NGINX_5XX_WARN_PCT = float(os.environ.get("NGINX_5XX_WARN_PCT", "1"))    # 5xx 比率 ≥ N% かつ
NGINX_5XX_WARN_MIN = int(os.environ.get("NGINX_5XX_WARN_MIN", "20"))     # 件数 ≥ N → WARN。それ以外で 5xx があれば INFO

# Slack 通知：状態が変わったときだけ送る（WARN/CRIT の新規・解消、総合ステータスの変化）。空なら送らない
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

GIB, MIB = 1024 ** 3, 1024 ** 2   # 容量は二進単位に統一（docker stats / df -h / slack_alert.sh と同じ）
STATE_FILE = os.path.join(OUT_DIR, "state.json")   # 前回巡検のカウンタ（再起動回数 / swap 換ページ等）。増分の計算に使う

# CloudWatch（aws CLI 経由。インスタンスロールに cloudwatch:GetMetricData / cloudwatch:DescribeAlarms が必要）
CLOUDWATCH = os.environ.get("CLOUDWATCH", "1") != "0"          # 0 = CloudWatch を参照しない
CW_INSTANCE_ID = os.environ.get("CW_INSTANCE_ID", "")          # 空なら IMDS から自動取得
CW_REGION = os.environ.get("AWS_REGION", "") or os.environ.get("AWS_DEFAULT_REGION", "")  # 空なら IMDS から取得
CW_CPU_WARN = float(os.environ.get("CW_CPU_WARN", "80"))        # 直近 1h の CPU 平均 % ≥ → WARN
CW_BALANCE_WARN = float(os.environ.get("CW_BALANCE_WARN", "20"))  # EBS IO/Byte バースト残高 % ≤ → WARN（枯渇すると帯域制限）
CW_CPU_CREDIT_WARN = float(os.environ.get("CW_CPU_CREDIT_WARN", "10"))  # T 系の CPU クレジット残高 ≤ → WARN
INSECURE = os.environ.get("WEB_INSECURE", "") == "1"


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


def collect_containers():
    """docker inspect で全コンテナの主要な状態を取得する。docker が使えない場合はエラーを返す。"""
    if shutil.which("docker") is None:
        return {"error": "docker コマンドが使えない（PATH に見つからない）"}, []
    # まず全コンテナ（停止中を含む）の完全な ID と名前を取得。ID は ps から取る（{{.ID}} は ps 形式で最も互換性が高い）
    try:
        ps_out = subprocess.run(
            ["docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}"],
            capture_output=True, text=True, timeout=20, check=True,
        ).stdout
    except subprocess.CalledProcessError as e:
        return {"error": f"docker ps 失敗：{_short(e.stderr) or e.returncode}"}, []
    except Exception as e:  # noqa
        return {"error": f"docker ps 例外：{e}"}, []

    ids = {}
    for line in ps_out.splitlines():
        if "\t" in line:
            cid, name = line.split("\t", 1)
            ids[name.strip()] = cid.strip()
    names = list(ids)
    if not names:
        return {"error": None, "note": "コンテナが見つからない"}, []

    # 一度の inspect で全件を取得し、区切り文字付きの行で出力
    fmt = ("{{.Name}}\t{{.State.Status}}\t"
           "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}\t"
           "{{.RestartCount}}\t{{.State.OOMKilled}}\t{{.State.StartedAt}}\t{{.State.ExitCode}}")
    try:
        r = subprocess.run(["docker", "inspect", "--format", fmt] + names,
                           capture_output=True, text=True, timeout=30)
    except Exception as e:  # noqa
        return {"error": f"docker inspect 例外：{e}"}, []
    insp = r.stdout
    # 非 0 終了でも取得できた出力は解析する（ps と inspect の間に削除されたコンテナがあっても、その 1 件だけの影響で済む）
    inspect_err = f"docker inspect 失敗（exit {r.returncode}）：{_short(r.stderr)}" if r.returncode else None

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
        print(f"[warn] {inspect_err}（{len(containers)}/{len(names)} コンテナを解析済み）", file=sys.stderr)
    return {"error": None, "partial": inspect_err}, containers


# ----------------------------------------------------------------------------
# 2) ホストリソース（依存なし：statvfs + /proc）
# ----------------------------------------------------------------------------
def collect_host():
    host = {}
    # ディスク（ルート）。算出方法は `df` と同じ（slack_alert.sh は df の Use% を使っている）：
    #   used = 全ブロック - 空きブロック、Use% = ceil(used / (used + 一般ユーザー利用可能))。予約ブロックは分母に含めない
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

    # メモリ / swap（/proc/meminfo、単位 kB）
    try:
        mi = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mi[k.strip()] = int(v.strip().split()[0])
        mem_total = mi.get("MemTotal", 0)
        mem_avail = mi.get("MemAvailable", 0)
        host["mem"] = {   # /proc/meminfo は KiB → GiB（slack_alert.sh の ÷1048576 と同じ）
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
# 1b) コンテナのメモリ / swap（cgroup v2 を直接読む。読めない場合は docker stats で代替、メモリのみ）
# ----------------------------------------------------------------------------
def _read_cg_int(path):
    with open(path) as f:
        v = f.read().strip()
    return None if v == "max" else int(v)


def _cgroup_dir(cid):
    # systemd cgroup ドライバ（Amazon Linux 2023 等の既定） / cgroupfs ドライバ
    for d in (f"/sys/fs/cgroup/system.slice/docker-{cid}.scope", f"/sys/fs/cgroup/docker/{cid}"):
        if os.path.isdir(d):
            return d
    return None


_SIZE_UNITS = {"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3}


def _parse_size(text):
    """'1.23GiB' → バイト数。"""
    t = text.strip().lower()
    for u in sorted(_SIZE_UNITS, key=len, reverse=True):
        if t.endswith(u):
            return float(t[: -len(u)]) * _SIZE_UNITS[u]
    return float(t)


def collect_container_mem(containers):
    """稼働中コンテナに mem_mib / swap_mib / mem_limit_mib を付与する（docker stats と同じ算出：memory.current - inactive_file）。"""
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
    # cgroup が読めない（cgroup v1 等）→ docker stats で代替（約 2 秒）
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
# 1c) swap の換入/換出（/proc/vmstat の累計ページ数 → 速度）
#     「swap 使用量」は過去に換出されたことを示すだけ。今メモリが逼迫しているかは「換ページ速度」で分かる。
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
    if din < 0 or dout < 0:      # ホスト再起動でカウンタがリセットされた
        return None
    return {"in_kbps": round(din * PAGE_KB / seconds, 1), "out_kbps": round(dout * PAGE_KB / seconds, 1)}


# ----------------------------------------------------------------------------
# 1d) 前回巡検の状態（再起動回数 / swap カウンタ等）。累計値ではなく「増分」を見るために使う
# ----------------------------------------------------------------------------
def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(prev, containers, collect_ok, vmstat, ts, disk_history, notify):
    state = {"ts": ts, "vmstat": vmstat, "disk_avail_history": disk_history, "notify": notify,
             # コンテナ取得に失敗したときは前回の値を引き継ぐ（次回に誤った増分を出さないため）
             "containers": ({c["name"]: {"restarts": c["restarts"], "started_at": c["started_at"]}
                             for c in containers} if collect_ok else prev.get("containers", {}))}
    os.makedirs(OUT_DIR, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def apply_restart_delta(containers, prev):
    """restarts_delta = 前回巡検以降の再起動回数の増分。前回の記録がない / コンテナ再作成（カウンタが 0 に戻る）の場合は None。
    restarted_since_last = 起動時刻が変わった。RestartCount は restart policy による再起動しか数えないため、
    `docker restart`・compose による再作成・定期ジョブによる再起動は起動時刻の変化でしか分からない。"""
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
# 1e) ディスク増加速度と閾値到達の予測（サンプルは state.json に保存。初回は out/ の過去スナップショットから補完）
# ----------------------------------------------------------------------------
def _seed_disk_history():
    """out/ の過去スナップショットから「空き容量 GiB」のサンプルを補完する。旧形式（十進 GB の total_gb/used_gb）にも対応。"""
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
    # 「使用量」ではなく「空き容量」を記録する：算出方法（予約ブロックの扱い）や単位が変わっても系列が途切れない
    hist = prev.get("disk_avail_history") or _seed_disk_history()
    if isinstance(disk.get("avail_gib"), (int, float)):
        hist.append([ts, disk["avail_gib"]])
    cutoff = ts - DISK_TREND_DAYS * 86400
    return [h for h in hist if h[0] >= cutoff]


def disk_trend(hist, disk):
    """最小二乗法で 1 日あたりの消費 GiB を求め、Use%（df 方式）が DISK_WARN / DISK_CRIT に達するまでの日数を予測する。サンプル期間が 12 時間未満なら計算しない。"""
    used, avail = disk.get("used_gib"), disk.get("avail_gib")
    if len(hist) < 2 or used is None or avail is None or hist[-1][0] - hist[0][0] < 12 * 3600:
        return None
    xs = [(t - hist[0][0]) / 86400 for t, _ in hist]
    ys = [a for _, a in hist]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    var = sum((x - mx) ** 2 for x in xs)
    growth = -sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / var   # 空き容量の減少速度 = 増加速度
    out = {"gib_per_day": round(growth, 2), "span_days": round(xs[-1], 1), "points": len(hist)}
    cap = used + avail     # df の Use% の分母
    for key, pct in (("warn", DISK_WARN), ("crit", DISK_CRIT)):
        remain = avail - cap * (1 - pct / 100)
        if growth > 0.01 and remain > 0:
            days = remain / growth
            out[f"days_to_{key}"] = round(days)
            out[f"eta_{key}"] = (dt.datetime.fromtimestamp(hist[-1][0], dt.timezone.utc)
                                 + dt.timedelta(days=days)).strftime("%Y-%m-%d")
    return out


# ----------------------------------------------------------------------------
# 3) Web 疎通
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
            rec["ok"] = False  # 4xx/5xx も「応答あり」だが ok=False とする
        except Exception as e:  # noqa
            rec["status"] = None
            rec["ok"] = False
            rec["error"] = str(e)
        rec["latency_ms"] = int((time.time() - t0) * 1000)
        results.append(rec)
    return results


# ----------------------------------------------------------------------------
# 3b) nginx アクセスログ：窓内のリクエスト数と 5xx（ストリームで数えるのでメモリ使用は一定）
#     パスはクエリを除去（Sentry の送信 URL には sentry_key が含まれる）、数字部分は {n} に正規化して集計
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
# 4) CloudWatch：AWS 側から見た EC2 インスタンス指標 + 本インスタンスに紐づく CloudWatch アラーム
#    aws CLI（Amazon Linux に標準搭載）経由で呼び、外部 Python 依存を増やさない。
#    ローカル信号は「コンテナ/プロセスの内側」、CloudWatch は「インスタンスの外側」（ネットワーク、EBS 制限、状態チェック、CPU クレジット）を見る。
# ----------------------------------------------------------------------------
CW_PERIOD = 300   # EC2 の基本モニタリングは 5 分粒度
CW_METRICS = [
    # (query id, MetricName, Stat, 換算, 単位)  換算：None=そのまま / "kbps"=Sum バイト÷期間÷1024 / "rate"=Sum÷期間
    ("cpu", "CPUUtilization", "Average", None, "%"),
    ("cpu_peak", "CPUUtilization", "Maximum", None, "%"),
    ("net_in", "NetworkIn", "Sum", "kbps", "KB/s"),
    ("net_out", "NetworkOut", "Sum", "kbps", "KB/s"),
    ("ebs_read", "EBSReadBytes", "Sum", "kbps", "KB/s"),
    ("ebs_write", "EBSWriteBytes", "Sum", "kbps", "KB/s"),
    ("ebs_read_iops", "EBSReadOps", "Sum", "rate", "IOPS"),
    ("ebs_write_iops", "EBSWriteOps", "Sum", "rate", "IOPS"),
    ("ebs_io_balance", "EBSIOBalance%", "Minimum", None, "%"),      # EBS 帯域のバースト残高（Nitro 小型インスタンス）
    ("ebs_byte_balance", "EBSByteBalance%", "Minimum", None, "%"),
    ("cpu_credit", "CPUCreditBalance", "Minimum", None, "credits"),  # T 系インスタンスのみ
    ("status_failed", "StatusCheckFailed", "Maximum", None, ""),     # 1 = システム/インスタンス状態チェック失敗
]


def _imds(path, token, timeout=2):
    req = request.Request(f"http://169.254.169.254/latest/{path}", headers={"X-aws-ec2-metadata-token": token})
    with request.urlopen(req, timeout=timeout) as r:
        return r.read().decode().strip()


def _instance_identity():
    """(instance_id, region, instance_type)。環境変数を優先し、残りは IMDSv2 から取得。EC2 上でなければ例外。"""
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
            raise RuntimeError(f"IMDS からインスタンス情報を取得できない（EC2 上ではない？）：{e}")
    return iid, region, itype


def _aws(args, region, timeout=40):
    try:
        r = subprocess.run(["aws"] + args + ["--region", region, "--output", "json"],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"aws {args[1]} タイムアウト（{timeout}s）") from None
    if r.returncode:
        err = r.stderr
        if "AccessDenied" in err or "not authorized" in err:
            raise RuntimeError(f"IAM 権限不足：インスタンスロールに cloudwatch:{_CW_ACTION.get(args[1], args[1])} がない")
        raise RuntimeError(f"aws {args[1]} 失敗：{_short(err)}")
    return json.loads(r.stdout or "{}")


_CW_ACTION = {"get-metric-data": "GetMetricData", "describe-alarms": "DescribeAlarms"}


def _summarize(points, conv):
    """points: [(ts, value)] 新→旧。latest と直近 1h / 24h の avg/min/max を返す（単位換算済み）。"""
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
    """None（CLOUDWATCH=0 で無効）または dict を返す。失敗しても例外は投げず error に記録し、他の巡検は続行する。"""
    if not CLOUDWATCH:
        return None
    cw = {"error": None}
    if shutil.which("aws") is None:
        cw["error"] = "aws CLI が使えない（PATH に見つからない）"
        return cw
    try:
        iid, region, itype = _instance_identity()
    except RuntimeError as e:
        cw["error"] = str(e)
        return cw
    cw.update({"instance_id": iid, "region": region, "instance_type": itype, "period_s": CW_PERIOD})

    # --- 指標：GetMetricData 1 回で 24h 分を取得（12 指標 × 288 点、1 回の上限を大きく下回る）
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
            if summ:   # データのない指標（T 系以外の CPUCreditBalance 等）は省略
                summ["unit"] = meta[qid][4]
                metrics[qid] = summ
        cw["metrics"] = metrics
    except RuntimeError as e:
        cw["error"] = str(e)
        return cw

    # --- 本インスタンスに紐づく CloudWatch アラーム（ディメンションに本インスタンス ID を含むもの）
    try:
        alarms = _aws(["cloudwatch", "describe-alarms"], region).get("MetricAlarms", [])
        mine = [a for a in alarms if any(d.get("Value") == iid for d in a.get("Dimensions", []))]
        cw["alarms"] = [{"name": a.get("AlarmName"), "state": a.get("StateValue"),
                         "metric": a.get("MetricName"), "threshold": a.get("Threshold"),
                         "reason": _short(a.get("StateReason"), 160)} for a in mine]
    except RuntimeError as e:
        cw["alarms_error"] = str(e)   # アラームが取れなくても指標には影響しない
    return cw


# ----------------------------------------------------------------------------
# 「注目ポイント」の算出（決定的なルール。AI の分析の焦点に使う。★リアルタイム通知は slack_alert.sh の担当）
# 本当に意味のある信号だけを拾い、Slack との重複や累計再起動回数のようなノイズを避ける。
# ----------------------------------------------------------------------------
def compute_alerts(host, containers, web, cw=None, nginx=None):
    alerts = []

    d = host.get("disk", {})
    if isinstance(d.get("used_pct"), (int, float)):
        if d["used_pct"] >= DISK_CRIT:
            alerts.append(f"[CRIT] ディスク使用率 {d['used_pct']}% ≥ {DISK_CRIT}%")
        elif d["used_pct"] >= DISK_WARN:
            alerts.append(f"[WARN] ディスク使用率 {d['used_pct']}% ≥ {DISK_WARN}%")
    tr = host.get("disk_trend") or {}
    if "days_to_warn" in tr and tr["days_to_warn"] <= DISK_FORECAST_WARN_DAYS:
        alerts.append(f"[WARN] ディスクが +{tr['gib_per_day']}GiB/日 で増加中、約 {tr['days_to_warn']} 日後（{tr['eta_warn']} 頃）"
                      f"に {DISK_WARN}% 到達見込み")

    m = host.get("mem", {})
    av = m.get("available_gib")
    if isinstance(av, (int, float)):
        if av < MEM_AVAIL_CRIT_GB:      # slack_alert.sh：floor(GiB) < 閾値 ⇔ GiB < 閾値
            alerts.append(f"[CRIT] 空きメモリ {av}GiB < {MEM_AVAIL_CRIT_GB}GiB")
        elif av < MEM_AVAIL_WARN_GB:
            alerts.append(f"[WARN] 空きメモリ {av}GiB < {MEM_AVAIL_WARN_GB}GiB")

    s = host.get("swap", {})
    sio = host.get("swap_io", {})
    # 「swap 使用量」に換ページ速度を注記する：使用量が多くてもほぼ換ページがなければ過去の残留
    # 「前回巡検以降」の長い窓を優先する（3 秒の瞬間値は巡検自体が引き起こす換入の影響を受けやすい）
    rate = sio.get("since_last") or sio.get("now")
    hint, idle = "", False
    if rate:
        tot = round(rate["in_kbps"] + rate["out_kbps"], 1)
        idle = tot < SWAP_IO_WARN_KBPS / 10
        hint = (f"（換ページ {tot}KB/s、ほぼ動きなし。過去に換出された残留のため 1 段階下げて表示）" if idle
                else f"（換ページ {tot}KB/s、現在も活発に換ページ中）")
    su = s.get("used_gib")
    if isinstance(su, (int, float)):
        # 動きのない swap は性能に影響しない：1 段階下げる（WARN→INFO、CRIT→WARN）。毎回ノイズとして出るのを防ぐ。
        # Slack の絶対閾値の通知には影響しない。実際のメモリ逼迫は下の「継続的な換ページ」ルールで検出する。
        if su >= SWAP_CRIT_GB:
            alerts.append(f"[{'WARN' if idle else 'CRIT'}] swap 使用量 {su}GiB ≥ {SWAP_CRIT_GB}GiB{hint}")
        elif su >= SWAP_WARN_GB:
            alerts.append(f"[{'INFO' if idle else 'WARN'}] swap 使用量 {su}GiB ≥ {SWAP_WARN_GB}GiB{hint}")
    sl = sio.get("since_last")
    if sl and sl["in_kbps"] + sl["out_kbps"] >= SWAP_IO_WARN_KBPS:
        alerts.append(f"[WARN] 前回巡検以降 swap の換ページが継続：換入 {sl['in_kbps']}KB/s / 換出 {sl['out_kbps']}KB/s"
                      f"（≥{SWAP_IO_WARN_KBPS}KB/s、実際にメモリが逼迫している）")

    l = host.get("load", {})
    if isinstance(l.get("per_cpu_1m"), (int, float)) and l["per_cpu_1m"] >= LOAD_PER_CPU_WARN:
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
        if c.get("budget_pct") is not None and c["budget_pct"] >= BUDGET_INFO_PCT:
            alerts.append(f"[INFO] {tag} {c['name']} のメモリ {c['mem_mib']}MiB、Slack 閾値 {c['budget_gib']}GiB の "
                          f"{c['budget_pct']}% に到達（95% 以上が続くと Slack がリアルタイム通知）")
        # 再起動は増分（前回巡検以降）だけを見る。累計回数は意味がないので見ない
        rd = c.get("restarts_delta")
        if rd:
            lv = "CRIT" if rd >= RESTART_DELTA_CRIT else "WARN"
            why = "、クラッシュの繰り返しの疑い" if lv == "CRIT" else ""
            alerts.append(f"[{lv}] {tag} {c['name']} が前回巡検以降 {rd} 回再起動（累計 {c['restarts']}{why}）")
            continue
        if c.get("restarted_since_last"):
            alerts.append(f"[INFO] {tag} {c['name']} が前回巡検以降に再起動された（RestartCount は増えていない → クラッシュによる自動再起動ではなく、"
                          f"手動 restart / compose 再作成 / 定期ジョブ。起動 {c['started_at'][:16]}Z）")
            continue
        # 増分データがない（初回実行等）場合は「最近再起動した」で代替
        ud = c.get("uptime_days")
        if rd is None and isinstance(ud, (int, float)) and ud < RECENT_RESTART_DAYS:
            alerts.append(f"[INFO] {tag} {c['name']} は最近再起動した（uptime {ud} 日、累計 {c['restarts']} 回）")

    for w in web:
        if not w.get("ok"):
            detail = w.get("error") or f"HTTP {w.get('status')}"
            alerts.append(f"[CRIT] Web {w['name']} の疎通失敗：{detail}")
        elif isinstance(w.get("latency_ms"), int) and w["latency_ms"] >= WEB_LATENCY_WARN_MS:
            alerts.append(f"[WARN] Web {w['name']} の応答が遅い：{w['latency_ms']}ms（≥{WEB_LATENCY_WARN_MS}ms、依存先の遅延の疑い）")

    for n in nginx or []:
        if n.get("error"):
            alerts.append(f"[INFO] nginx ログ {n['container']} を取得できない：{n['error']}")
        elif n.get("5xx"):
            lv = "WARN" if n["5xx"] >= NGINX_5XX_WARN_MIN and n["5xx_pct"] >= NGINX_5XX_WARN_PCT else "INFO"
            codes = ", ".join(f"{k}×{v}" for k, v in sorted(n["by_code"].items()))
            alerts.append(f"[{lv}] nginx {n['container']} 直近 {n['window_h']}h で 5xx {n['5xx']} 件 / {n['requests']} リクエスト"
                          f"（{n['5xx_pct']}%：{codes}）")

    if cw is not None:
        if cw.get("error"):
            # データソースが欠けてもプラットフォームの異常ではなく、ローカル信号は揃っている → INFO（総合ステータスに影響しない）
            alerts.append(f"[INFO] CloudWatch を取得できない：{cw['error']}")
        m = cw.get("metrics", {})
        sf = m.get("status_failed", {}).get("1h", {})
        if sf.get("max", 0) >= 1:
            alerts.append("[CRIT] CloudWatch：直近 1h に EC2 状態チェック失敗（StatusCheckFailed=1、AWS 側のハードウェア/ネットワークまたはインスタンス OS の異常）")
        cpu = m.get("cpu", {}).get("1h", {})
        if cpu.get("avg", 0) >= CW_CPU_WARN:
            alerts.append(f"[WARN] CloudWatch：直近 1h の CPU 平均 {cpu['avg']}% ≥ {CW_CPU_WARN}%（ピーク {m.get('cpu_peak', {}).get('1h', {}).get('max')}%）")
        for key, label in (("ebs_io_balance", "EBS IO バースト残高"), ("ebs_byte_balance", "EBS スループットバースト残高")):
            b = m.get(key)
            if b and b["latest"] <= CW_BALANCE_WARN:
                alerts.append(f"[WARN] CloudWatch：{label} {b['latest']}% ≤ {CW_BALANCE_WARN}%（枯渇するとディスク IO が制限される。"
                              f"24h 最低 {b.get('24h', {}).get('min')}%）")
        cc = m.get("cpu_credit")
        if cc and cc["latest"] <= CW_CPU_CREDIT_WARN:
            alerts.append(f"[WARN] CloudWatch：CPU クレジット残高 {cc['latest']} ≤ {CW_CPU_CREDIT_WARN}（枯渇すると CPU がベースライン性能に制限される）")
        for a in cw.get("alarms", []):
            if a["state"] == "ALARM":
                alerts.append(f"[WARN] CloudWatch アラーム {a['name']} が ALARM 状態（{a['metric']} 閾値 {a['threshold']}）")

    return alerts


# ----------------------------------------------------------------------------
# 「実際に AI に送る軽量 payload」の構築。ローカルには全量スナップショットを保存し、LLM には必要な部分だけ送って token を節約する
# ----------------------------------------------------------------------------
def build_ai_payload(snapshot):
    conts = [c for c in snapshot["containers"] if not c.get("ignored")]
    n_ignored = len(snapshot["containers"]) - len(conts)

    def is_nominal(c):
        # 累計再起動回数は判定に使わない（長期間で積み上がるのは普通でノイズ）。現在の状態と「最近の再起動」だけを見る
        ud = c.get("uptime_days")
        recent = isinstance(ud, (int, float)) and ud < RECENT_RESTART_DAYS
        return (c["status"] == "running" and c["health"] in ("healthy", "none")
                and not c.get("oom_killed") and not recent and not c.get("restarts_delta")
                and not c.get("restarted_since_last"))

    # notable = 通常と異なる特徴を持つコンテナ（停止 / unhealthy / OOM / 最近の再起動 / 前回巡検以降の再起動）
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

    # メモリ使用量上位 N（異常の有無に関係なく送る）。AI がメモリ/swap の問題を具体的なコンテナに結び付けられるように
    top_mem = sorted((c for c in conts if isinstance(c.get("mem_mib"), int)),
                     key=lambda c: c["mem_mib"], reverse=True)[:TOP_MEM_N]
    top_memory = [{k: c.get(k) for k in ("name", "mem_mib", "swap_mib", "budget_gib", "budget_pct")}
                  for c in top_mem]
    top_swap = sorted((c for c in conts if c.get("swap_mib")), key=lambda c: c["swap_mib"], reverse=True)[:TOP_MEM_N]
    # slack_alert.sh が監視しているコンテナ：閾値に対する余裕（上位 N に入っていなくても送る）
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
            "notable": notable,   # 注目すべきコンテナだけ送り、正常なものは件数のみ
            "top_memory": top_memory,
            "top_swap": [{"name": c["name"], "swap_mib": c["swap_mib"]} for c in top_swap],
            "slack_mem_budgets": budgets,
        },
        "web": snapshot["web"],
        "cloudwatch": snapshot.get("cloudwatch"),
        "nginx": snapshot.get("nginx"),
        "flags": snapshot["alerts"],   # 決定的な注目ポイント
        "rule_status": _overall(snapshot["alerts"]),
        "note_for_ai": ("flags はルールによる決定的な注目ポイント。リアルタイム通知は別途 Slack が担当している。"
                        "正常なコンテナは件数に集約し、IGNORE_CONTAINERS のコンテナは除外済み。"
                        "exit 0 で終了したコンテナの多くは一回限りのタスク。restarts は累計値（長期間で積み上がるのは普通）で、"
                        "restarts_delta が前回巡検以降の再起動増分。host.swap_io は換ページ速度：swap 使用量が多くても"
                        "換ページ速度が ≈0 なら過去の残留であり、現在のメモリ逼迫ではない。"
                        "mem_mib/swap_mib は各コンテナの cgroup 実測値（MiB）。容量の単位はすべて二進（GiB/MiB）。"
                        "slack_mem_budgets は既存のリアルタイム通知 slack_alert.sh が一部コンテナに設定しているメモリ閾値（GiB）"
                        "と現在の割合で、95% 以上が 15 分続くと Slack がリアルタイム通知する。"
                        "nginx はリバースプロキシのアクセスログ集計（窓内のリクエスト数、5xx 件数と比率、ステータスコード別/パス別）。"
                        "restarted_since_last=true かつ restarts_delta=0 はクラッシュ以外の再起動（手動/再作成/定期ジョブ）。"
                        "host.disk_trend はディスク増加速度（GiB/日、線形回帰）と WARN/CRIT 閾値到達までの見込み日数・日付。"
                        "cloudwatch は AWS 側から見た本 EC2 インスタンスの指標（5 分粒度、latest と直近 1h/24h の avg/min/max、"
                        "単位は unit）で、ローカル信号との突き合わせに使う。cloudwatch が null の場合は無効。"),
    }


# ----------------------------------------------------------------------------
# AI 診断
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
    """JSON を POST し、レスポンス本文を返す。レート制限 / 5xx / ネットワークエラーは間隔を空けて再試行し、それ以外は即座に例外。"""
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
            msg = f"ネットワークエラー：{e}"
            if attempt == retries - 1:
                raise RuntimeError(msg) from None
        wait = backoff[min(attempt, len(backoff) - 1)]
        print(f"[warn] {msg} → {wait}s 後に再試行（{attempt + 2}/{retries}）", file=sys.stderr)
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
            print(f"[warn] {model} 失敗：{e} → {models[i + 1]} に切り替え", file=sys.stderr)


def _diagnose_gemini_model(snapshot, model):
    payload = {
        "systemInstruction": {"parts": [{"text": _system_prompt()}]},
        "contents": [{"role": "user", "parts": [{"text": _user_content(snapshot)}]}],
        # 2.5 系は思考 token も maxOutputTokens に含まれるため、本文が途中で切れないよう余裕を持たせる
        "generationConfig": {"maxOutputTokens": 8192},
    }
    data = _post_json(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        payload, {"x-goog-api-key": GEMINI_API_KEY}, timeout=180,
    )
    cands = data.get("candidates", [])
    if not cands:
        raise RuntimeError(f"Gemini の応答に候補がない：{json.dumps(data, ensure_ascii=False)[:300]}")
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
    # name: (診断関数, 必要な API キーの変数名, モデル名)
    "gemini": (_diagnose_gemini, "GEMINI_API_KEY", GEMINI_MODEL),
    "anthropic": (_diagnose_anthropic, "ANTHROPIC_API_KEY", ANTHROPIC_MODEL),
}


# ----------------------------------------------------------------------------
# レポート生成 + 保存 + 古いファイルの削除
# ----------------------------------------------------------------------------
def _overall(alerts):
    # INFO は総合ステータスに影響しない
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
    # ホスト
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


# ----------------------------------------------------------------------------
# Slack 通知：状態が変わったときだけ送る。比較対象は前回「通知に成功した」状態（state.json に保存）。
# 送信に失敗した場合は更新せず、次回の実行で再送する。INFO は対象外。
# ----------------------------------------------------------------------------
_COLOR = {"危険": "danger", "注意": "warning", "正常": "good"}
NOTIFY_STATE_VERSION = 2   # アラート文言を変えたら上げる（旧文言との比較で誤通知しないため）
_EMOJI = {"危険": ":red_circle:", "注意": ":large_yellow_circle:", "正常": ":white_check_mark:"}


def _alert_key(a):
    # 数字を除く：同じ問題で数値が変わっただけ（swap 5.7→5.8GiB）は変化とみなさない
    return re.sub(r"\d+(?:\.\d+)?", "#", a)


def _send_slack(title, text, color, footer):
    payload = {"attachments": [{"color": color, "title": title, "text": text[:3500],
                                "footer": footer, "mrkdwn_in": ["text"]}]}
    _post(SLACK_WEBHOOK_URL, payload, {}, timeout=15, backoff=(3, 10))


def notify_on_change(alerts, prev_notify, ai_text, generated_at):
    """state に書き戻す notify 状態を返す。"""
    overall = _overall(alerts)
    cur = {_alert_key(a): a for a in alerts if a.startswith(("[WARN]", "[CRIT]"))}
    prev_keys = prev_notify.get("keys", {})
    prev_status = prev_notify.get("status", "正常")
    if prev_notify and prev_notify.get("v") != NOTIFY_STATE_VERSION:
        # 文言変更前の記録とは個別アラートを比較できない → 総合ステータスの変化だけで判断する
        prev_keys = {k: cur[k] for k in cur}
    new = [cur[k] for k in cur if k not in prev_keys]
    resolved = [prev_keys[k] for k in prev_keys if k not in cur]
    new_state = {"v": NOTIFY_STATE_VERSION, "status": overall, "keys": cur}
    if overall == prev_status and not new and not resolved:
        print("[ok] 状態に変化なし、Slack 通知なし")
        return new_state
    if not SLACK_WEBHOOK_URL:
        print("[warn] 状態は変化したが SLACK_WEBHOOK_URL が未設定のため通知しない", file=sys.stderr)
        return prev_notify     # 通知済みにしない：設定後の初回実行で送られる
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
        print("[ok] Slack に通知した")
        return new_state
    except RuntimeError as e:
        print(f"[warn] Slack 通知に失敗（次回の実行で再送）：{e}", file=sys.stderr)
        return prev_notify


def _short_lines(text, n):
    return text if len(text) <= n else text[:n] + "…"


def _acquire_lock():
    """巡検の重複実行を防ぐ（前回が docker や AI で止まっている場合など）。ロックが取れなければそのまま終了する。"""
    os.makedirs(OUT_DIR, exist_ok=True)
    fh = open(os.path.join(OUT_DIR, ".lock"), "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("[warn] 別の巡検が実行中のため、今回はスキップ", file=sys.stderr)
        sys.exit(0)
    return fh


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Sentry + PostHog プラットフォーム健康巡検")
    ap.add_argument("--dry-run", action="store_true", help="収集とルール判定のみ（LLM を呼ばない）")
    ap.add_argument("--stdout", action="store_true", help="レポートを端末にも出力する")
    ap.add_argument("--show-payload", action="store_true",
                    help="AI に送る JSON をそのまま端末に出力する（AI は呼ばない）")
    ap.add_argument("--no-notify", action="store_true", help="Slack 通知を送らない（--dry-run 時も送らない）")
    ap.add_argument("--notify-test", action="store_true", help="SLACK_WEBHOOK_URL にテストメッセージを 1 件送って終了する")
    args = ap.parse_args()

    if args.notify_test:
        if not SLACK_WEBHOOK_URL:
            sys.exit("SLACK_WEBHOOK_URL が未設定")
        _send_slack(":test_tube: プラットフォーム巡検: 通知テスト", "platform_health.py からのテスト送信です。",
                    "#439FE0", socket.gethostname())
        print("[ok] テストメッセージを送信した")
        return
    _lock = _acquire_lock()  # noqa: F841  プロセス終了時に自動で解放される

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

    # swap 換ページ速度：今回の実行中（最低 3 秒の窓）+ 前回巡検以降の平均
    elapsed = time.time() - t0
    if elapsed < 3:
        time.sleep(3 - elapsed)
    t1, vm1 = time.time(), read_vmstat()
    host["swap_io"] = {"now": _swap_rate(vm0, vm1, t1 - t0), "now_window_s": round(t1 - t0, 1)}
    if prev.get("ts") and prev.get("vmstat"):
        host["swap_io"]["since_last"] = _swap_rate(prev["vmstat"], vm1, t1 - prev["ts"])
        host["swap_io"]["since_last_min"] = round((t1 - prev["ts"]) / 60)
    if cinfo.get("error"):
        print(f"[warn] コンテナ情報の取得に失敗: {cinfo['error']}", file=sys.stderr)
    cw = collect_cloudwatch()
    alerts = compute_alerts(host, containers, web, cw, nginx)
    if cinfo.get("error"):
        # 取得できない ≠ 問題なし：総合ステータスを 🟢 にしてはいけない
        alerts.insert(0, f"[WARN] コンテナ状態の取得に失敗、今回の結果は不完全：{cinfo['error']}")
    elif cinfo.get("partial"):
        alerts.insert(0, f"[WARN] 一部コンテナの状態取得に失敗：{cinfo['partial']}")

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

    # AI に送る payload を出力して終了（--show-payload は AI を呼ばない）
    if args.show_payload:
        print("===== 以下が AI に送る JSON（--show-payload、軽量化済み）=====")
        print(json.dumps(ai_payload, ensure_ascii=False, indent=2))
        print("===== 終了（AI 呼び出し・ファイル書き込みなし。全量スナップショットは out/health_*.json）=====")
        return

    ai_text = ""
    if not args.dry_run:
        prov = PROVIDERS.get(AI_PROVIDER)
        if prov is None:
            print(f"[warn] 不明な AI_PROVIDER={AI_PROVIDER}（選択肢 {'/'.join(PROVIDERS)}）、AI 診断をスキップ", file=sys.stderr)
        elif not globals()[prov[1]]:
            print(f"[warn] {prov[1]} が未設定のため AI 診断をスキップ（--dry-run と同じ）", file=sys.stderr)
        else:
            try:
                ai_text = prov[0](ai_payload)
            except Exception as e:  # noqa
                print(f"[warn] AI 診断に失敗: {e}", file=sys.stderr)

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