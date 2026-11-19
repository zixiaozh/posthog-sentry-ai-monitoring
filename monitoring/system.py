"""ホストリソース（ディスク・メモリ・swap・load）、swap 換ページ速度、ディスク増加予測。"""

import datetime as dt
import json
import math
import os

from . import config as cfg


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
            "total_gib": round(st.f_blocks * st.f_frsize / cfg.GIB, 1),
            "used_gib": round(used / cfg.GIB, 1),
            "avail_gib": round(avail / cfg.GIB, 1),
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
# 1e) ディスク増加速度と閾値到達の予測（サンプルは state.json に保存。初回は out/ の過去スナップショットから補完）
# ----------------------------------------------------------------------------
def _seed_disk_history():
    """out/ の過去スナップショットから「空き容量 GiB」のサンプルを補完する。旧形式（十進 GB の total_gb/used_gb）にも対応。"""
    hist = []
    try:
        names = sorted(n for n in os.listdir(cfg.OUT_DIR) if n.startswith("health_2") and n.endswith(".json"))
    except OSError:
        return hist
    for n in names:
        try:
            ts = dt.datetime.strptime(n[7:22], "%Y%m%d_%H%M%S").replace(tzinfo=dt.timezone.utc).timestamp()
            with open(os.path.join(cfg.OUT_DIR, n), encoding="utf-8") as f:
                d = json.load(f)["host"]["disk"]
            avail = d["avail_gib"] if "avail_gib" in d else (d["total_gb"] - d["used_gb"]) * 1e9 / cfg.GIB
            hist.append([ts, round(avail, 2)])
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return hist


def update_disk_history(prev, disk, ts):
    # 「使用量」ではなく「空き容量」を記録する：算出方法（予約ブロックの扱い）や単位が変わっても系列が途切れない
    hist = prev.get("disk_avail_history") or _seed_disk_history()
    if isinstance(disk.get("avail_gib"), (int, float)):
        hist.append([ts, disk["avail_gib"]])
    cutoff = ts - cfg.DISK_TREND_DAYS * 86400
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
    for key, pct in (("warn", cfg.DISK_WARN), ("crit", cfg.DISK_CRIT)):
        remain = avail - cap * (1 - pct / 100)
        if growth > 0.01 and remain > 0:
            days = remain / growth
            out[f"days_to_{key}"] = round(days)
            out[f"eta_{key}"] = (dt.datetime.fromtimestamp(hist[-1][0], dt.timezone.utc)
                                 + dt.timedelta(days=days)).strftime("%Y-%m-%d")
    return out
