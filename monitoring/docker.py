"""コンテナ：状態・メモリ / swap（cgroup v2）・Slack 閾値に対する割合・既知の定期再起動。"""

import os
import shutil
import subprocess
import sys

from . import config as cfg
from . import util


def _scheduled_restart(c):
    """既知の定期再起動によるもの（RestartCount は増えていない）なら True。"""
    return (any(p in c["name"] for p in cfg.SCHEDULED_RESTARTS) and not c.get("restarts_delta")
            and c.get("status") == "running")


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
        return {"error": f"docker ps 失敗：{util._short(e.stderr) or e.returncode}"}, []
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
    inspect_err = f"docker inspect 失敗（exit {r.returncode}）：{util._short(r.stderr)}" if r.returncode else None

    containers = []
    for line in insp.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        name = parts[0].lstrip("/")
        watched = any(name.startswith(p.strip()) or (p.strip() in name) for p in cfg.WATCH_PREFIXES if p.strip())
        containers.append({
            "name": name,
            "status": parts[1],
            "health": parts[2],
            "restarts": int(parts[3]) if parts[3].isdigit() else parts[3],
            "oom_killed": parts[4].strip().lower() == "true",
            "started_at": parts[5],
            "uptime_days": util._uptime_days(parts[5]),
            "exit_code": int(parts[6]) if parts[6].lstrip("-").isdigit() else None,
            "watched": watched,
            "ignored": any(p in name for p in cfg.IGNORE_CONTAINERS),
            "id": ids.get(name, ""),
        })
    containers.sort(key=lambda c: (not c["watched"], c["name"]))
    if inspect_err and not containers:
        return {"error": inspect_err}, []
    if inspect_err:
        print(f"[warn] {inspect_err}（{len(containers)}/{len(names)} コンテナを解析済み）", file=sys.stderr)
    return {"error": None, "partial": inspect_err}, containers


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
            c["mem_mib"] = round((cur - inactive) / cfg.MIB)
            sw = os.path.join(d, "memory.swap.current")
            if os.path.exists(sw):
                c["swap_mib"] = round(_read_cg_int(sw) / cfg.MIB)
            lim = _read_cg_int(os.path.join(d, "memory.max"))
            c["mem_limit_mib"] = round(lim / cfg.MIB) if lim else None
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
                by_name[name]["mem_mib"] = round(_parse_size(used) / cfg.MIB)
                by_name[name]["mem_limit_mib"] = round(_parse_size(limit) / cfg.MIB)
        except ValueError:
            continue


def apply_mem_budgets(containers):
    budgets = {}
    for item in cfg.CONTAINER_MEM_BUDGETS.split(","):
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
            c["budget_pct"] = round(c["mem_mib"] * cfg.MIB * 100 / (b * cfg.GIB))
