"""前回巡検の状態（out/state.json）と、それとの比較（再起動の増分）。"""

import json
import os

from . import config as cfg


# ----------------------------------------------------------------------------
# 1d) 前回巡検の状態（再起動回数 / swap カウンタ等）。累計値ではなく「増分」を見るために使う
# ----------------------------------------------------------------------------
def load_state():
    try:
        with open(cfg.STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(prev, containers, collect_ok, vmstat, ts, disk_history, notify):
    state = {"ts": ts, "vmstat": vmstat, "disk_avail_history": disk_history, "notify": notify,
             # コンテナ取得に失敗したときは前回の値を引き継ぐ（次回に誤った増分を出さないため）
             "containers": ({c["name"]: {"restarts": c["restarts"], "started_at": c["started_at"]}
                             for c in containers} if collect_ok else prev.get("containers", {}))}
    os.makedirs(cfg.OUT_DIR, exist_ok=True)
    tmp = cfg.STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, cfg.STATE_FILE)


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
