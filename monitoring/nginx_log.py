"""nginx アクセスログの集計（docker logs、失敗時は json-file を直接読む）。パスはクエリ除去・ID 正規化。"""

import datetime as dt
import json
import os
import re
import subprocess
import time

from . import config as cfg
from . import util


# ----------------------------------------------------------------------------
# 3b) nginx アクセスログ：窓内のリクエスト数と 5xx（ストリームで数えるのでメモリ使用は一定）
#     パスはクエリを除去（Sentry の送信 URL には sentry_key が含まれる）、数字部分は {n} に正規化して集計
# ----------------------------------------------------------------------------
_ACCESS_RE = re.compile(r'"([A-Z]+) (\S+) [^"]*" (\d{3}) ')


def _norm_path(path):
    path = path.split("?", 1)[0]
    return re.sub(r"/[0-9a-f]{16,}|/\d+", lambda m: "/{id}" if len(m.group()) > 12 else "/{n}", path)[:80]


class _Counter:
    """アクセスログ行を数える（ストリーム処理、メモリ使用は一定）。"""

    def __init__(self):
        self.total = self.n5 = 0
        self.codes, self.paths = {}, {}

    def feed(self, line):
        m = _ACCESS_RE.search(line)
        if not m:
            return False
        self.total += 1
        if m.group(3).startswith("5"):
            self.n5 += 1
            self.codes[m.group(3)] = self.codes.get(m.group(3), 0) + 1
            key = f"{m.group(1)} {_norm_path(m.group(2))}"
            if key in self.paths or len(self.paths) < 200:
                self.paths[key] = self.paths.get(key, 0) + 1
        return True

    def result(self):
        return {"requests": self.total, "5xx": self.n5,
                "5xx_pct": round(self.n5 * 100 / self.total, 2) if self.total else 0.0,
                "by_code": self.codes,
                "top_paths": sorted(self.paths.items(), key=lambda kv: -kv[1])[:5]}


def _nginx_via_docker(name, window_s, cnt, rec):
    """docker logs で読む。失敗したら (False, エラー文) を返す。"""
    proc = subprocess.Popen(["docker", "logs", "--since", f"{int(window_s)}s", name],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    other = ""    # アクセスログ以外の最後の行（失敗時の原因表示用。docker のエラーは stderr→stdout に来る）
    deadline = time.time() + 60
    for line in proc.stdout:
        if not cnt.feed(line) and line.strip():
            other = line.strip()
        if time.time() > deadline:
            proc.kill()
            rec["truncated"] = True
            break
    proc.wait(timeout=10)
    if proc.returncode not in (0, None, -9) and cnt.total == 0:
        return False, f"docker logs exit {proc.returncode}" + (f": {other}" if other else "")
    return True, None


def _reverse_lines(path, block=1 << 20):
    """ファイルを末尾から 1 行ずつ（bytes）返す。巨大なログでも窓の分だけ読めば済む。"""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pos, rest = f.tell(), b""
        while pos > 0:
            n = min(block, pos)
            pos -= n
            f.seek(pos)
            buf = f.read(n) + rest
            lines = buf.split(b"\n")
            rest = lines.pop(0)
            for ln in reversed(lines):
                yield ln
        if rest:
            yield rest


def _nginx_via_file(name, window_s, cnt, rec):
    """docker の json-file ログを直接読む（docker logs がログ破損で失敗するときの代替）。
    壊れた行（NUL 混入等）は飛ばして数える。"""
    r = subprocess.run(["docker", "inspect", "-f", "{{.LogPath}}", name], capture_output=True, text=True, timeout=15)
    path = r.stdout.strip() if r.returncode == 0 else ""
    if not path or not os.path.exists(path):
        raise RuntimeError(f"ログファイルが見つからない（{path or 'LogPath 取得失敗'}）")
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=window_s)).strftime("%Y-%m-%dT%H:%M:%S")
    bad, reached_start, deadline = 0, True, time.time() + 60
    for raw in _reverse_lines(path):
        if time.time() > deadline:
            rec["truncated"] = True
            reached_start = False
            break
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw.replace(b"\x00", b"").decode("utf-8", "replace"))
            ts = obj.get("time", "")[:19]
        except ValueError:
            bad += 1
            continue
        if ts and ts < since:
            reached_start = False
            break
        cnt.feed(obj.get("log", ""))
    rec["source"] = "logfile"
    rec["corrupt_lines"] = bad
    if reached_start:
        rec["partial_window"] = True    # 現在のログファイルが窓より新しい（ローテーション/再作成直後）


def collect_nginx(window_s):
    out = []
    for name in cfg.NGINX_CONTAINERS:
        rec = {"container": name, "window_h": round(window_s / 3600, 1)}
        try:
            cnt = _Counter()
            ok, err = _nginx_via_docker(name, window_s, cnt, rec)
            if not ok:
                rec["docker_logs_error"] = err
                cnt = _Counter()
                _nginx_via_file(name, window_s, cnt, rec)
            rec.update(cnt.result())
        except Exception as e:  # noqa
            rec["error"] = util._short(str(e))
        out.append(rec)
    return out
