#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""collect.py — 監視データを読み取り専用で返す CLI（MCP サーバーから SSM 経由で呼ばれる入口）。

  python3 collect.py list                          # 使えるコマンドと引数（JSON）
  python3 collect.py status
  python3 collect.py nginx --hours 6
  python3 collect.py logs --name sentry-self-hosted-nginx-1 --minutes 30 --contains " 502 " --max-lines 50

安全上の約束（docs/SECURITY.md も参照）：
  - 実行できるのは monitoring/queries.py の COMMANDS（許可リスト）だけ。引数は型・範囲・形式を検証し、
    コンテナ名は実在する名前との完全一致のみ。任意のコマンド・SQL・docker 引数は受け付けない。
  - 書き込まない：state.json は読むだけ（日次巡検に影響しない）。例外は監査ログ（out/collect_audit.log）への追記のみ。
  - 出力はすべてマスキングする（IP・メールアドレス・API キー・トークン・Webhook・DSN 等）。
    ログ等の外部由来の文字列は制御文字を除き、「信頼できないデータ」と明示して返す。
  - 実行時間（COLLECT_TIMEOUT_S）と出力サイズ（COLLECT_MAX_BYTES）に上限を設ける。
出力：標準出力に JSON 1 つ。終了コード 0 = 成功 / 1 = 実行時エラー / 2 = 引数エラー。
"""
import json
import os
import signal
import sys
import time

from monitoring import audit
from monitoring import config as cfg
from monitoring import mask
from monitoring import queries

TIMEOUT_S = int(os.environ.get("COLLECT_TIMEOUT_S", "120"))
MAX_BYTES = int(os.environ.get("COLLECT_MAX_BYTES", "262144"))     # 256 KiB（AI のコンテキストと SSM の出力上限を考慮）
AUDIT_FILE = os.path.join(cfg.OUT_DIR, "collect_audit.log")
AUDIT_MAX_BYTES = 5 * 1024 * 1024


def _emit(obj, code):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
    sys.stdout.flush()
    return code


def _audit(rec):
    """誰が・いつ・何を・どの引数で実行し、成否と出力サイズはどうだったかを 1 行 JSON で追記する。"""
    audit.append(AUDIT_FILE, rec, AUDIT_MAX_BYTES)


def _parse(argv):
    """argparse は使わない：未知のオプションの扱いや短縮形（--ho → --hours）で予期しない受け付けをしないよう、
    --key value の形だけを厳密に解釈する。"""
    if not argv or argv[0] in ("-h", "--help"):
        return "list", {}
    cmd, rest = argv[0], argv[1:]
    if cmd != "list" and cmd not in queries.COMMANDS:
        raise ValueError(f"許可されていないコマンド：{cmd[:40]}（collect.py list で一覧）")
    specs = queries.COMMANDS[cmd]["params"] if cmd != "list" else {}
    raw = {}
    if len(rest) % 2:
        raise ValueError("引数は --名前 値 の組で指定する")
    for k, v in zip(rest[::2], rest[1::2]):
        if not k.startswith("--"):
            raise ValueError(f"引数名が不正：{k[:40]}")
        key = k[2:].replace("-", "_")
        if key not in specs:
            raise ValueError(f"{cmd} に引数 {k[:40]} はない")
        if key in raw:
            raise ValueError(f"引数 {k} が重複している")
        raw[key] = v
    return cmd, raw


def _list():
    out = {}
    for name, c in queries.COMMANDS.items():
        out[name] = {"help": c["help"], "params": {
            k: {kk: vv for kk, vv in p.items() if kk in ("type", "range", "default", "max_len", "required", "help")}
            for k, p in c["params"].items()}}
    return {"commands": out}


def _on_timeout(signum, frame):
    raise TimeoutError(f"実行時間の上限（{TIMEOUT_S} 秒）を超えた")


def main(argv):
    t0 = time.time()
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "argv": argv[:12],
           "user": os.environ.get("SUDO_USER") or os.environ.get("USER") or str(os.getuid())}
    try:
        cmd, raw = _parse(argv)
        rec["command"] = cmd
        if cmd == "list":
            return _emit(_list(), 0)
        spec = queries.COMMANDS[cmd]
        args = {k: queries.validate(p, raw.get(k)) for k, p in spec["params"].items()}
        rec["params"] = args
    except ValueError as e:
        rec.update(ok=False, error=f"引数エラー：{e}", ms=int((time.time() - t0) * 1000))
        _audit(rec)
        return _emit({"error": f"引数エラー：{e}"}, 2)
    except RuntimeError as e:   # コンテナ名の検証で docker が使えない等
        rec.update(ok=False, error=str(e), ms=int((time.time() - t0) * 1000))
        _audit(rec)
        return _emit({"error": str(e)}, 1)

    signal.signal(signal.SIGALRM, _on_timeout)
    signal.alarm(TIMEOUT_S)
    try:
        result = spec["func"](**args)
        code = 0
    except Exception as e:  # noqa  どんな失敗でも JSON で返す（スタックトレースにパス等を出さない）
        result, code = {"error": f"{type(e).__name__}: {str(e)[:300]}"}, 1
    finally:
        signal.alarm(0)

    body = mask.mask_obj(result)
    body["_meta"] = {"command": cmd, "params": args, "generated_at": rec["ts"], "masked": True,
                     "host": "ec2 (read-only collector)"}
    text = json.dumps(body, ensure_ascii=False, default=str)
    if len(text.encode("utf-8")) > MAX_BYTES:
        body = {"error": f"出力が上限 {MAX_BYTES} バイトを超えた。期間や行数を絞って再実行すること", "_meta": body["_meta"]}
        code = 1
    rec.update(ok=code == 0, error=body.get("error"), ms=int((time.time() - t0) * 1000),
               bytes=len(text.encode("utf-8")))
    _audit(rec)
    return _emit(body, code)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
