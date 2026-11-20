"""監査ログ：呼び出し 1 回を 1 行 JSON で追記する（collect.py と MCP サーバーで共用）。

記録はマスキングしてから書く。上限サイズを超えたら .1 に 1 世代だけ退避する。
書けなくても本処理は止めない（警告を標準エラーに出すだけ）。
"""
import json
import os
import sys

from . import mask

MAX_BYTES = 5 * 1024 * 1024


def append(path, rec, max_bytes=MAX_BYTES):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path) and os.path.getsize(path) > max_bytes:
            os.replace(path, path + ".1")
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(mask.mask_obj(rec), ensure_ascii=False, default=str) + "\n")
    except OSError as e:
        print(f"[warn] 監査ログに書けない：{e}", file=sys.stderr)
