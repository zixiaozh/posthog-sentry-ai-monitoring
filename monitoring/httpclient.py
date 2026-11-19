"""HTTP POST（再試行あり）。AI と Slack が使う。"""

from urllib import request, error
import json
import sys
import time

from . import util


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
            msg = f"HTTP {e.code} {e.reason}: {util._short(e.read().decode('utf-8', 'replace'), 200)}"
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
