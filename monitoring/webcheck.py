"""Web 疎通（ヘルス端点への HTTP GET）。"""

from urllib import request, error
import ssl
import time

from . import config as cfg


# ----------------------------------------------------------------------------
# 3) Web 疎通
# ----------------------------------------------------------------------------
def _ssl_ctx():
    if cfg.INSECURE:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


def collect_web():
    targets = []
    if cfg.SENTRY_URL:
        targets.append(("Sentry", cfg.SENTRY_URL))
    if cfg.POSTHOG_URL:
        targets.append(("PostHog", cfg.POSTHOG_URL))
    for item in cfg.WEB_TARGETS.split(","):
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
            with request.urlopen(req, timeout=cfg.HTTP_TIMEOUT, context=_ssl_ctx()) as resp:
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
