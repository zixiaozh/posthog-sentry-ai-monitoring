"""Slack 通知：状態が変わったときだけ送る。"""

import os
import re
import socket
import sys

from . import config as cfg
from . import httpclient
from . import rules


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
    httpclient._post(cfg.SLACK_WEBHOOK_URL, payload, {}, timeout=15, backoff=(3, 10))


def notify_on_change(alerts, prev_notify, ai_text, generated_at):
    """state に書き戻す notify 状態を返す。"""
    overall = rules._overall(alerts)
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
    if not cfg.SLACK_WEBHOOK_URL:
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
                    f"{host} | {generated_at} | 詳細: {os.path.join(cfg.OUT_DIR, 'health_latest.md')}")
        print("[ok] Slack に通知した")
        return new_state
    except RuntimeError as e:
        print(f"[warn] Slack 通知に失敗（次回の実行で再送）：{e}", file=sys.stderr)
        return prev_notify


def _short_lines(text, n):
    return text if len(text) <= n else text[:n] + "…"
