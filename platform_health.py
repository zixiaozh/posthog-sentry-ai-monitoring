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

構成：本ファイルは CLI（引数・ロック・実行の流れ）だけを持つ。収集・判定・AI・通知は monitoring/ パッケージにあり、
      MCP サーバー等からも同じ処理を呼べるようにしている。

使い方：
  # 収集とルール判定のみ（LLM を呼ばない。まず収集の確認に）
  python3 platform_health.py --dry-run
  # AI 診断あり（AI_PROVIDER=gemini は GEMINI_API_KEY、=anthropic は ANTHROPIC_API_KEY が必要）
  python3 platform_health.py

注意：docker 情報の取得には権限が必要。普段 `sudo docker` を使っているなら
      `sudo python3 platform_health.py` で実行する（.env はスクリプト自身が読むので -E は不要）。
      または実行ユーザーを docker グループに追加する。
"""

import argparse
import datetime as dt
import fcntl
import json
import os
import socket
import sys

from monitoring import config as cfg
from monitoring import ai
from monitoring import queries
from monitoring import report
from monitoring import slack
from monitoring import state


def _acquire_lock():
    """巡検の重複実行を防ぐ（前回が docker や AI で止まっている場合など）。ロックが取れなければそのまま終了する。"""
    os.makedirs(cfg.OUT_DIR, exist_ok=True)
    fh = open(os.path.join(cfg.OUT_DIR, ".lock"), "w")
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
        if not cfg.SLACK_WEBHOOK_URL:
            sys.exit("SLACK_WEBHOOK_URL が未設定")
        slack._send_slack(":test_tube: プラットフォーム巡検: 通知テスト", "platform_health.py からのテスト送信です。",
                    "#439FE0", socket.gethostname())
        print("[ok] テストメッセージを送信した")
        return
    _lock = _acquire_lock()  # noqa: F841  プロセス終了時に自動で解放される

    now = dt.datetime.now(dt.timezone.utc)
    generated_at = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    prev = state.load_state()
    r = queries.run_checks(prev, generated_at)
    snapshot, cinfo = r["snapshot"], r["cinfo"]
    vm1, t1, disk_hist = r["vm1"], r["t1"], r["disk_hist"]
    containers, alerts = snapshot["containers"], snapshot["alerts"]

    ai_payload = ai.build_ai_payload(snapshot)

    # AI に送る payload を出力して終了（--show-payload は AI を呼ばない）
    if args.show_payload:
        print("===== 以下が AI に送る JSON（--show-payload、軽量化済み）=====")
        print(json.dumps(ai_payload, ensure_ascii=False, indent=2))
        print("===== 終了（AI 呼び出し・ファイル書き込みなし。全量スナップショットは out/health_*.json）=====")
        return

    ai_text = ""
    if not args.dry_run:
        prov = ai.PROVIDERS.get(cfg.AI_PROVIDER)
        if prov is None:
            print(f"[warn] 不明な AI_PROVIDER={cfg.AI_PROVIDER}（選択肢 {'/'.join(ai.PROVIDERS)}）、AI 診断をスキップ", file=sys.stderr)
        elif not getattr(cfg, prov[1]):
            print(f"[warn] {prov[1]} が未設定のため AI 診断をスキップ（--dry-run と同じ）", file=sys.stderr)
        else:
            try:
                ai_text = prov[0](ai_payload)
            except Exception as e:  # noqa
                print(f"[warn] AI 診断に失敗: {e}", file=sys.stderr)

    md = report.render_markdown(snapshot, ai_text, generated_at)

    os.makedirs(cfg.OUT_DIR, exist_ok=True)
    stamp = now.strftime("%Y%m%d_%H%M%S")
    with open(os.path.join(cfg.OUT_DIR, f"health_{stamp}.json"), "w", encoding="utf-8") as f:
        json.dump(snapshot, f, ensure_ascii=False, indent=2)
    notify = prev.get("notify", {})
    if not (args.dry_run or args.no_notify):
        notify = slack.notify_on_change(alerts, notify, ai_text, generated_at)
    state.save_state(prev, containers, not cinfo.get("error"), vm1, t1, disk_hist, notify)
    with open(os.path.join(cfg.OUT_DIR, f"health_{stamp}.md"), "w", encoding="utf-8") as f:
        f.write(md)
    with open(os.path.join(cfg.OUT_DIR, "health_latest.md"), "w", encoding="utf-8") as f:
        f.write(md)
    report.cleanup_old(cfg.OUT_DIR, cfg.KEEP_DAYS)

    n_crit = sum(1 for a in alerts if a.startswith("[CRIT]"))
    print(f"[ok] containers={len(containers)} alerts={len(alerts)} crit={n_crit}")
    if args.stdout or args.dry_run:
        print("\n" + md)


if __name__ == "__main__":
    main()
