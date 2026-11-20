"""Sentry + PostHog プラットフォーム巡検の共通処理（収集・判定・AI 診断・通知）。

モジュール：
  config      設定（環境変数と .env）。cfg.X として実行時に参照する
  docker      コンテナの状態・メモリ / swap・既知の定期再起動
  system      ホストリソース・swap 換ページ速度・ディスク増加予測
  webcheck    Web 疎通
  nginx_log   nginx アクセスログの集計（パスのマスキング、ログ破損時の代替経路）
  sentry      Sentry の取り込み量（ClickHouse）
  cloudwatch  CloudWatch 指標とアラーム
  state       前回巡検の状態と増分
  rules       判定ルール（WARN / CRIT / INFO）
  ai          AI 診断（payload・プロンプト・Gemini / Anthropic）
  httpclient  HTTP POST（再試行）
  report      Markdown レポート
  slack       状態変化時の Slack 通知
  queries     collect.py のコマンド（許可リスト）と巡検の共通処理
  mask        出力のマスキングと外部由来文字列の無害化
  audit       監査ログ（collect.py と MCP サーバーで共用）

標準ライブラリのみに依存する（EC2 の日次巡検でそのまま使うため）。
"""
