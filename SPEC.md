# platform_health.py 仕様書

自前ホストの **Sentry + PostHog プラットフォーム**（EC2・Docker）の健康巡検スクリプト。
本書では **何をチェックするか、閾値と指標、AI に何を渡すか、通知と運用** を説明する。

- 対象：`platform_health.py`（外部依存なし。Python 標準ライブラリ + aws CLI）
- 位置づけ：**1 日 1 回の診断と予測 + AI による原因分析**。リアルタイム通知の `slack_alert.sh` / `slack_alert_http.sh` を補完し、役割は重複させない
- データソース：ローカル（docker / /proc / nginx ログ / HTTP 疎通）+ CloudWatch。Sentry / PostHog へのログインや API token は不要

---

## 1. 処理の流れ

```
収集（ローカル信号 + CloudWatch） → ルール層（決定的な flags と総合ステータス）
  → 軽量化（AI 用 payload） → AI 診断 → 出力（JSON + Markdown） → 状態変化時のみ Slack 通知
```

`--show-payload` は軽量化の直後で止まり、**AI に送る JSON** を端末に出力する（AI 呼び出し・ファイル書き込みなし）。

---

## 2. 収集項目

### 2.1 ホストリソース（`/proc`、`os.statvfs`）

| 項目 | フィールド | 取得元 |
|------|-----------|--------|
| ディスク（ルート `/`） | `total_gib` / `used_gib` / `avail_gib` / `used_pct` | statvfs（Use% は `df` と同じ算出：予約ブロックを除外、切り上げ） |
| メモリ | `total_gib` / `available_gib` / `used_pct` | /proc/meminfo |
| swap | `total_gib` / `used_gib` / `used_pct` | /proc/meminfo |
| load | `1m` / `5m` / `15m` / `cpu_count` / `per_cpu_1m` | os.getloadavg |

> 容量は**二進単位（GiB / MiB）に統一**。`slack_alert.sh`（÷1048576）、`docker stats`、`df -h` と揃えることで閾値が比較可能になる。

### 2.2 ディスク増加予測（`host.disk_trend`）

毎回**空き容量**を `out/state.json` に保存し（直近 `DISK_TREND_DAYS` 日分。初回は `out/health_*.json` の過去スナップショットから補完）、
最小二乗法で **GiB/日** を求め、Use% が `DISK_WARN` / `DISK_CRIT` に達するまでの日数と日付を予測する。サンプル期間が 12 時間未満なら計算しない。
使用量ではなく空き容量を記録するのは、算出方法や単位が変わっても系列が途切れないようにするため。

### 2.3 swap の換ページ（`/proc/vmstat` の `pswpin` / `pswpout`）

| フィールド | 意味 |
|-----------|------|
| `swap_io.now` | 今回の実行中（3 秒以上の窓）の換入 / 換出速度 KB/s |
| `swap_io.since_last` | 前回巡検以降の平均換入 / 換出速度 KB/s |

> 「swap 使用量」は過去に換出されたことを示すだけ。**今メモリが逼迫しているかは換ページ速度**で分かる。使用量が多くても速度 ≈0 なら過去の残留。

### 2.4 コンテナ（`docker inspect` + cgroup、root または docker グループが必要）

**全コンテナ**（停止中を含む）について取得する：

| フィールド | 意味 |
|-----------|------|
| `name` / `status` / `health` / `exit_code` | 名前 / running・exited 等 / healthy・unhealthy・none / 終了コード |
| `restarts` | 累計再起動回数（参考のみ。単独では判定に使わない） |
| `restarts_delta` | **前回巡検以降の再起動増分**（`out/state.json` と比較。初回やコンテナ再作成時は空） |
| `restarted_since_last` | 起動時刻が前回と違う。RestartCount は restart policy の自動再起動しか数えないため、`docker restart` / compose 再作成 / 定期ジョブによる再起動はこれでしか分からない |
| `oom_killed` | OOM kill されたか |
| `started_at` / `uptime_days` | 起動時刻 / 稼働日数 |
| `watched` | 名前が `WATCH_PREFIXES` のいずれかを含む = コアコンテナ（★） |
| `mem_mib` / `swap_mib` / `mem_limit_mib` | メモリ / swap の実使用量と上限（cgroup v2 を直接読む。`docker stats` と同じ算出。読めない場合は `docker stats` で代替、メモリのみ） |
| `budget_gib` / `budget_pct` | `slack_alert.sh` がそのコンテナに設定しているメモリ閾値（`CONTAINER_MEM_BUDGETS`）と現在の割合 |

### 2.5 Web 疎通（ヘルス端点への HTTP GET）

| フィールド | 意味 |
|-----------|------|
| `name` / `url` | 対象名 / URL |
| `status` / `ok` | HTTP ステータス / 2xx–3xx か |
| `latency_ms` / `error` | 応答時間 / 接続失敗時のエラー |

確認済みの端点（依存先まで検査する深いヘルスチェック。いずれも 200）：
- Sentry：`https://sentry.randd-nn-freebit.net/_health/`
- PostHog：`https://posthog.randd-nn-freebit.net/_health`（EC2 上の実測は約 150ms、2026-10）

### 2.6 nginx アクセスログ（`docker logs`）

`NGINX_CONTAINERS`（既定 `sentry-self-hosted-nginx-1`）の**前回巡検以降**（最長 `NGINX_MAX_WINDOW_H`=24h）について、
リクエスト数、5xx の件数と比率、ステータスコード別件数、5xx の多いパス上位 5 を集計する。ストリームで数えるためメモリ使用は一定、最長 60 秒。
パスは**クエリを除去**（Sentry の送信 URL には `sentry_key` が含まれる）し、数字部分は `{n}` に正規化する。

> `slack_alert_http.sh` との違い：あちらは 5 分ごとに 5xx が 1 件でもあれば即通知。こちらは 1 日分の**比率と分布**を見て、異常かどうかを AI に判断させる。

### 2.7 CloudWatch（`aws cloudwatch get-metric-data` / `describe-alarms`）

ローカル信号は「コンテナ / プロセスの内側」、CloudWatch は「インスタンスの外側」を見る。両者を突き合わせて原因を絞る。

- インスタンス ID / リージョン / インスタンスタイプは IMDSv2 から自動取得（`CW_INSTANCE_ID` / `AWS_REGION` で上書き可）
- 1 回のリクエストで直近 24h・5 分粒度の以下の指標を取得し、`latest` と直近 1h / 24h の `avg / min / max` に集約する：

| 指標 | 統計 | 換算 | 見るもの |
|------|------|------|---------|
| CPUUtilization | Average / Maximum | % | インスタンス全体の CPU |
| NetworkIn / NetworkOut | Sum | KB/s | 通信量の異常（急増・ゼロ） |
| EBSReadBytes / EBSWriteBytes | Sum | KB/s | ディスクのスループット |
| EBSReadOps / EBSWriteOps | Sum | IOPS | ディスク IOPS |
| EBSIOBalance% / EBSByteBalance% | Minimum | % | EBS バースト残高（枯渇すると制限される） |
| CPUCreditBalance | Minimum | credits | T 系インスタンスのみ |
| StatusCheckFailed | Maximum | 0/1 | AWS の状態チェック |

- アラーム：ディメンションに本インスタンス ID を含む CloudWatch アラームとその状態（他プロジェクトのアラームは対象外）
- 必要な権限：`cloudwatch:GetMetricData`、`cloudwatch:DescribeAlarms`（`iam/cloudwatch-read-policy.json`）
- 費用：GetMetricData は約 $0.01 / 1000 指標。1 回 12 指標なので無視できる

---

## 3. 閾値と判定ルール

> ★これは**リアルタイム通知ではない**。リアルタイム通知は `slack_alert.sh` が担当する。ここでの閾値は **AI への注目ポイント（flags）** と **総合ステータス** の算出に使う。
> 数値は **`slack_alert.sh` と意図的に揃えて**おり、変更するときは両方を直すこと。

### 3.1 ホスト

| 指標 | WARN | CRIT | 対応する Slack 側の変数 |
|------|------|------|----------------------|
| ディスク使用率 | ≥ 85% | ≥ 95% | DISK_WARN_PCT / DISK_CRIT_PCT |
| 空きメモリ | < 2 GiB | < 1 GiB | RAM_WARN_GB / RAM_CRIT_GB |
| swap 使用量 | ≥ 8 GiB | ≥ 10 GiB | SWAP_WARN_GB / SWAP_CRIT_GB（換ページがなければ 1 段階下げる。下記） |
| コアあたり load（1m） | ≥ 1.5 | — | （本スクリプト独自） |
| swap 換ページ（前回巡検以降の平均） | ≥ 1024 KB/s | — | （本スクリプト独自、`SWAP_IO_WARN_KBPS`） |
| ディスク到達予測 | `DISK_FORECAST_WARN_DAYS`（30）日以内に `DISK_WARN` 到達見込み | — | （本スクリプト独自） |

> 2026-10-21 に `slack_alert.sh` の実物と照合して修正：swap WARN は誤って 5 になっていた。単位も十進 GB だった。

- swap 使用量のアラートには換ページ速度を注記する（前回巡検以降の長い窓を優先）。**換ページが `SWAP_IO_WARN_KBPS`/10 未満なら残留とみなして 1 段階下げる**（WARN→INFO、CRIT→WARN）。
  長期間残っている swap が毎回ノイズとして出るのを防ぐため。実際のメモリ逼迫は「継続的な換ページ」ルールで検出する。Slack 側の絶対閾値の通知には影響しない。

### 3.2 コンテナ

| 状況 | レベル |
|------|--------|
| `oom_killed` = true（**稼働中かどうかに関係なく**） | CRIT |
| `exited` かつ終了コード ≠ 0 / `restarting` / `dead` | CRIT |
| `exited` かつ終了コード = 0（正常終了。多くは一回限りのタスク） | INFO |
| `created`（作成後一度も起動していない） | INFO |
| `paused` | WARN |
| running だが `health` が healthy / none 以外 | WARN |
| 前回巡検以降の再起動 ≥ `RESTART_DELTA_CRIT`（3） | CRIT（クラッシュの繰り返しの疑い） |
| 前回巡検以降の再起動 1 〜 N-1 回 | WARN |
| 起動時刻が変わったが RestartCount は増えていない（手動 restart / 再作成 / 定期ジョブ） | INFO |
| 増分データなし（初回 / 再作成）かつ `uptime_days` < `RECENT_RESTART_DAYS`（1） | INFO |
| メモリが Slack 閾値の `BUDGET_INFO_PCT`（80%）以上 | INFO |
| 名前が `IGNORE_CONTAINERS` に一致 | 判定しない・AI に送らない |
| docker 自体の取得失敗（権限等） | WARN（誤って 🟢 にしないため） |
| 一部コンテナの inspect 失敗（取得中に削除された等） | WARN（他のコンテナは通常どおり判定） |

> 累計再起動回数は**単独では判定にも AI への材料にも使わない**（数か月で数十回積み上がるのは普通でノイズ）。**増分**だけを見る。
> 初回実行は基準を作るだけで、増分は 2 回目以降に出る。

### 3.3 Web と nginx

| 状況 | レベル |
|------|--------|
| 疎通失敗（接続不可 / 4xx / 5xx） | CRIT |
| 応答 ≥ `WEB_LATENCY_WARN_MS`（5000ms） | WARN |
| nginx 5xx ≥ `NGINX_5XX_WARN_MIN`（20）件 かつ ≥ `NGINX_5XX_WARN_PCT`（1%） | WARN |
| 上記未満で 5xx あり / nginx ログが取れない | INFO |

### 3.4 CloudWatch

| 状況 | レベル |
|------|--------|
| 直近 1h に `StatusCheckFailed` = 1 | CRIT |
| 直近 1h の CPU 平均 ≥ `CW_CPU_WARN`（80%） | WARN |
| EBS IO / スループットのバースト残高 ≤ `CW_BALANCE_WARN`（20%） | WARN |
| CPU クレジット残高 ≤ `CW_CPU_CREDIT_WARN`（10、T 系のみ） | WARN |
| 本インスタンスの CloudWatch アラームが ALARM | WARN |
| CloudWatch を取得できない（権限不足 / EC2 外 / aws CLI なし） | INFO（ローカル信号は揃っているので総合ステータスに影響しない） |

### 3.5 総合ステータス

- **CRIT** が 1 つでもある → 🔴 危険
- **WARN** がある → 🟡 注意
- **INFO** だけ → 🟢 正常（INFO は総合ステータスに影響しない）

ルール層の総合ステータスは `rule_status` として AI にも渡し、AI はこれを基準にする（異なる判断をする場合は根拠を明記させる）。

---

## 4. AI に渡す内容（token の節約）

**ローカルには全量スナップショットを保存し、LLM には必要な部分だけ送る。**

- **正常なコンテナは件数に集約**（`summary = { total, running, not_running, nominal, ignored }`）。
  nominal = running かつ health が healthy/none かつ OOM なし かつ最近の再起動なし かつ再起動増分なし。
- **notable（正常でない）コンテナだけ個別に送る**：`name / status / exit_code / health / restarts / restarts_delta / restarted_since_last / started_at / oom_killed / uptime_days / mem_mib / swap_mib`。
- **メモリ / swap 上位 N は常に送る**（`top_memory` / `top_swap`、`TOP_MEM_N`=8）。メモリの問題を具体的なコンテナに結び付けるため。
- **Slack 側のメモリ閾値に対する割合**（`slack_mem_budgets`）、nginx 集計、CloudWatch、`disk_trend`、`swap_io` も送る。
- `note_for_ai` で各フィールドの読み方（累計と増分の違い、残留 swap の扱い等）を説明する。

### プロンプトの要件

- 構成：① 総合ステータス（1 行）② 検出された異常と影響 ③ 想定原因 ④ 推奨アクション
- 総合ステータスは `rule_status` を基準にする
- ローカル信号と CloudWatch を突き合わせ、関連があれば言及する
- 再起動など**サービスに影響する操作は具体的な根拠がある場合のみ**推奨する（swap 使用量だけを理由にしない）
- `disk_trend` があれば容量到達の見込み時期と対策に触れる
- 前置き・挨拶なし、与えられたデータのみ使用

`AI_PROVIDER` でモデルを選ぶ（既定 `gemini`。`anthropic` も可）。キーが未設定ならスキップしてルール判定のみ出力する。

---

## 5. 出力

| ファイル | 内容 |
|---------|------|
| `out/health_YYYYMMDD_HHMMSS.json` | 全量スナップショット（保存用） |
| `out/health_YYYYMMDD_HHMMSS.md` | Markdown レポート |
| `out/health_latest.md` | 最新レポート（固定パス） |
| `out/state.json` | 前回巡検の状態（再起動回数・起動時刻、swap カウンタ、ディスク空き容量の履歴、通知状態）。削除すると基準を作り直す |

`KEEP_DAYS`（14）日より古いファイルは自動削除。

---

## 6. 既存の Slack bot との役割分担

| | slack_alert.sh + slack_alert_http.sh | platform_health.py（本スクリプト） |
|---|---|---|
| 役割 | **リアルタイム検知**（5 分ごと） | **日次の診断と予測**（1 日 1 回） |
| 対象 | RAM / Disk / Swap の閾値、4 コンテナのメモリ、nginx 5xx | コンテナ状態・再起動増分・非クラッシュ再起動、Web 疎通、CloudWatch、nginx 5xx 比率、ディスク増加予測、AI による原因分析 |
| 閾値 | **正（唯一の基準）** | Slack に合わせる（swap 8/10 GiB、RAM 2/1 GiB、Disk 85/95%、コンテナのメモリ閾値） |
| 通知 | 閾値超過で即時（同じアラートは 24h に 1 回） | **状態が変わったときだけ**同じチャンネルへ（新規 / 解消 / 総合ステータスの変化 + AI 要約） |

注意：本スクリプトは 1 日 1 回なので、**「サービスが落ちた」のリアルタイム検知には向かない**（最大 24 時間遅れる）。
コンテナ停止、Web の完全な不通、AWS 状態チェック失敗をリアルタイムで知りたい場合は、Slack bot か CloudWatch アラームに追加する。

---

## 7. 実行と設定

```bash
cd posthog-sentry-ai-monitoring
cp .env.example .env                                 # ★ スクリプトが読むのは .env
sudo python3 platform_health.py --show-payload       # AI に送る内容を確認（AI は呼ばない）
sudo python3 platform_health.py --dry-run --stdout   # ルール判定のみ、レポートを表示
sudo python3 platform_health.py                      # 通常実行：AI 診断 + 状態変化時の Slack 通知
sudo python3 platform_health.py --no-notify          # 通常実行だが Slack には送らない
sudo python3 platform_health.py --notify-test        # SLACK_WEBHOOK_URL にテストメッセージを送るだけ
```

- `.env` はスクリプトが**自分で読み込む**（`sudo` で環境変数が消えても問題ない）。既存の環境変数が優先、空の値は未設定扱い。
- コンテナ情報の取得に権限が必要なため `sudo` で実行する。

### 7.1 Slack 通知

- `.env` に `SLACK_WEBHOOK_URL` を設定する（`slack_alert.sh` と同じ Webhook / チャンネルで可）。**コードに書いたり git にコミットしたりしないこと。**
- WARN/CRIT の集合または総合ステータスが**変わったとき**だけ送る（INFO は対象外。swap 5.7→5.8 のような数値だけの変化は変化とみなさない）。
- 比較対象は前回**通知に成功した**状態（`state.json` の `notify`）。送信に失敗したら更新せず、次回の実行で再送する。
- `--dry-run` / `--no-notify` のときは送らない。

### 7.2 エラー時のリカバリ

- AI / Slack の呼び出しは 429 / 5xx / ネットワークエラー時に間隔を空けて再試行（最大 3 回）。
- `gemini-2.5-pro` が再試行後も失敗したら `GEMINI_FALLBACK_MODEL`（既定 `gemini-2.5-flash`）に切り替え、レポートに明記する。AI がすべて失敗したらルール判定のみのレポートを出す。
- `out/.lock` で巡検の重複実行を防ぐ。一部のデータソース（docker / CloudWatch / nginx ログ）が失敗しても INFO / WARN として記録し、他は続行する。

### 7.3 定期実行（1 日 1 回）

root の crontab（`sudo crontab -e`）に登録する。`systemd-run` で**本スクリプト自身**のリソースを制限する（コンテナには影響しない）：

```
0 0 * * * cd /path/to/posthog-sentry-ai-monitoring && systemd-run --scope --quiet -p MemoryMax=256M -p CPUQuota=50\% nice -n 10 ionice -c3 python3 platform_health.py >> out/cron.log 2>&1
```

（UTC 0 時 = JST 9 時。crond がない場合は systemd timer を使う。）

### 主な環境変数

| 変数 | 既定値 | 説明 |
|------|--------|------|
| SENTRY_URL / POSTHOG_URL | ヘルス端点 | Web 疎通の対象 |
| WEB_LATENCY_WARN_MS | 5000 | 応答遅延の閾値 |
| WATCH_PREFIXES | -web-,-nginx-,-relay-,-postgres-,-db-,-pgbouncer-,-kafka-,-clickhouse-,-redis,-snuba-api-,-taskworker-,-capture-,-ingestion- | コアコンテナ（名前に含まれていれば一致） |
| IGNORE_CONTAINERS | 空 | 判定から除外するコンテナ |
| DISK_WARN / DISK_CRIT | 85 / 95 | ディスク使用率 % |
| MEM_AVAIL_WARN_GB / _CRIT_GB | 2 / 1 | 空きメモリ GiB（< で判定、Slack と同じ） |
| SWAP_WARN_GB / _CRIT_GB | 8 / 10 | swap 使用量 GiB（Slack と同じ） |
| LOAD_PER_CPU_WARN | 1.5 | コアあたり load |
| RECENT_RESTART_DAYS | 1 | 増分データがないときの「最近再起動」の日数 |
| RESTART_DELTA_CRIT | 3 | 前回巡検以降の再起動 ≥N → CRIT（≥1 → WARN） |
| SWAP_IO_WARN_KBPS | 1024 | 前回巡検以降の換ページ平均 KB/s |
| TOP_MEM_N | 8 | AI に渡すメモリ / swap 上位 N |
| DISK_TREND_DAYS | 14 | ディスク増加速度の回帰期間（日） |
| DISK_FORECAST_WARN_DAYS | 30 | N 日以内に DISK_WARN 到達見込み → WARN |
| CONTAINER_MEM_BUDGETS | slack_alert.sh の CONTAINERS と同じ | コンテナのメモリ閾値 `名前:GiB,...` |
| BUDGET_INFO_PCT | 80 | 閾値の N% 以上 → INFO |
| NGINX_CONTAINERS | sentry-self-hosted-nginx-1 | 5xx を集計する nginx コンテナ |
| NGINX_MAX_WINDOW_H | 24 | 集計窓の上限（時間） |
| NGINX_5XX_WARN_PCT / _MIN | 1 / 20 | 5xx 比率 % かつ件数 → WARN |
| CLOUDWATCH | 1 | 0 = CloudWatch を参照しない |
| CW_INSTANCE_ID / AWS_REGION | 空（IMDS から取得） | インスタンス ID / リージョンの上書き |
| CW_CPU_WARN / CW_BALANCE_WARN / CW_CPU_CREDIT_WARN | 80 / 20 / 10 | CloudWatch の閾値 |
| SLACK_WEBHOOK_URL | 空 | 状態変化の通知先。空なら送らない |
| AI_PROVIDER | gemini | gemini / anthropic |
| GEMINI_API_KEY / GEMINI_MODEL | 空 / gemini-2.5-pro | Gemini（AI Studio で発行） |
| GEMINI_FALLBACK_MODEL | gemini-2.5-flash | 主モデル失敗時の降格先 |
| ANTHROPIC_API_KEY / ANTHROPIC_MODEL | 空 / claude-sonnet-5-5 | Claude（Anthropic Console で発行、別途従量課金） |
| REPORT_LANG | ja | AI 診断の言語 ja / zh / en |
| KEEP_DAYS | 14 | 成果物の保存日数 |

---

## 8. プライバシー

収集するのは**プラットフォームの稼働・健康データ**（コンテナ状態、ホストリソース、HTTP ステータス、nginx のステータスコードとパス）のみ。
**ユーザーの個人情報や端末情報は含まない**。nginx のパスはクエリを除去し数字を正規化するため、`sentry_key` 等は残らない。Sentry に集まるモバイルのエラー内容も読まない。

---

## 9. 今後の拡張（未実装）

- Sentry の読み取り専用 token で「最新イベント時刻」を確認し、取り込み停止を検知する。
- Kafka consumer lag / キュー滞留 / worker ログによる根本原因の調査。
- Cost Explorer（AWS コスト）をデータソースに追加。
- 1 日 1 回の定期実行の設定（7.3）。
