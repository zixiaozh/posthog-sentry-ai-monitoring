"""設定（環境変数と .env）。各モジュールは `from . import config as cfg` で参照し、cfg.X を実行時に読む
（テストや MCP サーバーが cfg の値を差し替えると全モジュールに反映される）。"""

import os

# リポジトリのルート（.env と out/ の基準）。本ファイルは monitoring/ の下にある
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ----------------------------------------------------------------------------
# リポジトリ直下の .env を自動で読み込む（既存の環境変数が優先、空の値は無視）
# 設定を読む前に実行する。sudo は環境変数を消すため、スクリプト自身がファイルを読むのが確実。
# ----------------------------------------------------------------------------
def _load_dotenv(path=None):
    # 単体テストは実際の .env（API キー・Webhook）に依存してはいけないため、PH_SKIP_DOTENV=1 で読み込みを止める
    if path is None:
        if os.environ.get("PH_SKIP_DOTENV") == "1":
            return
        path = os.path.join(BASE_DIR, ".env")
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.split(" #", 1)[0].strip().strip('"').strip("'")
                if v:  # 空の値は未設定とみなし、コードの既定値を使う（例：OUT_DIR=）
                    os.environ.setdefault(k.strip(), v)
    except FileNotFoundError:
        pass


_load_dotenv()

# ----------------------------------------------------------------------------
# 設定（環境変数）
# ----------------------------------------------------------------------------
# コアコンテナ（名前に含まれていれば一致、★ を付ける）。sentry / posthog のように全コンテナが含む語は書かないこと（★ の意味がなくなる）。
WATCH_PREFIXES = os.environ.get(
    "WATCH_PREFIXES",
    "-web-,-nginx-,-relay-,-postgres-,-db-,-pgbouncer-,-kafka-,-clickhouse-,-redis,"
    "-snuba-api-,-taskworker-,-capture-,-ingestion-",
).split(",")
# 判定から完全に除外するコンテナ（カンマ区切り、名前に含まれていれば一致）。既知の一回限り・廃止済みコンテナ用
IGNORE_CONTAINERS = [p.strip() for p in os.environ.get("IGNORE_CONTAINERS", "").split(",") if p.strip()]
# cron 等で定期的に restart される既知のコンテナ（名前に含まれていれば一致）。クラッシュ以外の再起動を正常扱いにする
# 既定：root の crontab で 2 日ごと 04:00 に `docker-compose restart snuba-api` が実行されている
SCHEDULED_RESTARTS = [p.strip() for p in (os.environ.get("SCHEDULED_RESTARTS") or "-snuba-api-").split(",") if p.strip()]

# Web 疎通の対象：「名前=URL」をカンマ区切りで。空なら Web チェックなし。
# SENTRY_URL / POSTHOG_URL を個別に指定してもよい
WEB_TARGETS = os.environ.get("WEB_TARGETS", "")
SENTRY_URL = os.environ.get("SENTRY_URL", "")
POSTHOG_URL = os.environ.get("POSTHOG_URL", "")

# 注目ポイントの閾値（★これは「リアルタイム通知」ではない。リアルタイム通知は既存の slack_alert.sh が担当。
#  ここでは AI への注目ポイントと総合ステータスの算出に使う。数値は slack_alert.sh と意図的に揃えており、
#  閾値を変えるときは slack_alert.sh も同時に変えること。）
DISK_WARN = float(os.environ.get("DISK_WARN", "85"))          # ディスク使用率 %（Slack の DISK_WARN_PCT と同じ）
DISK_CRIT = float(os.environ.get("DISK_CRIT", "95"))          # Slack の DISK_CRIT_PCT と同じ
MEM_AVAIL_WARN_GB = float(os.environ.get("MEM_AVAIL_WARN_GB", "2"))  # 空きメモリ < N GiB（Slack の RAM_WARN_GB と同じ）
MEM_AVAIL_CRIT_GB = float(os.environ.get("MEM_AVAIL_CRIT_GB", "1"))  # Slack の RAM_CRIT_GB と同じ
SWAP_WARN_GB = float(os.environ.get("SWAP_WARN_GB", "8"))     # swap 使用量 ≥ N GiB（Slack の SWAP_WARN_GB と同じ）
SWAP_CRIT_GB = float(os.environ.get("SWAP_CRIT_GB", "10"))    # Slack の SWAP_CRIT_GB と同じ
LOAD_PER_CPU_WARN = float(os.environ.get("LOAD_PER_CPU_WARN", "1.5"))  # コアあたり load
RECENT_RESTART_DAYS = float(os.environ.get("RECENT_RESTART_DAYS", "1"))  # uptime < N 日を「最近再起動」とみなす
WEB_LATENCY_WARN_MS = int(os.environ.get("WEB_LATENCY_WARN_MS", "5000"))  # Web / ヘルス端点の応答遅延の閾値
# 以下は本スクリプト独自（Slack が扱わない「傾向・活動」系の信号。前回巡検の state.json に依存）
SWAP_IO_WARN_KBPS = float(os.environ.get("SWAP_IO_WARN_KBPS", "1024"))  # 前回巡検以降の swap 換入+換出の平均 KB/s
RESTART_DELTA_CRIT = int(os.environ.get("RESTART_DELTA_CRIT", "3"))  # 前回巡検以降の再起動増分 ≥N → CRIT（≥1 → WARN）
TOP_MEM_N = int(os.environ.get("TOP_MEM_N", "8"))                     # AI に渡すメモリ使用量上位 N コンテナ
DISK_TREND_DAYS = float(os.environ.get("DISK_TREND_DAYS", "14"))      # ディスク増加速度は直近 N 日のサンプルで線形回帰
DISK_FORECAST_WARN_DAYS = float(os.environ.get("DISK_FORECAST_WARN_DAYS", "30"))  # N 日以内に DISK_WARN 到達見込み → WARN

# AI
AI_PROVIDER = os.environ.get("AI_PROVIDER", "gemini").strip().lower()   # gemini | anthropic
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-4-hydrogen")
GEMINI_FALLBACK_MODEL = os.environ.get("GEMINI_FALLBACK_MODEL", "gemini-3.8-flash")  # 主モデルが再試行後も失敗したときに使う（空 = 降格しない）
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5")
REPORT_LANG = os.environ.get("REPORT_LANG", "ja")

# 成果物
OUT_DIR = os.environ.get("OUT_DIR", os.path.join(BASE_DIR, "out"))
KEEP_DAYS = int(os.environ.get("KEEP_DAYS", "14"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "10"))
# slack_alert.sh が一部コンテナに設定しているメモリ閾値（GiB）。形式は同スクリプトの CONTAINERS 配列と同じ。変更時は両方を直す
CONTAINER_MEM_BUDGETS = os.environ.get(
    "CONTAINER_MEM_BUDGETS",
    "posthog-web-1:5,posthog-clickhouse-1:2,sentry-self-hosted-web-1:1.5,sentry-self-hosted-snuba-api-1:2")
BUDGET_INFO_PCT = float(os.environ.get("BUDGET_INFO_PCT", "80"))   # 閾値の N% 以上 → INFO（Slack は 95% 継続でリアルタイム通知）

# nginx アクセスログの 5xx 集計（窓 = 前回巡検以降、最長 NGINX_MAX_WINDOW_H 時間）
NGINX_CONTAINERS = [c.strip() for c in os.environ.get("NGINX_CONTAINERS", "sentry-self-hosted-nginx-1").split(",") if c.strip()]
NGINX_MAX_WINDOW_H = float(os.environ.get("NGINX_MAX_WINDOW_H", "24"))
NGINX_5XX_WARN_PCT = float(os.environ.get("NGINX_5XX_WARN_PCT", "1"))    # 5xx 比率 ≥ N% かつ
NGINX_5XX_WARN_MIN = int(os.environ.get("NGINX_5XX_WARN_MIN", "20"))     # 件数 ≥ N → WARN。それ以外で 5xx があれば INFO

NGINX_SILENT_MIN_H = float(os.environ.get("NGINX_SILENT_MIN_H", "1"))   # 窓 ≥ N 時間でアクセスログ 0 件 → WARN（ログ欠落 or 流入停止）

# Sentry の取り込み量：ClickHouse の errors_local を日別に数え、昨日を直近 7 日の中央値と比べる
SENTRY_CLICKHOUSE = os.environ.get("SENTRY_CLICKHOUSE", "sentry-self-hosted-clickhouse-1")   # "0" = 無効
INGEST_DROP_PCT = float(os.environ.get("INGEST_DROP_PCT", "10"))   # 昨日 < 中央値の N% → WARN（0 件も WARN）

# Slack 通知：状態が変わったときだけ送る（WARN/CRIT の新規・解消、総合ステータスの変化）。空なら送らない
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

GIB, MIB = 1024 ** 3, 1024 ** 2   # 容量は二進単位に統一（docker stats / df -h / slack_alert.sh と同じ）
STATE_FILE = os.path.join(OUT_DIR, "state.json")   # 前回巡検のカウンタ（再起動回数 / swap 換ページ等）。増分の計算に使う

# CloudWatch（aws CLI 経由。インスタンスロールに cloudwatch:GetMetricData / cloudwatch:DescribeAlarms が必要）
CLOUDWATCH = os.environ.get("CLOUDWATCH", "1") != "0"          # 0 = CloudWatch を参照しない
CW_INSTANCE_ID = os.environ.get("CW_INSTANCE_ID", "")          # 空なら IMDS から自動取得
CW_REGION = os.environ.get("AWS_REGION", "") or os.environ.get("AWS_DEFAULT_REGION", "")  # 空なら IMDS から取得
CW_CPU_WARN = float(os.environ.get("CW_CPU_WARN", "80"))        # 直近 1h の CPU 平均 % ≥ → WARN
CW_BALANCE_WARN = float(os.environ.get("CW_BALANCE_WARN", "20"))  # EBS IO/Byte バースト残高 % ≤ → WARN（枯渇すると帯域制限）
CW_CPU_CREDIT_WARN = float(os.environ.get("CW_CPU_CREDIT_WARN", "10"))  # T 系の CPU クレジット残高 ≤ → WARN
INSECURE = os.environ.get("WEB_INSECURE", "") == "1"
