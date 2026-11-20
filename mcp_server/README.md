# 読み取り専用の監視 MCP サーバー

AI エージェント（Claude Code 等）が、障害調査のために監視データを **読み取り専用で** 参照するための MCP サーバー（stdio）。
利用者の PC で動かす。設計の全体像は [docs/SECURITY.md](../docs/SECURITY.md)。

## ツール（現在）

| ツール | 内容 | 主な引数 |
|--------|------|----------|
| `ec2_metrics_summary` | CloudWatch 指標（CPU・ネットワーク・EBS 帯域/IOPS・バースト残高・状態チェック）の要約。最新値と直近 1h・期間全体の平均/最小/最大 | `hours`（1〜72）、`end` |
| `ec2_metric_series` | 指標 1 つの時系列。変化の始まった時刻の特定に使う。最大 288 点（長い期間は粒度を粗くする） | `metric`（許可リスト）、`hours`（1〜168）、`end` |
| `cloudwatch_alarms` | 本インスタンスに紐づく CloudWatch アラームと状態 | なし |

`end` は期間の終わり（UTC、ISO 8601。例 `2026-11-08T06:00Z`）。過去 60 日まで遡れる。

EC2 内部のデータ（コンテナ・ホスト・nginx・Sentry 取り込み量・ログ）は、`collect.py` を SSM 経由で呼ぶツールとして今後追加する。

## 安全上の約束

- **接続先は起動時に固定**：AWS プロファイル・インスタンス ID・リージョンは環境変数で与え、ツール引数では変えられない。
- **専用の読み取り専用ロール**：`default`（管理者権限のことが多い）は `MCP_ALLOW_DEFAULT_PROFILE=1` を明示しない限り起動しない。
  環境変数の認証情報（`AWS_ACCESS_KEY_ID` 等）は子プロセスに渡さない。
- **引数の検証**：型・範囲はツール定義（JSON Schema）とサーバー側（`tools.py`）の二重で検証。指標名は許可リスト。
- **出力**：マスキング（`monitoring/mask.py`）、整形しない JSON、256 KiB 上限。
- **監査**：すべての呼び出し（失敗を含む）を `out/mcp_audit.log` に 1 行 JSON で記録（時刻・ツール・引数・プロファイル・成否・所要時間・サイズ）。
  ただし JSON Schema の段階で SDK が弾いた呼び出し（範囲外の `hours` 等）はサーバーの標準エラーにのみ出る。
- ツールはすべて `readOnlyHint: true` / `destructiveHint: false` を宣言する。復旧操作は提案のみで実行しないよう、サーバーの instructions で AI に伝える。

## セットアップ

```
[管理者が 1 回だけ]  iam/create_mcp_role.sh      → ロール ai-monitoring-mcp-readonly とグループ ai-monitoring-users を作る
[使う人ごと]         ~/.aws/config に 3 行追加     → 自分の IAM ユーザーからロールを引き受けるプロファイル
                     mcp_server/setup.sh          → venv 作成・ロールの確認・接続確認
                     リポジトリで Claude Code を開く → .mcp.json の ai-monitoring を初回だけ承認
```

### 1. AWS 側（管理者が 1 回だけ）

```bash
iam/create_mcp_role.sh            # 管理者権限のプロファイルで。確認のあと作成し、実行者を自動でグループに追加
```

- ロール `ai-monitoring-mcp-readonly`：[iam/mcp-readonly-policy.json](../iam/mcp-readonly-policy.json)（CloudWatch の読み取り 2 操作のみ。
  `ssm:StartSession`・IAM 操作等は明示的に拒否）。
- グループ `ai-monitoring-users`：このロールを AssumeRole できる権限だけを持つ。**使う人の追加・交代はグループのメンバーを変えるだけ**：
  `aws iam add-user-to-group --group-name ai-monitoring-users --user-name <名前>`
- IAM のグループは信任ポリシーの Principal に書けないため、ロールの信任は「同じアカウントの、AssumeRole を許可された者」とし、
  誰が使えるかはグループ側のポリシーで決める。
- 長期のアクセスキーは新たに作らない。各自が自分の IAM ユーザーの認証情報から一時的にロールを引き受ける（CloudTrail に本人の名前が残る）。

### 2. 使う人ごと（新しい環境・引き継ぎ時も同じ）

`~/.aws/config` に追記（`<ACCOUNT_ID>` は create_mcp_role.sh の最後に表示される）：

```ini
[profile mcp-readonly]
role_arn = arn:aws:iam::<ACCOUNT_ID>:role/ai-monitoring-mcp-readonly
source_profile = default
region = ap-northeast-1
```

```bash
mcp_server/setup.sh
```

setup.sh は何度実行してもよい。次を順に確認し、問題があればそこで止まって理由を表示する：
1. Python 3.10 以上で `mcp_server/.venv` を作り、MCP SDK を入れる
2. プロファイルが `assumed-role/ai-monitoring-mcp-readonly/...` になること、CloudWatch 以外（SSM）の操作が拒否されること
3. Claude Code と同じ stdio でサーバーを起動し、ツールを 1 回呼べること（`mcp_server/selftest.py`）

### 3. Claude Code で使う

リポジトリのディレクトリで Claude Code を開くと、[.mcp.json](../.mcp.json) の `ai-monitoring` が見つかり、初回だけ有効にするか確認される。
接続先は `.mcp.json` の既定値（`MCP_AWS_PROFILE` 等）で、同名の環境変数を設定すれば上書きできる。

どのディレクトリでも使いたい場合は、ユーザー単位で登録する：

```bash
claude mcp add -s user ai-monitoring -e MCP_AWS_PROFILE=mcp-readonly \
    -e MCP_INSTANCE_ID=i-08ba45b5cffc2313e -e MCP_REGION=ap-northeast-1 -- "$PWD/mcp_server/run.sh"
```

例：「11/8 未明に EBS の書き込みが増えていないか調べて」のように聞くと、ツールを使って調べる。

### 読み取り専用を確実にするには

同じ環境の Claude Code がシェル（Bash）と管理者の認証情報も使えると、MCP を迂回できてしまう。
調査用のセッションでは Bash を無効にし MCP のツールだけを許可する、または管理者の認証情報を置かない環境で使う。

## テスト

```bash
python3 -m unittest discover -s tests                         # tools.py のみ（MCP SDK 不要）
mcp_server/.venv/bin/python -m unittest discover -s tests     # server.py（MCP 経由の呼び出し）も含めて
```
