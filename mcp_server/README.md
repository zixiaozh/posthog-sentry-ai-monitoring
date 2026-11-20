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

### 1. Python 環境（Python 3.10 以上）

```bash
python3 -m venv mcp_server/.venv
mcp_server/.venv/bin/pip install -r mcp_server/requirements.txt
```

### 2. MCP 専用の IAM ロールとプロファイル

長期のアクセスキーは新たに作らず、自分の IAM ユーザーから **読み取り専用ロールを引き受ける（AssumeRole）** 形にする。

```bash
# iam/mcp-readonly-trust.json の <ACCOUNT_ID> と <IAM_USER_NAME> を自分のものに置き換えてから
aws iam create-role --role-name ai-monitoring-mcp-readonly \
    --assume-role-policy-document file://iam/mcp-readonly-trust.json
aws iam put-role-policy --role-name ai-monitoring-mcp-readonly \
    --policy-name mcp-readonly --policy-document file://iam/mcp-readonly-policy.json
```

`~/.aws/config` に追記：

```ini
[profile mcp-readonly]
role_arn = arn:aws:iam::<ACCOUNT_ID>:role/ai-monitoring-mcp-readonly
source_profile = default
region = ap-northeast-1
```

確認（`assumed-role/ai-monitoring-mcp-readonly/...` と表示されればよい。2 行目は AccessDenied になるのが正しい）：

```bash
aws sts get-caller-identity --profile mcp-readonly
aws ec2 describe-instances --profile mcp-readonly --max-items 1
```

ポリシー（[iam/mcp-readonly-policy.json](../iam/mcp-readonly-policy.json)）は CloudWatch の読み取り 2 操作だけを許可し、
`ssm:StartSession`（シェル）・IAM 操作などを明示的に拒否する。

### 3. Claude Code に登録

```bash
claude mcp add ai-monitoring \
    -e MCP_AWS_PROFILE=mcp-readonly \
    -e MCP_INSTANCE_ID=i-08ba45b5cffc2313e \
    -e MCP_REGION=ap-northeast-1 \
    -- "$PWD/mcp_server/.venv/bin/python" "$PWD/mcp_server/server.py"
```

登録後、Claude Code で「11/8 未明に EBS の書き込みが増えていないか調べて」のように聞くと、ツールを使って調べる。

## テスト

```bash
python3 -m unittest discover -s tests                         # tools.py のみ（MCP SDK 不要）
mcp_server/.venv/bin/python -m unittest discover -s tests     # server.py（MCP 経由の呼び出し）も含めて
```
