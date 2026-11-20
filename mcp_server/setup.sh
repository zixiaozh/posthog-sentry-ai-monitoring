#!/usr/bin/env bash
# MCP サーバーのセットアップと確認（新しい環境・引き継ぎ時に 1 回実行。何度実行してもよい）。
#   1) Python 3.10+ の venv を作り、mcp_server/requirements.txt を入れる
#   2) AWS プロファイル（既定 mcp-readonly）が読み取り専用ロールになっているか確認する
#   3) Claude Code と同じ stdio でサーバーを起動し、ツールを 1 回呼んでみる
# AWS アカウント側の準備（ロール・グループの作成）は iam/create_mcp_role.sh（管理者が 1 回だけ）。
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
cd "$DIR/.."
PROFILE=${MCP_AWS_PROFILE:-mcp-readonly}
ROLE=ai-monitoring-mcp-readonly
ok()   { echo "  ✅ $*"; }
fail() { echo "  ❌ $*"; exit 1; }

echo "1) Python 環境"
PY=$(command -v python3 || true)
[[ -n "$PY" ]] || fail "python3 がない"
"$PY" -c 'import sys; sys.exit(sys.version_info < (3, 10))' || fail "Python 3.10 以上が必要（現在 $("$PY" -V)）"
if [[ ! -x mcp_server/.venv/bin/python ]]; then
  "$PY" -m venv mcp_server/.venv || fail "venv を作れない（Ubuntu なら sudo apt install python3-venv）"
fi
mcp_server/.venv/bin/pip install -q --upgrade pip >/dev/null
mcp_server/.venv/bin/pip install -q -r mcp_server/requirements.txt
ok "mcp_server/.venv（$(mcp_server/.venv/bin/python -c 'import importlib.metadata as m; print("mcp", m.version("mcp"))')）"

echo "2) AWS プロファイル $PROFILE"
command -v aws >/dev/null || fail "aws CLI がない"
aws configure get role_arn --profile "$PROFILE" >/dev/null 2>&1 \
  || fail "~/.aws/config に [profile $PROFILE]（role_arn / source_profile）がない。mcp_server/README.md 参照"
ARN=$(env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
      aws sts get-caller-identity --profile "$PROFILE" --query Arn --output text 2>&1) \
  || fail "ロールを引き受けられない：$ARN（ai-monitoring-users グループに入っているか確認）"
[[ "$ARN" == *":assumed-role/$ROLE/"* ]] || fail "想定外の身元：$ARN（$ROLE であるべき）"
ok "$ARN"
DENY=$(env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
     aws ssm describe-sessions --state Active --profile "$PROFILE" --region ap-northeast-1 2>&1 >/dev/null || true)
case "$DENY" in
  *AccessDenied*|*"not authorized"*) ok "CloudWatch 以外の操作は拒否される（ssm:DescribeSessions が AccessDenied）" ;;
  "") fail "読み取り専用のはずのロールで SSM の操作が通った。ロールの権限を確認すること" ;;
  *)  echo "  ⚠️  拒否の確認ができなかった（${DENY:0:200}）" ;;
esac

echo "3) MCP サーバーの起動と呼び出し"
mcp_server/.venv/bin/python mcp_server/selftest.py | sed 's/^/  /'
ok "stdio で起動・呼び出しできた"

cat <<'MSG'

完了。このリポジトリのディレクトリで Claude Code を開くと .mcp.json の ai-monitoring が見つかり、
初回だけ有効にするか確認される。どのディレクトリでも使いたい場合は次で登録する：
  claude mcp add -s user ai-monitoring -e MCP_AWS_PROFILE=mcp-readonly \
    -e MCP_INSTANCE_ID=i-08ba45b5cffc2313e -e MCP_REGION=ap-northeast-1 -- "$PWD/mcp_server/run.sh"
MSG
