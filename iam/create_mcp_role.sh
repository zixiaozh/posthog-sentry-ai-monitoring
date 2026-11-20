#!/usr/bin/env bash
# MCP 専用の読み取り専用ロールと、それを使える IAM グループを作る（管理者権限のプロファイルで 1 回だけ実行）。
#
#   iam/create_mcp_role.sh                 # default プロファイルで実行
#   AWS_PROFILE=admin iam/create_mcp_role.sh
#
# 作るもの：
#   ロール   ai-monitoring-mcp-readonly   権限 = iam/mcp-readonly-policy.json（CloudWatch 読み取りのみ、シェル・IAM 操作は拒否）
#   グループ ai-monitoring-users          権限 = 上のロールを AssumeRole できるだけ
# ロールの信任ポリシーは「同じアカウントの、AssumeRole を許可された者」。IAM のグループは信任ポリシーの
# Principal に書けないため、グループ側のポリシーで誰が使えるかを決める（交代時はグループのメンバーを変えるだけ）。
# 実行した本人が IAM ユーザーならグループに追加する。既にあるものは作り直さず、ポリシーだけ最新にする。
set -euo pipefail
cd "$(dirname "$0")"

ROLE=ai-monitoring-mcp-readonly
GROUP=ai-monitoring-users
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

ident=$(aws sts get-caller-identity --output json)
ACCOUNT=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["Account"])' <<<"$ident")
CALLER=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["Arn"])' <<<"$ident")
echo "アカウント：$ACCOUNT"
echo "実行者    ：$CALLER"
echo "作成/更新 ：ロール $ROLE、グループ $GROUP"
read -r -p "続けますか？ [y/N] " ans
[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "中止"; exit 1; }

sed "s/<ACCOUNT_ID>/$ACCOUNT/" mcp-readonly-trust.json > "$TMP/trust.json"
sed "s/<ACCOUNT_ID>/$ACCOUNT/" mcp-users-group-policy.json > "$TMP/group.json"

if aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
  echo "- ロールは既にある：信任ポリシーを更新"
  aws iam update-assume-role-policy --role-name "$ROLE" --policy-document "file://$TMP/trust.json"
else
  echo "- ロールを作成"
  aws iam create-role --role-name "$ROLE" --max-session-duration 3600 \
    --description "AI monitoring MCP server (read-only)" \
    --assume-role-policy-document "file://$TMP/trust.json" >/dev/null
fi
aws iam put-role-policy --role-name "$ROLE" --policy-name mcp-readonly \
  --policy-document file://mcp-readonly-policy.json
echo "- ロールの権限を設定（mcp-readonly-policy.json）"

if ! aws iam get-group --group-name "$GROUP" >/dev/null 2>&1; then
  aws iam create-group --group-name "$GROUP" >/dev/null
  echo "- グループを作成"
fi
aws iam put-group-policy --group-name "$GROUP" --policy-name assume-mcp-readonly \
  --policy-document "file://$TMP/group.json"
echo "- グループの権限を設定（ロールの AssumeRole のみ）"

if [[ "$CALLER" == *":user/"* ]]; then
  USER_NAME=${CALLER##*:user/}; USER_NAME=${USER_NAME##*/}
  aws iam add-user-to-group --group-name "$GROUP" --user-name "$USER_NAME"
  echo "- $USER_NAME をグループに追加"
else
  echo "- 実行者が IAM ユーザーではないため、グループへの追加は手動で：aws iam add-user-to-group --group-name $GROUP --user-name <名前>"
fi

cat <<MSG

完了。~/.aws/config に次を追記してから mcp_server/setup.sh を実行する：

[profile mcp-readonly]
role_arn = arn:aws:iam::$ACCOUNT:role/$ROLE
source_profile = default
region = ap-northeast-1

（反映まで数十秒かかることがある。別の人を追加するとき：aws iam add-user-to-group --group-name $GROUP --user-name <名前>）
MSG
