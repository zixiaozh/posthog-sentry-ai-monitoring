#!/usr/bin/env sh
# MCP サーバーの起動（.mcp.json から呼ばれる）。作業ディレクトリに依存しないよう自分の場所から辿る。
DIR=$(cd "$(dirname "$0")" && pwd)
PY="$DIR/.venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "[mcp-server] $PY がない。先に mcp_server/setup.sh を実行すること" >&2
  exit 2
fi
exec "$PY" "$DIR/server.py"
