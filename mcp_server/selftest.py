#!/usr/bin/env python3
"""MCP サーバーの接続確認：Claude Code と同じく stdio で起動し、ツール一覧の取得と 1 回の呼び出しを行う。

  mcp_server/.venv/bin/python mcp_server/selftest.py     # 環境変数 MCP_* は .mcp.json と同じ既定値を使う
"""
import asyncio
import os
import sys

from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = {"MCP_AWS_PROFILE": "mcp-readonly", "MCP_INSTANCE_ID": "i-08ba45b5cffc2313e", "MCP_REGION": "ap-northeast-1"}


async def main():
    env = dict(os.environ)
    for k, v in DEFAULTS.items():
        env.setdefault(k, v)
    params = StdioServerParameters(command=os.path.join(HERE, "run.sh"), env=env)
    async with Client(params) as c:
        names = sorted(t.name for t in (await c.list_tools()).tools)
        print(f"ツール：{', '.join(names)}")
        r = await c.call_tool("ec2_metrics_summary", {"hours": 1})
        text = r.content[0].text if r.content else ""
        if r.is_error:
            print(f"呼び出し失敗：{text[:300]}")
            return 1
        print(f"ec2_metrics_summary(hours=1)：OK（{len(text)} 文字）")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
