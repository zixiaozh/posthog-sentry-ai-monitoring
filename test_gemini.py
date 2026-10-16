#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_gemini.py — 独立验证「能否正常调用 Gemini API 对话」。零依赖，仅标准库（走 REST）。

对应你贴的 SDK 写法：
  - send_message(history_context, question)  ≈ model.start_chat(history=[...]).send_message(question)
  - generate_tag(user_input, model_reply)    ≈ model.generate_content(prompt)
不用 pip install google-generativeai，直接标准库调 REST，更适合资源受限的 EC2。

API key：在 https://aistudio.google.com/app/apikey 生成（有免费额度）。

用法：
  GEMINI_API_KEY=AIza... python3 test_gemini.py
  # 或写进同目录 .env（GEMINI_API_KEY=AIza...），直接：
  python3 test_gemini.py
  # 自定义问一句：
  python3 test_gemini.py "用一句话解释什么是 SRE"
"""

import os
import sys
import json
from urllib import request, error

# --- 自动加载同目录 .env（与其它脚本一致）---
def _load_dotenv():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.split(" #", 1)[0].strip().strip('"').strip("'")
                os.environ.setdefault(k.strip(), v)
    except FileNotFoundError:
        pass


_load_dotenv()

API_KEY = os.environ.get("GEMINI_API_KEY", "")
MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-pro")
BASE = "https://generativelanguage.googleapis.com/v1beta"


def _call(contents):
    """底层：给 generateContent 发 contents 数组，返回 (text, usage)。"""
    url = f"{BASE}/models/{MODEL}:generateContent"
    payload = {"contents": contents}
    req = request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json", "x-goog-api-key": API_KEY},
        method="POST",
    )
    with request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    cands = data.get("candidates", [])
    if not cands:
        raise RuntimeError(f"无候选回复（可能被安全策略拦截）：{json.dumps(data, ensure_ascii=False)[:300]}")
    parts = cands[0].get("content", {}).get("parts", [])
    text = "".join(p.get("text", "") for p in parts).strip()
    return text, data.get("usageMetadata", {})


def send_message(history_context: str, question: str):
    """带前置上下文的对话（等价 start_chat(history=[user:history_context]).send_message(question)）。"""
    contents = [
        {"role": "user", "parts": [{"text": history_context}]},
        {"role": "user", "parts": [{"text": question}]},
    ]
    return _call(contents)


def generate_tag(user_input: str, model_reply: str):
    """给一段对话生成简短标签（等价你贴的 generate_tag）。"""
    prompt = (
        "下の会話を要約して、短いタグを生成してください。\n"
        f"ユーザーの質問: {user_input}\n"
        f"AIの回答: {model_reply[:100]}...\n"
        "タグ: "
    )
    text, _ = _call([{"role": "user", "parts": [{"text": prompt}]}])
    return text.replace("タグ:", "").replace(":", "").strip()


def main():
    if not API_KEY:
        sys.exit("ERROR: 未设置 GEMINI_API_KEY（可临时传或写进 .env）")

    question = sys.argv[1] if len(sys.argv) > 1 else "请用一句话回复，确认你能正常收到我的消息。"
    history_context = "あなたは運用監視のアシスタントです。簡潔に答えてください。"

    print(f"[..] 使用模型 {MODEL} 发送测试消息…")
    print(f"[..] 提问：{question}\n")
    try:
        reply, usage = send_message(history_context, question)
    except error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        hint = {
            400: "→ 常见于 API key 无效（API_KEY_INVALID）或请求格式错，去 aistudio.google.com 核对 key。",
            403: "→ 无权限/key 受限；确认 key 未被限制或所属项目已启用 Generative Language API。",
            404: "→ 模型名不对；确认 GEMINI_MODEL（如 gemini-2.5-pro / gemini-2.5-flash）。",
            429: "→ 触发限流/配额用尽，稍后再试或换模型。",
        }.get(e.code, "")
        sys.exit(f"[X] HTTP {e.code} {e.reason} {hint}\n返回体：{body}")
    except Exception as e:  # noqa
        sys.exit(f"[X] 请求失败（网络/出站问题？）：{e}")

    print("[OK] Gemini 回复：")
    print("  " + reply.replace("\n", "\n  "))
    print(f"\n[OK] token 用量：输入 {usage.get('promptTokenCount')} / 输出 {usage.get('candidatesTokenCount')}")

    # 顺带演示 generate_tag
    try:
        tag = generate_tag(question, reply)
        print(f"[OK] 生成标签演示：{tag}")
    except Exception as e:  # noqa
        print(f"[warn] 标签生成失败（不影响主测试）：{e}")

    print("\n说明能正常对话，GEMINI_API_KEY、网络出站都没问题。")


if __name__ == "__main__":
    main()