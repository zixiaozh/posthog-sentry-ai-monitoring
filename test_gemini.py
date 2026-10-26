#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_gemini.py — Gemini API と正常に対話できるかを単独で確認する。依存なし、標準ライブラリのみ（REST を直接呼ぶ）。

SDK での書き方との対応：
  - send_message(history_context, question)  ≈ model.start_chat(history=[...]).send_message(question)
  - generate_tag(user_input, model_reply)    ≈ model.generate_content(prompt)
pip install google-generativeai は不要。標準ライブラリで REST を呼ぶので、リソースの少ない EC2 に向いている。

API キー：https://aistudio.google.com/app/apikey で発行（無料枠あり）。

使い方：
  GEMINI_API_KEY=AIza... python3 test_gemini.py
  # または同じディレクトリの .env に書いておけば（GEMINI_API_KEY=AIza...）そのまま：
  python3 test_gemini.py
  # 任意の質問を送る：
  python3 test_gemini.py "SRE とは何かを一文で説明して"
"""

import os
import sys
import json
from urllib import request, error

# --- 同じディレクトリの .env を自動で読み込む（他のスクリプトと同じ）---
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
    """内部用：generateContent に contents 配列を送り、(text, usage) を返す。"""
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
        raise RuntimeError(f"応答に候補がない（安全フィルタでブロックされた可能性）：{json.dumps(data, ensure_ascii=False)[:300]}")
    parts = cands[0].get("content", {}).get("parts", [])
    text = "".join(p.get("text", "") for p in parts).strip()
    return text, data.get("usageMetadata", {})


def send_message(history_context: str, question: str):
    """前提コンテキスト付きの対話（start_chat(history=[user:history_context]).send_message(question) 相当）。"""
    contents = [
        {"role": "user", "parts": [{"text": history_context}]},
        {"role": "user", "parts": [{"text": question}]},
    ]
    return _call(contents)


def generate_tag(user_input: str, model_reply: str):
    """会話に短いタグを付ける（generate_tag 相当）。"""
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
        sys.exit("ERROR: GEMINI_API_KEY が未設定（環境変数で渡すか .env に書く）")

    question = sys.argv[1] if len(sys.argv) > 1 else "このメッセージを受け取れたことを一文で返してください。"
    history_context = "あなたは運用監視のアシスタントです。簡潔に答えてください。"

    print(f"[..] モデル {MODEL} にテストメッセージを送信中…")
    print(f"[..] 質問：{question}\n")
    try:
        reply, usage = send_message(history_context, question)
    except error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        hint = {
            400: "→ API キーが無効（API_KEY_INVALID）かリクエスト形式の誤りが多い。aistudio.google.com でキーを確認する。",
            403: "→ 権限なし / キーが制限されている。キーの制限と、プロジェクトで Generative Language API が有効かを確認する。",
            404: "→ モデル名が誤っている。GEMINI_MODEL を確認する（例：gemini-2.5-pro / gemini-2.5-flash）。",
            429: "→ レート制限 / クォータ超過。時間を置くかモデルを変える。",
        }.get(e.code, "")
        sys.exit(f"[X] HTTP {e.code} {e.reason} {hint}\nレスポンス本文：{body}")
    except Exception as e:  # noqa
        sys.exit(f"[X] リクエスト失敗（ネットワーク / 外向き通信の問題？）：{e}")

    print("[OK] Gemini の応答：")
    print("  " + reply.replace("\n", "\n  "))
    print(f"\n[OK] token 使用量：入力 {usage.get('promptTokenCount')} / 出力 {usage.get('candidatesTokenCount')}")

    # ついでに generate_tag を試す
    try:
        tag = generate_tag(question, reply)
        print(f"[OK] タグ生成：{tag}")
    except Exception as e:  # noqa
        print(f"[warn] タグ生成に失敗（メインのテストには影響なし）：{e}")

    print("\n正常に対話できた。GEMINI_API_KEY と外向き通信に問題なし。")


if __name__ == "__main__":
    main()