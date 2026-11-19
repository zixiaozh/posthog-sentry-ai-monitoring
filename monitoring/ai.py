"""AI 診断：軽量 payload の構築、プロンプト、Gemini / Anthropic の呼び出し（降格あり）。"""

import json
import sys

from . import config as cfg
from . import docker
from . import httpclient
from . import rules


# ----------------------------------------------------------------------------
# 「実際に AI に送る軽量 payload」の構築。ローカルには全量スナップショットを保存し、LLM には必要な部分だけ送って token を節約する
# ----------------------------------------------------------------------------
def build_ai_payload(snapshot):
    conts = [c for c in snapshot["containers"] if not c.get("ignored")]
    n_ignored = len(snapshot["containers"]) - len(conts)

    def is_nominal(c):
        # 累計再起動回数は判定に使わない（長期間で積み上がるのは普通でノイズ）。現在の状態と「最近の再起動」だけを見る
        ud = c.get("uptime_days")
        recent = isinstance(ud, (int, float)) and ud < cfg.RECENT_RESTART_DAYS
        if docker._scheduled_restart(c):
            recent = False
            c = {**c, "restarted_since_last": False}
        return (c["status"] == "running" and c["health"] in ("healthy", "none")
                and not c.get("oom_killed") and not recent and not c.get("restarts_delta")
                and not c.get("restarted_since_last"))

    # notable = 通常と異なる特徴を持つコンテナ（停止 / unhealthy / OOM / 最近の再起動 / 前回巡検以降の再起動）
    notable = []
    for c in conts:
        if not is_nominal(c):
            notable.append({
                "name": c["name"],
                "status": c["status"],
                "exit_code": c.get("exit_code") if c["status"] == "exited" else None,
                "health": c["health"],
                "restarts": c["restarts"],
                "oom_killed": c["oom_killed"],
                "uptime_days": c.get("uptime_days"),
                "restarts_delta": c.get("restarts_delta"),
                "restarted_since_last": c.get("restarted_since_last"),
                "started_at": c.get("started_at"),
                "mem_mib": c.get("mem_mib"),
                "swap_mib": c.get("swap_mib"),
            })

    # メモリ使用量上位 N（異常の有無に関係なく送る）。AI がメモリ/swap の問題を具体的なコンテナに結び付けられるように
    top_mem = sorted((c for c in conts if isinstance(c.get("mem_mib"), int)),
                     key=lambda c: c["mem_mib"], reverse=True)[:cfg.TOP_MEM_N]
    top_memory = [{k: c.get(k) for k in ("name", "mem_mib", "swap_mib", "budget_gib", "budget_pct")}
                  for c in top_mem]
    top_swap = sorted((c for c in conts if c.get("swap_mib")), key=lambda c: c["swap_mib"], reverse=True)[:cfg.TOP_MEM_N]
    # slack_alert.sh が監視しているコンテナ：閾値に対する余裕（上位 N に入っていなくても送る）
    budgets = [{k: c.get(k) for k in ("name", "mem_mib", "budget_gib", "budget_pct")}
               for c in conts if c.get("budget_gib")]

    total = len(conts)
    running = sum(1 for c in conts if c["status"] == "running")
    return {
        "generated_at": snapshot["generated_at"],
        "host": snapshot["host"],
        "containers": {
            "summary": {"total": total, "running": running,
                        "not_running": total - running, "nominal": total - len(notable),
                        "ignored": n_ignored},
            "notable": notable,   # 注目すべきコンテナだけ送り、正常なものは件数のみ
            "top_memory": top_memory,
            "top_swap": [{"name": c["name"], "swap_mib": c["swap_mib"]} for c in top_swap],
            "slack_mem_budgets": budgets,
        },
        "web": snapshot["web"],
        "cloudwatch": snapshot.get("cloudwatch"),
        "nginx": snapshot.get("nginx"),
        "sentry_ingest": snapshot.get("sentry_ingest"),
        "flags": snapshot["alerts"],   # 決定的な注目ポイント
        "rule_status": rules._overall(snapshot["alerts"]),
        "note_for_ai": ("flags はルールによる決定的な注目ポイント。リアルタイム通知は別途 Slack が担当している。"
                        "正常なコンテナは件数に集約し、IGNORE_CONTAINERS のコンテナは除外済み。"
                        "exit 0 で終了したコンテナの多くは一回限りのタスク。restarts は累計値（長期間で積み上がるのは普通）で、"
                        "restarts_delta が前回巡検以降の再起動増分。host.swap_io は換ページ速度：swap 使用量が多くても"
                        "換ページ速度が ≈0 なら過去の残留であり、現在のメモリ逼迫ではない。"
                        "mem_mib/swap_mib は各コンテナの cgroup 実測値（MiB）。容量の単位はすべて二進（GiB/MiB）。"
                        "slack_mem_budgets は既存のリアルタイム通知 slack_alert.sh が一部コンテナに設定しているメモリ閾値（GiB）"
                        "と現在の割合で、95% 以上が 15 分続くと Slack がリアルタイム通知する。"
                        "nginx はリバースプロキシのアクセスログ集計（窓内のリクエスト数、5xx 件数と比率、ステータスコード別/パス別）。"
                        "restarted_since_last=true かつ restarts_delta=0 はクラッシュ以外の再起動（手動/再作成/定期ジョブ）。"
                        "host.disk_trend はディスク増加速度（GiB/日、線形回帰）と WARN/CRIT 閾値到達までの見込み日数・日付。"
                        "sentry_ingest は Sentry が取り込んだエラーイベント数（ClickHouse、UTC 日別）。"
                        "モバイルアプリのクラッシュ数なので曜日やリリースで自然に増減する。急減・0 件は取り込み経路の障害を疑う。"
                        "nginx のリクエスト数と食い違う場合はどちらかの計測（ログ）の問題。"
                        "cloudwatch は AWS 側から見た本 EC2 インスタンスの指標（5 分粒度、latest と直近 1h/24h の avg/min/max、"
                        "単位は unit）で、ローカル信号との突き合わせに使う。cloudwatch が null の場合は無効。"),
    }


# ----------------------------------------------------------------------------
# AI 診断
# ----------------------------------------------------------------------------
LANG_LABEL = {"ja": "日本語", "zh": "中文", "en": "English"}


def _system_prompt():
    lang = LANG_LABEL.get(cfg.REPORT_LANG, "日本語")
    return (
        "あなたは SRE / インフラ運用のアシスタントです。以下は自前ホストの "
        "Sentry + PostHog プラットフォーム（EC2 上、Docker 運用）の健康チェック結果です。"
        "ローカル信号（コンテナ・ホスト）と CloudWatch のインスタンス指標を突き合わせ、"
        "両者の関連（例: EBS 限速とディスク IO、ネットワークと Web 応答）があれば言及すること。"
        f"{lang} で簡潔な健康レポートを書いてください。与えられたデータのみ使用し、"
        "数値を捏造しないこと。構成: 1) 総合ステータス(正常/注意/危険を1行で) "
        "2) 検出された異常とその影響 3) 想定原因 4) 推奨アクション(具体的に)。"
        "異常が無ければその旨を明記。前置き・挨拶は不要、1) から書き始めること。"
        "総合ステータスは rule_status（ルール判定）を基準とし、異なる判断をする場合は根拠を1行で示すこと。"
        "コンテナ再起動・設定変更などサービスに影響する操作は、持続的な換ページ・メモリ上限への接近・"
        "サービス異常など具体的な根拠がある場合に限り推奨し、その根拠を明記すること。"
        "スワップ使用量だけを理由に再起動を推奨しないこと。"
        "disk_trend がある場合は、容量到達の見込み時期と、それまでに取るべき対策（データ保持期間の見直し等）に触れること。"
    )


def _user_content(snapshot):
    return "健康チェックデータ(JSON):\n" + json.dumps(snapshot, ensure_ascii=False, indent=2)


def _diagnose_gemini(snapshot):
    models = [cfg.GEMINI_MODEL] + ([cfg.GEMINI_FALLBACK_MODEL] if cfg.GEMINI_FALLBACK_MODEL and cfg.GEMINI_FALLBACK_MODEL != cfg.GEMINI_MODEL else [])
    for i, model in enumerate(models):
        try:
            text = _diagnose_gemini_model(snapshot, model)
            return text + (f"\n\n（※ {cfg.GEMINI_MODEL} が失敗したため {model} で生成）" if i else "")
        except RuntimeError as e:
            if i == len(models) - 1:
                raise
            print(f"[warn] {model} 失敗：{e} → {models[i + 1]} に切り替え", file=sys.stderr)


def _diagnose_gemini_model(snapshot, model):
    payload = {
        "systemInstruction": {"parts": [{"text": _system_prompt()}]},
        "contents": [{"role": "user", "parts": [{"text": _user_content(snapshot)}]}],
        # 思考型モデルは思考 token も maxOutputTokens に含まれるため、本文が途中で切れないよう余裕を持たせる
        "generationConfig": {"maxOutputTokens": 8192},
    }
    data = httpclient._post_json(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        payload, {"x-goog-api-key": cfg.GEMINI_API_KEY}, timeout=180,
    )
    cands = data.get("candidates", [])
    if not cands:
        raise RuntimeError(f"Gemini の応答に候補がない：{json.dumps(data, ensure_ascii=False)[:300]}")
    parts = cands[0].get("content", {}).get("parts", [])
    text = "".join(p.get("text", "") for p in parts if not p.get("thought")).strip()
    if cands[0].get("finishReason") == "MAX_TOKENS":
        text += "\n\n（※ 出力が上限に達したため途中で切れている可能性あり）"
    return text


def _diagnose_anthropic(snapshot):
    payload = {
        "model": cfg.ANTHROPIC_MODEL,
        "max_tokens": 4096,
        "system": _system_prompt(),
        "messages": [{"role": "user", "content": _user_content(snapshot)}],
    }
    data = httpclient._post_json("https://api.anthropic.com/v1/messages", payload,
                      {"x-api-key": cfg.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01"}, timeout=120)
    return "\n".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text").strip()


PROVIDERS = {
    # name: (診断関数, 必要な API キーの変数名, モデル名)
    "gemini": (_diagnose_gemini, "GEMINI_API_KEY", cfg.GEMINI_MODEL),
    "anthropic": (_diagnose_anthropic, "ANTHROPIC_API_KEY", cfg.ANTHROPIC_MODEL),
}
