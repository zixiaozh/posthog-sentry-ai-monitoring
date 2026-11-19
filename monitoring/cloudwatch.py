"""CloudWatch：EC2 インスタンス指標と本インスタンスに紐づくアラーム（aws CLI 経由）。"""

from urllib import request, error
import datetime as dt
import json
import shutil
import subprocess

from . import config as cfg
from . import util


# ----------------------------------------------------------------------------
# 4) CloudWatch：AWS 側から見た EC2 インスタンス指標 + 本インスタンスに紐づく CloudWatch アラーム
#    aws CLI（Amazon Linux に標準搭載）経由で呼び、外部 Python 依存を増やさない。
#    ローカル信号は「コンテナ/プロセスの内側」、CloudWatch は「インスタンスの外側」（ネットワーク、EBS 制限、状態チェック、CPU クレジット）を見る。
# ----------------------------------------------------------------------------
CW_PERIOD = 300   # EC2 の基本モニタリングは 5 分粒度
CW_METRICS = [
    # (query id, MetricName, Stat, 換算, 単位)  換算：None=そのまま / "kbps"=Sum バイト÷期間÷1024 / "rate"=Sum÷期間
    ("cpu", "CPUUtilization", "Average", None, "%"),
    ("cpu_peak", "CPUUtilization", "Maximum", None, "%"),
    ("net_in", "NetworkIn", "Sum", "kbps", "KB/s"),
    ("net_out", "NetworkOut", "Sum", "kbps", "KB/s"),
    ("ebs_read", "EBSReadBytes", "Sum", "kbps", "KB/s"),
    ("ebs_write", "EBSWriteBytes", "Sum", "kbps", "KB/s"),
    ("ebs_read_iops", "EBSReadOps", "Sum", "rate", "IOPS"),
    ("ebs_write_iops", "EBSWriteOps", "Sum", "rate", "IOPS"),
    ("ebs_io_balance", "EBSIOBalance%", "Minimum", None, "%"),      # EBS 帯域のバースト残高（Nitro 小型インスタンス）
    ("ebs_byte_balance", "EBSByteBalance%", "Minimum", None, "%"),
    ("cpu_credit", "CPUCreditBalance", "Minimum", None, "credits"),  # T 系インスタンスのみ
    ("status_failed", "StatusCheckFailed", "Maximum", None, ""),     # 1 = システム/インスタンス状態チェック失敗
]


def _imds(path, token, timeout=2):
    req = request.Request(f"http://169.254.169.254/latest/{path}", headers={"X-aws-ec2-metadata-token": token})
    with request.urlopen(req, timeout=timeout) as r:
        return r.read().decode().strip()


def _instance_identity():
    """(instance_id, region, instance_type)。環境変数を優先し、残りは IMDSv2 から取得。EC2 上でなければ例外。"""
    iid, region, itype = cfg.CW_INSTANCE_ID, cfg.CW_REGION, None
    try:
        tok_req = request.Request("http://169.254.169.254/latest/api/token", method="PUT",
                                  headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        with request.urlopen(tok_req, timeout=2) as r:
            token = r.read().decode()
        iid = iid or _imds("meta-data/instance-id", token)
        region = region or _imds("meta-data/placement/region", token)
        itype = _imds("meta-data/instance-type", token)
    except Exception as e:  # noqa
        if not (iid and region):
            raise RuntimeError(f"IMDS からインスタンス情報を取得できない（EC2 上ではない？）：{e}")
    return iid, region, itype


def _aws(args, region, timeout=40):
    try:
        r = subprocess.run(["aws"] + args + ["--region", region, "--output", "json"],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"aws {args[1]} タイムアウト（{timeout}s）") from None
    if r.returncode:
        err = r.stderr
        if "AccessDenied" in err or "not authorized" in err:
            raise RuntimeError(f"IAM 権限不足：インスタンスロールに cloudwatch:{_CW_ACTION.get(args[1], args[1])} がない")
        raise RuntimeError(f"aws {args[1]} 失敗：{util._short(err)}")
    return json.loads(r.stdout or "{}")


_CW_ACTION = {"get-metric-data": "GetMetricData", "describe-alarms": "DescribeAlarms"}


def _summarize(points, conv):
    """points: [(ts, value)] 新→旧。latest と直近 1h / 24h の avg/min/max を返す（単位換算済み）。"""
    if not points:
        return None
    f = (lambda v: v / CW_PERIOD / 1024) if conv == "kbps" else (lambda v: v / CW_PERIOD) if conv == "rate" else (lambda v: v)
    newest = points[0][0]
    out = {"latest": round(f(points[0][1]), 1)}
    for label, hours in (("1h", 1), ("24h", 24)):
        vals = [f(v) for ts, v in points if (newest - ts).total_seconds() < hours * 3600]
        if vals:
            out[label] = {"avg": round(sum(vals) / len(vals), 1), "min": round(min(vals), 1), "max": round(max(vals), 1)}
    return out


def _parse_cw_ts(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def collect_cloudwatch():
    """None（CLOUDWATCH=0 で無効）または dict を返す。失敗しても例外は投げず error に記録し、他の巡検は続行する。"""
    if not cfg.CLOUDWATCH:
        return None
    cw = {"error": None}
    if shutil.which("aws") is None:
        cw["error"] = "aws CLI が使えない（PATH に見つからない）"
        return cw
    try:
        iid, region, itype = _instance_identity()
    except RuntimeError as e:
        cw["error"] = str(e)
        return cw
    cw.update({"instance_id": iid, "region": region, "instance_type": itype, "period_s": CW_PERIOD})

    # --- 指標：GetMetricData 1 回で 24h 分を取得（12 指標 × 288 点、1 回の上限を大きく下回る）
    end = dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0)
    queries = [{"Id": qid, "ReturnData": True,
                "MetricStat": {"Metric": {"Namespace": "AWS/EC2", "MetricName": name,
                                          "Dimensions": [{"Name": "InstanceId", "Value": iid}]},
                               "Period": CW_PERIOD, "Stat": stat}}
               for qid, name, stat, _, _ in CW_METRICS]
    try:
        data = _aws(["cloudwatch", "get-metric-data",
                     "--metric-data-queries", json.dumps(queries),
                     "--start-time", (end - dt.timedelta(hours=24)).isoformat(),
                     "--end-time", end.isoformat(),
                     "--scan-by", "TimestampDescending"], region)
        meta = {q[0]: q for q in CW_METRICS}
        metrics = {}
        for res in data.get("MetricDataResults", []):
            qid = res.get("Id")
            pts = list(zip(map(_parse_cw_ts, res.get("Timestamps", [])), res.get("Values", [])))
            summ = _summarize(pts, meta[qid][3]) if qid in meta else None
            if summ:   # データのない指標（T 系以外の CPUCreditBalance 等）は省略
                summ["unit"] = meta[qid][4]
                metrics[qid] = summ
        cw["metrics"] = metrics
    except RuntimeError as e:
        cw["error"] = str(e)
        return cw

    # --- 本インスタンスに紐づく CloudWatch アラーム（ディメンションに本インスタンス ID を含むもの）
    try:
        alarms = _aws(["cloudwatch", "describe-alarms"], region).get("MetricAlarms", [])
        mine = [a for a in alarms if any(d.get("Value") == iid for d in a.get("Dimensions", []))]
        cw["alarms"] = [{"name": a.get("AlarmName"), "state": a.get("StateValue"),
                         "metric": a.get("MetricName"), "threshold": a.get("Threshold"),
                         "reason": util._short(a.get("StateReason"), 160)} for a in mine]
    except RuntimeError as e:
        cw["alarms_error"] = str(e)   # アラームが取れなくても指標には影響しない
    return cw
