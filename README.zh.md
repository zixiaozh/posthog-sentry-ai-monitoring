# platform_health.py 仕様書 / 设计说明

自建 **Sentry + PostHog 平台**（EC2 · Docker）健康巡检脚本。本文档说明：**检查哪些项目、设了哪些阈值和指标、如何打包成发给 AI 的内容**。

- 版本对象：`platform_health.py`（零依赖，仅 Python 标准库）
- 定位：**定期综合巡检 + AI 诊断**，与实时告警 `slack_alert.sh` 互补，不重复其职责
- 数据来源：全部本机（docker / /proc / 本地 HTTP 探活），健康检查本身无需 Sentry/PostHog 登录或 token

---

## 1. 处理流程总览

```
采集(本机三类信号) → 规则层(算确定性 flags) → 打包(精简成 AI payload)
   → [可选] AI 诊断 → 输出(JSON + Markdown 落盘, 自动清理)
```

`--show-payload` 会在「打包」后停下，把**准备发给 AI 的 JSON** 打到终端，不调 AI、不写文件。

---

## 2. 采集项目（发给 AI 前检查的内容）

### 2.1 主机资源（来源：`/proc`、`os.statvfs`）

| 项目 | 字段 | 来源 |
|------|------|------|
| 磁盘（根分区 `/`） | `total_gb` / `used_gb` / `used_pct` | statvfs |
| 内存 | `total_gb` / `available_gb` / `used_pct` | /proc/meminfo |
| swap | `total_gb` / `used_gb` / `used_pct` | /proc/meminfo |
| 负载 | `1m` / `5m` / `15m` / `cpu_count` / `per_cpu_1m` | os.getloadavg |

### 2.2 容器健康（来源：`docker inspect`，需 root/docker 组）

对**所有**容器（含已停止）采集：

| 字段 | 含义 |
|------|------|
| `name` | 容器名 |
| `status` | running / exited / restarting … |
| `health` | healthy / unhealthy / starting / none（无 healthcheck） |
| `restarts` | 累计重启次数（仅参考，不单独告警） |
| `oom_killed` | 是否曾被 OOM kill |
| `started_at` / `uptime_days` | 启动时间 / 已运行天数（用于判「最近重启」） |
| `watched` | 名称是否包含 `WATCH_PREFIXES` 中的任一项，即是否平台核心容器（★） |
| `exit_code` | 退出码（区分正常结束与崩溃） |
| `restarts_delta` | **上次巡检以来新增的重启次数**（与 `out/state.json` 比较；首次运行或容器被重建时为空） |
| `mem_mb` / `swap_mb` / `mem_limit_mb` | 容器内存 / swap 实际占用与上限（cgroup v2 直读，口径同 `docker stats`；读不到时退回 `docker stats`，仅内存） |

### 2.2b swap 换页活动（来源：`/proc/vmstat` 的 `pswpin` / `pswpout`）

| 字段 | 含义 |
|------|------|
| `swap_io.now` | 本次运行期间（≥3 秒窗口）的换入 / 换出速率 KB/s |
| `swap_io.since_last` | 上次巡检以来的平均换入 / 换出速率 KB/s |

> 「swap 已用量」只说明过去换出过；**换页速率**才说明现在是否有内存压力。已用多但速率≈0 → 多为历史残留。

### 2.3 网页可用性（来源：本地 HTTP GET 健康端点）

| 字段 | 含义 |
|------|------|
| `name` / `url` | 目标名 / URL |
| `status` | HTTP 状态码 |
| `ok` | 是否 2xx–3xx |
| `latency_ms` | 响应延迟 |
| `error` | 连接失败时的错误信息 |

已确认端点（深度健康检查，会验依赖，均返回 200）：
- Sentry：`https://sentry.randd-nn-freebit.net/_health/`
- PostHog：`https://posthog.randd-nn-freebit.net/_health`（EC2 本机实测约 150ms，2026-10）

---

## 3. 阈值与判定规则

> ★重要：这些阈值**不是告警通道**。实时告警由 `slack_alert.sh` 负责。这里只用于**给 AI 提示（flags）**和**算总合状态**。数值**刻意对齐 `slack_alert.sh`**，改动时两边一起改，保持单一心智模型。

### 3.1 主机阈值（对齐 Slack bot）

| 指标 | WARN | CRIT | 对应 Slack 变量 |
|------|------|------|----------------|
| 磁盘使用率 | ≥ 85% | ≥ 95% | DISK_WARN_PCT / DISK_CRIT_PCT |
| 可用内存 | ≤ 2 GB | ≤ 1 GB | RAM_WARN_GB / RAM_CRIT_GB |
| swap 已用 | ≥ 5 GB | ≥ 10 GB | SWAP_WARN_GB / SWAP_CRIT_GB |
| 每核 load(1m) | ≥ 1.5 | — | （本脚本独有） |
| swap 换页（上次巡检以来平均） | ≥ 1024 KB/s | — | （本脚本独有，`SWAP_IO_WARN_KBPS`） |

> swap 已用量的告警文字会附上换页速率，注明是「仍在活跃换页」还是「历史残留」。

### 3.2 容器判定

| 情况 | 级别 |
|------|------|
| `oom_killed` = true（**不论当前是否在运行**） | CRIT |
| `exited` 且 exit code ≠ 0 / `restarting` / `dead` | CRIT |
| `exited` 且 exit code = 0（正常结束，多为一次性任务） | INFO |
| `created`（创建后从未启动） | INFO |
| `paused` | WARN |
| running 但 `health` ∈ {unhealthy, starting…}（非 healthy/none） | WARN |
| 上次巡检以来新增重启 ≥ `RESTART_DELTA_CRIT`(默认 3) | CRIT（疑似反复崩溃） |
| 上次巡检以来新增重启 1 ～ N-1 次 | WARN |
| 无增量数据（首次运行/容器重建）且 `uptime_days` < `RECENT_RESTART_DAYS`(默认 1) | INFO |
| 名称匹配 `IGNORE_CONTAINERS` | 不判定、不发给 AI |
| docker 本身采集失败（权限等） | WARN（避免误显示 🟢） |
| 部分容器 inspect 失败（如采集途中被删除） | WARN（其余容器照常判定） |

> 累计重启次数**不单独告警，也不作为发给 AI 的依据**（三个月累计几十次是常态，属噪音）；只看**增量**这种真信号。
> 首次运行只建立基准（`out/state.json`），从第二次起才有增量。

### 3.3 网页判定

| 情况 | 级别 |
|------|------|
| `ok` = false（探活失败 / 5xx / 连不上） | CRIT |
| `ok` = true 但 `latency_ms` ≥ `WEB_LATENCY_WARN_MS`(默认 5000) | WARN |

### 3.4 flags 分级

- **CRIT**：服务不可用类（容器停、OOM、网页挂、磁盘/内存到危险线）→ 总合状态 🔴
- **WARN**：需关注（磁盘/内存/swap/load 到警戒、health 异常、网页慢）→ 🟡
- **INFO**：仅提示（最近重启过）→ 不影响总合状态

> 规则层的总合状态作为 `rule_status` 一并发给 AI，AI 以此为基准；若判断不同须写明根据。

---

## 4. 打包成发给 AI 的内容（token 精简）

**本地存全量快照，但只把必要内容喂给 LLM**，减少 token。`build_ai_payload()` 做两件精简：

### 4.1 容器折叠

- **正常容器（nominal）折叠为计数**，不逐条发送。
  nominal 判定 = running 且 health∈{healthy,none} 且 未 OOM 且 非最近重启 且 无新增重启（累计 restarts 不参与）。
- **内存 / swap 前 N 名始终发送**（`top_memory` / `top_swap`，`TOP_MEM_N` 默认 8），让 AI 能把内存问题落到具体容器。
- **只发 notable 容器**：不满足 nominal 的。
- `IGNORE_CONTAINERS` 中的容器完全排除，只计数。
- 折叠信息：`summary = { total, running, not_running, nominal, ignored }`。

### 4.2 字段裁剪

发给 AI 的 notable 容器只保留：`name / status / exit_code（仅 exited 时）/ health / restarts / restarts_delta / oom_killed / uptime_days / mem_mb / swap_mb`。
去掉：`watched`（冗余）、`started_at`（纳秒时间戳，已由 uptime_days 表达）。

### 4.3 AI payload 结构

```json
{
  "generated_at": "...",
  "host": { disk, mem, swap, load, swap_io },
  "containers": {
    "summary": { total, running, not_running, nominal, ignored },
    "notable": [ {name,status,exit_code,health,restarts,restarts_delta,oom_killed,uptime_days,mem_mb,swap_mb}, ... ],
    "top_memory": [ {name,mem_mb,swap_mb,mem_limit_mb}, ... ],
    "top_swap": [ {name,swap_mb}, ... ]
  },
  "web": [ {name,url,status,ok,latency_ms}, ... ],
  "flags": [ "[CRIT/WARN/INFO] ...", ... ],
  "note_for_ai": "flags 是确定性提示，实时告警另由 Slack 负责；正常容器已折叠为计数，..."
}
```

> 完整、未折叠的快照仍写入 `out/health_*.json` 留档，不受精简影响。

### 4.4 AI 诊断（可选）

按 `AI_PROVIDER` 选择模型（默认 `gemini`，需 `GEMINI_API_KEY`；`anthropic` 需 `ANTHROPIC_API_KEY`），把上面 payload 交给 AI，要求用 `REPORT_LANG`（默认 ja）输出：
① 总合状态一行 ② 检测到的异常与影响 ③ 想定原因 ④ 推奨アクション。对应 key 未设则跳过，仅出规则 flags。报告中的「AI 診断」标题会注明所用 provider / 模型。

---

## 5. 输出产物

| 文件 | 内容 |
|------|------|
| `out/health_YYYYMMDD_HHMMSS.json` | 全量快照（留档） |
| `out/health_YYYYMMDD_HHMMSS.md` | 渲染后的健康报告 |
| `out/health_latest.md` | 最新报告（固定路径便于查看） |
| `out/state.json` | 上次巡检的计数器（各容器重启次数、swap 换页计数），用于算增量；删掉即重新建立基准 |

保留 `KEEP_DAYS`（默认 14）天，更早的自动删除。原始 docker/主机数据不额外落盘。

---

## 6. 与 slack_alert.sh 的分工

| | slack_alert.sh | platform_health.py（本脚本） |
|---|---|---|
| 角色 | **实时告警** | **定期综合巡检 + AI 诊断** |
| 触发 | 指标破线即时 ping | cron 定期运行 |
| 覆盖 | 主机 RAM/Disk/Swap 阈值、容器内存 vs 限额 | 容器 status/health/OOM/重启/uptime、网页可用性、跨项画像 |
| 阈值 | **唯一真源** | 对齐 Slack，仅用于给 AI 提示 |

两者互补：Slack 负责「现在破线了叫我」，本脚本负责「整体健康画像 + 原因分析 + 建议」。

---

## 7. 运行与配置

```bash
cd posthog-sentry-ai-monitoring
cp .env.example .env             # ★ 脚本读的是 .env，不是 .env.example
sudo python3 platform_health.py --show-payload   # 只看 payload，不调 AI
sudo python3 platform_health.py --dry-run --stdout  # 看渲染报告，写 out/
sudo python3 platform_health.py                  # 完整：含 AI 诊断（需 API key）
```

- 脚本**自动加载同目录 `.env`**（因此 `sudo` 清空环境变量也不影响）；已存在的环境变量优先，`.env` 中的空值视为未设置。
- 读容器信息需权限，故用 `sudo`。
- 常用配置项见 `.env.example`（URL、阈值、语言、保留天数等）。

### 主要环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| SENTRY_URL / POSTHOG_URL | 已填健康端点 | 网页探活目标 |
| WEB_LATENCY_WARN_MS | 5000 | 网页响应过慢阈值 |
| WATCH_PREFIXES | -web-,-nginx-,-relay-,-postgres-,-db-,-pgbouncer-,-kafka-,-clickhouse-,-redis,-snuba-api-,-taskworker-,-capture-,-ingestion- | 核心容器（名称包含即匹配） |
| IGNORE_CONTAINERS | 空 | 完全排除判定的容器（名称包含即匹配） |
| DISK_WARN / DISK_CRIT | 85 / 95 | 磁盘阈值 % |
| MEM_AVAIL_WARN_GB / _CRIT_GB | 2 / 1 | 可用内存阈值 GB |
| SWAP_WARN_GB / _CRIT_GB | 5 / 10 | swap 已用阈值 GB |
| LOAD_PER_CPU_WARN | 1.5 | 每核 load |
| RECENT_RESTART_DAYS | 1 | 无增量数据时「最近重启」判定天数 |
| RESTART_DELTA_CRIT | 3 | 上次巡检以来新增重启 ≥N → CRIT（≥1 → WARN） |
| SWAP_IO_WARN_KBPS | 1024 | 上次巡检以来 swap 换页平均 KB/s 阈值 |
| TOP_MEM_N | 8 | 发给 AI 的内存 / swap 前 N 名容器 |
| AI_PROVIDER | gemini | AI 诊断用哪家：gemini / anthropic |
| GEMINI_API_KEY / MODEL | 空 / gemini-2.5-pro | Gemini（AI Studio 发行） |
| ANTHROPIC_API_KEY / MODEL | 空 / claude-sonnet-5-5 | Claude（Anthropic Console 发行，单独计费） |
| REPORT_LANG | ja | 报告语言 ja/zh/en |
| KEEP_DAYS | 14 | 产物保留天数 |

---

## 8. 隐私

本脚本采集的是**平台运行/健康数据**（容器状态、主机资源、网页状态码），**不涉及用户个人或设备信息**，也不读取 Sentry 中的移动端错误内容。

---

## 9. 后续扩展（未实现）

- **层次 2**：用 Sentry 只读 token 查「最新事件时间」，检测摄取停滞（覆盖「issues 没显示」）。
- **层次 3**：Kafka consumer lag / 队列深度 / worker 日志，查根因（如 export 失败）。
- 接入 CloudWatch，跨源关联（达成 task「2 个以上数据源统合」）。
- 上 cron + `systemd-run` 资源护栏定期运行。