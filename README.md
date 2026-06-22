# 原生 KV over NOF Fuzz

这是一个面向 **NVMe Key Value Command Set over NVMe-oF** 的可定位 fuzz harness。它按 KV 命令层生成 corpus，通过 `nvme-cli io-passthru` 执行 case，并为每条 case 保存可复现、可定位、可聚类的证据链。

## 能力概览

- 生成 KV 协议语法感知 campaign：`store`、`retrieve`、`list`、`delete`、`exist`。
- 覆盖 KV 字段变异：`opcode`、`nsid`、`cdw2/3/10/11/12/13/14/15`、key length、value length、host buffer size、option bits、reserved bits、PRP/SGL direction。
- 每条 case 独立落盘：`case.yaml`、`command.json`、`kv-trace.jsonl`、stdout/stderr、前后状态和 `summary.json`。
- 生成中文 Markdown 报告和机器可读 JSON 报告。
- 按 `(verdict, reason, operation, field, strategy, nvme_status)` 聚类失败桶。
- 支持 `replay` 和 `minimize`，方便把失败 case 交给阵列/驱动同事复现。
- Live target 默认有安全护栏：必须显式 `--allow-live-target`，并校验设备路径、NQN、model/serial allowlist、限速和超时。

## 快速开始

生成 campaign：

```bash
python -m nvme_kv_fuzz.cli generate-campaign \
  --seed 20260622 \
  --count 100 \
  --output artifacts/campaign.jsonl \
  --summary
```

先做 dry-run，确认命令、产物和报告链路：

```bash
python -m nvme_kv_fuzz.cli run \
  --campaign artifacts/campaign.jsonl \
  --config config.example.yaml \
  --artifacts-dir artifacts \
  --limit 10 \
  --dry-run
```

生成中文报告：

```bash
python -m nvme_kv_fuzz.cli generate-report \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts \
  --output-md artifacts/fuzz-report.md \
  --output-json artifacts/fuzz-report.json
```

真实阵列执行必须显式打开：

```bash
python -m nvme_kv_fuzz.cli run \
  --campaign artifacts/campaign.jsonl \
  --config config.yaml \
  --artifacts-dir artifacts/live-run \
  --limit 100 \
  --allow-live-target
```

## CLI

- `generate-case`：按 seed 生成单条 KV fuzz case。
- `generate-campaign`：生成 JSONL corpus。
- `run`：执行 campaign，支持 dry-run 和 live target。
- `replay`：重放单条 `case.yaml`。
- `minimize`：抽取最小复现 case。
- `generate-report`：生成中文 Markdown 报告和 JSON 报告。
- `collect-env`：采集主机、网络、NOF、NVMe 环境证据。

## 关键产物

每条 case 写入：

```text
artifacts/<run-id>/case-<index>-seed-<seed>/
```

目录内包含：

- `case.yaml`：seed、operation、字段、策略、key/value 摘要和期望 verdict。
- `command.json`：实际 `nvme io-passthru` 命令、opcode、NSID、CDW、数据方向和 payload 文件。
- `kv-trace.jsonl`：`precheck -> send -> completion -> semantic_verify -> cleanup` 阶段 trace。
- `summary.json`：verdict、reason、bucket_key、operation、field、strategy、nvme_status、errno、latency_ms、replay_command。
- `stdout.log` / `stderr.log`：命令输出。
- `nvme-before.json` / `nvme-after.json`：case 前后 NVMe 设备状态。
- `dmesg-before.log` / `dmesg-after.log` / `journal-kernel.log`：内核侧证据。

## 报告内容

中文 Markdown 报告包含：

- 执行摘要
- KV 覆盖矩阵
- Verdict 分布
- 失败桶
- 语义一致性检查
- 主机 / 网络 / NOF 环境检查清单
- 行业 fuzz 报告字段映射

## 安全说明

Live target 模式会先做 precheck：

- `device_path` 必须形如 `/dev/nvmeXnY`。
- `target_nqn` 必须匹配 `nvme list-subsys`。
- `allowed_model_or_serial` 必须匹配 `nvme list -v -o json`。
- 所有 key 默认带 `key_prefix`，避免污染非测试 keyspace。
- 达到连续 timeout、controller/namespace 异常或安全类错误时会熔断。

第一版聚焦 KV I/O 命令语义 fuzz，不做 NVMe/TCP TLS PDU 代理层变异。
