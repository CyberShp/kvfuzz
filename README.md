# Native KV over NOF Fuzz

This project is a locateable fuzz harness for the NVMe Key Value Command Set over
NVMe-oF. It generates KV command-layer corpus, executes cases through
`nvme-cli io-passthru`, and records enough artifacts to reproduce and triage each
result.

## Quick Start

```bash
python -m nvme_kv_fuzz.cli generate-campaign --seed 20260622 --count 100 --output artifacts/campaign.jsonl --summary

python -m nvme_kv_fuzz.cli run \
  --campaign artifacts/campaign.jsonl \
  --config config.example.yaml \
  --artifacts-dir artifacts \
  --limit 10 \
  --dry-run

python -m nvme_kv_fuzz.cli generate-report \
  --campaign artifacts/campaign.jsonl \
  --artifacts-dir artifacts \
  --output-md artifacts/fuzz-report.md \
  --output-json artifacts/fuzz-report.json
```

Live array execution requires `--allow-live-target`. The config file must declare
the device path, NSID, target NQN, model/serial allowlist, key prefix, rate limit,
and timeout to avoid hitting the wrong namespace.

## CLI

- `generate-campaign`: generate JSONL corpus.
- `run`: execute a campaign in dry-run or live-target mode.
- `replay`: re-run a single `case.yaml` into fresh artifacts.
- `minimize`: extract a minimal reproducer from a case file.
- `generate-report`: generate Markdown and JSON reports.
- `collect-env`: collect `nvme list -v`, `id-ctrl`, `id-ns`, `list-subsys`,
  `dmesg`, `modinfo`, and related host evidence.

## Artifacts

Each case is written under `artifacts/<run-id>/case-<index>-seed-<seed>/`:

- `case.yaml`
- `command.json`
- `kv-trace.jsonl`
- `stdout.log`
- `stderr.log`
- `summary.json`
- `nvme-before.json`
- `nvme-after.json`
- `dmesg-before.log`
- `dmesg-after.log`
- `journal-kernel.log`

`summary.json` includes `verdict`, `reason`, `bucket_key`, `operation`, `field`,
`strategy`, `nvme_status`, `errno`, `latency_ms`, `device_state_delta`, and
`replay_command`.
