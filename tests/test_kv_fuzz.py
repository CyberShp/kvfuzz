import json
from pathlib import Path

from nvme_kv_fuzz.campaign import CampaignConfig, CampaignGenerator
from nvme_kv_fuzz.catalog import FieldCatalog
from nvme_kv_fuzz.case_generator import CaseGenerator
from nvme_kv_fuzz.oracle import OracleAnalyzer, Verdict
from nvme_kv_fuzz.report import ReportGenerator
from nvme_kv_fuzz.run import RunConfig, RunOrchestrator


def test_catalog_and_case_generation_are_reproducible():
    catalog = FieldCatalog.from_yaml(Path("kv_field_catalog.yaml"))

    first = CaseGenerator(catalog).generate(seed=1337, operation="store", strategy="length_mismatch")
    second = CaseGenerator(catalog).generate(seed=1337, operation="store", strategy="length_mismatch")

    assert first.to_dict() == second.to_dict()
    assert first.operation == "store"
    assert first.opcode == 0x01
    assert first.key.startswith(b"kvfuzz-")
    assert first.mutation.strategy == "length_mismatch"
    assert first.mutation.field.path in catalog.field_paths()


def test_opcode_and_nsid_mutations_affect_command_model():
    catalog = FieldCatalog.from_yaml(Path("kv_field_catalog.yaml"))

    opcode_case = CaseGenerator(catalog).generate(
        seed=9,
        operation="delete",
        strategy="random_value",
        field_path="kv.opcode",
    )
    nsid_case = CaseGenerator(catalog).generate(
        seed=10,
        operation="delete",
        strategy="random_value",
        field_path="kv.nsid",
    )

    assert opcode_case.opcode == opcode_case.mutation.mutated_value
    assert opcode_case.cdw["operation_id"] == opcode_case.opcode
    assert nsid_case.nsid == nsid_case.mutation.mutated_value


def test_dry_run_writes_locator_artifacts(tmp_path):
    catalog = FieldCatalog.from_yaml(Path("kv_field_catalog.yaml"))
    campaign_path = tmp_path / "campaign.jsonl"
    config_path = tmp_path / "config.yaml"
    artifacts_dir = tmp_path / "artifacts"

    cases = list(CampaignGenerator(catalog).iter_cases(CampaignConfig(seed=7, count=3, random_ratio=0.34)))
    campaign_path.write_text("\n".join(json.dumps(item.to_dict(), sort_keys=True) for item in cases) + "\n")
    config_path.write_text(
        "\n".join(
            [
                "device_path: /dev/nvme1n1",
                "nsid: 1",
                "target_nqn: nqn.2026-06.test:kv",
                "allowed_model_or_serial: [TEST_ARRAY]",
                "key_prefix: kvfuzz-test-",
                "max_qps: 10",
                "timeout_ms: 1000",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = RunOrchestrator(
        RunConfig(
            campaign_path=campaign_path,
            config_path=config_path,
            artifacts_dir=artifacts_dir,
            dry_run=True,
            limit=2,
        )
    ).run()

    assert result["executed_cases"] == 2
    run_dirs = sorted(artifacts_dir.glob("*/case-*"))
    assert len(run_dirs) == 2
    for run_dir in run_dirs:
        assert (run_dir / "case.yaml").exists()
        assert (run_dir / "command.json").exists()
        assert (run_dir / "kv-trace.jsonl").exists()
        assert (run_dir / "summary.json").exists()
        summary = json.loads((run_dir / "summary.json").read_text())
        assert summary["verdict"] == "PASS_VALID"
        assert {"operation", "field", "strategy", "bucket_key", "replay_command"} <= set(summary)
        trace = (run_dir / "kv-trace.jsonl").read_text()
        assert '"stage": "precheck"' in trace
        assert '"stage": "send"' in trace
        assert '"stage": "semantic_verify"' in trace


def test_report_buckets_failures_and_renders_chinese_sections(tmp_path):
    campaign = tmp_path / "campaign.jsonl"
    artifacts = tmp_path / "artifacts"
    run_dir = artifacts / "run-1" / "case-0-seed-1"
    run_dir.mkdir(parents=True)
    case = {
        "campaign_index": 0,
        "seed": 1,
        "operation": "retrieve",
        "opcode": 0x02,
        "random_mutation": False,
        "mutation": {"field": "kv.value_length", "strategy": "buffer_too_small"},
        "expected": {"allowed": ["PASS_REJECTED", "PASS_RECOVERED"], "forbidden": ["FAIL_ORACLE"]},
    }
    campaign.write_text(json.dumps(case) + "\n", encoding="utf-8")
    (run_dir / "case.yaml").write_text(json.dumps(case), encoding="utf-8")
    (run_dir / "summary.json").write_text(
        json.dumps(
            {
                "verdict": "FAIL_ORACLE",
                "reason": "buffer too small silently succeeded",
                "bucket_key": "FAIL_ORACLE|buffer too small silently succeeded|retrieve|kv.value_length|buffer_too_small|0x0",
                "operation": "retrieve",
                "field": "kv.value_length",
                "strategy": "buffer_too_small",
                "nvme_status": "0x0",
                "replay_command": "python -m nvme_kv_fuzz.cli replay case.yaml --config config.yaml",
            }
        ),
        encoding="utf-8",
    )

    report = ReportGenerator.from_files(campaign_path=campaign, artifacts_dir=artifacts).build()
    markdown = ReportGenerator.render_markdown(report)

    assert report["execution"]["verdict_counts"]["FAIL_ORACLE"] == 1
    assert report["failures"][0]["operation"] == "retrieve"
    assert report["failures"][0]["field"] == "kv.value_length"
    assert "\u539f\u751f KV over NOF Fuzz \u62a5\u544a" in markdown
    assert "\u5931\u8d25\u6876" in markdown
    assert "\u4e3b\u673a / \u7f51\u7edc / NOF \u73af\u5883" in markdown


def test_oracle_classifies_safety_hang_cleanup_and_semantic_failures():
    oracle = OracleAnalyzer()

    assert oracle.analyze(dmesg="BUG: unable to handle kernel NULL pointer").verdict == Verdict.FAIL_SAFETY
    assert oracle.analyze(timed_out=True).verdict == Verdict.FAIL_HANG
    assert (
        oracle.analyze(
            semantic_error="value mismatch after retrieve",
            expected_allowed=("PASS_VALID",),
            command_returncode=0,
        ).verdict
        == Verdict.FAIL_ORACLE
    )
    assert (
        oracle.analyze(
            nvme_before={"Controllers": [{"Name": "nvme1"}]},
            nvme_after={"Controllers": [{"Name": "nvme1"}, {"Name": "nvme9"}]},
        ).verdict
        == Verdict.FAIL_CLEANUP
    )
