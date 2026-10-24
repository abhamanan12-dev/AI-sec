"""Unit tests for Workstream A: Adversarial Red-Teaming."""

import pytest
from safety_pipeline.core.config import DATA_DIR, PROJECT_ROOT
from safety_pipeline.core.target_app import TargetAssistant
from safety_pipeline.workstream_a_redteam.test_suite import AdversarialTestSuiteRunner
from safety_pipeline.workstream_a_redteam.promptfoo_exporter import PromptfooExporter


def test_probes_dataset_validity():
    runner = AdversarialTestSuiteRunner(DATA_DIR / "red_team_probes.json")
    assert len(runner.probes) >= 15
    categories = {p.category.value for p in runner.probes}
    assert "jailbreak_instruction_override" in categories
    assert "system_prompt_context_leakage" in categories
    assert "sensitive_data_disclosure" in categories
    assert "toxic_abusive_output" in categories
    assert "dangerous_high_impact_advice" in categories


def test_adversarial_baseline_catches_vulnerabilities():
    target = TargetAssistant(mode="vulnerable")
    runner = AdversarialTestSuiteRunner(DATA_DIR / "red_team_probes.json", target_assistant=target)
    results = runner.run_suite()

    failed = [r for r in results if not r.passed]
    assert len(failed) > 0, "Vulnerable target should trigger failures across red-team probes"


def test_adversarial_hardened_passes_probes():
    target = TargetAssistant(mode="hardened")
    runner = AdversarialTestSuiteRunner(DATA_DIR / "red_team_probes.json", target_assistant=target)
    results = runner.run_suite()

    failed = [r for r in results if not r.passed]
    assert len(failed) == 0, f"Hardened target should pass all probes. Failed: {[f.probe_id for f in failed]}"


def test_promptfoo_yaml_export(tmp_path):
    exporter = PromptfooExporter(DATA_DIR / "red_team_probes.json")
    out_yaml = tmp_path / "promptfoo_test.yaml"
    res_path = exporter.export_config(out_yaml)

    assert res_path.exists()
    assert res_path.stat().st_size > 500
