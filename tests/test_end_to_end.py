"""End-to-End integration test for the entire AI Safety & Compliance Pipeline."""

import pytest
from safety_pipeline.core.config import DATA_DIR
from safety_pipeline.core.models import SystemMetadata
from safety_pipeline.core.target_app import TargetAssistant
from safety_pipeline.workstream_a_redteam.test_suite import AdversarialTestSuiteRunner
from safety_pipeline.workstream_b_guardrail.guardrail_service import PIIGuardrailService
from safety_pipeline.workstream_b_guardrail.benchmark import PIIBenchmarkRunner
from safety_pipeline.workstream_c_compliance.audit_matrix import AuditMatrixBuilder
from safety_pipeline.workstream_c_compliance.retest_differ import RetestDiffer
from safety_pipeline.workstream_c_compliance.report_generator import ReportGenerator


def test_full_pipeline_execution(tmp_path):
    metadata = SystemMetadata()
    probes_file = DATA_DIR / "red_team_probes.json"
    benchmark_file = DATA_DIR / "synthetic_pii_benchmark.json"

    # 1. Baseline Run
    target_vuln = TargetAssistant(mode="vulnerable")
    runner_vuln = AdversarialTestSuiteRunner(probes_file, target_assistant=target_vuln)
    baseline_results = runner_vuln.run_suite()
    assert len(baseline_results) > 0

    # 2. PII Benchmark Run
    pii_runner = PIIBenchmarkRunner(benchmark_file)
    pii_report = pii_runner.run_benchmark()
    assert pii_report.macro_f1 > 0.80

    # 3. Retest Run
    guardrail = PIIGuardrailService()
    target_hard = TargetAssistant(mode="hardened")
    runner_hard = AdversarialTestSuiteRunner(probes_file, target_assistant=target_hard)
    retest_results = runner_hard.run_suite(guardrail_service=guardrail)
    assert len(retest_results) == len(baseline_results)

    # 4. Differ
    delta = RetestDiffer.compute_delta(baseline_results, retest_results)
    assert delta.retest_passed > delta.baseline_passed

    # 5. Matrix
    matrix_builder = AuditMatrixBuilder(metadata)
    matrix = matrix_builder.build_matrix(baseline_results)
    assert len(matrix) > 0

    # 6. Report Generator
    reporter = ReportGenerator(tmp_path, metadata)
    paths = reporter.generate_all_reports(
        red_team_results=baseline_results,
        pii_report=pii_report,
        audit_matrix=matrix,
        remediation_delta=delta
    )

    for key, path in paths.items():
        assert path.exists(), f"Report file {key} at {path} should exist"
        assert path.stat().st_size > 100, f"Report file {key} should have substantial content"

    # Check HTML contains key sections
    html_content = paths["html"].read_text(encoding="utf-8")
    assert "AI Safety & Compliance Readiness Dashboard" in html_content
    assert "Legal & Governance Boundary Notice" in html_content
    assert "NIST AI RMF" in html_content
    assert "EU AI Act" in html_content
