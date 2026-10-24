"""Unit tests for Workstream C: Compliance Audit Matrix and Retest Differ."""

import pytest
from safety_pipeline.core.config import DATA_DIR
from safety_pipeline.core.models import SystemMetadata, Severity, RetestStatus
from safety_pipeline.core.target_app import TargetAssistant
from safety_pipeline.workstream_a_redteam.test_suite import AdversarialTestSuiteRunner
from safety_pipeline.workstream_c_compliance.audit_matrix import AuditMatrixBuilder
from safety_pipeline.workstream_c_compliance.retest_differ import RetestDiffer


def test_audit_matrix_generation():
    target = TargetAssistant(mode="vulnerable")
    runner = AdversarialTestSuiteRunner(DATA_DIR / "red_team_probes.json", target_assistant=target)
    results = runner.run_suite()

    builder = AuditMatrixBuilder()
    matrix = builder.build_matrix(results)

    assert len(matrix) >= 10
    frameworks = {e.framework for e in matrix}
    assert "NIST AI RMF 1.0" in frameworks
    assert "EU AI Act (Preparation)" in frameworks

    # Vulnerable target should have FAILED entries with mitigations and assigned owners
    failed_entries = [e for e in matrix if e.retest_status == RetestStatus.FAILED]
    assert len(failed_entries) > 0
    for fe in failed_entries:
        assert len(fe.mitigation_and_owner) > 10
        assert fe.severity in [Severity.HIGH, Severity.CRITICAL, Severity.MODERATE]


def test_retest_differential_computation():
    target_vuln = TargetAssistant(mode="vulnerable")
    runner_vuln = AdversarialTestSuiteRunner(DATA_DIR / "red_team_probes.json", target_assistant=target_vuln)
    baseline_results = runner_vuln.run_suite()

    target_hard = TargetAssistant(mode="hardened")
    runner_hard = AdversarialTestSuiteRunner(DATA_DIR / "red_team_probes.json", target_assistant=target_hard)
    retest_results = runner_hard.run_suite()

    delta = RetestDiffer.compute_delta(baseline_results, retest_results)

    assert delta.baseline_failed > 0
    assert delta.retest_passed > delta.baseline_passed
    assert len(delta.fixed_vulnerabilities) > 0
    assert len(delta.new_regressions) == 0
