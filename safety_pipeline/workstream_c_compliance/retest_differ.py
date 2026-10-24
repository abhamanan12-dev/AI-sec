"""Remediation & Retest Differential Analysis Engine.

Compares a baseline evaluation with a remediated / guardrailed retest run
to quantify risk reduction, track resolved vulnerabilities, and detect regressions.
"""

from typing import List, Dict, Any
from safety_pipeline.core.models import RedTeamResult, RemediationDelta


class RetestDiffer:
    @staticmethod
    def compute_delta(
        baseline_results: List[RedTeamResult],
        retest_results: List[RedTeamResult],
        baseline_id: str = "BASELINE-RUN-001",
        retest_id: str = "RETEST-HARDENED-002"
    ) -> RemediationDelta:
        baseline_map: Dict[str, RedTeamResult] = {r.probe_id: r for r in baseline_results}
        retest_map: Dict[str, RedTeamResult] = {r.probe_id: r for r in retest_results}

        total_probes = len(baseline_map)
        baseline_passed = sum(1 for r in baseline_results if r.passed)
        baseline_failed = len(baseline_results) - baseline_passed

        retest_passed = sum(1 for r in retest_results if r.passed)
        retest_failed = len(retest_results) - retest_passed

        fixed_vulnerabilities = []
        unresolved_vulnerabilities = []
        new_regressions = []

        for pid, b_res in baseline_map.items():
            r_res = retest_map.get(pid)
            if not r_res:
                continue

            if not b_res.passed and r_res.passed:
                fixed_vulnerabilities.append(f"[{pid}] {b_res.probe_name} ({b_res.severity.value}) - RESOLVED")
            elif not b_res.passed and not r_res.passed:
                unresolved_vulnerabilities.append(f"[{pid}] {b_res.probe_name} ({b_res.severity.value}) - PERSISTENT: {r_res.failure_reason}")
            elif b_res.passed and not r_res.passed:
                new_regressions.append(f"[{pid}] {b_res.probe_name} ({b_res.severity.value}) - REGRESSION DETECTED: {r_res.failure_reason}")

        return RemediationDelta(
            baseline_run_id=baseline_id,
            retest_run_id=retest_id,
            total_tests=total_probes,
            baseline_passed=baseline_passed,
            baseline_failed=baseline_failed,
            retest_passed=retest_passed,
            retest_failed=retest_failed,
            fixed_vulnerabilities=fixed_vulnerabilities,
            unresolved_vulnerabilities=unresolved_vulnerabilities,
            new_regressions=new_regressions,
        )
