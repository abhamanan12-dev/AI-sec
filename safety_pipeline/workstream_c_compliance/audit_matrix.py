"""Compliance Audit Matrix Builder.

Synthesizes technical test evidence (Adversarial Red-Teaming + PII Guardrail evaluations)
into traceable, framework-aligned controls for NIST AI RMF and EU AI Act.
Preserves initial baseline findings alongside retest results without overstating human review approvals.
"""

from typing import List, Dict, Any, Optional
from safety_pipeline.core.models import (
    AuditMatrixEntry,
    RedTeamResult,
    RetestStatus,
    ReviewStatus,
    Severity,
    SystemMetadata,
)
from safety_pipeline.workstream_c_compliance.nist_rmf import NIST_AI_RMF_CATALOG
from safety_pipeline.workstream_c_compliance.eu_ai_act import EU_AI_ACT_CATALOG


class AuditMatrixBuilder:
    def __init__(self, metadata: Optional[SystemMetadata] = None):
        self.metadata = metadata or SystemMetadata()

    def build_matrix(
        self,
        baseline_results: List[RedTeamResult],
        retest_results: Optional[List[RedTeamResult]] = None
    ) -> List[AuditMatrixEntry]:
        matrix: List[AuditMatrixEntry] = []

        # Index baseline results by category
        by_category_baseline: Dict[str, List[RedTeamResult]] = {}
        for r in baseline_results:
            cat = str(r.category.value if hasattr(r.category, "value") else r.category)
            by_category_baseline.setdefault(cat, []).append(r)

        # Index retest results by probe_id
        retest_by_probe: Dict[str, RedTeamResult] = {}
        if retest_results:
            for r in retest_results:
                retest_by_probe[r.probe_id] = r

        # 1. NIST AI RMF Mappings
        for ctrl_id, ctrl in NIST_AI_RMF_CATALOG.items():
            matched_baseline: List[RedTeamResult] = []
            for rel_cat in ctrl["related_categories"]:
                matched_baseline.extend(by_category_baseline.get(rel_cat, []))

            if not matched_baseline:
                continue

            base_failures = [r for r in matched_baseline if not r.passed]
            all_evidence_ids = [r.probe_id for r in matched_baseline]

            # Determine baseline finding and severity
            if base_failures:
                max_sev = self._highest_severity([f.severity for f in base_failures])
                base_finding = f"Baseline: {len(base_failures)} probe(s) failed out of {len(matched_baseline)} tested. Notable failure: [{base_failures[0].probe_id}] {base_failures[0].probe_name} - {base_failures[0].failure_reason}"
                mitigation = self._recommend_mitigation(base_failures[0])
            else:
                max_sev = Severity.LOW
                base_finding = f"Baseline: All {len(matched_baseline)} adversarial probe(s) passed under initial configuration."
                mitigation = "Maintain automated continuous regression evaluation and monitoring in CI/CD pipeline."

            # Determine retest status and finding from retest_results
            if retest_results is not None:
                matched_retest = [retest_by_probe[pid] for pid in all_evidence_ids if pid in retest_by_probe]
                retest_failures = [r for r in matched_retest if not r.passed]
                if not retest_failures:
                    retest_status = RetestStatus.PASSED
                    retest_finding = f"Retest: All {len(matched_retest)} probe(s) passed after remediation guardrails applied."
                else:
                    retest_status = RetestStatus.FAILED
                    retest_finding = f"Retest: {len(retest_failures)} probe(s) still failing after remediation."
            else:
                retest_status = RetestStatus.FAILED if base_failures else RetestStatus.PASSED
                retest_finding = "Retest not yet conducted; awaiting hardened evaluation."

            # Review status defaults to pending human review rather than claiming approval
            review_status = ReviewStatus.PENDING_TECHNICAL_REVIEW

            matrix.append(
                AuditMatrixEntry(
                    control_id=ctrl_id,
                    framework="NIST AI RMF 1.0",
                    function_or_article=ctrl["subcategory"],
                    control_name=ctrl["name"],
                    test_evidence_ids=all_evidence_ids,
                    baseline_finding=base_finding,
                    retest_finding=retest_finding,
                    severity=max_sev,
                    applicability_status="Applies (Enterprise AI Assistant)",
                    actor_role="Deployer",
                    applicability_rationale=f"Applicable to {self.metadata.name} as an enterprise-facing assistant handling organizational data.",
                    mitigation_and_owner=mitigation,
                    target_date="2026-11-15",
                    retest_status=retest_status,
                    review_status=review_status,
                    reviewed_by=None,
                    review_date=None,
                    residual_risk_acceptance=None,
                )
            )

        # 2. EU AI Act Mappings
        for art_id, art in EU_AI_ACT_CATALOG.items():
            matched_baseline = []
            for rel_cat in art["related_categories"]:
                matched_baseline.extend(by_category_baseline.get(rel_cat, []))

            if not matched_baseline:
                continue

            base_failures = [r for r in matched_baseline if not r.passed]
            all_evidence_ids = [r.probe_id for r in matched_baseline]

            if base_failures:
                max_sev = self._highest_severity([f.severity for f in base_failures])
                base_finding = f"Baseline: {len(base_failures)} probe(s) failed out of {len(matched_baseline)} tested for {art['title']}."
                mitigation = self._recommend_mitigation(base_failures[0])
            else:
                max_sev = Severity.LOW
                base_finding = f"Baseline: Tested probes align with technical expectations for {art['title']} in sandbox test environment."
                mitigation = "Continuous audit logging and regular verification of human-in-the-loop escalation paths."

            if retest_results is not None:
                matched_retest = [retest_by_probe[pid] for pid in all_evidence_ids if pid in retest_by_probe]
                retest_failures = [r for r in matched_retest if not r.passed]
                if not retest_failures:
                    retest_status = RetestStatus.PASSED
                    retest_finding = f"Retest: All {len(matched_retest)} probe(s) passed under hardened controls."
                else:
                    retest_status = RetestStatus.FAILED
                    retest_finding = f"Retest: {len(retest_failures)} probe(s) still failing."
            else:
                retest_status = RetestStatus.FAILED if base_failures else RetestStatus.PASSED
                retest_finding = "Retest not yet conducted; awaiting hardened evaluation."

            review_status = ReviewStatus.LEGAL_REVIEW_REQUIRED if max_sev == Severity.CRITICAL else ReviewStatus.PENDING_TECHNICAL_REVIEW

            matrix.append(
                AuditMatrixEntry(
                    control_id=art_id,
                    framework="EU AI Act (Preparation)",
                    function_or_article=art["article"],
                    control_name=art["title"],
                    test_evidence_ids=all_evidence_ids,
                    baseline_finding=base_finding,
                    retest_finding=retest_finding,
                    severity=max_sev,
                    applicability_status=art.get("default_applicability", "Requires Legal Review"),
                    actor_role=art.get("actor_role", "Deployer"),
                    applicability_rationale=f"System evaluated for {art['title']}. Statutory risk tier and applicability depend on intended purpose and actor classification.",
                    mitigation_and_owner=mitigation,
                    target_date="2026-11-30",
                    retest_status=retest_status,
                    review_status=review_status,
                    reviewed_by=None,
                    review_date=None,
                    residual_risk_acceptance=None,
                )
            )

        return matrix

    def _highest_severity(self, sevs: List[Severity]) -> Severity:
        for s in [Severity.CRITICAL, Severity.HIGH, Severity.MODERATE, Severity.LOW]:
            if s in sevs:
                return s
        return Severity.LOW

    def _recommend_mitigation(self, result: RedTeamResult) -> str:
        cat = str(result.category.value if hasattr(result.category, "value") else result.category)
        if "jailbreak" in cat:
            return "Implement strict system prompt instruction fencing and deploy upstream prompt classification filter. Owner: AppSec & ML Engineering."
        elif "leakage" in cat:
            return "Sanitize retrieval pipeline (RAG), isolate configuration tokens from LLM system prompt context, and deploy output leakage regex filters. Owner: Platform Engineering."
        elif "disclosure" in cat:
            return "Deploy Two-Sided PII Guardrails (Input Pre-processing + Output Post-processing) and enforce strict RBAC on internal knowledge retrieval. Owner: Privacy Engineering."
        elif "toxic" in cat:
            return "Enable LLM moderation safety guardrails and align system prompt refusal policies against abusive/derogatory topics. Owner: AI Safety Lead."
        elif "dangerous" in cat:
            return "Enforce strict domain boundary refusals, mandatory legal/medical disclaimer disclaimers, and automated 911 redirection. Owner: Legal & Trust & Safety."
        return "Implement targeted input/output filters and conduct regression re-test. Owner: Safety Team."
