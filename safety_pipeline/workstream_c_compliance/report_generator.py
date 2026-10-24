"""Multi-Format Compliance Readiness Report Generator.

Generates:
1. Executive Interactive HTML Dashboard
2. Markdown Compliance Readiness Audit Report (including dedicated Findings Log)
3. Dedicated standalone Findings Log (Markdown & JSON)
4. Tabular CSV exports
"""

import csv
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from safety_pipeline.core.models import (
    AuditMatrixEntry,
    ComplianceReport,
    PIIBenchmarkReport,
    RedTeamResult,
    RemediationDelta,
    Severity,
    SystemMetadata,
)


class ReportGenerator:
    def __init__(self, output_dir: Path, metadata: Optional[SystemMetadata] = None):
        self.output_dir = output_dir
        self.metadata = metadata or SystemMetadata()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_all_reports(
        self,
        red_team_results: List[RedTeamResult],
        pii_report: PIIBenchmarkReport,
        audit_matrix: List[AuditMatrixEntry],
        remediation_delta: Optional[RemediationDelta] = None,
        report_id: str = "COMPLIANCE-REPORT-2026-Q4"
    ) -> Dict[str, Path]:
        """Generates HTML, Markdown, JSON, and CSV reports and returns their paths."""
        paths = {}
        paths["markdown"] = self.generate_markdown_report(red_team_results, pii_report, audit_matrix, remediation_delta, report_id)
        paths["findings_log_md"] = self.generate_findings_log_markdown(red_team_results)
        paths["html"] = self.generate_html_report(red_team_results, pii_report, audit_matrix, remediation_delta, report_id)
        paths["json_matrix"] = self.generate_json_matrix(audit_matrix)
        paths["json_findings"] = self.generate_json_findings(red_team_results)
        paths["csv_matrix"] = self.generate_csv_matrix(audit_matrix)
        paths["csv_findings"] = self.generate_csv_findings(red_team_results)
        return paths

    def generate_json_matrix(self, audit_matrix: List[AuditMatrixEntry]) -> Path:
        out_path = self.output_dir / "audit_matrix.json"
        data = [entry.model_dump() for entry in audit_matrix]
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return out_path

    def generate_json_findings(self, results: List[RedTeamResult]) -> Path:
        out_path = self.output_dir / "findings_log.json"
        data = [r.model_dump(mode="json") for r in results]
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return out_path

    def generate_findings_log_markdown(self, results: List[RedTeamResult]) -> Path:
        """Generates a dedicated, highly presentable Findings Log Markdown document."""
        out_path = self.output_dir / "findings_log.md"
        failures = [r for r in results if not r.passed]
        passes = [r for r in results if r.passed]

        lines = [
            "# Adversarial Red-Team Findings Log",
            f"**Target System**: `{self.metadata.name}` | **Target Type**: `{self.metadata.target_type.upper()}` | **Date**: `{self.metadata.test_date}`",
            f"**Total Probes Evaluated**: {len(results)} | **Failures**: {len(failures)} | **Passes**: {len(passes)}",
            "",
            "> [!NOTE]",
            "> This log records each adversarial security failure with its **Severity**, **Reproduction Steps**, **Empirical Evidence**, and **Recommended Remediation**.",
            "",
            "---",
            "",
            "## Summary Table of Discovered Vulnerabilities",
            "| Probe ID | Category | Severity | Name | Reproducible | Failure Reason |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for r in failures:
            lines.append(f"| `{r.probe_id}` | {r.category.value} | **{r.severity.value}** | {r.probe_name} | {'Yes' if r.reproducible else 'No'} | {r.failure_reason} |")

        lines.extend([
            "",
            "---",
            "",
            "## Detailed Failure Records (Evidence & Remediation)",
            ""
        ])

        if not failures:
            lines.append("🎉 *Zero failures detected in this test run.*")
        else:
            for idx, f in enumerate(failures, 1):
                sev_icon = "🔴" if f.severity == Severity.CRITICAL else ("🟠" if f.severity == Severity.HIGH else "🟡")
                repro_badge = "✅ Confirmed Reproducible" if f.reproducible else "⚠️ Single Trial"
                
                lines.extend([
                    f"### {idx}. [{f.probe_id}] {f.probe_name}",
                    f"- **Severity**: {sev_icon} **{f.severity.value}**",
                    f"- **Category**: `{f.category.value}`",
                    f"- **Reproducibility**: {repro_badge}",
                    f"- **Expected Safe Behavior**: {f.expected_behavior}",
                    f"- **Assertion Violation**: {f.failure_reason}",
                    "",
                    "#### 🔁 Reproduction Steps",
                    "```text",
                    f.reproduction_steps or f"1. Send prompt to target: {f.prompt}\n2. Observe model response for forbidden indicators.",
                    "```",
                    "",
                    "#### 🔍 Empirical Evidence",
                    "**Adversarial Prompt Sent:**",
                    "```text",
                    f.prompt,
                    "```",
                    "**Actual Model Output Observed:**",
                    "```text",
                    f.model_response,
                    "```",
                    "",
                    "#### 🛡️ Recommended Remediation",
                    f"> {f.remediation_suggestion or 'Deploy targeted prompt fencing and input/output guardrails.'}",
                    "",
                    "---",
                    ""
                ])

        with open(out_path, "w", encoding="utf-8") as file:
            file.write("\n".join(lines))

        return out_path

    def generate_csv_matrix(self, audit_matrix: List[AuditMatrixEntry]) -> Path:
        out_path = self.output_dir / "compliance_matrix.csv"
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Control ID", "Framework", "Function/Article", "Control Name",
                "Evidence IDs", "Baseline Finding", "Retest Finding", "Severity",
                "Applicability Status", "Actor Role", "Applicability Rationale",
                "Mitigation & Owner", "Target Date", "Retest Status", "Review Status"
            ])
            for e in audit_matrix:
                writer.writerow([
                    e.control_id, e.framework, e.function_or_article, e.control_name,
                    "; ".join(e.test_evidence_ids), e.baseline_finding, e.retest_finding,
                    e.severity.value, e.applicability_status, e.actor_role,
                    e.applicability_rationale, e.mitigation_and_owner, e.target_date,
                    e.retest_status.value, e.review_status.value
                ])
        return out_path

    def generate_csv_findings(self, results: List[RedTeamResult]) -> Path:
        out_path = self.output_dir / "findings.csv"
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Probe ID", "Probe Name", "Category", "Severity", "Passed",
                "Failure Reason", "Reproducible", "Reproduction Steps", "Evidence",
                "Remediation Suggestion", "Prompt", "Model Response", "Latency (ms)"
            ])
            for r in results:
                writer.writerow([
                    r.probe_id, r.probe_name, r.category.value, r.severity.value,
                    "PASSED" if r.passed else "FAILED", r.failure_reason or "N/A",
                    str(r.reproducible),
                    (r.reproduction_steps or "N/A").replace("\n", " "),
                    (r.evidence or "N/A").replace("\n", " "),
                    (r.remediation_suggestion or "N/A").replace("\n", " "),
                    r.prompt.replace("\n", " "), r.model_response.replace("\n", " "),
                    r.latency_ms
                ])
        return out_path

    def generate_markdown_report(
        self,
        red_team_results: List[RedTeamResult],
        pii_report: PIIBenchmarkReport,
        audit_matrix: List[AuditMatrixEntry],
        remediation_delta: Optional[RemediationDelta] = None,
        report_id: str = "COMPLIANCE-REPORT-2026-Q4"
    ) -> Path:
        out_path = self.output_dir / "compliance_readiness_report.md"

        total_probes = len(red_team_results)
        passed_probes = sum(1 for r in red_team_results if r.passed)
        failed_probes = total_probes - passed_probes
        pass_rate = (passed_probes / total_probes * 100.0) if total_probes > 0 else 0.0

        content = []
        content.append(f"# AI Safety & Compliance Readiness Report")
        content.append(f"**Report ID**: `{report_id}` | **Run ID**: `{self.metadata.run_id}` | **Assessment Date**: `{self.metadata.test_date}` | **Operator**: `{self.metadata.operator}`\n")
        content.append("> [!IMPORTANT]")
        content.append("> **Legal & Governance Boundary Notice**: This report provides technical risk assessment evidence and compliance readiness tracking. Automated tests and metrics do NOT constitute a legal certification of compliance with the EU AI Act, NIST AI RMF, GDPR, or other statutory regulations. Deployment authorization requires context-specific review by designated legal, privacy, security, and product executives.\n")

        # 1. Executive Summary
        content.append("## 1. Executive Summary & Assessment Scope")
        content.append(f"This assessment evaluated the safety, privacy resilience, and regulatory readiness of **{self.metadata.name}** ({self.metadata.version}).")
        content.append(f"- **Target Type**: `{self.metadata.target_type}`")
        content.append(f"- **Model Identifier / Endpoint**: `{self.metadata.model_name}` ({self.metadata.endpoint_url or 'Internal Simulator Fixture'})")
        content.append(f"- **Adversarial Security Probes**: {total_probes} executed across 5 core risk categories.")
        content.append(f"- **Baseline Pass Rate**: **{pass_rate:.1f}%** ({passed_probes} passed, {failed_probes} failed).")
        content.append(f"- **PII Guardrail Performance**: Macro F1 Score of **{pii_report.macro_f1:.2f}** (Backend: `{pii_report.backend_used}`) with average end-to-end latency of **{pii_report.avg_latency_ms:.2f} ms**.")
        content.append(f"- **Frameworks Mapped**: NIST AI RMF 1.0 (Govern, Map, Measure, Manage) and EU AI Act (Articles 5, 9, 10, 13, 14, 15, 50, 53).\n")

        # 2. System Description
        content.append("## 2. System Description & Intended Operational Context")
        content.append(f"- **Target Application**: {self.metadata.name}")
        content.append(f"- **Target Model / Engine**: {self.metadata.model_name}")
        content.append(f"- **Target Architecture**: {self.metadata.target_type.upper()} ({'Deterministic Unit-Test Fixture' if self.metadata.target_type == 'simulated' else 'Live Model API'})")
        content.append(f"- **Environment**: {self.metadata.environment}")
        content.append(f"- **Intended Purpose**: Internal employee enterprise assistant supporting account management, general customer support inquiries, and workplace productivity.")
        content.append(f"- **Deployment Boundary**: Authorized internal testing environment using synthetic datasets. Production deployment gated on remediation of High and Critical severity findings.\n")

        # 3. Methodology & Test Coverage
        content.append("## 3. Methodology, Test Coverage & Known Limitations")
        content.append("The testing methodology combines three integrated pillars:")
        content.append("1. **Adversarial Red-Teaming**: Targeted probes executing jailbreak attacks, prompt extraction, sensitive data queries, toxicity elicitation, and high-stakes advice requests.")
        content.append("2. **Two-Sided PII Guardrails**: Pre-processing user prompts to replace PII with typed placeholders, followed by post-processing model responses to redact sensitive data.")
        content.append("3. **Compliance Matrix Mapping**: Synthesizing empirical test results directly against NIST AI RMF subcategories and EU AI Act requirements.\n")
        content.append("### Known Limitations")
        for lim in pii_report.operational_limitations:
            content.append(f"- {lim}")
        content.append("- Automated test suites represent discrete snapshots in time; behavioral drift across upstream model releases requires continuous regression monitoring.\n")

        # 4. Adversarial Findings & Log
        content.append("## 4. Adversarial Red-Team Findings & Detailed Log")
        content.append("| Probe ID | Category | Severity | Name | Status | Reproducible | Failure Reason |")
        content.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for r in red_team_results:
            status_str = "✅ PASS" if r.passed else "❌ FAIL"
            reason = r.failure_reason or "Met expected safety behavior"
            repro_str = "Yes" if r.reproducible else "No / Single Trial"
            content.append(f"| `{r.probe_id}` | {r.category.value} | **{r.severity.value}** | {r.probe_name} | {status_str} | {repro_str} | {reason} |")
        content.append("")

        failures = [r for r in red_team_results if not r.passed]
        if failures:
            content.append("### Detailed Failure Log (Reproduction Steps, Evidence & Remediation)")
            for f in failures:
                content.append(f"#### [{f.probe_id}] {f.probe_name} ({f.severity.value})")
                content.append(f"- **Category**: `{f.category.value}`")
                content.append(f"- **Assertion Violation**: {f.failure_reason}")
                content.append(f"- **Reproduction Steps**:\n  ```text\n  {f.reproduction_steps}\n  ```")
                content.append(f"- **Empirical Evidence**:\n  - Prompt: `{f.prompt[:90]}...`\n  - Output: `{f.model_response[:100]}...`")
                content.append(f"- **Recommended Remediation**: {f.remediation_suggestion}\n")

        # 5. PII Guardrail Evaluation
        content.append("## 5. PII & Data Guardrail Evaluation")
        content.append(f"### Performance Summary ({pii_report.total_test_cases} Synthetic Test Cases)")
        content.append(f"- **Detection Engine**: `{pii_report.backend_used}`")
        content.append(f"- **Macro Precision**: `{pii_report.macro_precision:.4f}`")
        content.append(f"- **Macro Recall**: `{pii_report.macro_recall:.4f}`")
        content.append(f"- **Macro F1 Score**: `{pii_report.macro_f1:.4f}`")
        content.append(f"- **Average Redaction Latency**: `{pii_report.avg_latency_ms:.2f} ms`\n")

        content.append("### Per-Entity Detection Metrics")
        content.append("| Entity Type | True Positives | False Positives | False Negatives | Precision | Recall | F1 Score |")
        content.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for etype, m in pii_report.per_entity_metrics.items():
            content.append(f"| `{m.entity_type}` | {m.true_positives} | {m.false_positives} | {m.false_negatives} | {m.precision:.2f} | {m.recall:.2f} | {m.f1_score:.2f} |")
        content.append("")

        content.append("### Locale Coverage")
        for loc in pii_report.locale_coverage:
            content.append(f"- {loc}")
        content.append("")

        # 6. Compliance Audit Matrix
        content.append("## 6. Compliance Audit Matrix (NIST AI RMF & EU AI Act)")
        content.append("| Control ID | Framework | Function/Article | Control Name | Severity | Retest Status | Review Status | Baseline Finding | Retest Finding |")
        content.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for e in audit_matrix:
            content.append(f"| `{e.control_id}` | {e.framework} | {e.function_or_article} | {e.control_name} | **{e.severity.value}** | `{e.retest_status.value}` | `{e.review_status.value}` | {e.baseline_finding} | {e.retest_finding} |")
        content.append("")

        # 7. Remediation Plan & Retest Status
        content.append("## 7. Prioritized Remediation Plan & Ownership")
        if remediation_delta:
            content.append(f"### Retest Progression Summary")
            content.append(f"- **Baseline Run**: {remediation_delta.baseline_passed}/{remediation_delta.total_tests} passed ({remediation_delta.baseline_failed} failed)")
            content.append(f"- **Remediated Retest**: **{remediation_delta.retest_passed}/{remediation_delta.total_tests} passed** ({remediation_delta.retest_failed} failed)")
            content.append(f"- **Resolved Vulnerabilities**: {len(remediation_delta.fixed_vulnerabilities)}")
            for fix in remediation_delta.fixed_vulnerabilities:
                content.append(f"  - ✅ {fix}")
            if remediation_delta.unresolved_vulnerabilities:
                content.append(f"- **Persistent Vulnerabilities**:")
                for unres in remediation_delta.unresolved_vulnerabilities:
                    content.append(f"  - ⚠️ {unres}")
            content.append("")

        content.append("| Priority | Framework Control | Remediation Strategy | Assigned Owner | Target Date |")
        content.append("| :--- | :--- | :--- | :--- | :--- |")
        failed_entries = [e for e in audit_matrix if e.retest_status == "Failed"] or audit_matrix[:5]
        for idx, fe in enumerate(failed_entries, 1):
            content.append(f"| P{idx} ({fe.severity.value}) | {fe.function_or_article} | {fe.mitigation_and_owner} | AppSec / Legal | {fe.target_date} |")
        content.append("")

        # 8. Residual Risks & Human Approvals
        content.append("## 8. Residual Risks, Assumptions & Required Approvals")
        content.append("1. **Residual Risks**: Sub-surface jailbreaks via multi-language obfuscation or novel prompt perturbations remain a residual risk. Regular red-teaming rotations must be scheduled.")
        content.append("2. **Name Entity Recognition**: Standalone personal names without honorifics require spaCy/Transformer NER scaling prior to production high-volume ingestion.")
        content.append("3. **Required Approvals**: Sign-off from Lead Application Security Engineer, Privacy Officer, Product Director, and Corporate Legal Counsel prior to staging promotion.")

        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(content))

        return out_path

    def generate_html_report(
        self,
        red_team_results: List[RedTeamResult],
        pii_report: PIIBenchmarkReport,
        audit_matrix: List[AuditMatrixEntry],
        remediation_delta: Optional[RemediationDelta] = None,
        report_id: str = "COMPLIANCE-REPORT-2026-Q4"
    ) -> Path:
        out_path = self.output_dir / "compliance_dashboard.html"

        total_probes = len(red_team_results)
        passed_probes = sum(1 for r in red_team_results if r.passed)
        failed_probes = total_probes - passed_probes
        pass_rate = (passed_probes / total_probes * 100.0) if total_probes > 0 else 0.0

        crit_count = sum(1 for r in red_team_results if not r.passed and r.severity == Severity.CRITICAL)
        high_count = sum(1 for r in red_team_results if not r.passed and r.severity == Severity.HIGH)
        mod_count = sum(1 for r in red_team_results if not r.passed and r.severity == Severity.MODERATE)

        # Build Findings Rows
        findings_rows = []
        for r in red_team_results:
            badge_class = "badge-pass" if r.passed else "badge-fail"
            sev_class = f"badge-{r.severity.value.lower()}"
            escaped_prompt = r.prompt.replace("<", "&lt;").replace(">", "&gt;")
            escaped_resp = r.model_response.replace("<", "&lt;").replace(">", "&gt;")
            reason = r.failure_reason or "Behavior within safety boundaries"

            repro_steps_html = f"<p><strong>Reproduction Steps:</strong></p><pre><code>{r.reproduction_steps or '1. Send adversarial prompt to target endpoint.'}</code></pre>" if not r.passed else ""
            remediation_html = f"<p><strong>Recommended Remediation:</strong></p><div style='padding:8px;background:rgba(59,130,246,0.1);border-left:3px solid #3b82f6;'>{r.remediation_suggestion}</div>" if not r.passed else ""

            findings_rows.append(f"""
            <tr>
                <td><code>{r.probe_id}</code></td>
                <td><strong>{r.probe_name}</strong><br><small class="text-muted">{r.category.value}</small></td>
                <td><span class="badge {sev_class}">{r.severity.value}</span></td>
                <td><span class="badge {badge_class}">{"PASS" if r.passed else "FAIL"}</span></td>
                <td>{reason}</td>
                <td>
                    <button class="btn-toggle" onclick="toggleDetails('{r.probe_id}')">Inspect</button>
                </td>
            </tr>
            <tr id="details-{r.probe_id}" class="details-row" style="display:none;">
                <td colspan="6">
                    <div class="evidence-box">
                        <p><strong>Adversarial Input Prompt:</strong></p>
                        <pre><code>{escaped_prompt}</code></pre>
                        <p><strong>Observed Model Response:</strong></p>
                        <pre><code>{escaped_resp}</code></pre>
                        <p><strong>Expected Safe Behavior:</strong> {r.expected_behavior}</p>
                        <p><small>Latency: {r.latency_ms} ms | Reproducible: {'Yes' if r.reproducible else 'No'}</small></p>
                        {repro_steps_html}
                        {remediation_html}
                    </div>
                </td>
            </tr>
            """)

        # Build Matrix Rows
        matrix_rows = []
        for m in audit_matrix:
            retest_badge = "badge-pass" if m.retest_status.value == "Passed" else ("badge-fail" if m.retest_status.value == "Failed" else "badge-mod")
            matrix_rows.append(f"""
            <tr>
                <td><code>{m.control_id}</code></td>
                <td><span class="framework-tag">{m.framework}</span></td>
                <td><strong>{m.function_or_article}</strong><br><small>{m.control_name}</small></td>
                <td><span class="badge badge-{m.severity.value.lower()}">{m.severity.value}</span></td>
                <td><span class="badge {retest_badge}">{m.retest_status.value}</span></td>
                <td><small>{m.retest_finding}</small></td>
                <td><small class="evidence-link">Probes: {', '.join(m.test_evidence_ids[:3])}{'...' if len(m.test_evidence_ids) > 3 else ''}</small></td>
            </tr>
            """)

        # Build PII Entity Rows
        pii_rows = []
        for etype, metric in pii_report.per_entity_metrics.items():
            pii_rows.append(f"""
            <tr>
                <td><code>{metric.entity_type}</code></td>
                <td>{metric.true_positives}</td>
                <td>{metric.false_positives}</td>
                <td>{metric.false_negatives}</td>
                <td><strong>{(metric.precision * 100):.1f}%</strong></td>
                <td><strong>{(metric.recall * 100):.1f}%</strong></td>
                <td><span class="badge badge-pass">{(metric.f1_score * 100):.1f}%</span></td>
            </tr>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Safety & Compliance Readiness Dashboard</title>
    <style>
        :root {{
            --bg: #f8fafc;
            --surface: #ffffff;
            --text: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --danger: #dc2626;
            --warning: #d97706;
            --success: #16a34a;
            --info: #0284c7;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1300px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 24px;
            background: var(--surface);
            border-radius: 12px;
            border: 1px solid var(--border);
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .header-title h1 {{
            margin: 0 0 6px 0;
            font-size: 24px;
            color: #1e293b;
        }}
        .header-meta {{
            font-size: 13px;
            color: var(--text-muted);
        }}
        .disclaimer-banner {{
            background: #fffbeb;
            border-left: 4px solid var(--warning);
            padding: 14px 18px;
            margin-bottom: 24px;
            border-radius: 6px;
            font-size: 13px;
            line-height: 1.5;
            color: #92400e;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--surface);
            padding: 18px 20px;
            border-radius: 10px;
            border: 1px solid var(--border);
            box-shadow: 0 1px 2px rgba(0,0,0,0.03);
        }}
        .stat-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 8px;
        }}
        .stat-value {{
            font-size: 28px;
            font-weight: 700;
        }}
        .stat-sub {{
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 4px;
        }}
        .tabs {{
            display: flex;
            gap: 8px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
        }}
        .tab-btn {{
            padding: 10px 18px;
            border: none;
            background: none;
            font-size: 14px;
            font-weight: 600;
            color: var(--text-muted);
            cursor: pointer;
            border-bottom: 2px solid transparent;
        }}
        .tab-btn.active {{
            color: var(--primary);
            border-bottom-color: var(--primary);
        }}
        .tab-panel {{
            display: none;
        }}
        .tab-panel.active {{
            display: block;
        }}
        .card {{
            background: var(--surface);
            border-radius: 10px;
            border: 1px solid var(--border);
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }}
        .card-title {{
            font-size: 18px;
            margin: 0 0 16px 0;
            color: #1e293b;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th, td {{
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #f1f5f9;
            color: #475569;
            font-weight: 600;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-pass {{ background: #dcfce7; color: #15803d; }}
        .badge-fail {{ background: #fee2e2; color: #b91c1c; }}
        .badge-critical {{ background: #7f1d1d; color: #ffffff; }}
        .badge-high {{ background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }}
        .badge-moderate {{ background: #fffbeb; color: #b45309; }}
        .badge-low {{ background: #f0fdf4; color: #166534; }}
        .framework-tag {{
            background: #e0f2fe;
            color: #0369a1;
            padding: 3px 7px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }}
        .btn-toggle {{
            padding: 4px 10px;
            font-size: 12px;
            border: 1px solid var(--border);
            border-radius: 4px;
            background: #f8fafc;
            cursor: pointer;
        }}
        .btn-toggle:hover {{
            background: #e2e8f0;
        }}
        .evidence-box {{
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 14px;
            margin: 8px 0;
        }}
        .evidence-box pre {{
            background: #1e293b;
            color: #f8fafc;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 12px;
        }}
        .delta-box {{
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-title">
                <h1>AI Safety & Compliance Readiness Dashboard</h1>
                <div class="header-meta">
                    Target: <strong>{self.metadata.name}</strong> ({self.metadata.version}) | 
                    Type: <strong>{self.metadata.target_type.upper()}</strong> |
                    Model: <strong>{self.metadata.model_name}</strong> |
                    Run ID: <code>{self.metadata.run_id}</code> | 
                    Date: <strong>{self.metadata.test_date}</strong>
                </div>
            </div>
            <div>
                <button onclick="window.print()" class="btn-toggle" style="padding: 8px 16px; font-weight: 600;">🖨️ Print / Export PDF</button>
            </div>
        </div>

        <!-- Governance Boundary Alert -->
        <div class="disclaimer-banner">
            ⚠️ <strong>Legal & Governance Boundary Notice:</strong> This dashboard provides technical safety test telemetry and compliance readiness tracking. Automated evaluations do NOT establish statutory compliance with the EU AI Act or NIST AI RMF. Final deployment approval requires formal review by qualified legal, privacy, and security officers.
        </div>

        <!-- Metrics Overview -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Adversarial Safety Pass Rate</div>
                <div class="stat-value" style="color: {'#16a34a' if pass_rate >= 80 else '#dc2626'}">{pass_rate:.1f}%</div>
                <div class="stat-sub">{passed_probes} passed / {failed_probes} failed ({total_probes} total)</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Critical & High Vulnerabilities</div>
                <div class="stat-value" style="color: {'#dc2626' if (crit_count + high_count) > 0 else '#16a34a'}">{crit_count + high_count}</div>
                <div class="stat-sub">{crit_count} Critical | {high_count} High | {mod_count} Moderate</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">PII Guardrail Macro F1</div>
                <div class="stat-value" style="color: #2563eb;">{(pii_report.macro_f1 * 100):.1f}%</div>
                <div class="stat-sub">Precision: {(pii_report.macro_precision * 100):.1f}% | Recall: {(pii_report.macro_recall * 100):.1f}%</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Redaction Processing Speed</div>
                <div class="stat-value" style="color: #0284c7;">{pii_report.avg_latency_ms:.2f} <small style="font-size: 16px;">ms</small></div>
                <div class="stat-sub">Two-sided protection overhead</div>
            </div>
        </div>

        <!-- Navigation Tabs -->
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('tab-findings')">1. Red-Team Findings ({total_probes})</button>
            <button class="tab-btn" onclick="switchTab('tab-pii')">2. PII Guardrail Benchmark</button>
            <button class="tab-btn" onclick="switchTab('tab-matrix')">3. Compliance Audit Matrix ({len(audit_matrix)})</button>
            <button class="tab-btn" onclick="switchTab('tab-retest')">4. Remediation & Retest Delta</button>
        </div>

        <!-- TAB 1: Adversarial Red-Team Findings -->
        <div id="tab-findings" class="tab-panel active">
            <div class="card">
                <h2 class="card-title">Adversarial Probe Evidence & Failure Analysis</h2>
                <p class="text-muted" style="margin-bottom: 16px;">
                    Probing 5 core categories: Jailbreaks, System-Prompt Leakage, Sensitive Data Disclosure, Toxic Output, and Dangerous High-Impact Advice.
                </p>
                <table>
                    <thead>
                        <tr>
                            <th>Probe ID</th>
                            <th>Probe Name & Category</th>
                            <th>Severity</th>
                            <th>Status</th>
                            <th>Failure Reason / Observations</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(findings_rows)}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 2: PII Guardrail Evaluation -->
        <div id="tab-pii" class="tab-panel">
            <div class="card">
                <h2 class="card-title">Two-Sided PII Guardrail Performance Benchmark</h2>
                <p class="text-muted" style="margin-bottom: 16px;">
                    Evaluated against synthetic multi-locale test set (US, UK, IN, Global) covering phone numbers, emails, credit cards (with Luhn check), SSNs, PAN, and Aadhaar identifiers.
                </p>
                <table>
                    <thead>
                        <tr>
                            <th>Entity Type</th>
                            <th>True Positives</th>
                            <th>False Positives</th>
                            <th>False Negatives</th>
                            <th>Precision</th>
                            <th>Recall</th>
                            <th>F1 Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(pii_rows)}
                    </tbody>
                </table>
                <div style="margin-top: 24px;">
                    <h4>Supported Locales & Coverage</h4>
                    <ul>
                        {"".join(f"<li>{loc}</li>" for loc in pii_report.locale_coverage)}
                    </ul>
                    <h4>Operational Limitations & Cautions</h4>
                    <ul>
                        {"".join(f"<li>{lim}</li>" for lim in pii_report.operational_limitations)}
                    </ul>
                </div>
            </div>
        </div>

        <!-- TAB 3: Compliance Audit Matrix -->
        <div id="tab-matrix" class="tab-panel">
            <div class="card">
                <h2 class="card-title">Traceable Compliance Audit Matrix</h2>
                <p class="text-muted" style="margin-bottom: 16px;">
                    Mapping empirical test evidence directly to NIST AI Risk Management Framework 1.0 (Govern, Map, Measure, Manage) and preparatory EU AI Act obligations.
                </p>
                <table>
                    <thead>
                        <tr>
                            <th>Control ID</th>
                            <th>Framework</th>
                            <th>Function / Article</th>
                            <th>Severity</th>
                            <th>Retest Status</th>
                            <th>Retest Finding Summary</th>
                            <th>Test Evidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(matrix_rows)}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 4: Remediation & Retest Delta -->
        <div id="tab-retest" class="tab-panel">
            <div class="card">
                <h2 class="card-title">Remediation & Regression Retest Telemetry</h2>
                {"<div class='delta-box'>" +
                 "<h3>Remediation Progression Observed</h3>" +
                 f"<p><strong>Baseline Score:</strong> {remediation_delta.baseline_passed}/{remediation_delta.total_tests} passed &rarr; " +
                 f"<strong>Remediated Retest Score:</strong> <span style='color:#16a34a; font-weight:700;'>{remediation_delta.retest_passed}/{remediation_delta.total_tests} passed</span></p>" +
                 f"<p><strong>Vulnerabilities Fixed ({len(remediation_delta.fixed_vulnerabilities)}):</strong></p>" +
                 "<ul>" + "".join(f"<li>{v}</li>" for v in remediation_delta.fixed_vulnerabilities) + "</ul>" +
                 (f"<p><strong>Residual / Persistent Vulnerabilities ({len(remediation_delta.unresolved_vulnerabilities)}):</strong></p><ul>" + "".join(f"<li>{u}</li>" for u in remediation_delta.unresolved_vulnerabilities) + "</ul>" if remediation_delta.unresolved_vulnerabilities else "<p style='color:#16a34a;'>Zero persistent high-severity vulnerabilities in current suite.</p>") +
                 "</div>" if remediation_delta else "<p>No comparative retest run recorded yet. Execute <code>python -m safety_pipeline.cli retest</code> to generate differential telemetry.</p>"}
            </div>
        </div>

    </div>

    <script>
        function switchTab(tabId) {{
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        }}

        function toggleDetails(probeId) {{
            const row = document.getElementById('details-' + probeId);
            if (row.style.display === 'none') {{
                row.style.display = 'table-row';
            }} else {{
                row.style.display = 'none';
            }}
        }}
    </script>
</body>
</html>
"""
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return out_path
