"""Command-Line Interface for the AI Safety & Compliance Readiness Pipeline."""

import sys
import argparse
from pathlib import Path
from typing import Optional

from safety_pipeline.core.config import DATA_DIR, ARTIFACTS_DIR, PROJECT_ROOT, PipelineConfig
from safety_pipeline.core.models import SystemMetadata, TargetType
from safety_pipeline.core.target_app import TargetAssistant
from safety_pipeline.workstream_a_redteam.test_suite import AdversarialTestSuiteRunner
from safety_pipeline.workstream_a_redteam.promptfoo_exporter import PromptfooExporter
from safety_pipeline.workstream_b_guardrail.guardrail_service import PIIGuardrailService
from safety_pipeline.workstream_b_guardrail.benchmark import PIIBenchmarkRunner
from safety_pipeline.workstream_c_compliance.audit_matrix import AuditMatrixBuilder
from safety_pipeline.workstream_c_compliance.retest_differ import RetestDiffer
from safety_pipeline.workstream_c_compliance.report_generator import ReportGenerator


def run_all(
    mode: str = "simulated",
    target_url: Optional[str] = None,
    model_name: Optional[str] = None,
    api_key: Optional[str] = None,
):
    print("=" * 70)
    print("AI Safety & Compliance Readiness Pipeline — End-to-End Assessment")
    print("=" * 70)

    is_external = (mode == "external")
    target_type = TargetType.EXTERNAL_API.value if is_external else TargetType.SIMULATED.value
    resolved_model = model_name or ("external-model" if is_external else "simulator-baseline-fixture")
    
    metadata = SystemMetadata(
        name=f"Assessment Target ({resolved_model})",
        version="v1.0.0-evaluated",
        target_type=target_type,
        model_name=resolved_model,
        endpoint_url=target_url if is_external else None,
        environment="Live External Endpoint" if is_external else "Simulated Unit Sandbox"
    )

    print(f"Target Type: {target_type.upper()}")
    print(f"Target Model: {resolved_model}")
    if is_external:
        print(f"Target Endpoint: {target_url}")

    guardrail = PIIGuardrailService()
    probes_file = DATA_DIR / "red_team_probes.json"
    benchmark_file = DATA_DIR / "synthetic_pii_benchmark.json"

    # Step 1: Baseline Red-Teaming
    print("\n[Step 1/6] Running Workstream A: Baseline Adversarial Red-Teaming...")
    target_vuln = TargetAssistant(
        mode="external" if is_external else "vulnerable",
        external_url=target_url,
        external_api_key=api_key,
        model_name=resolved_model
    )
    runner_vuln = AdversarialTestSuiteRunner(probes_file, target_assistant=target_vuln)
    baseline_results = runner_vuln.run_suite(confirm_reproducibility=True)

    passed_base = sum(1 for r in baseline_results if r.passed)
    failed_base = len(baseline_results) - passed_base
    print(f" -> Completed {len(baseline_results)} probes: {passed_base} Passed, {failed_base} Failed.")

    # Step 2: Promptfoo Configuration Export
    print("\n[Step 2/6] Exporting Promptfoo YAML Configuration (promptfoo.yaml)...")
    exporter = PromptfooExporter(probes_file)
    pf_target_url = target_url or "http://localhost:8000/v1/chat/completions"
    pf_path = exporter.export_config(PROJECT_ROOT / "promptfoo.yaml", target_url=pf_target_url)
    print(f" -> Promptfoo configuration exported to: {pf_path} (target: {pf_target_url})")

    # Step 3: PII Guardrail Synthetic Evaluation
    print("\n[Step 3/6] Running Workstream B: PII & Data Guardrail Evaluation...")
    pii_runner = PIIBenchmarkRunner(benchmark_file)
    pii_report = pii_runner.run_benchmark()
    print(f" -> Evaluated {pii_report.total_test_cases} test cases across {len(pii_report.per_entity_metrics)} entity types.")
    print(f" -> Macro Precision: {pii_report.macro_precision:.2f} | Recall: {pii_report.macro_recall:.2f} | F1: {pii_report.macro_f1:.2f}")
    print(f" -> Average Redaction Latency: {pii_report.avg_latency_ms:.2f} ms")

    # Step 4: Remediation & Retest
    print("\n[Step 4/6] Running Remediation Retest (Hardened Fences + Two-Sided Guardrails)...")
    target_hard = TargetAssistant(
        mode="external" if is_external else "hardened",
        external_url=target_url,
        external_api_key=api_key,
        model_name=resolved_model
    )
    runner_hard = AdversarialTestSuiteRunner(probes_file, target_assistant=target_hard)
    retest_results = runner_hard.run_suite(guardrail_service=guardrail, confirm_reproducibility=True)

    retest_delta = RetestDiffer.compute_delta(baseline_results, retest_results)
    print(f" -> Retest Results: {retest_delta.retest_passed}/{retest_delta.total_tests} probes Passed ({retest_delta.retest_failed} Failed)")
    print(f" -> Resolved Vulnerabilities: {len(retest_delta.fixed_vulnerabilities)}")

    # Step 5: Compliance Audit Matrix Mapping
    print("\n[Step 5/6] Building Compliance Audit Matrix (NIST AI RMF & EU AI Act)...")
    matrix_builder = AuditMatrixBuilder(metadata)
    audit_matrix = matrix_builder.build_matrix(baseline_results=baseline_results, retest_results=retest_results)
    print(f" -> Generated {len(audit_matrix)} framework-mapped control entries.")

    # Step 6: Multi-Format Report Generation
    print("\n[Step 6/6] Generating Compliance Readiness Reports...")
    reporter = ReportGenerator(ARTIFACTS_DIR, metadata)
    report_paths = reporter.generate_all_reports(
        red_team_results=baseline_results,
        pii_report=pii_report,
        audit_matrix=audit_matrix,
        remediation_delta=retest_delta
    )

    print("\n" + "=" * 70)
    print("ASSESSMENT COMPLETE — Artifacts Generated:")
    print("=" * 70)
    for name, path in report_paths.items():
        print(f" • {name.upper()}: {path}")
    print("=" * 70)


def run_adversarial(
    mode: str = "vulnerable",
    guardrails: bool = False,
    target_url: Optional[str] = None,
    model_name: Optional[str] = None,
    api_key: Optional[str] = None,
):
    print(f"Running Adversarial Suite [Mode: {mode}, Guardrails: {guardrails}]...")
    probes_file = DATA_DIR / "red_team_probes.json"
    target = TargetAssistant(
        mode=mode,
        external_url=target_url,
        external_api_key=api_key,
        model_name=model_name
    )
    runner = AdversarialTestSuiteRunner(probes_file, target_assistant=target)
    g_service = PIIGuardrailService() if guardrails else None
    results = runner.run_suite(guardrail_service=g_service)

    passed = sum(1 for r in results if r.passed)
    print(f"\nResults: {passed}/{len(results)} Passed ({len(results) - passed} Failed)")
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"[{status}] [{r.severity.value}] {r.probe_id}: {r.probe_name} - {r.failure_reason or 'Safe'}")


def eval_pii():
    print("Evaluating Two-Sided PII Guardrails against Synthetic Benchmark...")
    benchmark_file = DATA_DIR / "synthetic_pii_benchmark.json"
    runner = PIIBenchmarkRunner(benchmark_file)
    rep = runner.run_benchmark()
    print(f"\nTotal Cases: {rep.total_test_cases} | Avg Latency: {rep.avg_latency_ms:.2f} ms (Backend: {rep.backend_used})")
    print(f"Macro Precision: {rep.macro_precision:.4f} | Recall: {rep.macro_recall:.4f} | F1: {rep.macro_f1:.4f}\n")
    print(f"{'Entity Type':<16} {'TP':<4} {'FP':<4} {'FN':<4} {'Precision':<10} {'Recall':<10} {'F1':<10}")
    print("-" * 62)
    for etype, m in rep.per_entity_metrics.items():
        print(f"{m.entity_type:<16} {m.true_positives:<4} {m.false_positives:<4} {m.false_negatives:<4} {m.precision:<10.2f} {m.recall:<10.2f} {m.f1_score:<10.2f}")


def serve_dashboard(host: str = "127.0.0.1", port: int = 8000):
    import uvicorn
    print(f"Starting Safety Pipeline Web Server at http://{host}:{port} ...")
    uvicorn.run("safety_pipeline.web.app:app", host=host, port=port, reload=False)


def main():
    parser = argparse.ArgumentParser(description="AI Safety & Compliance Readiness Assessment Pipeline")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    run_all_parser = subparsers.add_parser("run-all", help="Execute complete end-to-end safety & compliance assessment")
    run_all_parser.add_argument("--mode", default="simulated", choices=["simulated", "external"], help="Target mode: simulated fixture or external model")
    run_all_parser.add_argument("--url", default=None, help="Target API URL when mode=external (e.g. http://localhost:11434/v1/chat/completions)")
    run_all_parser.add_argument("--model", default=None, help="Model name identifier (e.g. llama3, mistral)")
    run_all_parser.add_argument("--api-key", default=None, help="Optional API key for external provider")

    adv_parser = subparsers.add_parser("run-adversarial", help="Run red-teaming test probes")
    adv_parser.add_argument("--mode", default="vulnerable", choices=["vulnerable", "hardened", "external"], help="Target assistant mode")
    adv_parser.add_argument("--guardrails", action="store_true", help="Enable PII input/output guardrails")
    adv_parser.add_argument("--url", default=None, help="Target API URL when mode=external")
    adv_parser.add_argument("--model", default=None, help="Model identifier")
    adv_parser.add_argument("--api-key", default=None, help="Optional API key")

    subparsers.add_parser("eval-pii", help="Run synthetic PII guardrail benchmark")

    retest_parser = subparsers.add_parser("retest", help="Execute comparative baseline vs remediated retest")
    retest_parser.add_argument("--mode", default="simulated", choices=["simulated", "external"], help="Target mode")
    retest_parser.add_argument("--url", default=None, help="Target API URL")
    retest_parser.add_argument("--model", default=None, help="Model name")
    retest_parser.add_argument("--api-key", default=None, help="Optional API key")

    serve_parser = subparsers.add_parser("serve", help="Launch interactive Web Dashboard")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host IP")
    serve_parser.add_argument("--port", default=8000, type=int, help="Port number")

    args = parser.parse_args()

    if args.command == "run-all" or args.command is None:
        run_all(
            mode=getattr(args, "mode", "simulated"),
            target_url=getattr(args, "url", None),
            model_name=getattr(args, "model", None),
            api_key=getattr(args, "api_key", None),
        )
    elif args.command == "run-adversarial":
        run_adversarial(
            mode=args.mode,
            guardrails=args.guardrails,
            target_url=args.url,
            model_name=args.model,
            api_key=args.api_key,
        )
    elif args.command == "eval-pii":
        eval_pii()
    elif args.command == "retest":
        run_all(
            mode=getattr(args, "mode", "simulated"),
            target_url=getattr(args, "url", None),
            model_name=getattr(args, "model", None),
            api_key=getattr(args, "api_key", None),
        )
    elif args.command == "serve":
        serve_dashboard(args.host, args.port)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
