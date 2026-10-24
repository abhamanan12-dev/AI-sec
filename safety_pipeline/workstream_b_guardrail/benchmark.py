"""Synthetic PII Guardrail Benchmark Runner & Evaluation Suite.

Evaluates:
- Precision, Recall, and F1 Score (Macro & Per-Entity)
- False Positives (over-redaction on normal text)
- False Negatives (missed sensitive entities)
- Processing latency per transaction
- Documentation of locale coverage and operational limitations
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Any
from safety_pipeline.core.models import (
    EntityMetric,
    PIIBenchmarkReport,
    PIIEntity,
)
from safety_pipeline.workstream_b_guardrail.guardrail_service import PIIGuardrailService


class PIIBenchmarkRunner:
    def __init__(self, benchmark_data_path: Path):
        self.benchmark_data_path = benchmark_data_path
        self.guardrail = PIIGuardrailService()

    def run_benchmark(self) -> PIIBenchmarkReport:
        with open(self.benchmark_data_path, "r", encoding="utf-8") as f:
            test_cases = json.load(f)

        per_entity: Dict[str, Dict[str, int]] = {}
        total_expected = 0
        total_detected = 0
        latencies = []
        known_errors: List[Dict[str, Any]] = []

        for case in test_cases:
            text = case["text"]
            expected = case.get("expected_entities", [])
            direction = case.get("type", "input")

            start_t = time.perf_counter()
            if direction == "output":
                res = self.guardrail.process_output(text)
            else:
                res = self.guardrail.process_input(text)
            latencies.append(res.processing_time_ms)

            detected = res.entities_detected
            total_expected += len(expected)
            total_detected += len(detected)

            # Match detected with expected
            matched_detected = set()
            for exp in expected:
                exp_type = exp["entity_type"]
                exp_val = exp["value"]

                if exp_type not in per_entity:
                    per_entity[exp_type] = {"tp": 0, "fp": 0, "fn": 0}

                found = False
                for d_idx, d in enumerate(detected):
                    if d_idx in matched_detected:
                        continue
                    if d.entity_type == exp_type and (exp_val in d.value or d.value in exp_val):
                        per_entity[exp_type]["tp"] += 1
                        matched_detected.add(d_idx)
                        found = True
                        break

                if not found:
                    per_entity[exp_type]["fn"] += 1
                    known_errors.append({
                        "case_id": case["id"],
                        "error_type": "FALSE_NEGATIVE",
                        "entity_type": exp_type,
                        "expected_value": exp_val,
                        "text": text
                    })

            for d_idx, d in enumerate(detected):
                if d_idx not in matched_detected:
                    if d.entity_type not in per_entity:
                        per_entity[d.entity_type] = {"tp": 0, "fp": 0, "fn": 0}
                    per_entity[d.entity_type]["fp"] += 1
                    known_errors.append({
                        "case_id": case["id"],
                        "error_type": "FALSE_POSITIVE",
                        "entity_type": d.entity_type,
                        "detected_value": d.value,
                        "text": text
                    })

        metrics: Dict[str, EntityMetric] = {}
        sum_prec = 0.0
        sum_rec = 0.0
        sum_f1 = 0.0
        count_entities = len(per_entity) if per_entity else 1

        for etype, counts in per_entity.items():
            tp = counts["tp"]
            fp = counts["fp"]
            fn = counts["fn"]
            prec = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fn == 0 else 0.0)
            rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

            metrics[etype] = EntityMetric(
                entity_type=etype,
                true_positives=tp,
                false_positives=fp,
                false_negatives=fn,
                precision=round(prec, 4),
                recall=round(rec, 4),
                f1_score=round(f1, 4),
            )
            sum_prec += prec
            sum_rec += rec
            sum_f1 += f1

        macro_p = sum_prec / count_entities
        macro_r = sum_rec / count_entities
        macro_f1 = (2 * macro_p * macro_r) / (macro_p + macro_r) if (macro_p + macro_r) > 0 else 0.0
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

        backend_name = "Microsoft Presidio (AnalyzerEngine + spaCy)" if self.guardrail.adapter.use_presidio else "Native High-Accuracy Multi-Locale Recognizers (Presidio optional)"

        return PIIBenchmarkReport(
            total_test_cases=len(test_cases),
            total_expected_entities=total_expected,
            total_detected_entities=total_detected,
            macro_precision=round(macro_p, 4),
            macro_recall=round(macro_r, 4),
            macro_f1=round(macro_f1, 4),
            avg_latency_ms=round(avg_latency, 3),
            per_entity_metrics=metrics,
            backend_used=backend_name,
            locale_coverage=[
                "US (United States: SSN, Phone, Email, CC)",
                "UK (United Kingdom: NINO, Phone, Email, CC)",
                "IN (India: PAN, Aadhaar UID, 10-digit Mobile)",
                "Global (Email, Credit Card with Luhn validation, IPv4, API Keys)",
            ],
            operational_limitations=[
                "Regex-based person name detection relies on honorific titles (e.g. Dr., Mr., Prof.); standalone lowercase names require deep NER models like spaCy en_core_web_trf.",
                "Credit card detection enforces Luhn checksums; test dummy cards with invalid checksums are intentionally discarded.",
                "Redaction does not replace downstream encryption, least-privilege RBAC, or retention policies.",
                "Aadhaar numbers require 12 digits starting with 2-9; unformatted continuous strings with spaces can cause boundary shifts in non-segmented text.",
            ],
            known_error_cases=known_errors,
        )
