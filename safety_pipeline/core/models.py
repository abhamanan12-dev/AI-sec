"""Core data schemas for the AI Safety & Compliance Readiness Pipeline."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"
    CRITICAL = "Critical"


class RetestStatus(str, Enum):
    NOT_STARTED = "Not Started"
    IN_PROGRESS = "In Progress"
    PASSED = "Passed"
    FAILED = "Failed"
    RESIDUAL_RISK_ACCEPTED = "Residual Risk Accepted"


class ReviewStatus(str, Enum):
    PENDING_TECHNICAL_REVIEW = "Pending Technical Review"
    TECHNICAL_REVIEW_COMPLETE = "Technical Review Complete"
    PRIVACY_REVIEW_REQUIRED = "Privacy Review Required"
    LEGAL_REVIEW_REQUIRED = "Legal Review Required"
    APPROVED = "Approved"


class RedTeamCategory(str, Enum):
    JAILBREAK = "jailbreak_instruction_override"
    SYSTEM_LEAKAGE = "system_prompt_context_leakage"
    SENSITIVE_DISCLOSURE = "sensitive_data_disclosure"
    TOXIC_OUTPUT = "toxic_abusive_output"
    DANGEROUS_ADVICE = "dangerous_high_impact_advice"


class TargetType(str, Enum):
    SIMULATED = "simulated"
    EXTERNAL_API = "external_api"


class RedTeamProbe(BaseModel):
    id: str
    category: RedTeamCategory
    name: str
    severity: Severity
    prompt: str
    intent: str
    expected_behavior: str
    forbidden_patterns: List[str] = Field(default_factory=list)
    required_patterns: List[str] = Field(default_factory=list)


class RedTeamResult(BaseModel):
    probe_id: str
    probe_name: str
    category: RedTeamCategory
    severity: Severity
    prompt: str
    model_response: str
    passed: bool
    failure_reason: Optional[str] = None
    expected_behavior: str
    reproducible: bool = False
    reproduction_steps: Optional[str] = None
    evidence: Optional[str] = None
    remediation_suggestion: Optional[str] = None
    latency_ms: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PIIEntity(BaseModel):
    entity_type: str
    value: str
    start: int
    end: int
    confidence: float = 1.0
    locale: Optional[str] = "Global"


class RedactionResult(BaseModel):
    direction: str  # "input" or "output"
    original_text: str
    redacted_text: str
    entities_detected: List[PIIEntity] = Field(default_factory=list)
    processing_time_ms: float = 0.0
    preserved_placeholders: Dict[str, str] = Field(default_factory=dict)


class EntityMetric(BaseModel):
    entity_type: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0


class PIIBenchmarkReport(BaseModel):
    total_test_cases: int
    total_expected_entities: int
    total_detected_entities: int
    macro_precision: float
    macro_recall: float
    macro_f1: float
    avg_latency_ms: float
    per_entity_metrics: Dict[str, EntityMetric]
    locale_coverage: List[str]
    operational_limitations: List[str]
    backend_used: str = "native_high_accuracy_recognizers"
    known_error_cases: List[Dict[str, Any]] = Field(default_factory=list)


class AuditMatrixEntry(BaseModel):
    control_id: str
    framework: str  # "NIST AI RMF" or "EU AI Act"
    function_or_article: str  # e.g., "MEASURE 2.7" or "Article 15 (Cybersecurity & Robustness)"
    control_name: str
    test_evidence_ids: List[str]
    baseline_finding: str
    retest_finding: str
    severity: Severity
    applicability_status: str = "Potentially Applies (Pending Legal Review)"
    actor_role: str = "Deployer"
    applicability_rationale: str
    mitigation_and_owner: str
    target_date: str
    retest_status: RetestStatus
    review_status: ReviewStatus
    reviewed_by: Optional[str] = None
    review_date: Optional[str] = None
    residual_risk_acceptance: Optional[str] = None


class SystemMetadata(BaseModel):
    name: str = "FinCorp Enterprise AI Assistant (Sandbox Simulator)"
    version: str = "v1.2.0-simulated-fixtures"
    target_type: str = "simulated"  # "simulated" or "external_api"
    model_name: str = "simulator-baseline-fixture"
    endpoint_url: Optional[str] = None
    environment: str = "Authorized Safety Sandbox"
    run_id: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("RUN-%Y%m%d-%H%M%S"))
    test_date: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    operator: str = "AI Safety & Compliance Intern"


class RemediationDelta(BaseModel):
    baseline_run_id: str
    retest_run_id: str
    total_tests: int
    baseline_passed: int
    baseline_failed: int
    retest_passed: int
    retest_failed: int
    fixed_vulnerabilities: List[str]
    unresolved_vulnerabilities: List[str]
    new_regressions: List[str]


class ComplianceReport(BaseModel):
    report_id: str
    metadata: SystemMetadata
    executive_summary: str
    adversarial_summary: Dict[str, Any]
    adversarial_findings: List[RedTeamResult]
    pii_guardrail_summary: Dict[str, Any]
    pii_benchmark: PIIBenchmarkReport
    audit_matrix: List[AuditMatrixEntry]
    remediation_plan: List[Dict[str, Any]]
    residual_risks: List[Dict[str, Any]]
    limitations: List[str]
    legal_disclaimer: str
