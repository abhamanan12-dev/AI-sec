"""NIST AI Risk Management Framework (AI RMF 1.0) Mapping Catalog."""

from typing import Dict, Any

NIST_AI_RMF_CATALOG: Dict[str, Dict[str, Any]] = {
    "GOVERN-1.1": {
        "function": "GOVERN",
        "subcategory": "GOVERN 1.1",
        "name": "Legal and Regulatory Compliance Requirements",
        "description": "Legal and other regulatory requirements specified for AI system development and use are documented and monitored.",
        "related_categories": ["dangerous_high_impact_advice", "sensitive_data_disclosure"]
    },
    "GOVERN-1.2": {
        "function": "GOVERN",
        "subcategory": "GOVERN 1.2",
        "name": "Roles, Responsibilities, and Ownership",
        "description": "Roles and responsibilities for AI system risk management are clearly defined, assigned, and documented.",
        "related_categories": ["jailbreak_instruction_override", "dangerous_high_impact_advice"]
    },
    "MAP-1.1": {
        "function": "MAP",
        "subcategory": "MAP 1.1",
        "name": "Intended Purpose & Operational Context",
        "description": "Context is established and understood; intended purposes, capabilities, and system limitations are documented.",
        "related_categories": ["dangerous_high_impact_advice"]
    },
    "MAP-2.1": {
        "function": "MAP",
        "subcategory": "MAP 2.1",
        "name": "Anticipated Threats, Vulnerabilities, and Misuse",
        "description": "Potential AI system failures, threats, and adversarial attacks (jailbreaks, prompt injection, context leakage) are identified.",
        "related_categories": ["jailbreak_instruction_override", "system_prompt_context_leakage"]
    },
    "MEASURE-2.2": {
        "function": "MEASURE",
        "subcategory": "MEASURE 2.2",
        "name": "Evaluations of Safe and Responsible Output",
        "description": "AI system is evaluated for performance metrics, including harmful, toxic, abusive, or discriminatory generation.",
        "related_categories": ["toxic_abusive_output"]
    },
    "MEASURE-2.5": {
        "function": "MEASURE",
        "subcategory": "MEASURE 2.5",
        "name": "Privacy Risk & Data Protection Assessment",
        "description": "AI systems are evaluated for privacy risks, including leakage of PII, re-identification, or disclosure of confidential records.",
        "related_categories": ["sensitive_data_disclosure"]
    },
    "MEASURE-2.7": {
        "function": "MEASURE",
        "subcategory": "MEASURE 2.7",
        "name": "Adversarial Robustness and Cybersecurity Testing",
        "description": "AI system is subjected to repeatable red-teaming, prompt injection, and extraction probes to measure resilience against compromise.",
        "related_categories": ["jailbreak_instruction_override", "system_prompt_context_leakage"]
    },
    "MANAGE-1.3": {
        "function": "MANAGE",
        "subcategory": "MANAGE 1.3",
        "name": "Risk Response and Control Implementation",
        "description": "Mechanisms to track and mitigate identified AI risks (e.g. guardrails, prompt fences, filter layers) are prioritized and deployed.",
        "related_categories": ["sensitive_data_disclosure", "jailbreak_instruction_override"]
    },
    "MANAGE-2.2": {
        "function": "MANAGE",
        "subcategory": "MANAGE 2.2",
        "name": "Remediation and Ongoing Re-assessment",
        "description": "Identified vulnerabilities are tracked through remediation and subjected to regression re-testing before deployment approval.",
        "related_categories": ["jailbreak_instruction_override", "system_prompt_context_leakage", "toxic_abusive_output"]
    }
}
