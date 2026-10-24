"""EU AI Act Provisions & Risk-Management Topics Catalog.

Note: Statutory classification and legal compliance under the EU AI Act
(Regulation (EU) 2024/1689) require fact-specific evaluation by qualified
legal counsel based on system purpose, risk tier (e.g. prohibited, high-risk,
or GPAI), and deployer vs. provider roles.
"""

from typing import Dict, Any

EU_AI_ACT_CATALOG: Dict[str, Dict[str, Any]] = {
    "EU-ACT-ART-5": {
        "article": "Article 5",
        "title": "Prohibited Artificial Intelligence Practices",
        "topic": "Prohibited Practices (Cognitive manipulation, exploitation of vulnerabilities, social scoring)",
        "actor_role": "Provider / Deployer",
        "default_applicability": "Requires Legal Review (Fact-specific intended use)",
        "description": "Prohibits AI systems placing on the market or putting into service systems deploying subliminal or purposefully manipulative techniques that distort human behavior and impair informed decision-making.",
        "related_categories": ["toxic_abusive_output", "dangerous_high_impact_advice"]
    },
    "EU-ACT-ART-9": {
        "article": "Article 9",
        "title": "Risk Management System (High-Risk AI Systems)",
        "topic": "Continuous Risk Management & Testing",
        "actor_role": "Provider of High-Risk AI Systems",
        "default_applicability": "Potentially Applies if Classified as High-Risk (Annex III)",
        "description": "Continuous, iterative risk management system to identify, estimate, and evaluate foreseeable risks to health, safety, and fundamental rights throughout the lifecycle.",
        "related_categories": ["jailbreak_instruction_override", "dangerous_high_impact_advice"]
    },
    "EU-ACT-ART-10": {
        "article": "Article 10",
        "title": "Data and Data Governance",
        "topic": "Training, Validation, Testing Data Governance & Privacy",
        "actor_role": "Provider of High-Risk AI Systems",
        "default_applicability": "Potentially Applies if High-Risk / Privacy Shield",
        "description": "High-risk AI systems training, validation, and testing data sets shall be subject to appropriate data governance and management practices covering bias and privacy safeguards.",
        "related_categories": ["sensitive_data_disclosure"]
    },
    "EU-ACT-ART-13": {
        "article": "Article 13",
        "title": "Transparency and Provision of Information to Deployers",
        "topic": "Operational Transparency & Limitations Disclosure",
        "actor_role": "Provider to Deployer",
        "default_applicability": "Potentially Applies to High-Risk AI Systems",
        "description": "High-risk AI systems shall be accompanied by instructions for use, capabilities, performance characteristics, and known limitations to enable deployers to interpret outputs.",
        "related_categories": ["dangerous_high_impact_advice", "system_prompt_context_leakage"]
    },
    "EU-ACT-ART-14": {
        "article": "Article 14",
        "title": "Human Oversight",
        "topic": "Human-in-the-Loop Safeguards",
        "actor_role": "Deployer / Provider",
        "default_applicability": "Potentially Applies to High-Risk AI Systems",
        "description": "Design and development to enable natural persons to oversee the system, prevent automation bias, and intervene or stop system outputs when needed.",
        "related_categories": ["dangerous_high_impact_advice"]
    },
    "EU-ACT-ART-15": {
        "article": "Article 15",
        "title": "Accuracy, Robustness and Cybersecurity",
        "topic": "Adversarial Resilience & Prompt Injection Protection",
        "actor_role": "Provider of High-Risk AI Systems",
        "default_applicability": "Potentially Applies to High-Risk AI Systems",
        "description": "Resilience against errors, faults, or adversarial third parties attempting to manipulate the system or exploit vulnerabilities (e.g., prompt injection, data poisoning).",
        "related_categories": ["jailbreak_instruction_override", "system_prompt_context_leakage"]
    },
    "EU-ACT-ART-50": {
        "article": "Article 50",
        "title": "Transparency Obligations for Certain AI Systems",
        "topic": "AI Interaction Disclosure to Natural Persons",
        "actor_role": "Deployer of Generative / Interactive AI",
        "default_applicability": "Applies directly to AI systems interacting with natural persons",
        "description": "Providers and deployers shall ensure that AI systems interacting directly with natural persons inform users in a timely and clear manner that they are interacting with an AI system.",
        "related_categories": ["dangerous_high_impact_advice"]
    },
    "EU-ACT-ART-53": {
        "article": "Article 53",
        "title": "Obligations for Providers of General Purpose AI (GPAI) Models",
        "topic": "GPAI Technical Documentation & Systemic Risk Evaluation",
        "actor_role": "Provider of General-Purpose AI Models",
        "default_applicability": "Applies to Foundation / GPAI Model Providers (Not typical enterprise application deployers)",
        "description": "GPAI model documentation, copyright policy compliance, and evaluation summaries of systemic and safety risks.",
        "related_categories": ["sensitive_data_disclosure", "system_prompt_context_leakage"]
    }
}
