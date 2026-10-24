"""Promptfoo Configuration & Test Case Exporter.

Generates official promptfoo.yaml configuration files compatible with
the Promptfoo CLI (npx promptfoo eval). Targets the standard OpenAI-compatible
endpoint (/v1/chat/completions) exposed by the application server.
"""

import json
from pathlib import Path
from typing import Any, Dict, List
import yaml


class PromptfooExporter:
    def __init__(self, probes_path: Path):
        self.probes_path = probes_path

    def export_config(self, output_yaml_path: Path, target_url: str = "http://localhost:8000/v1/chat/completions") -> Path:
        with open(self.probes_path, "r", encoding="utf-8") as f:
            raw_probes = json.load(f)

        tests: List[Dict[str, Any]] = []

        for p in raw_probes:
            assertions = []
            for forbidden in p.get("forbidden_patterns", []):
                assertions.append({
                    "type": "not-icontains",
                    "value": forbidden
                })
            for required in p.get("required_patterns", []):
                assertions.append({
                    "type": "icontains",
                    "value": required
                })

            tests.append({
                "description": f"[{p['id']}] {p['name']} ({p['category']})",
                "vars": {
                    "prompt": p["prompt"]
                },
                "assert": assertions
            })

        # Compatible with standard Promptfoo HTTP/OpenAI provider schema
        config = {
            "description": "AI Safety & Compliance Readiness Red-Teaming Assessment",
            "prompts": ["{{prompt}}"],
            "providers": [
                {
                    "id": "http",
                    "config": {
                        "url": target_url,
                        "method": "POST",
                        "headers": {
                            "Content-Type": "application/json"
                        },
                        "body": {
                            "model": "fincorp-assistant-v1",
                            "messages": [
                                {
                                    "role": "user",
                                    "content": "{{prompt}}"
                                }
                            ]
                        },
                        "transformResponse": "json.choices[0].message.content"
                    }
                }
            ],
            "tests": tests,
            "metadata": {
                "framework": "NIST AI RMF & EU AI Act Readiness",
                "version": "1.0.0",
                "target_environment": "Safety Sandbox"
            }
        }

        with open(output_yaml_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        return output_yaml_path
