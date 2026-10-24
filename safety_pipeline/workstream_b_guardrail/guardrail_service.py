"""Two-Sided PII Guardrail Service (Input Pre-processing & Output Post-processing).

Implements the pattern:
- Input Pre-processing: Masks PII from user inputs with typed placeholders before reaching LLM.
- Output Post-processing: Masks PII from model responses before presenting to the end user.
"""

import time
from typing import List, Optional, Tuple, Dict
from safety_pipeline.core.models import PIIEntity, RedactionResult
from safety_pipeline.workstream_b_guardrail.presidio_adapter import PresidioAdapter
from safety_pipeline.workstream_b_guardrail.session_context import PlaceholderSessionContext


class PIIGuardrailService:
    def __init__(self, languages: Optional[List[str]] = None, placeholder_format: str = "[{entity_type}]"):
        self.adapter = PresidioAdapter(languages=languages)
        self.placeholder_format = placeholder_format
        self.session_context = PlaceholderSessionContext()

    def process_input(
        self,
        text: str,
        session_id: Optional[str] = None,
        preserve_placeholders: bool = False
    ) -> RedactionResult:
        """
        Input Pre-processing:
        Detects sensitive entities in the user's message and replaces them with
        typed placeholders before model processing.
        """
        return self._redact(
            text=text,
            direction="input",
            session_id=session_id,
            preserve_placeholders=preserve_placeholders,
        )

    def process_output(
        self,
        text: str,
        session_id: Optional[str] = None,
        preserve_placeholders: bool = False
    ) -> RedactionResult:
        """
        Output Post-processing:
        Inspects the model response and redacts detected sensitive entities
        before returning the response to the end user.
        """
        return self._redact(
            text=text,
            direction="output",
            session_id=session_id,
            preserve_placeholders=preserve_placeholders,
        )

    def _redact(
        self,
        text: str,
        direction: str,
        session_id: Optional[str] = None,
        preserve_placeholders: bool = False,
    ) -> RedactionResult:
        start_time = time.perf_counter()
        entities = self.adapter.analyze(text)

        if not entities:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return RedactionResult(
                direction=direction,
                original_text=text,
                redacted_text=text,
                entities_detected=[],
                processing_time_ms=elapsed,
            )

        # Sort entities by start index in reverse order to replace from back to front without index shifting
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        redacted_chars = list(text)
        preserved_map: Dict[str, str] = {}

        for idx, entity in enumerate(sorted_entities):
            placeholder = self.placeholder_format.format(entity_type=entity.entity_type)
            # If preservation is requested, we can use indexed placeholder e.g. [PHONE_NUMBER_1]
            if preserve_placeholders:
                p_key = f"[{entity.entity_type}_{len(sorted_entities) - idx}]"
                preserved_map[p_key] = entity.value
                if session_id:
                    self.session_context.store_mapping(session_id, p_key, entity.value)
                replacement = p_key
            else:
                replacement = placeholder

            redacted_chars[entity.start : entity.end] = list(replacement)

        redacted_text = "".join(redacted_chars)
        elapsed = (time.perf_counter() - start_time) * 1000.0

        return RedactionResult(
            direction=direction,
            original_text=text,
            redacted_text=redacted_text,
            entities_detected=entities,
            processing_time_ms=elapsed,
            preserved_placeholders=preserved_map,
        )
