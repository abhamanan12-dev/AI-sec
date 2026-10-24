"""Microsoft Presidio integration adapter with seamless fallback.

Allows the pipeline to leverage Microsoft Presidio AnalyzerEngine and spaCy
when installed, while falling back gracefully to the built-in multi-locale
recognizers when running in lightweight or air-gapped environments.
"""

import logging
from typing import List, Optional
from safety_pipeline.core.models import PIIEntity
from safety_pipeline.workstream_b_guardrail.recognizers import get_default_recognizers

logger = logging.getLogger("safety_pipeline.presidio_adapter")

# Check if Microsoft Presidio is available
try:
    from presidio_analyzer import AnalyzerEngine, RecognizerResult
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False
    AnalyzerEngine = None


class PresidioAdapter:
    def __init__(self, languages: Optional[List[str]] = None):
        self.languages = languages or ["en"]
        self.use_presidio = PRESIDIO_AVAILABLE
        self.presidio_engine = None
        self.native_recognizers = get_default_recognizers()

        if self.use_presidio:
            try:
                self.presidio_engine = AnalyzerEngine()
                logger.info("Microsoft Presidio AnalyzerEngine initialized successfully.")
            except Exception as e:
                logger.warning(f"Presidio installed but engine failed to initialize ({e}). Falling back to native recognizers.")
                self.use_presidio = False
        else:
            logger.info("Microsoft Presidio not installed in environment; using high-accuracy native recognizer suite.")

    def analyze(self, text: str, correlation_id: Optional[str] = None) -> List[PIIEntity]:
        """Detect entities across the text using Presidio (if present) and native recognizers."""
        entities: List[PIIEntity] = []

        # 1. Native Recognizers detection
        for recognizer in self.native_recognizers:
            try:
                found = recognizer.detect(text)
                entities.extend(found)
            except Exception as err:
                logger.error(f"Error in recognizer {recognizer.entity_type}: {err}")

        # 2. Microsoft Presidio detection (if available)
        if self.use_presidio and self.presidio_engine:
            try:
                presidio_results = self.presidio_engine.analyze(
                    text=text,
                    language=self.languages[0],
                    entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "IP_ADDRESS", "PERSON"],
                )
                for res in presidio_results:
                    # Normalize Presidio PERSON -> PERSON_NAME
                    etype = "PERSON_NAME" if res.entity_type == "PERSON" else res.entity_type
                    val = text[res.start:res.end]
                    entities.append(
                        PIIEntity(
                            entity_type=etype,
                            value=val,
                            start=res.start,
                            end=res.end,
                            confidence=res.score,
                            locale="Global",
                        )
                    )
            except Exception as e:
                logger.warning(f"Presidio analyze execution error: {e}")

        # Deduplicate and resolve overlapping entity spans (prefer longest match)
        return self._deduplicate_spans(entities)

    def _deduplicate_spans(self, entities: List[PIIEntity]) -> List[PIIEntity]:
        if not entities:
            return []

        # Sort by start asc, then length desc
        sorted_entities = sorted(entities, key=lambda e: (e.start, -(e.end - e.start)))
        deduped: List[PIIEntity] = []

        for entity in sorted_entities:
            # Check overlap with already accepted entities
            overlap = False
            for accepted in deduped:
                if not (entity.end <= accepted.start or entity.start >= accepted.end):
                    overlap = True
                    break
            if not overlap:
                deduped.append(entity)

        return deduped
