"""Ephemeral In-Memory Placeholder Registry for Safe Context Preservation & Restoration.

Allows downstream workflows to refer to sanitized tokens while keeping raw PII
isolated in a controlled, ephemeral memory vault with audit logging.
"""

import time
import uuid
from typing import Dict, Optional, Tuple


class PlaceholderSessionContext:
    def __init__(self, ttl_seconds: int = 600):
        self.ttl_seconds = ttl_seconds
        # session_id -> { "placeholder": "raw_value", "_created_at": timestamp }
        self._registry: Dict[str, Dict[str, str]] = {}
        self._audit_log: list[Dict[str, str]] = []

    def create_session(self) -> str:
        session_id = str(uuid.uuid4())
        self._registry[session_id] = {"_created_at": str(time.time())}
        return session_id

    def store_mapping(self, session_id: str, placeholder: str, raw_value: str) -> None:
        if session_id not in self._registry:
            self.create_session()
        self._registry[session_id][placeholder] = raw_value

    def get_mappings(self, session_id: str) -> Dict[str, str]:
        if session_id not in self._registry:
            return {}
        # Clean internal keys
        return {k: v for k, v in self._registry[session_id].items() if not k.startswith("_")}

    def restore_placeholders(self, text: str, session_id: str, authorized_actor: str = "internal_service") -> str:
        """Safely restore placeholders to raw values with audit event logging."""
        mappings = self.get_mappings(session_id)
        if not mappings:
            return text

        restored = text
        for placeholder, raw_val in mappings.items():
            if placeholder in restored:
                restored = restored.replace(placeholder, raw_val)
                self._audit_log.append({
                    "timestamp": str(time.time()),
                    "session_id": session_id,
                    "placeholder": placeholder,
                    "authorized_actor": authorized_actor,
                    "action": "RESTORE_PII_SUCCESS"
                })

        return restored

    def purge_session(self, session_id: str) -> None:
        if session_id in self._registry:
            del self._registry[session_id]
            self._audit_log.append({
                "timestamp": str(time.time()),
                "session_id": session_id,
                "action": "SESSION_PURGED_ZERO_RETENTION"
            })
