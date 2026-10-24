"""Unit tests for Workstream B: PII & Data Guardrail."""

import pytest
from safety_pipeline.workstream_b_guardrail.guardrail_service import PIIGuardrailService
from safety_pipeline.workstream_b_guardrail.recognizers import luhn_checksum


def test_luhn_checksum():
    # Valid credit card numbers
    assert luhn_checksum("4532012345678910") is True
    assert luhn_checksum("4532-0123-4567-8910") is True
    # Invalid card number
    assert luhn_checksum("4532012345678911") is False


def test_input_preprocessing_email_and_phone():
    service = PIIGuardrailService()
    raw = "My email is alice.smith@example.com and mobile is 415-555-2671."
    res = service.process_input(raw)

    assert "[EMAIL_ADDRESS]" in res.redacted_text
    assert "[PHONE_NUMBER]" in res.redacted_text
    assert "alice.smith@example.com" not in res.redacted_text
    assert "415-555-2671" not in res.redacted_text
    assert len(res.entities_detected) == 2


def test_output_postprocessing_credit_card():
    service = PIIGuardrailService()
    raw = "The customer card on file is 4532-0123-4567-8910."
    res = service.process_output(raw)

    assert "[CREDIT_CARD]" in res.redacted_text
    assert "4532-0123-4567-8910" not in res.redacted_text


def test_indian_national_identifiers():
    service = PIIGuardrailService()
    raw = "PAN: ABCDE1234F, Aadhaar: 3675 9834 6012, Mobile: 9876543210"
    res = service.process_input(raw)

    assert "[IN_PAN]" in res.redacted_text
    assert "[IN_AADHAAR]" in res.redacted_text
    assert "[PHONE_NUMBER]" in res.redacted_text


def test_uk_national_insurance_number():
    service = PIIGuardrailService()
    raw = "My National Insurance number is QQ 12 34 56 A."
    res = service.process_input(raw)

    assert "[UK_NINO]" in res.redacted_text
    assert "QQ 12 34 56 A" not in res.redacted_text


def test_negative_controls_not_over_redacted():
    service = PIIGuardrailService()
    clean_text = "Meeting on 2026-10-24 at 14:00 with Model ISO-9001 and price $450.00."
    res = service.process_input(clean_text)

    # Clean text without PII should remain identical
    assert res.redacted_text == clean_text
    assert len(res.entities_detected) == 0


def test_placeholder_preservation_and_safe_restoration():
    service = PIIGuardrailService()
    session_id = service.session_context.create_session()
    raw = "Contact Alex at alex@example.com."
    res = service.process_input(raw, session_id=session_id, preserve_placeholders=True)

    assert "[EMAIL_ADDRESS_1]" in res.redacted_text

    # Safe restore simulation
    restored = service.session_context.restore_placeholders(res.redacted_text, session_id)
    assert restored == raw

    # Purge session clears memory
    service.session_context.purge_session(session_id)
    assert service.session_context.get_mappings(session_id) == {}
