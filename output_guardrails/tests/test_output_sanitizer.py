"""
tests/test_output_sanitizer.py
================================
Test suite for the OutputSanitizer module — covers all three guardrail layers:
  1. Mapping check (PII leak detection via session token map)
  2. Honey-token monitoring (trap token detection & security alerting)
  3. Audit trail (structured, timestamped interception logging)

Run with:
    pytest tests/test_output_sanitizer.py -v
"""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from output_guardrails import (
    AuditLogger,
    InterceptionReason,
    OutputSanitizer,
    SanitizationAction,
    SessionTokenMap,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def token_map() -> SessionTokenMap:
    """A pre-populated SessionTokenMap mimicking the input pseudonymiser."""
    tm = SessionTokenMap(session_id="test-session-001")
    tm.add("Alice Johnson", "NAME")
    tm.add("alice@example.com", "EMAIL")
    tm.add("+1-800-555-0199", "PHONE")
    tm.add("123-45-6789", "SSN")
    return tm


@pytest.fixture
def token_map_with_honey(token_map: SessionTokenMap) -> SessionTokenMap:
    """SessionTokenMap that also contains honey-tokens."""
    token_map.add_honey("trap-data-abc", "SECRET")
    token_map.add_honey("honey-email@internal.com", "EMAIL")
    return token_map


@pytest.fixture
def audit_logger() -> AuditLogger:
    return AuditLogger()


@pytest.fixture
def sanitizer(token_map, audit_logger) -> OutputSanitizer:
    return OutputSanitizer(token_map, audit_logger, enable_heuristics=True)


@pytest.fixture
def sanitizer_with_honey(token_map_with_honey, audit_logger) -> OutputSanitizer:
    return OutputSanitizer(token_map_with_honey, audit_logger, enable_heuristics=True)


# ---------------------------------------------------------------------------
# 1. Clean output – no modification expected
# ---------------------------------------------------------------------------

class TestCleanOutput:
    def test_no_pii_unchanged(self, sanitizer):
        text = "The analysis shows a 12% increase in Q4 revenue."
        result = sanitizer.sanitize(text)

        assert result.sanitized_text == text
        assert result.was_modified is False
        assert result.security_alert is False
        assert result.interceptions == []

    def test_placeholder_tokens_pass_through(self, sanitizer):
        """Placeholder tokens in output must never be double-replaced."""
        text = "Hello NAME_01, your request has been processed."
        result = sanitizer.sanitize(text)

        assert result.sanitized_text == text
        assert result.was_modified is False


# ---------------------------------------------------------------------------
# 2. Mapping Check — real PII leaked back in output
# ---------------------------------------------------------------------------

class TestMappingCheck:
    def test_name_leak_replaced(self, sanitizer):
        text = "The user Alice Johnson has been verified."
        result = sanitizer.sanitize(text)

        assert "Alice Johnson" not in result.sanitized_text
        assert "NAME_01" in result.sanitized_text
        assert result.was_modified is True
        assert result.security_alert is False

        entry = result.interceptions[0]
        assert entry.reason == InterceptionReason.PII_LEAK
        assert entry.action == SanitizationAction.REPLACED
        assert entry.token_type == "NAME"
        assert entry.session_id == "test-session-001"

    def test_email_leak_replaced(self, sanitizer):
        text = "Send the report to alice@example.com immediately."
        result = sanitizer.sanitize(text)

        assert "alice@example.com" not in result.sanitized_text
        assert "EMAIL_01" in result.sanitized_text

    def test_phone_leak_replaced(self, sanitizer):
        text = "Call the customer at +1-800-555-0199 for follow-up."
        result = sanitizer.sanitize(text)

        assert "+1-800-555-0199" not in result.sanitized_text

    def test_ssn_leak_replaced(self, sanitizer):
        text = "SSN on file: 123-45-6789."
        result = sanitizer.sanitize(text)

        assert "123-45-6789" not in result.sanitized_text

    def test_multiple_pii_values_in_one_response(self, sanitizer):
        text = "Alice Johnson can be reached at alice@example.com or +1-800-555-0199."
        result = sanitizer.sanitize(text)

        assert "Alice Johnson" not in result.sanitized_text
        assert "alice@example.com" not in result.sanitized_text
        assert "+1-800-555-0199" not in result.sanitized_text
        assert len(result.interceptions) >= 3

    def test_partial_leak_in_long_text(self, sanitizer):
        text = (
            "Based on our records, the account holder is Alice Johnson. "
            "All transactions appear normal with no suspicious activity."
        )
        result = sanitizer.sanitize(text)
        assert "Alice Johnson" not in result.sanitized_text
        assert "NAME_01" in result.sanitized_text


# ---------------------------------------------------------------------------
# 3. Honey-Token Monitoring
# ---------------------------------------------------------------------------

class TestHoneyTokenMonitoring:
    def test_honey_token_in_output_triggers_alert(self, sanitizer_with_honey):
        """If a honey-token placeholder appears in LLM output, security_alert=True."""
        # Simulate LLM echoing back the honey-token placeholder
        honey_placeholder = sanitizer_with_honey._map.honey_placeholders[0]
        text = f"The field value is {honey_placeholder} as specified."

        result = sanitizer_with_honey.sanitize(text)

        assert result.security_alert is True
        assert result.was_modified is True
        assert honey_placeholder not in result.sanitized_text

        entry = next(
            e for e in result.interceptions
            if e.reason == InterceptionReason.HONEY_TOKEN_FIRED
        )
        assert entry.action == SanitizationAction.FLAGGED

    def test_all_honey_tokens_detected(self, sanitizer_with_honey):
        """Both honey-tokens in the map should fire if present."""
        placeholders = sanitizer_with_honey._map.honey_placeholders
        text = f"Values: {placeholders[0]} and {placeholders[1]}"

        result = sanitizer_with_honey.sanitize(text)

        assert result.security_alert is True
        honey_entries = [
            e for e in result.interceptions
            if e.reason == InterceptionReason.HONEY_TOKEN_FIRED
        ]
        assert len(honey_entries) == 2

    def test_clean_output_no_honey_alert(self, sanitizer_with_honey):
        text = "All data processed successfully. No anomalies detected."
        result = sanitizer_with_honey.sanitize(text)

        assert result.security_alert is False

    def test_honey_token_replaced_with_redacted(self, token_map_with_honey, audit_logger):
        """With redact_on_alert=True (default), honey-token is replaced with [REDACTED]."""
        s = OutputSanitizer(
            token_map_with_honey,
            audit_logger,
            redact_on_alert=True,
        )
        placeholder = token_map_with_honey.honey_placeholders[0]
        text = f"The intercepted value is {placeholder}."
        result = s.sanitize(text)

        assert "[REDACTED]" in result.sanitized_text
        assert placeholder not in result.sanitized_text


# ---------------------------------------------------------------------------
# 4. Heuristic Scan (pattern-based PII not in the token map)
# ---------------------------------------------------------------------------

class TestHeuristicScan:
    def test_novel_email_caught_by_heuristic(self, token_map, audit_logger):
        """An email NOT in the token map should be caught by the regex heuristic."""
        s = OutputSanitizer(token_map, audit_logger, enable_heuristics=True)
        text = "Please forward to newperson@company.org for review."
        result = s.sanitize(text)

        assert "newperson@company.org" not in result.sanitized_text
        entry = next(
            e for e in result.interceptions
            if e.reason == InterceptionReason.PATTERN_MATCH
        )
        assert entry.token_type == "EMAIL"
        assert entry.action == SanitizationAction.REDACTED

    def test_heuristics_disabled_skips_pattern_match(self, token_map, audit_logger):
        s = OutputSanitizer(token_map, audit_logger, enable_heuristics=False)
        text = "Contact external@other.com for details."
        result = s.sanitize(text)

        assert "external@other.com" in result.sanitized_text   # not caught
        assert all(
            e.reason != InterceptionReason.PATTERN_MATCH
            for e in result.interceptions
        )

    def test_ssn_pattern_heuristic(self, token_map, audit_logger):
        s = OutputSanitizer(token_map, audit_logger, enable_heuristics=True)
        text = "The SSN 987-65-4321 was mentioned in the document."
        result = s.sanitize(text)

        assert "987-65-4321" not in result.sanitized_text


# ---------------------------------------------------------------------------
# 5. Audit Trail
# ---------------------------------------------------------------------------

class TestAuditTrail:
    def test_audit_entries_have_required_fields(self, sanitizer):
        sanitizer.sanitize("Hello Alice Johnson.")
        entries = sanitizer._audit.get_entries()

        assert len(entries) >= 1
        e = entries[0]
        assert e.entry_id
        assert e.timestamp
        assert e.session_id == "test-session-001"
        assert e.reason
        assert e.action
        assert e.token_type
        assert e.original_value_hash   # SHA-256 hash, never the raw value
        assert e.placeholder
        assert e.context_snippet

    def test_audit_does_not_store_raw_pii(self, sanitizer):
        """The raw PII value must NEVER appear in audit entries."""
        sanitizer.sanitize("Leaked: alice@example.com in the response.")
        for entry in sanitizer._audit.get_entries():
            assert "alice@example.com" not in entry.original_value_hash
            assert "alice@example.com" not in entry.context_snippet

    def test_audit_filter_by_session(self, audit_logger):
        tm1 = SessionTokenMap(session_id="session-A")
        tm1.add("Bob Smith", "NAME")
        tm2 = SessionTokenMap(session_id="session-B")
        tm2.add("Carol White", "NAME")

        OutputSanitizer(tm1, audit_logger).sanitize("User is Bob Smith.")
        OutputSanitizer(tm2, audit_logger).sanitize("User is Carol White.")

        a_entries = audit_logger.get_entries(session_id="session-A")
        b_entries = audit_logger.get_entries(session_id="session-B")

        assert len(a_entries) == 1
        assert len(b_entries) == 1
        assert a_entries[0].session_id == "session-A"
        assert b_entries[0].session_id == "session-B"

    def test_audit_filter_by_reason(self, sanitizer_with_honey):
        honey_ph = sanitizer_with_honey._map.honey_placeholders[0]
        sanitizer_with_honey.sanitize(f"Leak: {honey_ph} and Alice Johnson.")

        honey_entries = sanitizer_with_honey._audit.get_entries(
            reason=InterceptionReason.HONEY_TOKEN_FIRED
        )
        pii_entries = sanitizer_with_honey._audit.get_entries(
            reason=InterceptionReason.PII_LEAK
        )

        assert len(honey_entries) >= 1
        assert len(pii_entries) >= 1

    def test_audit_export_json(self, sanitizer):
        sanitizer.sanitize("Hello Alice Johnson, call +1-800-555-0199.")
        raw = sanitizer._audit.export_json()
        parsed = json.loads(raw)

        assert isinstance(parsed, list)
        assert len(parsed) >= 1
        for entry in parsed:
            assert "entry_id" in entry
            assert "timestamp" in entry
            assert "reason" in entry

    def test_audit_file_persistence(self, tmp_path, token_map):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=str(log_file))
        s = OutputSanitizer(token_map, logger)
        s.sanitize("User is Alice Johnson.")

        assert log_file.exists()
        lines = log_file.read_text().strip().splitlines()
        assert len(lines) >= 1
        record = json.loads(lines[0])
        assert record["reason"] == InterceptionReason.PII_LEAK


# ---------------------------------------------------------------------------
# 6. SanitizationResult helpers
# ---------------------------------------------------------------------------

class TestSanitizationResult:
    def test_summary_structure(self, sanitizer):
        result = sanitizer.sanitize("Email alice@example.com to confirm.")
        summary = result.summary()

        assert "was_modified" in summary
        assert "security_alert" in summary
        assert "interception_count" in summary
        assert "reasons" in summary
        assert summary["interception_count"] >= 1

    def test_result_unchanged_for_clean_text(self, sanitizer):
        text = "No sensitive data here."
        result = sanitizer.sanitize(text)

        assert result.sanitized_text == text
        assert not result.was_modified
        assert not result.security_alert
        assert result.interceptions == []


# ---------------------------------------------------------------------------
# 7. SessionTokenMap
# ---------------------------------------------------------------------------

class TestSessionTokenMap:
    def test_add_and_retrieve(self):
        tm = SessionTokenMap()
        ph = tm.add("John Doe", "NAME")
        assert ph == "NAME_01"
        assert tm.get_placeholder("John Doe") == "NAME_01"
        assert tm.get_real_value("NAME_01") == "John Doe"

    def test_idempotent_add(self):
        tm = SessionTokenMap()
        ph1 = tm.add("John Doe", "NAME")
        ph2 = tm.add("John Doe", "NAME")
        assert ph1 == ph2
        assert len(tm) == 1

    def test_honey_token_flagged(self):
        tm = SessionTokenMap()
        ph = tm.add_honey("trap-value", "SECRET")
        assert tm.is_honey_token(ph)
        assert "HONEY_" in ph

    def test_real_values_sorted_longest_first(self):
        tm = SessionTokenMap()
        tm.add("Al", "NAME")
        tm.add("Alice", "NAME")
        tm.add("Alice Johnson", "NAME")
        values = tm.real_values
        assert values[0] == "Alice Johnson"
        assert values[-1] == "Al"
