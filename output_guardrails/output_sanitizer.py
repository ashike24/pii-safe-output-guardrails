"""
output_sanitizer.py
====================
OutputSanitizer — Output Guardrails for Indirect Prompt Injection Defense
Addresses: https://github.com/c2siorg/PII-Safe/issues/16

This module acts as a secondary post-processing layer that intercepts LLM
responses BEFORE they reach the user or any external tool.  It implements:

  1. Mapping Check   – re-replaces any real PII that leaked back through the
                       reverse of the session's pseudonymisation token map.
  2. Honey-Token     – detects trap tokens injected during pseudonymisation;
     Monitoring        fires a security alert if the LLM surfaces one.
  3. Audit Trail     – structured, timestamped log of every interception.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums & constants
# ---------------------------------------------------------------------------

class InterceptionReason(str, Enum):
    PII_LEAK          = "PII_LEAK"          # real value found in output
    HONEY_TOKEN_FIRED = "HONEY_TOKEN_FIRED" # trap token found in output
    PATTERN_MATCH     = "PATTERN_MATCH"     # regex heuristic hit


class SanitizationAction(str, Enum):
    REPLACED  = "REPLACED"   # value was substituted with placeholder
    REDACTED  = "REDACTED"   # value was hard-redacted
    FLAGGED   = "FLAGGED"    # honey-token: flag only (no replacement needed)


# Prefix used for honey-tokens so they are distinct from normal placeholders
HONEY_TOKEN_PREFIX = "HONEY_"

# Regex patterns for common PII that might slip through even without a token map
_HEURISTIC_PATTERNS: Dict[str, re.Pattern] = {
    "EMAIL":   re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "PHONE":   re.compile(r"(?:\+?\d[\d\-\s().]{7,}\d)"),
    "SSN":     re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "IP_ADDR": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AuditEntry:
    entry_id:       str
    timestamp:      str
    session_id:     str
    reason:         InterceptionReason
    action:         SanitizationAction
    token_type:     str          # e.g. NAME, EMAIL, HONEY_EMAIL …
    original_value_hash: str     # SHA-256 of the leaked value (never stored raw)
    placeholder:    str          # the token that replaced / flagged the value
    context_snippet: str         # short surrounding text (anonymised)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SanitizationResult:
    sanitized_text:  str
    was_modified:    bool
    security_alert:  bool          # True if any honey-token fired
    interceptions:   List[AuditEntry] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "was_modified":  self.was_modified,
            "security_alert": self.security_alert,
            "interception_count": len(self.interceptions),
            "reasons": [e.reason for e in self.interceptions],
        }


# ---------------------------------------------------------------------------
# Session Token Map
# ---------------------------------------------------------------------------

class SessionTokenMap:
    """
    Holds the bidirectional mapping created during input pseudonymisation.

    Typical usage by the upstream pseudonymiser::

        token_map = SessionTokenMap(session_id="abc-123")
        placeholder = token_map.add("Alice Johnson", "NAME")   # → "USER_NAME_01"
        honey      = token_map.add_honey("555-123-4567", "PHONE")  # → "HONEY_PHONE_01"

    The OutputSanitizer receives this same object and uses it to detect leaks.
    """

    def __init__(self, session_id: Optional[str] = None) -> None:
        self.session_id: str = session_id or str(uuid.uuid4())
        # real_value → placeholder
        self._forward: Dict[str, str] = {}
        # placeholder → real_value
        self._reverse: Dict[str, str] = {}
        # set of placeholder strings that are honey-tokens
        self._honey_tokens: set[str] = set()
        self._counters: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Building the map (called by the input pseudonymiser)
    # ------------------------------------------------------------------

    def add(self, real_value: str, token_type: str) -> str:
        """Register a real PII value and return its placeholder token."""
        if real_value in self._forward:
            return self._forward[real_value]
        placeholder = self._next_placeholder(token_type)
        self._forward[real_value]    = placeholder
        self._reverse[placeholder]   = real_value
        return placeholder

    def add_honey(self, real_value: str, token_type: str) -> str:
        """
        Register a *honey-token*: a trap value injected into a sensitive field.
        The placeholder is prefixed with HONEY_ so OutputSanitizer can identify
        it instantly.
        """
        placeholder = self._next_placeholder(f"{HONEY_TOKEN_PREFIX}{token_type}")
        self._forward[real_value]  = placeholder
        self._reverse[placeholder] = real_value
        self._honey_tokens.add(placeholder)
        return placeholder

    # ------------------------------------------------------------------
    # Query helpers (used by OutputSanitizer)
    # ------------------------------------------------------------------

    def get_placeholder(self, real_value: str) -> Optional[str]:
        return self._forward.get(real_value)

    def get_real_value(self, placeholder: str) -> Optional[str]:
        return self._reverse.get(placeholder)

    def is_honey_token(self, placeholder: str) -> bool:
        return placeholder in self._honey_tokens

    @property
    def real_values(self) -> List[str]:
        """All known real PII values, sorted longest-first to avoid partial matches."""
        return sorted(self._forward.keys(), key=len, reverse=True)

    @property
    def honey_placeholders(self) -> List[str]:
        return list(self._honey_tokens)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _next_placeholder(self, token_type: str) -> str:
        idx = self._counters.get(token_type, 0) + 1
        self._counters[token_type] = idx
        return f"{token_type}_{idx:02d}"

    def __len__(self) -> int:
        return len(self._forward)


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    Persists interception events.  By default entries are written to a
    structured JSON-lines file; callers can subclass / swap this for a
    database writer, SIEM sink, etc.
    """

    def __init__(self, log_path: Optional[str] = None) -> None:
        self._entries: List[AuditEntry] = []
        self._log_path = log_path

    def record(self, entry: AuditEntry) -> None:
        self._entries.append(entry)
        logger.warning(
            "[PII-Safe Audit] reason=%s action=%s token_type=%s session=%s",
            entry.reason, entry.action, entry.token_type, entry.session_id,
        )
        if self._log_path:
            self._flush_entry(entry)

    def get_entries(
        self,
        session_id: Optional[str] = None,
        reason: Optional[InterceptionReason] = None,
    ) -> List[AuditEntry]:
        entries = self._entries
        if session_id:
            entries = [e for e in entries if e.session_id == session_id]
        if reason:
            entries = [e for e in entries if e.reason == reason]
        return entries

    def export_json(self) -> str:
        return json.dumps([e.to_dict() for e in self._entries], indent=2)

    def _flush_entry(self, entry: AuditEntry) -> None:
        with open(self._log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict()) + "\n")


# ---------------------------------------------------------------------------
# OutputSanitizer
# ---------------------------------------------------------------------------

class OutputSanitizer:
    """
    Post-processing guardrail that checks an LLM's raw output for PII leakage
    caused by indirect prompt injection or model misbehaviour.

    Usage::

        sanitizer = OutputSanitizer(token_map, audit_logger)
        result    = sanitizer.sanitize(llm_response_text)

        if result.security_alert:
            raise SecurityAlert("Honey-token triggered – possible prompt injection")

        safe_text = result.sanitized_text
    """

    def __init__(
        self,
        token_map: SessionTokenMap,
        audit_logger: Optional[AuditLogger] = None,
        *,
        enable_heuristics: bool = True,
        redact_on_alert: bool = True,
        context_window: int = 40,
    ) -> None:
        """
        Parameters
        ----------
        token_map          : SessionTokenMap built during input pseudonymisation.
        audit_logger       : AuditLogger instance (created internally if None).
        enable_heuristics  : Also apply regex-based PII detection as a fallback.
        redact_on_alert    : Replace honey-token source value with [REDACTED]
                             instead of its placeholder on alert.
        context_window     : Characters of surrounding text captured per entry.
        """
        self._map              = token_map
        self._audit            = audit_logger or AuditLogger()
        self._heuristics       = enable_heuristics
        self._redact_on_alert  = redact_on_alert
        self._ctx_window       = context_window

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sanitize(self, text: str) -> SanitizationResult:
        """
        Run all guardrail checks on *text* and return a SanitizationResult.
        Checks are applied in priority order:

          1. Honey-token scan  (highest priority – always fires an alert)
          2. Mapping check     (real PII values from the session token map)
          3. Heuristic scan    (regex patterns for common PII formats)
        """
        entries:       List[AuditEntry] = []
        security_alert = False
        working        = text

        # 1. Honey-token scan ------------------------------------------------
        working, honey_entries, alerted = self._honey_token_scan(working)
        entries.extend(honey_entries)
        if alerted:
            security_alert = True

        # 2. Mapping check ---------------------------------------------------
        working, map_entries = self._mapping_check(working)
        entries.extend(map_entries)

        # 3. Heuristic scan --------------------------------------------------
        if self._heuristics:
            working, heuristic_entries = self._heuristic_scan(working)
            entries.extend(heuristic_entries)

        # Log all entries
        for entry in entries:
            self._audit.record(entry)

        return SanitizationResult(
            sanitized_text = working,
            was_modified   = working != text,
            security_alert = security_alert,
            interceptions  = entries,
        )

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    def _honey_token_scan(
        self, text: str
    ) -> Tuple[str, List[AuditEntry], bool]:
        """
        Detect any honey-token placeholder appearing literally in the output.
        Honey-tokens should NEVER appear in LLM output – their presence means
        the model was manipulated into surfacing internal identifiers.
        """
        entries: List[AuditEntry] = []
        alerted = False
        working = text

        for placeholder in self._map.honey_placeholders:
            if placeholder not in working:
                continue

            alerted = True
            real_value = self._map.get_real_value(placeholder) or ""
            token_type = self._token_type_from_placeholder(placeholder)

            replacement = "[REDACTED]" if self._redact_on_alert else placeholder
            working = working.replace(placeholder, replacement)

            entries.append(self._make_entry(
                reason         = InterceptionReason.HONEY_TOKEN_FIRED,
                action         = SanitizationAction.FLAGGED,
                token_type     = token_type,
                leaked_value   = placeholder,   # it's the placeholder itself that fired
                placeholder    = replacement,
                text           = text,
            ))

        return working, entries, alerted

    def _mapping_check(self, text: str) -> Tuple[str, List[AuditEntry]]:
        """
        Scan for real PII values (from the session token map) present in the
        output.  Replace each occurrence with its placeholder.
        Values are matched longest-first to avoid partial substitutions.
        """
        entries: List[AuditEntry] = []
        working = text

        for real_value in self._map.real_values:
            if real_value not in working:
                continue

            placeholder = self._map.get_placeholder(real_value)
            if placeholder is None:
                continue

            # Skip honey-token source values (handled in honey scan)
            if self._map.is_honey_token(placeholder):
                continue

            token_type = self._token_type_from_placeholder(placeholder)
            working = working.replace(real_value, placeholder)

            entries.append(self._make_entry(
                reason       = InterceptionReason.PII_LEAK,
                action       = SanitizationAction.REPLACED,
                token_type   = token_type,
                leaked_value = real_value,
                placeholder  = placeholder,
                text         = text,
            ))

        return working, entries

    def _heuristic_scan(self, text: str) -> Tuple[str, List[AuditEntry]]:
        """
        Apply regex heuristics for PII that may not be in the token map
        (e.g. PII introduced by the LLM itself or hallucinated data).
        """
        entries: List[AuditEntry] = []
        working = text

        for pii_type, pattern in _HEURISTIC_PATTERNS.items():
            for match in pattern.finditer(working):
                matched = match.group(0)
                # If we already have a placeholder for this value, skip
                if self._map.get_placeholder(matched):
                    continue
                placeholder = f"[{pii_type}_DETECTED]"
                working = working.replace(matched, placeholder, 1)

                entries.append(self._make_entry(
                    reason       = InterceptionReason.PATTERN_MATCH,
                    action       = SanitizationAction.REDACTED,
                    token_type   = pii_type,
                    leaked_value = matched,
                    placeholder  = placeholder,
                    text         = text,
                ))

        return working, entries

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_entry(
        self,
        *,
        reason:       InterceptionReason,
        action:       SanitizationAction,
        token_type:   str,
        leaked_value: str,
        placeholder:  str,
        text:         str,
    ) -> AuditEntry:
        idx     = text.find(leaked_value)
        start   = max(0, idx - self._ctx_window)
        end     = min(len(text), idx + len(leaked_value) + self._ctx_window)
        snippet = text[start:end].replace(leaked_value, f"<{placeholder}>")

        return AuditEntry(
            entry_id             = str(uuid.uuid4()),
            timestamp            = datetime.now(timezone.utc).isoformat(),
            session_id           = self._map.session_id,
            reason               = reason,
            action               = action,
            token_type           = token_type,
            original_value_hash  = hashlib.sha256(leaked_value.encode()).hexdigest(),
            placeholder          = placeholder,
            context_snippet      = snippet,
        )

    @staticmethod
    def _token_type_from_placeholder(placeholder: str) -> str:
        """Extract the human-readable token type from a placeholder string."""
        # e.g. "USER_NAME_01" → "USER_NAME"
        #      "HONEY_EMAIL_02" → "HONEY_EMAIL"
        parts = placeholder.rsplit("_", 1)
        return parts[0] if len(parts) == 2 and parts[1].isdigit() else placeholder
