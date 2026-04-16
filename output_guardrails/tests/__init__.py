"""
output_guardrails
=================
Output-side PII guardrails for PII-Safe — closes the loop on prompt injection
by monitoring LLM responses before they reach the user or downstream tools.

Public surface::

    from output_guardrails import OutputSanitizer, SessionTokenMap, AuditLogger

See output_sanitizer.py for full documentation.
"""

from .output_sanitizer import (
    AuditEntry,
    AuditLogger,
    InterceptionReason,
    SanitizationAction,
    SanitizationResult,
    OutputSanitizer,
    SessionTokenMap,
    HONEY_TOKEN_PREFIX,
)

__all__ = [
    "AuditEntry",
    "AuditLogger",
    "InterceptionReason",
    "SanitizationAction",
    "SanitizationResult",
    "OutputSanitizer",
    "SessionTokenMap",
    "HONEY_TOKEN_PREFIX",
]
