# Output Guardrails for Indirect Prompt Injection Defense

**Fixes:** [c2siorg/PII-Safe Issue #16](https://github.com/c2siorg/PII-Safe/issues/16)

This module adds an `OutputSanitizer` layer to [PII-Safe](https://github.com/c2siorg/PII-Safe) — a secondary post-processing guardrail that intercepts LLM responses **before** they reach the user or any external tool, closing the loop on output-side prompt injection attacks.

---

## Problem

PII-Safe already redacts PII on the **input** side before it reaches the LLM. But agentic workflows face a second attack surface: **indirect prompt injection** can trick the LLM into echoing back real PII in its *output*, bypassing all input-level protections.

---

## Solution — `OutputSanitizer`

Three-layer guardrail applied to every LLM response:

### 1. Mapping Check
Scans the LLM's output for any real PII values that exist in the session's pseudonymisation token map. If found, replaces them back with their placeholder tokens.

```
LLM says: "The user is Alice Johnson, email alice@example.com"
After:     "The user is NAME_01, email EMAIL_01"
```

### 2. Honey-Token Monitoring
Trap tokens (prefixed `HONEY_`) are injected into sensitive fields during input pseudonymisation. They should **never** appear in any LLM output. If one surfaces, an immediate `security_alert=True` is raised — indicating the model was manipulated.

```
LLM says: "Internal key: HONEY_ROUTING_KEY_01"
After:     "Internal key: [REDACTED]"   ← + security_alert raised
```

### 3. Heuristic Scan (bonus layer)
Regex-based fallback that catches PII not in the token map — hallucinated emails, SSNs, phone numbers, IP addresses, credit card numbers.

### 4. Audit Trail
Every interception is logged as a structured, timestamped entry with session ID, reason, action, token type, and a SHA-256 hash of the leaked value (raw PII is never stored). Entries can be exported as JSON or written to a `.jsonl` file.

---

## File Structure

```
output_guardrails/
├── __init__.py                  # Public API
├── output_sanitizer.py          # Core module
├── example_integration.py       # End-to-end demo
└── tests/
    └── test_output_sanitizer.py # 27 tests, 7 test classes
```

---

## Quick Start

```python
from output_guardrails import OutputSanitizer, SessionTokenMap, AuditLogger

# 1. Build the token map during input pseudonymisation (existing PII-Safe step)
token_map = SessionTokenMap(session_id="session-001")
token_map.add("Alice Johnson", "NAME")
token_map.add("alice@example.com", "EMAIL")
token_map.add_honey("trap-key-abc", "SECRET")   # honey-token

# 2. After getting the LLM response, sanitize it
audit_logger = AuditLogger(log_path="audit.jsonl")
sanitizer    = OutputSanitizer(token_map, audit_logger)

result = sanitizer.sanitize(llm_response_text)

# 3. Check results
if result.security_alert:
    raise Exception("Prompt injection detected — honey-token triggered!")

safe_text = result.sanitized_text
print(result.summary())
```

---

## Running Tests

```bash
pip install pytest
pytest tests/test_output_sanitizer.py -v
```

All 27 tests pass across these categories:
- Clean output (no false positives)
- Mapping check (PII leak detection)
- Honey-token monitoring
- Heuristic scan
- Audit trail (fields, privacy, filtering, JSON export, file persistence)
- `SanitizationResult` helpers
- `SessionTokenMap` unit tests

---

## How It Fits Into PII-Safe

```
[User input with PII]
      ↓
InputPseudonymiser   ← existing PII-Safe layer
      ↓
[Redacted prompt → LLM]
      ↓
[LLM response — may leak PII via prompt injection]
      ↓
OutputSanitizer      ← this module (Issue #16)
      ↓
[Clean, safe response → user / external tool]
```

---

## License

Apache 2.0 — consistent with the parent [PII-Safe](https://github.com/c2siorg/PII-Safe) project.
