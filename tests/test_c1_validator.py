"""
tests/test_c1_validator.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Tests for c1.validator — Task 4.8.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SRC_DIR = Path(__file__).resolve().parents[1] / "src "
sys.path.insert(0, str(_SRC_DIR))

from c1.validator import validate_trace, assert_valid_trace, InvalidTraceError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def schema_path() -> Path:
    return Path(__file__).resolve().parents[1] / "phase_2" / "outputs" / "normalized_event_schema.json"

@pytest.fixture
def vocabulary_path() -> Path:
    return Path(__file__).resolve().parents[1] / "phase_2" / "outputs" / "vocabulary.yaml"

@pytest.fixture
def valid_trace() -> dict:
    return {
        "trace_id": "t1",
        "schema_version": "0.1",
        "events": [
            {
                "event_id": "e_001",
                "trace_id": "t1",
                "step_id": 1,
                "timestamp": None,
                "parent_event": None,
                "phase": "before_action",
                "action_type": "tool_call",
                "action_name": "send_email",
                "effect_type": "send",
                "target_resource": "email",
                "typed_args": {"recipient": "team@example.com"},
                "tool_output": None,
                "input_refs": None,
                "output_ref": None,
                "pre_state": None,
                "post_state": None,
                "status": "pending",
                "error_type": None,
                "reversibility": "hard",
                "raw_event_ref": "raw_001",
                "metadata": {},
            }
        ],
    }

@pytest.fixture
def invalid_trace(valid_trace: dict) -> dict:
    trace = dict(valid_trace)
    # duplicate event_id
    trace["events"].append(dict(trace["events"][0]))
    return trace


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_valid_minimal_trace_passes(valid_trace, schema_path, vocabulary_path):
    report = validate_trace(
        valid_trace,
        schema_path=schema_path,
        vocabulary_path=vocabulary_path,
    )
    assert report.valid is True


def test_duplicate_event_id_fails(valid_trace, schema_path, vocabulary_path):
    event_copy = dict(valid_trace["events"][0])
    valid_trace["events"].append(event_copy)

    report = validate_trace(valid_trace, schema_path, vocabulary_path)

    assert report.valid is False
    assert any(e.code == "DUPLICATE_EVENT_ID" for e in report.errors)


def test_trace_id_mismatch_fails(valid_trace, schema_path, vocabulary_path):
    valid_trace["events"][0]["trace_id"] = "other_trace"

    report = validate_trace(valid_trace, schema_path, vocabulary_path)

    assert report.valid is False
    assert any(e.code == "TRACE_ID_MISMATCH" for e in report.errors)


def test_negative_step_id_fails(valid_trace, schema_path, vocabulary_path):
    valid_trace["events"][0]["step_id"] = -1

    report = validate_trace(valid_trace, schema_path, vocabulary_path)

    assert report.valid is False
    assert any(e.code == "NEGATIVE_STEP_ID" for e in report.errors)


def test_unordered_step_id_fails(valid_trace, schema_path, vocabulary_path):
    e1 = valid_trace["events"][0]
    e2 = dict(e1)
    e2["event_id"] = "e_002"
    e2["step_id"] = 0

    valid_trace["events"] = [e1, e2]

    report = validate_trace(valid_trace, schema_path, vocabulary_path)

    assert report.valid is False
    assert any(e.code == "STEP_ID_NOT_ORDERED" for e in report.errors)


def test_broken_parent_event_fails(valid_trace, schema_path, vocabulary_path):
    valid_trace["events"][0]["parent_event"] = "missing_event"

    report = validate_trace(valid_trace, schema_path, vocabulary_path)

    assert report.valid is False
    assert any(e.code == "BROKEN_PARENT_EVENT_REF" for e in report.errors)


def test_broken_approval_event_fails(valid_trace, schema_path, vocabulary_path):
    valid_trace["events"][0]["approval"] = {
        "exists": True,
        "status": "approved",
        "target": {"recipient": "team@example.com"},
        "approved_by": "user",
        "approval_event": "missing_event",
    }

    report = validate_trace(valid_trace, schema_path, vocabulary_path)

    assert report.valid is False
    assert any(e.code == "BROKEN_APPROVAL_EVENT_REF" for e in report.errors)


def test_unresolved_input_ref_is_warning(valid_trace, schema_path, vocabulary_path):
    valid_trace["events"][0]["input_refs"] = ["missing_doc"]

    report = validate_trace(valid_trace, schema_path, vocabulary_path)

    assert report.valid is True
    assert any(w.code == "UNRESOLVED_INPUT_REF" for w in report.warnings)


def test_invalid_enum_fails(valid_trace, schema_path, vocabulary_path):
    valid_trace["events"][0]["phase"] = "bad_phase"

    report = validate_trace(valid_trace, schema_path, vocabulary_path)

    assert report.valid is False
    assert any(
        e.code in {"JSON_SCHEMA_ERROR", "VOCAB_ENUM_MISMATCH"}
        for e in report.errors
    )


def test_missing_approval_does_not_fail(valid_trace, schema_path, vocabulary_path):
    valid_trace["events"][0].pop("approval", None)

    report = validate_trace(valid_trace, schema_path, vocabulary_path)

    assert report.valid is True


def test_assert_valid_trace_raises(invalid_trace, schema_path, vocabulary_path):
    with pytest.raises(InvalidTraceError):
        assert_valid_trace(
            invalid_trace,
            schema_path=schema_path,
            vocabulary_path=vocabulary_path,
        )
