import copy
import json
from pathlib import Path
from typing import Any

import pytest

from src.c1.canonicalizer import (
    CanonicalizationResult,
    Canonicalizer,
    AdapterSelectionError,
    RawTraceFormatError,
    NormalizedTraceValidationError,
    canonicalize,
    canonicalize_with_report,
    canonicalize_file,
)


@pytest.fixture
def minimal_raw_trace():
    return {
        "trace_id": "case_001",
        "source": "custom_react",
        "events": [
            {
                "event_id": "raw_001",
                "event_type": "tool_call",
                "step_id": 1,
                "tool_name": "gmail_send",
                "input": {"recipient": "team@example.com"},
                "status": "pending",
            }
        ],
    }


def test_canonicalize_minimal_custom_trace(minimal_raw_trace):
    trace = canonicalize(minimal_raw_trace)

    assert trace["trace_id"] == "case_001"
    assert trace["schema_version"] == "0.1"
    assert len(trace["events"]) == 1

    event = trace["events"][0]
    # The normalizer for custom_react should map gmail_send to send_email
    assert event["action_name"] == "send_email"
    assert event["effect_type"] == "send"
    assert event["target_resource"] == "email"


def test_canonicalize_with_report_returns_report(minimal_raw_trace):
    result = canonicalize_with_report(minimal_raw_trace)

    assert result.trace["trace_id"] == "case_001"
    assert result.report.trace_id == "case_001"
    assert result.report.raw_event_count == 1
    assert result.report.normalized_event_count == 1
    assert result.report.adapter_name == "CustomReActAdapter"


def test_unsupported_source_raises(minimal_raw_trace):
    minimal_raw_trace["source"] = "unknown_framework"

    with pytest.raises(AdapterSelectionError):
        canonicalize(minimal_raw_trace)


def test_missing_trace_id_raises(minimal_raw_trace):
    minimal_raw_trace.pop("trace_id")

    with pytest.raises(RawTraceFormatError):
        canonicalize(minimal_raw_trace)


def test_missing_events_raises():
    raw_trace = {"trace_id": "case_001", "source": "custom_react"}

    with pytest.raises(RawTraceFormatError):
        canonicalize(raw_trace)


def test_raw_trace_is_not_mutated(minimal_raw_trace):
    original = copy.deepcopy(minimal_raw_trace)
    canonicalize(minimal_raw_trace)

    assert minimal_raw_trace == original


class FakeReport:
    def __init__(self, valid: bool, errors=None, warnings=None):
        self.valid = valid
        self.errors = errors or []
        self.warnings = warnings or []

    def to_dict(self):
        return {"valid": self.valid, "errors": self.errors, "warnings": self.warnings}


class FakeIssue:
    def __init__(self, code, message):
        self.code = code
        self.message = message


class FakeNormalizer:
    def __init__(self, calls):
        self.calls = calls

    def normalize_raw_event(self, raw_event, trace_id):
        self.calls.append("normalize")
        return {"event_id": "e_001"}


class FakeCausalLinker:
    def __init__(self, calls):
        self.calls = calls

    def link_trace(self, trace):
        self.calls.append("causal")
        return trace


class FakeEvidenceExtractor:
    def __init__(self, calls):
        self.calls = calls

    def extract_trace(self, trace):
        self.calls.append("evidence")
        return trace


class FakeValidator:
    def __init__(self, calls):
        self.calls = calls

    def validate_trace(self, trace):
        self.calls.append("validate")
        return FakeReport(valid=True)


def test_pipeline_calls_modules_in_order(minimal_raw_trace):
    calls = []
    
    canonicalizer = Canonicalizer(
        normalizer=FakeNormalizer(calls),
        causal_linker=FakeCausalLinker(calls),
        evidence_extractor=FakeEvidenceExtractor(calls),
        validator=FakeValidator(calls),
    )
    
    canonicalizer.canonicalize(minimal_raw_trace)
    assert calls == ["normalize", "causal", "evidence", "validate"]


class FakeInvalidValidator:
    def validate_trace(self, trace):
        report = FakeReport(valid=False, errors=[FakeIssue("ERR01", "Invalid trace")])
        return report


def test_validation_failure_raises_by_default(minimal_raw_trace):
    canonicalizer = Canonicalizer(validator=FakeInvalidValidator())

    with pytest.raises(NormalizedTraceValidationError):
        canonicalizer.canonicalize(minimal_raw_trace)


def test_validation_failure_can_be_non_fatal(minimal_raw_trace):
    canonicalizer = Canonicalizer(
        validator=FakeInvalidValidator(),
        fail_on_validation_error=False,
    )

    result = canonicalizer.canonicalize_with_report(minimal_raw_trace)

    assert result.report.schema_valid is False
    assert len(result.report.errors) > 0


def test_canonicalize_file_writes_output_and_report(tmp_path, minimal_raw_trace):
    input_path = tmp_path / "raw.json"
    output_path = tmp_path / "normalized.json"
    report_path = tmp_path / "report.json"

    with open(input_path, "w") as f:
        json.dump(minimal_raw_trace, f)

    result = canonicalize_file(
        input_path,
        output_path=output_path,
        report_path=report_path,
    )

    assert output_path.exists()
    assert report_path.exists()
    
    with open(output_path) as f:
        saved_trace = json.load(f)
    assert saved_trace["trace_id"] == "case_001"

    with open(report_path) as f:
        saved_report = json.load(f)
    assert saved_report["trace_id"] == "case_001"
