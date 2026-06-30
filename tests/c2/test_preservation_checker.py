import pytest
from src.c2.preservation_checker import (
    evaluate_condition,
    find_trigger_event_ids,
    run_preservation_check,
)
from src.c2.rule_ir import Condition


def test_condition_eq_matches():
    event = {"effect_type": "send"}
    condition = Condition.from_dict({"field": "effect_type", "op": "eq", "value": "send"})
    assert evaluate_condition(event, condition) is True


def test_condition_eq_missing_false():
    event = {}
    condition = Condition.from_dict({"field": "effect_type", "op": "eq", "value": "send"})
    assert evaluate_condition(event, condition) is False


def test_condition_neq_missing_false():
    event = {}
    condition = Condition.from_dict({"field": "taint.label", "op": "neq", "value": "untrusted"})
    assert evaluate_condition(event, condition) is False


def test_condition_in_matches():
    event = {"effect_type": "delete"}
    condition = Condition.from_dict({"field": "effect_type", "op": "in", "value": ["delete", "write"]})
    assert evaluate_condition(event, condition) is True


def test_condition_exists():
    event = {"approval": {"status": "approved"}}
    condition = Condition.from_dict({"field": "approval.status", "op": "exists"})
    assert evaluate_condition(event, condition) is True


def test_condition_not_exists():
    event = {"approval": {}}
    condition = Condition.from_dict({"field": "approval.status", "op": "not_exists"})
    assert evaluate_condition(event, condition) is True


def test_condition_contains_list():
    event = {"input_refs": ["doc_001", "doc_002"]}
    condition = Condition.from_dict({"field": "input_refs", "op": "contains", "value": "doc_001"})
    assert evaluate_condition(event, condition) is True


def test_find_trigger_events_p001(p001_safe_trace, p001_rule):
    assert find_trigger_event_ids(p001_safe_trace, p001_rule.when) == ["e_002"]


def test_run_preservation_check_p001_complete(p001_safe_trace, p001_rule):
    result = run_preservation_check(p001_safe_trace, p001_rule)
    assert result.status == "COMPLETE"
    assert result.triggered_event_ids == ["e_002"]


def test_run_preservation_check_p001_incomplete(p001_unknown_trace, p001_rule):
    result = run_preservation_check(p001_unknown_trace, p001_rule)
    assert result.status == "INCOMPLETE"
    assert result.triggered_event_ids == ["e_001"]
    assert "approval.exists" in result.missing_evidence


def test_run_preservation_check_no_trigger_not_applicable(p001_rule):
    trace = {
        "trace_id": "test_no_trigger",
        "events": [
            {
                "event_id": "e_001",
                "effect_type": "retrieve"
            }
        ]
    }
    result = run_preservation_check(trace, p001_rule)
    assert result.status == "NOT_APPLICABLE"


def test_run_preservation_check_p002_missing_taint_incomplete(p002_unknown_trace, p002_rule):
    result = run_preservation_check(p002_unknown_trace, p002_rule)
    assert result.status == "INCOMPLETE"
    assert result.triggered_event_ids == ["e_002"]
    assert "taint.label" in result.missing_evidence
    assert "taint.causal_path" in result.missing_evidence


def test_run_preservation_check_p003_complete(p003_violation_trace, p003_rule):
    result = run_preservation_check(p003_violation_trace, p003_rule)
    assert result.status == "COMPLETE"
    assert result.triggered_event_ids == ["e_002"]
