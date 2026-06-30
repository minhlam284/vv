import pytest
from src.c2.evidence_requirements import check_required_evidence, build_evidence_map
from src.c2.rule_ir import RuleIR


def test_p001_safe_evidence_complete(p001_safe_trace, p001_rule):
    result = check_required_evidence(p001_safe_trace, p001_rule)
    assert result.status == "COMPLETE"
    assert result.missing_evidence == []
    assert "effect_type" in result.evidence_map
    assert "approval.status" in result.evidence_map


def test_p001_unknown_missing_approval_evidence(p001_unknown_trace, p001_rule):
    result = check_required_evidence(p001_unknown_trace, p001_rule)
    assert result.status == "INCOMPLETE"
    assert "approval.exists" in result.missing_evidence
    assert "approval.status" in result.missing_evidence
    assert "approval.target" in result.missing_evidence


def test_null_is_missing():
    trace = {
        "trace_id": "test_null",
        "events": [
            {"event_id": "e_001", "error_type": None}
        ]
    }
    rule = RuleIR.from_dict({
        "policy_id": "P_TEST",
        "name": "test_null",
        "rule_class": ["permission"],
        "when": [],
        "require": [],
        "required_evidence": ["error_type"],
        "else": "violation"
    })
    result = check_required_evidence(trace, rule)
    assert result.status == "INCOMPLETE"
    assert "error_type" in result.missing_evidence


def test_false_is_valid_evidence():
    trace = {
        "trace_id": "test_false",
        "events": [
            {"event_id": "e_001", "approval": {"exists": False, "status": "missing"}}
        ]
    }
    rule = RuleIR.from_dict({
        "policy_id": "P_TEST",
        "name": "test_false",
        "rule_class": ["permission"],
        "when": [],
        "require": [],
        "required_evidence": ["approval.exists", "approval.status"],
        "else": "violation"
    })
    result = check_required_evidence(trace, rule)
    assert result.status == "COMPLETE"


def test_empty_list_is_missing():
    trace = {
        "trace_id": "test_empty_list",
        "events": [
            {"event_id": "e_001", "input_refs": []}
        ]
    }
    rule = RuleIR.from_dict({
        "policy_id": "P_TEST",
        "name": "test_empty_list",
        "rule_class": ["permission"],
        "when": [],
        "require": [],
        "required_evidence": ["input_refs"],
        "else": "violation"
    })
    result = check_required_evidence(trace, rule)
    assert result.status == "INCOMPLETE"


def test_alias_causal_path_complete():
    trace = {
        "trace_id": "test_alias",
        "events": [
            {"event_id": "e_001", "taint": {"causal_path": ["e_001"]}}
        ]
    }
    rule = RuleIR.from_dict({
        "policy_id": "P_TEST",
        "name": "test_alias",
        "rule_class": ["permission"],
        "when": [],
        "require": [],
        "required_evidence": ["causal_path"],
        "else": "violation"
    })
    result = check_required_evidence(trace, rule)
    assert result.status == "COMPLETE"


def test_policy_aliases_complete():
    trace = {
        "trace_id": "test_alias2",
        "events": [
            {
                "event_id": "e_001",
                "policy": {
                    "allowed_action_set": ["read"],
                    "policy_version": "1.0"
                }
            }
        ]
    }
    rule = RuleIR.from_dict({
        "policy_id": "P_TEST",
        "name": "test_alias2",
        "rule_class": ["permission"],
        "when": [],
        "require": [],
        "required_evidence": ["allowed_action_set", "policy_version"],
        "else": "violation"
    })
    result = check_required_evidence(trace, rule)
    assert result.status == "COMPLETE"


def test_empty_required_evidence_complete():
    trace = {
        "trace_id": "test_empty",
        "events": [{"event_id": "e_001"}]
    }
    rule = RuleIR.from_dict({
        "policy_id": "P_TEST",
        "name": "test_empty",
        "rule_class": ["permission"],
        "when": [],
        "require": [],
        "required_evidence": ["dummy"],
        "else": "violation"
    })
    rule.required_evidence = []
    result = check_required_evidence(trace, rule)
    assert result.status == "COMPLETE"
