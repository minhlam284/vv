import copy
import pytest
from src.c2.verdict_engine import evaluate_rule, evaluate_rules
from src.c2.rule_ir import RuleIR


def test_p001_safe(p001_safe_trace, p001_rule):
    result = evaluate_rule(p001_safe_trace, p001_rule)
    assert result.verdict == "SAFE"


def test_p001_violation(p001_violation_trace, p001_rule):
    result = evaluate_rule(p001_violation_trace, p001_rule)
    assert result.verdict == "VIOLATION"
    assert "approval" in result.reason.lower() or "missing" in result.reason.lower()


def test_p001_unknown(p001_unknown_trace, p001_rule):
    result = evaluate_rule(p001_unknown_trace, p001_rule)
    assert result.verdict == "UNKNOWN"
    assert "approval.exists" in result.missing_evidence


def test_p002_safe(p002_safe_trace, p002_rule):
    result = evaluate_rule(p002_safe_trace, p002_rule)
    assert result.verdict == "SAFE"


def test_p002_violation(p002_violation_trace, p002_rule):
    result = evaluate_rule(p002_violation_trace, p002_rule)
    assert result.verdict == "VIOLATION"
    assert "untrusted" in result.reason.lower()


def test_p002_unknown(p002_unknown_trace, p002_rule):
    result = evaluate_rule(p002_unknown_trace, p002_rule)
    assert result.verdict == "UNKNOWN"
    assert "taint.label" in result.missing_evidence
    assert "taint.causal_path" in result.missing_evidence


def test_p003_safe(p003_safe_trace, p003_rule):
    result = evaluate_rule(p003_safe_trace, p003_rule)
    assert result.verdict == "SAFE"


def test_p003_violation(p003_violation_trace, p003_rule):
    result = evaluate_rule(p003_violation_trace, p003_rule)
    assert result.verdict == "VIOLATION"
    reason_lower = result.reason.lower()
    assert "failed" in reason_lower or "success" in reason_lower or "link" in reason_lower


def test_p003_unknown(p003_unknown_trace, p003_rule):
    result = evaluate_rule(p003_unknown_trace, p003_rule)
    assert result.verdict == "UNKNOWN"
    reason_lower = result.reason.lower()
    assert "link" in reason_lower or "evidence" in reason_lower or "determine" in reason_lower or result.missing_evidence


def test_unknown_policy_returns_unknown():
    rule = RuleIR.from_dict({
        "policy_id": "P999",
        "name": "unknown_policy",
        "rule_class": ["permission"],
        "when": [{"field": "effect_type", "op": "eq", "value": "test"}],
        "require": [],
        "required_evidence": ["effect_type"],
        "else": "violation"
    })
    trace = {
        "trace_id": "t13",
        "events": [{"event_id": "e_001", "effect_type": "test"}]
    }
    result = evaluate_rule(trace, rule)
    assert result.verdict == "UNKNOWN"


def test_evaluate_rules_preserves_order(p001_rule, p002_rule, p003_rule, p001_safe_trace):
    rules = [p001_rule, p002_rule, p003_rule]
    results = evaluate_rules(p001_safe_trace, rules)
    assert len(results) == 3
    assert results[0].policy_id == "P001"
    assert results[1].policy_id == "P002"
    assert results[2].policy_id == "P003"


def test_p001_inconsistent_approval_contradiction(p001_rule):
    trace = {
        "trace_id": "t4",
        "events": [
            {
                "event_id": "e_001",
                "step_id": 1,
                "effect_type": "send",
                "target_resource": "email",
                "approval": {"exists": False, "status": "approved", "target": {"recipient": "team@example.com"}},
                "typed_args": {"recipient": "team@example.com"},
                "input_refs": ["ref1"]
            }
        ]
    }
    result = evaluate_rule(trace, p001_rule)
    assert result.verdict == "INCONSISTENT"


def test_c2_end_to_end_all_nine_cases(
    p001_rule, p002_rule, p003_rule,
    p001_safe_trace, p001_violation_trace, p001_unknown_trace,
    p002_safe_trace, p002_violation_trace, p002_unknown_trace,
    p003_safe_trace, p003_violation_trace, p003_unknown_trace
):
    cases = [
        (p001_safe_trace, p001_rule, "SAFE"),
        (p001_violation_trace, p001_rule, "VIOLATION"),
        (p001_unknown_trace, p001_rule, "UNKNOWN"),
        (p002_safe_trace, p002_rule, "SAFE"),
        (p002_violation_trace, p002_rule, "VIOLATION"),
        (p002_unknown_trace, p002_rule, "UNKNOWN"),
        (p003_safe_trace, p003_rule, "SAFE"),
        (p003_violation_trace, p003_rule, "VIOLATION"),
        (p003_unknown_trace, p003_rule, "UNKNOWN"),
    ]

    for trace, rule, expected in cases:
        result = evaluate_rule(trace, rule)
        assert result.verdict == expected
