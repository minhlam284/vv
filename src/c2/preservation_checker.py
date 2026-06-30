import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .rule_ir import Condition, RuleIR, PreservationResult
from .field_resolver import get_any_field, has_field, iter_events, MISSING, is_missing
from .evidence_requirements import check_required_evidence

def normalize_op(op: str) -> str:
    """Normalize operator string to a standard form."""
    op = op.strip().lower()
    aliases = {
        "=": "eq",
        "==": "eq",
        "!=": "neq",
        "not_in": "not_in",
        "not exists": "not_exists"
    }
    op = aliases.get(op, op)
    supported_ops = {"eq", "neq", "in", "not_in", "exists", "not_exists", "contains"}
    if op not in supported_ops:
        raise ValueError(f"Unsupported operator: {op}")
    return op

def evaluate_condition(event: Mapping[str, Any], condition: Condition) -> bool:
    """Evaluate a single condition against an event."""
    op = normalize_op(condition.op)
    val = get_any_field(event, condition.field)

    if op == "exists":
        return not is_missing(val) and val not in (None, "")
    
    if op == "not_exists":
        return is_missing(val) or val in (None, "")

    if is_missing(val):
        return False

    if op == "eq":
        return val == condition.value
    elif op == "neq":
        return val != condition.value
    elif op == "in":
        if not isinstance(condition.value, (list, tuple, set)):
            raise ValueError(f"'in' operator requires a list/tuple/set, got {type(condition.value)}")
        return val in condition.value
    elif op == "not_in":
        if not isinstance(condition.value, (list, tuple, set)):
            raise ValueError(f"'not_in' operator requires a list/tuple/set, got {type(condition.value)}")
        return val not in condition.value
    elif op == "contains":
        if isinstance(val, (list, tuple, set, str)):
            return condition.value in val
        elif isinstance(val, dict):
            return condition.value in val
        return False

    raise ValueError(f"Unsupported operator: {op}")

def match_conditions(
    event: Mapping[str, Any],
    conditions: Sequence[Condition],
    *,
    mode: str = "all"
) -> bool:
    """Match multiple conditions against an event."""
    if mode not in {"all", "any"}:
        raise ValueError(f"Invalid mode: {mode}")
        
    if not conditions:
        return mode == "all"
        
    if mode == "all":
        return all(evaluate_condition(event, cond) for cond in conditions)
    else:
        return any(evaluate_condition(event, cond) for cond in conditions)

def event_matches_when(event: Mapping[str, Any], when: Sequence[Condition]) -> bool:
    """Check if an event matches the rule.when conditions."""
    return match_conditions(event, when, mode="all")

def find_trigger_events(
    trace_or_events: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    when: Sequence[Condition]
) -> list[Mapping[str, Any]]:
    """Find all events that trigger a rule based on its when conditions."""
    return [event for event in iter_events(trace_or_events) if event_matches_when(event, when)]

def find_trigger_event_ids(
    trace_or_events: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    when: Sequence[Condition]
) -> list[str]:
    """Find IDs of all events that trigger a rule based on its when conditions."""
    return [
        str(event.get("event_id", "<unknown_event>"))
        for event in find_trigger_events(trace_or_events, when)
    ]

def _get_trace_id(trace_or_events: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> str:
    """Helper to extract trace_id from trace or its events."""
    if isinstance(trace_or_events, dict) and "trace_id" in trace_or_events:
        return str(trace_or_events["trace_id"])
    for event in iter_events(trace_or_events):
        if "trace_id" in event:
            return str(event["trace_id"])
    return "<unknown_trace>"

def run_preservation_check(
    trace: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    rule_ir: RuleIR
) -> PreservationResult:
    """Run preservation check for a single rule against a trace."""
    triggered_events = find_trigger_events(trace, rule_ir.when)
    
    if not triggered_events:
        return PreservationResult.not_applicable(
            policy_id=rule_ir.policy_id,
            trace_id=_get_trace_id(trace),
            reason="Rule condition did not match any event."
        )
        
    triggered_event_ids = [str(ev.get("event_id", "<unknown_event>")) for ev in triggered_events]
    return check_required_evidence(trace, rule_ir, triggered_event_ids=triggered_event_ids)

def run_preservation_checks(
    trace: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    rules: Iterable[RuleIR]
) -> list[PreservationResult]:
    """Run preservation checks for multiple rules against a trace."""
    return [run_preservation_check(trace, rule) for rule in rules]

def load_trace(path: str | Path) -> dict[str, Any]:
    """Load a trace from a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
