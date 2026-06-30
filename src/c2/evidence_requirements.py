from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from src.c2.rule_ir import RuleIR, PreservationResult
from src.c2.field_resolver import find_any_field_locations


def get_trace_id(trace: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> str:
    if isinstance(trace, Mapping):
        if "trace_id" in trace:
            return trace["trace_id"]
        if "events" in trace and isinstance(trace["events"], Sequence) and len(trace["events"]) > 0:
            first_event = trace["events"][0]
            if isinstance(first_event, Mapping) and "trace_id" in first_event:
                return first_event["trace_id"]
    elif isinstance(trace, Sequence) and len(trace) > 0:
        first_event = trace[0]
        if isinstance(first_event, Mapping) and "trace_id" in first_event:
            return first_event["trace_id"]
    
    return "<unknown_trace>"


def dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    seen = set()
    result = []
    for val in values:
        if val and val not in seen:
            seen.add(val)
            result.append(val)
    return result


def normalize_required_evidence(fields: Iterable[str]) -> list[str]:
    cleaned = [f.strip() for f in fields if f and f.strip()]
    return dedupe_preserve_order(cleaned)


def find_evidence_locations(
    trace: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    field_path: str
) -> list[str]:
    locations = find_any_field_locations(trace, field_path)
    return dedupe_preserve_order(locations)


def build_evidence_map(
    trace: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    required_evidence: Iterable[str]
) -> tuple[dict[str, list[str]], list[str]]:
    evidence_map = {}
    missing_evidence = []
    
    for field in normalize_required_evidence(required_evidence):
        locations = find_evidence_locations(trace, field)
        if locations:
            evidence_map[field] = locations
        else:
            missing_evidence.append(field)
            
    return evidence_map, missing_evidence


def check_required_evidence(
    trace: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    rule_ir: RuleIR,
    *,
    triggered_event_ids: list[str] | None = None
) -> PreservationResult:
    trace_id = get_trace_id(trace)
    req_evidence = normalize_required_evidence(rule_ir.required_evidence)
    
    if not req_evidence:
        return PreservationResult.complete(
            policy_id=rule_ir.policy_id,
            trace_id=trace_id,
            evidence_map={},
            triggered_event_ids=triggered_event_ids
        )
        
    evidence_map, missing_evidence = build_evidence_map(trace, req_evidence)
    
    if missing_evidence:
        reason = f"Missing required evidence: {', '.join(missing_evidence)}"
        return PreservationResult.incomplete(
            policy_id=rule_ir.policy_id,
            trace_id=trace_id,
            missing_evidence=missing_evidence,
            evidence_map=evidence_map,
            triggered_event_ids=triggered_event_ids,
            reason=reason
        )
        
    return PreservationResult.complete(
        policy_id=rule_ir.policy_id,
        trace_id=trace_id,
        evidence_map=evidence_map,
        triggered_event_ids=triggered_event_ids
    )


def check_required_evidence_for_rules(
    trace: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    rules: Iterable[RuleIR]
) -> list[PreservationResult]:
    return [check_required_evidence(trace, rule) for rule in rules]


def preservation_results_to_rows(
    results: Iterable[PreservationResult]
) -> list[dict[str, Any]]:
    rows = []
    for res in results:
        rows.append({
            "trace_id": res.trace_id,
            "policy_id": res.policy_id,
            "status": res.status,
            "missing_evidence": "|".join(res.missing_evidence),
            "evidence_fields": "|".join(res.evidence_map.keys()),
            "triggered_event_ids": "|".join(res.triggered_event_ids),
            "reason": res.reason or ""
        })
    return rows
