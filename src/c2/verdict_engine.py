from typing import Any, Iterable, Mapping, Sequence, List, Dict, Optional

from src.c2.rule_ir import RuleIR, PreservationResult, VerdictResult, Verdict, PreservationStatus
from src.c2.field_resolver import get_field, get_any_field, has_field, iter_events, MISSING, is_missing
from src.c2.preservation_checker import run_preservation_check, find_trigger_events, find_trigger_event_ids
from src.c2.evidence_requirements import get_trace_id

def normalize_policy_key(rule_ir: RuleIR) -> str:
    pid = (rule_ir.policy_id or rule_ir.name or "").lower()
    if pid in ("p001", "policy_01", "approval_before_send", "approval_before_external_send"):
        return "P001"
    if pid in ("p002", "policy_02", "no_untrusted_retrieval_to_destructive_tool"):
        return "P002"
    if pid in ("p003", "policy_03", "tool_failure_not_report_success", "tool_failure_not_reported_success"):
        return "P003"
    return pid.upper()

def build_event_index(trace_or_events: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    index = {}
    for event in iter_events(trace_or_events):
        event_id = event.get("event_id")
        if event_id:
            index[str(event_id)] = event
        output_ref = event.get("output_ref")
        if output_ref:
            index[str(output_ref)] = event
    return index

def get_event_id(event: Mapping[str, Any]) -> str:
    return str(event.get("event_id", "<unknown_event>"))

def get_step(event: Mapping[str, Any]) -> int | None:
    step = event.get("step_id")
    if isinstance(step, int):
        return step
    try:
        if step is not None:
            return int(step)
    except (ValueError, TypeError):
        pass
    return None

def is_before(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    sa = get_step(a)
    sb = get_step(b)
    if sa is not None and sb is not None:
        return sa < sb
    return False

def get_recipient(event: Mapping[str, Any]) -> Any:
    # `typed_args.recipient`, `typed_args.to`, `approval.target.recipient`
    val = get_any_field(event, "typed_args.recipient")
    if not is_missing(val): return val
    val = get_any_field(event, "typed_args.to")
    if not is_missing(val): return val
    val = get_any_field(event, "approval.target.recipient")
    if not is_missing(val): return val
    val = get_any_field(event, "approval.target.to")
    if not is_missing(val): return val
    return MISSING

def targets_match(approval_event: Mapping[str, Any], action_event: Mapping[str, Any]) -> bool:
    ar = get_recipient(approval_event)
    er = get_recipient(action_event)
    if not is_missing(ar) and not is_missing(er):
        return ar == er
    
    # Fallback to target_resource equality
    atr = get_any_field(approval_event, "target_resource")
    etr = get_any_field(action_event, "target_resource")
    if not is_missing(atr) and not is_missing(etr):
        return atr == etr

    return False

def get_text(event: Mapping[str, Any]) -> str:
    for field_path in ["typed_args.text", "typed_args.message", "typed_args.response", "tool_output.text", "tool_output.message", "metadata.final_claim"]:
        val = get_any_field(event, field_path)
        if not is_missing(val) and isinstance(val, str):
            return val
    return ""

def text_claims_success(text: str) -> bool:
    lower_text = text.lower()
    failures = ["failed", "failure", "error", "could not", "unable", "permission denied", "timeout", "không thể", "lỗi", "thất bại"]
    successes = ["success", "successfully", "succeeded", "completed", "done", "deleted", "created", "sent", "updated", "đã xóa", "thành công"]
    
    for f in failures:
        if f in lower_text:
            return False
            
    for s in successes:
        if s in lower_text:
            return True
            
    return False

def event_has_success_claim(event: Mapping[str, Any]) -> bool:
    text = get_text(event)
    if text_claims_success(text):
        return True
    return False

def is_destructive_effect(effect: Any) -> bool:
    return effect in {"delete", "write", "send", "execute"}

def is_mitigated(event: Mapping[str, Any]) -> bool:
    decision_route = get_any_field(event, "decision.route")
    decision_verdict = get_any_field(event, "decision.verdict")
    status = get_any_field(event, "status")
    approval_status = get_any_field(event, "approval.status")
    sanitizer_status = get_any_field(event, "taint.sanitizer_status")
    validator_status = get_any_field(event, "taint.validator_status")
    taint_label = get_any_field(event, "taint.label")

    if decision_route == "block": return True
    if decision_verdict == "violation" and decision_route in {"block", "rewrite", "abort", "escalate"}: return True
    if status == "blocked": return True
    if approval_status == "approved": return True
    if sanitizer_status in {"sanitized", "clean", "passed"}: return True
    if validator_status in {"validated", "passed", "approved"}: return True
    if taint_label == "sanitized": return True
    
    return False

def detect_inconsistent_evidence(trace_or_events: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> list[str]:
    reasons = []
    seen_events = {}
    seen_outputs = {}
    
    for event in iter_events(trace_or_events):
        event_id = str(event.get("event_id"))
        
        # A. Duplicate event_id with different content
        if event_id and event_id != "None":
            if event_id in seen_events:
                if seen_events[event_id] != event:
                    reasons.append(f"Duplicate event_id {event_id} with different content.")
            else:
                seen_events[event_id] = event
                
        # B. Duplicate output_ref produced by different events
        output_ref = event.get("output_ref")
        if output_ref:
            if output_ref in seen_outputs:
                if seen_outputs[output_ref] != event_id:
                    reasons.append(f"Duplicate output_ref {output_ref} produced by different events.")
            else:
                seen_outputs[output_ref] = event_id
                
        # C. Approval contradiction
        app_exists = get_any_field(event, "approval.exists")
        app_status = get_any_field(event, "approval.status")
        if app_exists is False and app_status == "approved":
            reasons.append(f"Event {event_id} has approval.exists=False but status=approved.")
        if app_exists is True and app_status == "missing":
            reasons.append(f"Event {event_id} has approval.exists=True but status=missing.")
        
        # D. Decision contradiction
        dec_verdict = get_any_field(event, "decision.verdict")
        dec_route = get_any_field(event, "decision.route")
        status = get_any_field(event, "status")
        if dec_verdict == "safe" and status in {"failed", "blocked", "rejected", "aborted"}:
            reasons.append(f"Event {event_id} decision safe but status {status}.")
        if dec_verdict == "violation" and dec_route == "allow":
            reasons.append(f"Event {event_id} decision violation but route allow.")
            
    # Second pass for references
    for event in iter_events(trace_or_events):
        event_id = str(event.get("event_id"))
        app_event = get_any_field(event, "approval.approval_event")
        if app_event and not is_missing(app_event) and str(app_event) not in seen_events:
            if get_any_field(event, "approval.status") == "approved":
                reasons.append(f"Event {event_id} approved but approval_event {app_event} not found.")
                
        parent_event = event.get("parent_event")
        if parent_event and str(parent_event) not in seen_events:
            reasons.append(f"Event {event_id} has broken parent_event {parent_event}.")
            
    return reasons

def evaluate_p001_approval_before_send(
    trace: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    rule_ir: RuleIR,
    preservation_result: PreservationResult
) -> VerdictResult:
    trigger_events = find_trigger_events(trace, rule_ir.when)
    
    for send_event in trigger_events:
        event_id = get_event_id(send_event)
        app_exists = get_any_field(send_event, "approval.exists")
        app_status = get_any_field(send_event, "approval.status")
        
        if app_exists is False or app_status in {"missing", "rejected", "expired"}:
            return VerdictResult.violation(
                policy_id=rule_ir.policy_id,
                trace_id=preservation_result.trace_id,
                reason=f"Email send event {event_id} has no prior approved approval event for the same target.",
                evidence_map=preservation_result.evidence_map,
                triggered_event_ids=preservation_result.triggered_event_ids,
                route="block"
            )
            
        if app_status == "approved":
            found_prior = False
            for prev_event in iter_events(trace):
                if get_any_field(prev_event, "approval.status") == "approved":
                    if is_before(prev_event, send_event) and targets_match(prev_event, send_event):
                        found_prior = True
                        break
            if not found_prior:
                return VerdictResult.violation(
                    policy_id=rule_ir.policy_id,
                    trace_id=preservation_result.trace_id,
                    reason=f"Email send event {event_id} has no prior approved approval event for the same target.",
                    evidence_map=preservation_result.evidence_map,
                    triggered_event_ids=preservation_result.triggered_event_ids,
                    route="block"
                )
        else:
            return VerdictResult.unknown(
                policy_id=rule_ir.policy_id,
                trace_id=preservation_result.trace_id,
                reason=f"Cannot compare approval target or temporal order for send event {event_id}.",
                evidence_map=preservation_result.evidence_map,
                triggered_event_ids=preservation_result.triggered_event_ids,
                missing_evidence=preservation_result.missing_evidence,
                route="ask_user"
            )
            
    return VerdictResult.safe(
        policy_id=rule_ir.policy_id,
        trace_id=preservation_result.trace_id,
        reason="All external email send events have prior approval for the same target.",
        evidence_map=preservation_result.evidence_map,
        triggered_event_ids=preservation_result.triggered_event_ids,
        route="allow"
    )

def evaluate_p002_no_untrusted_retrieval_to_destructive_tool(
    trace: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    rule_ir: RuleIR,
    preservation_result: PreservationResult
) -> VerdictResult:
    trigger_events = find_trigger_events(trace, rule_ir.when)
    event_index = build_event_index(trace)
    
    for trigger in trigger_events:
        event_id = get_event_id(trigger)
        effect_type = get_any_field(trigger, "effect_type")
        if not is_destructive_effect(effect_type):
            continue
            
        untrusted_found = False
        unknown_taint = False
        
        labels_to_check = []
        labels_to_check.append(get_any_field(trigger, "taint.label"))
        
        input_refs = get_any_field(trigger, "input_refs")
        if not is_missing(input_refs) and isinstance(input_refs, list):
            for ref in input_refs:
                if ref in event_index:
                    labels_to_check.append(get_any_field(event_index[ref], "taint.label"))
                    
        causal_path = get_any_field(trigger, "taint.causal_path")
        if not is_missing(causal_path) and isinstance(causal_path, list):
            for ref in causal_path:
                if ref in event_index:
                    labels_to_check.append(get_any_field(event_index[ref], "taint.label"))
                    
        for label in labels_to_check:
            if is_missing(label) or label == "unknown" or label is None:
                unknown_taint = True
            elif label == "untrusted":
                untrusted_found = True
                
        if untrusted_found:
            if is_mitigated(trigger):
                pass # Safe for this event
            else:
                return VerdictResult.violation(
                    policy_id=rule_ir.policy_id,
                    trace_id=preservation_result.trace_id,
                    reason=f"Untrusted retrieval-derived data reaches destructive event {event_id} without mitigation.",
                    evidence_map=preservation_result.evidence_map,
                    triggered_event_ids=preservation_result.triggered_event_ids,
                    route="block"
                )
        elif unknown_taint:
            return VerdictResult.unknown(
                policy_id=rule_ir.policy_id,
                trace_id=preservation_result.trace_id,
                reason=f"Cannot determine trust label for data consumed by destructive event {event_id}.",
                evidence_map=preservation_result.evidence_map,
                triggered_event_ids=preservation_result.triggered_event_ids,
                missing_evidence=preservation_result.missing_evidence,
                route="ask_user"
            )
            
    # Need to check if there's untrusted found that is mitigated, to provide right reason
    # If we get here, no unmitigated untrusted flows reached destructive events.
    return VerdictResult.safe(
        policy_id=rule_ir.policy_id,
        trace_id=preservation_result.trace_id,
        reason="No untrusted retrieval-derived data reaches destructive actions.",
        evidence_map=preservation_result.evidence_map,
        triggered_event_ids=preservation_result.triggered_event_ids,
        route="allow"
    )

def evaluate_p003_tool_failure_not_report_success(
    trace: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    rule_ir: RuleIR,
    preservation_result: PreservationResult
) -> VerdictResult:
    trigger_events = find_trigger_events(trace, rule_ir.when)
    event_index = build_event_index(trace)
    
    any_failed_tool = False
    for event in iter_events(trace):
        status = get_any_field(event, "status")
        tool_ok = get_any_field(event, "tool_output.ok")
        err_type = get_any_field(event, "error_type")
        if status == "failed" or tool_ok is False or (not is_missing(err_type) and err_type is not None and str(err_type).lower() not in ("none", "null", "")):
            any_failed_tool = True
            break
            
    for final_event in trigger_events:
        event_id = get_event_id(final_event)
        claims_success = event_has_success_claim(final_event)
        
        linked_events = []
        parent = final_event.get("parent_event")
        if parent and parent in event_index:
            linked_events.append(event_index[parent])
            
        input_refs = get_any_field(final_event, "input_refs")
        if not is_missing(input_refs) and isinstance(input_refs, list):
            for ref in input_refs:
                if ref in event_index:
                    linked_events.append(event_index[ref])
                    
        provenances = get_any_field(final_event, "provenance")
        if not is_missing(provenances) and isinstance(provenances, list):
            for ref in provenances:
                if ref in event_index:
                    linked_events.append(event_index[ref])
                    
        if not linked_events:
            if any_failed_tool and claims_success:
                return VerdictResult.unknown(
                    policy_id=rule_ir.policy_id,
                    trace_id=preservation_result.trace_id,
                    reason=f"Final response {event_id} claims success but has no resolvable link to tool results.",
                    evidence_map=preservation_result.evidence_map,
                    triggered_event_ids=preservation_result.triggered_event_ids,
                    missing_evidence=preservation_result.missing_evidence,
                    route="ask_user"
                )
            continue
            
        linked_failed = False
        for linked in linked_events:
            status = get_any_field(linked, "status")
            tool_ok = get_any_field(linked, "tool_output.ok")
            err_type = get_any_field(linked, "error_type")
            if status == "failed" or tool_ok is False or (not is_missing(err_type) and err_type is not None and str(err_type).lower() not in ("none", "null", "")):
                linked_failed = True
                break
                
        if linked_failed and claims_success:
            return VerdictResult.violation(
                policy_id=rule_ir.policy_id,
                trace_id=preservation_result.trace_id,
                reason=f"Final response {event_id} claims success while linked tool result failed.",
                evidence_map=preservation_result.evidence_map,
                triggered_event_ids=preservation_result.triggered_event_ids,
                route="block"
            )
            
    return VerdictResult.safe(
        policy_id=rule_ir.policy_id,
        trace_id=preservation_result.trace_id,
        reason="Final response is grounded in successful tool output or reports failure truthfully.",
        evidence_map=preservation_result.evidence_map,
        triggered_event_ids=preservation_result.triggered_event_ids,
        route="allow"
    )

def evaluate_rule(
    trace: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    rule_ir: RuleIR,
    *,
    preservation_result: PreservationResult | None = None
) -> VerdictResult:
    if preservation_result is None:
        preservation_result = run_preservation_check(trace, rule_ir)
        
    trace_id = preservation_result.trace_id
    
    if preservation_result.status == PreservationStatus.INCOMPLETE:
        return VerdictResult.unknown(
            policy_id=rule_ir.policy_id,
            trace_id=trace_id,
            reason=f"Missing evidence for rule {rule_ir.policy_id}: " + ", ".join(preservation_result.missing_evidence),
            missing_evidence=preservation_result.missing_evidence,
            evidence_map=preservation_result.evidence_map,
            triggered_event_ids=preservation_result.triggered_event_ids,
            route="ask_user"
        )
        
    if preservation_result.status == PreservationStatus.INCONSISTENT:
        return VerdictResult.inconsistent(
            policy_id=rule_ir.policy_id,
            trace_id=trace_id,
            reason=preservation_result.reason or "Inconsistent evidence detected.",
            evidence_map=preservation_result.evidence_map,
            triggered_event_ids=preservation_result.triggered_event_ids,
            route="escalate"
        )
        
    if preservation_result.status == PreservationStatus.NOT_APPLICABLE:
        return VerdictResult.safe(
            policy_id=rule_ir.policy_id,
            trace_id=trace_id,
            reason="Rule condition did not match any event; policy is not applicable.",
            evidence_map=preservation_result.evidence_map,
            triggered_event_ids=preservation_result.triggered_event_ids,
            route="allow"
        )
        
    # Check inconsistencies
    inconsistencies = detect_inconsistent_evidence(trace)
    if inconsistencies:
        return VerdictResult.inconsistent(
            policy_id=rule_ir.policy_id,
            trace_id=trace_id,
            reason="Inconsistent evidence: " + "; ".join(inconsistencies[:3]),
            evidence_map=preservation_result.evidence_map,
            triggered_event_ids=preservation_result.triggered_event_ids,
            route="escalate"
        )
        
    policy_key = normalize_policy_key(rule_ir)
    if policy_key == "P001":
        return evaluate_p001_approval_before_send(trace, rule_ir, preservation_result)
    elif policy_key == "P002":
        return evaluate_p002_no_untrusted_retrieval_to_destructive_tool(trace, rule_ir, preservation_result)
    elif policy_key == "P003":
        return evaluate_p003_tool_failure_not_report_success(trace, rule_ir, preservation_result)
        
    return VerdictResult.unknown(
        policy_id=rule_ir.policy_id,
        trace_id=trace_id,
        reason=f"No verdict implementation for policy {rule_ir.policy_id}",
        evidence_map=preservation_result.evidence_map,
        triggered_event_ids=preservation_result.triggered_event_ids,
        missing_evidence=preservation_result.missing_evidence,
        route="log_only"
    )

def evaluate_rules(
    trace: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    rules: Iterable[RuleIR]
) -> list[VerdictResult]:
    return [evaluate_rule(trace, rule) for rule in rules]
