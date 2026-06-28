"""
tests/test_c1_evidence_extractor.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tests for c1.evidence_extractor — Task 4.7.

All tests exercise the public API ``extract_evidence()`` / ``EvidenceExtractor``.
No external dependencies (vocabulary.yaml, network, …) are required.
"""

from __future__ import annotations

import pytest
import sys
from pathlib import Path

# Add "src " directory (note the trailing space in the actual folder name)
_SRC_DIR = Path(__file__).resolve().parents[1] / "src "
sys.path.insert(0, str(_SRC_DIR))

from c1.evidence_extractor import EvidenceExtractor, extract_evidence  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_trace(*events) -> dict:
    """Wrap events in a minimal trace envelope."""
    return {
        "trace_id": "t_test",
        "schema_version": "0.1",
        "events": list(events),
    }


def _find_event(trace: dict, event_id: str) -> dict:
    for e in trace["events"]:
        if e.get("event_id") == event_id:
            return e
    raise KeyError(f"Event {event_id!r} not found")


# ---------------------------------------------------------------------------
# Test 1 — Approval event extraction
# ---------------------------------------------------------------------------


class TestApprovalExtraction:
    """Approval slot is correctly extracted from governance_action events."""

    def _approval_event(self) -> dict:
        return {
            "event_id": "e_001",
            "step_id": 1,
            "action_type": "governance_action",
            "action_name": "ask_user_approval",
            "effect_type": "approve",
            "target_resource": "email",
            "typed_args": {"recipient": "team@example.com"},
            "tool_output": {"approved": True, "approved_by": "user"},
            "output_ref": "approval_001",
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }

    def test_approval_exists(self):
        trace = _make_trace(self._approval_event())
        enriched = extract_evidence(trace)
        event = _find_event(enriched, "e_001")
        assert event["approval"]["exists"] is True

    def test_approval_status_approved(self):
        trace = _make_trace(self._approval_event())
        enriched = extract_evidence(trace)
        event = _find_event(enriched, "e_001")
        assert event["approval"]["status"] == "approved"

    def test_approval_target_recipient(self):
        trace = _make_trace(self._approval_event())
        enriched = extract_evidence(trace)
        event = _find_event(enriched, "e_001")
        assert event["approval"]["target"]["recipient"] == "team@example.com"

    def test_approval_event_ref(self):
        trace = _make_trace(self._approval_event())
        enriched = extract_evidence(trace)
        event = _find_event(enriched, "e_001")
        assert event["approval"]["approval_event"] == "e_001"

    def test_approval_approved_by(self):
        trace = _make_trace(self._approval_event())
        enriched = extract_evidence(trace)
        event = _find_event(enriched, "e_001")
        assert event["approval"]["approved_by"] == "user"

    def test_request_without_response_is_unknown_status(self):
        """An ask_user_approval with no approval signal → status unknown."""
        event = {
            "event_id": "e_req",
            "step_id": 1,
            "action_type": "governance_action",
            "action_name": "ask_user_approval",
            "effect_type": "approve",
            "target_resource": "email",
            "typed_args": {"recipient": "x@example.com"},
            "tool_output": {},
            "output_ref": None,
            "status": "pending",
            "input_refs": None,
            "parent_event": None,
            "metadata": {"raw_event_type": "approval_request"},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_req")
        assert e["approval"]["exists"] is True
        assert e["approval"]["status"] == "unknown"

    def test_raw_approval_passthrough(self):
        """If the event already has an approval slot, it must be preserved."""
        event = {
            "event_id": "e_pass",
            "step_id": 1,
            "action_type": "governance_action",
            "action_name": "approve_send_email",
            "effect_type": "approve",
            "target_resource": "email",
            "typed_args": {},
            "tool_output": {},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "approval": {
                "exists": True,
                "status": "approved",
                "target": {"recipient": "boss@corp.com"},
                "approved_by": "admin",
                "approval_event": "e_pass",
            },
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_pass")
        assert e["approval"]["approved_by"] == "admin"
        assert e["approval"]["target"]["recipient"] == "boss@corp.com"


# ---------------------------------------------------------------------------
# Test 2 — Approval propagation to send_email
# ---------------------------------------------------------------------------


class TestApprovalPropagation:
    """Approved event propagates to a subsequent send_email with the same target."""

    def _trace(self) -> dict:
        approval_event = {
            "event_id": "e_001",
            "step_id": 1,
            "action_type": "governance_action",
            "action_name": "ask_user_approval",
            "effect_type": "approve",
            "target_resource": "email",
            "typed_args": {"recipient": "team@example.com"},
            "tool_output": {"approved": True, "approved_by": "user"},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        send_event = {
            "event_id": "e_002",
            "step_id": 2,
            "action_type": "tool_call",
            "action_name": "send_email",
            "effect_type": "send",
            "target_resource": "email",
            "typed_args": {"recipient": "team@example.com"},
            "tool_output": {"ok": True},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        return _make_trace(approval_event, send_event)

    def test_approval_propagated_to_send(self):
        enriched = extract_evidence(self._trace())
        send = _find_event(enriched, "e_002")
        assert send.get("approval") is not None, "approval should be propagated"
        assert send["approval"]["status"] == "approved"

    def test_propagated_approval_event_id(self):
        enriched = extract_evidence(self._trace())
        send = _find_event(enriched, "e_002")
        assert send["approval"]["approval_event"] == "e_001"

    def test_no_propagation_if_approval_after_send(self):
        """Approval that comes AFTER the send should NOT be propagated."""
        approval_event = {
            "event_id": "e_late",
            "step_id": 3,
            "action_type": "governance_action",
            "action_name": "ask_user_approval",
            "effect_type": "approve",
            "target_resource": "email",
            "typed_args": {"recipient": "team@example.com"},
            "tool_output": {"approved": True, "approved_by": "user"},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        send_event = {
            "event_id": "e_send",
            "step_id": 2,
            "action_type": "tool_call",
            "action_name": "send_email",
            "effect_type": "send",
            "target_resource": "email",
            "typed_args": {"recipient": "team@example.com"},
            "tool_output": None,
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(send_event, approval_event))
        send = _find_event(enriched, "e_send")
        # Approval exists on e_late; send (step 2) should NOT get it.
        assert send.get("approval") is None


# ---------------------------------------------------------------------------
# Test 3 — Retrieval trusted taint
# ---------------------------------------------------------------------------


class TestRetrievalTrustedTaint:
    def test_trusted_taint_label(self):
        event = {
            "event_id": "e_001",
            "step_id": 1,
            "action_type": "retrieval",
            "action_name": "retrieve_document",
            "effect_type": "retrieve",
            "target_resource": "document",
            "typed_args": {"source": "internal_kb", "doc_id": "doc_001"},
            "tool_output": {"doc_id": "doc_001", "content": "Hello"},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_001")
        assert e["taint"]["label"] == "trusted"

    def test_trusted_provenance_set(self):
        event = {
            "event_id": "e_001",
            "step_id": 1,
            "action_type": "retrieval",
            "action_name": "retrieve_document",
            "effect_type": "retrieve",
            "target_resource": "document",
            "typed_args": {"source": "internal_kb", "doc_id": "doc_001"},
            "tool_output": {"doc_id": "doc_001"},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_001")
        assert e["provenance"] is not None

    def test_trusted_causal_path(self):
        event = {
            "event_id": "e_001",
            "step_id": 1,
            "action_type": "retrieval",
            "action_name": "retrieve_document",
            "effect_type": "retrieve",
            "target_resource": "document",
            "typed_args": {"source": "internal_kb"},
            "tool_output": {},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_001")
        assert "e_001" in e["taint"]["causal_path"]


# ---------------------------------------------------------------------------
# Test 4 — Retrieval untrusted taint
# ---------------------------------------------------------------------------


class TestRetrievalUntrustedTaint:
    def test_untrusted_label_from_url(self):
        event = {
            "event_id": "e_001",
            "step_id": 1,
            "action_type": "retrieval",
            "action_name": "retrieve_document",
            "effect_type": "retrieve",
            "target_resource": "document",
            "typed_args": {"url": "https://external-site.com/data"},
            "tool_output": {},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_001")
        assert e["taint"]["label"] == "untrusted"

    def test_untrusted_source_set(self):
        event = {
            "event_id": "e_001",
            "step_id": 1,
            "action_type": "retrieval",
            "action_name": "retrieve_document",
            "effect_type": "retrieve",
            "target_resource": "document",
            "typed_args": {"source": "external_web"},
            "tool_output": {},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_001")
        assert e["taint"]["label"] == "untrusted"
        assert e["taint"]["source"] is not None

    def test_unknown_source_emits_warning(self):
        """A retrieval with no source hints → label unknown + warning."""
        event = {
            "event_id": "e_unk",
            "step_id": 1,
            "action_type": "retrieval",
            "action_name": "retrieve_document",
            "effect_type": "retrieve",
            "target_resource": "document",
            "typed_args": {},
            "tool_output": {},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_unk")
        assert e["taint"]["label"] == "unknown"
        warnings = e["metadata"].get("evidence_warnings", [])
        assert any("unknown_retrieval_trust_source" in w for w in warnings)


# ---------------------------------------------------------------------------
# Test 5 — Propagate taint to destructive tool
# ---------------------------------------------------------------------------


class TestTaintPropagation:
    def _trace(self) -> dict:
        retrieval = {
            "event_id": "e_001",
            "step_id": 1,
            "action_type": "retrieval",
            "action_name": "retrieve_document",
            "effect_type": "retrieve",
            "target_resource": "document",
            "typed_args": {"url": "https://external.com/data"},
            "tool_output": {},
            "output_ref": "doc_untrusted_001",
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        delete_op = {
            "event_id": "e_002",
            "step_id": 2,
            "action_type": "tool_call",
            "action_name": "delete_file",
            "effect_type": "delete",
            "target_resource": "file",
            "typed_args": {"path": "/tmp/target.txt"},
            "tool_output": None,
            "output_ref": None,
            "status": "success",
            "input_refs": ["doc_untrusted_001"],
            "parent_event": None,
            "metadata": {},
        }
        return _make_trace(retrieval, delete_op)

    def test_taint_propagated_to_delete(self):
        enriched = extract_evidence(self._trace())
        delete = _find_event(enriched, "e_002")
        assert delete.get("taint") is not None
        assert delete["taint"]["label"] == "untrusted"

    def test_provenance_contains_doc_ref(self):
        enriched = extract_evidence(self._trace())
        delete = _find_event(enriched, "e_002")
        assert delete.get("provenance") is not None
        provenance_list = delete["provenance"]
        assert any("doc_untrusted_001" in str(p) for p in provenance_list)

    def test_causal_path_includes_both_events(self):
        enriched = extract_evidence(self._trace())
        delete = _find_event(enriched, "e_002")
        causal_path = delete["taint"]["causal_path"]
        assert "e_001" in causal_path
        assert "e_002" in causal_path


# ---------------------------------------------------------------------------
# Test 6 — Tool failure status/error
# ---------------------------------------------------------------------------


class TestToolFailureStatusError:
    def test_ok_false_sets_failed_status(self):
        event = {
            "event_id": "e_fail",
            "step_id": 1,
            "action_type": "tool_call",
            "action_name": "call_api",
            "effect_type": "connect",
            "target_resource": "api",
            "typed_args": {},
            "tool_output": {"ok": False, "error": "permission denied"},
            "output_ref": None,
            "status": "success",  # wrong status — should be corrected
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_fail")
        assert e["status"] == "failed"

    def test_permission_denied_error_type(self):
        event = {
            "event_id": "e_perm",
            "step_id": 1,
            "action_type": "tool_call",
            "action_name": "call_api",
            "effect_type": "connect",
            "target_resource": "api",
            "typed_args": {},
            "tool_output": {"ok": False, "error": "permission denied"},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_perm")
        assert e["error_type"] == "permission_denied"

    def test_timeout_error_type(self):
        event = {
            "event_id": "e_to",
            "step_id": 1,
            "action_type": "tool_call",
            "action_name": "call_api",
            "effect_type": "connect",
            "target_resource": "api",
            "typed_args": {},
            "tool_output": {"success": False, "error": "request timed out"},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_to")
        assert e["error_type"] == "timeout"

    def test_existing_error_type_not_overwritten(self):
        event = {
            "event_id": "e_err",
            "step_id": 1,
            "action_type": "tool_call",
            "action_name": "call_api",
            "effect_type": "connect",
            "target_resource": "api",
            "typed_args": {},
            "tool_output": {"ok": False, "error": "some error"},
            "output_ref": None,
            "status": "failed",
            "error_type": "runtime_exception",  # already set
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_err")
        assert e["error_type"] == "runtime_exception"


# ---------------------------------------------------------------------------
# Test 7 — Final response missing causal link warning
# ---------------------------------------------------------------------------


class TestFinalResponseMissingCausalLink:
    def test_warning_emitted_when_no_input_refs_no_parent(self):
        event = {
            "event_id": "e_final",
            "step_id": 10,
            "action_type": "agent_response",
            "action_name": "final_response",
            "effect_type": None,
            "target_resource": None,
            "typed_args": {},
            "tool_output": {"message": "Task complete."},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_final")
        warnings = e["metadata"].get("evidence_warnings", [])
        assert "final_response_missing_causal_link" in warnings

    def test_no_warning_when_input_refs_present(self):
        retrieval = {
            "event_id": "e_r",
            "step_id": 1,
            "action_type": "retrieval",
            "action_name": "retrieve_document",
            "effect_type": "retrieve",
            "target_resource": "document",
            "typed_args": {"source": "internal_kb"},
            "tool_output": {},
            "output_ref": "retrieval_e_r",
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        final = {
            "event_id": "e_final",
            "step_id": 2,
            "action_type": "agent_response",
            "action_name": "final_response",
            "effect_type": None,
            "target_resource": None,
            "typed_args": {},
            "tool_output": {"message": "Done"},
            "output_ref": None,
            "status": "success",
            "input_refs": ["retrieval_e_r"],
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(retrieval, final))
        e = _find_event(enriched, "e_final")
        warnings = e["metadata"].get("evidence_warnings", [])
        assert "final_response_missing_causal_link" not in warnings


# ---------------------------------------------------------------------------
# Test 8 — No fake SAFE/VIOLATION verdict
# ---------------------------------------------------------------------------


class TestNoFakeVerdicts:
    def _run_extractor(self) -> list[dict]:
        """Run extractor on a varied trace and return all events."""
        events = [
            {
                "event_id": "e_msg",
                "step_id": 1,
                "action_type": "message",
                "action_name": "user_message",
                "effect_type": None,
                "target_resource": None,
                "typed_args": {"content": "Send the report"},
                "tool_output": None,
                "output_ref": None,
                "status": "success",
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            },
            {
                "event_id": "e_ret",
                "step_id": 2,
                "action_type": "retrieval",
                "action_name": "retrieve_document",
                "effect_type": "retrieve",
                "target_resource": "document",
                "typed_args": {"source": "internal_kb"},
                "tool_output": {"doc_id": "doc_001"},
                "output_ref": None,
                "status": "success",
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            },
            {
                "event_id": "e_send",
                "step_id": 3,
                "action_type": "tool_call",
                "action_name": "send_email",
                "effect_type": "send",
                "target_resource": "email",
                "typed_args": {"recipient": "boss@corp.com"},
                "tool_output": {"ok": True},
                "output_ref": None,
                "status": "success",
                "input_refs": ["doc_001"],
                "parent_event": None,
                "metadata": {},
            },
        ]
        trace = _make_trace(*events)
        enriched = extract_evidence(trace)
        return enriched["events"]

    def test_no_safe_verdict_manufactured(self):
        """Extractor must not set decision.verdict = 'safe' on its own."""
        for event in self._run_extractor():
            decision = event.get("decision")
            if decision is not None:
                verdict = decision.get("verdict")
                # verdict may only exist if raw trace logged it;
                # extractor itself should not fabricate safe/violation.
                # In this test, no raw decision was in the input → must be absent.
                assert verdict is None or verdict not in ("safe", "violation"), (
                    f"Extractor fabricated verdict={verdict!r} on {event['event_id']}"
                )

    def test_no_decision_slot_on_plain_events(self):
        """Non-governance events must not receive a fabricated decision slot."""
        for event in self._run_extractor():
            if event.get("action_type") not in ("governance_action", "policy_decision"):
                assert event.get("decision") is None, (
                    f"Unexpected decision on {event['event_id']}: {event.get('decision')}"
                )

    def test_no_approval_exists_false_manufactured(self):
        """Extractor must not create approval={exists:false, status:missing}."""
        for event in self._run_extractor():
            approval = event.get("approval")
            if approval is not None:
                # If approval was attached by propagation, it must be real
                assert approval.get("exists") is not False, (
                    f"Extractor created exists=False approval on {event['event_id']}"
                )


# ---------------------------------------------------------------------------
# Test 9 — Provenance pass-through
# ---------------------------------------------------------------------------


class TestProvenancePassthrough:
    def test_raw_provenance_preserved(self):
        event = {
            "event_id": "e_prov",
            "step_id": 1,
            "action_type": "retrieval",
            "action_name": "retrieve_document",
            "effect_type": "retrieve",
            "target_resource": "document",
            "typed_args": {},
            "tool_output": {},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "provenance": ["existing_source_001"],
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_prov")
        assert "existing_source_001" in e["provenance"]


# ---------------------------------------------------------------------------
# Test 10 — Policy / decision pass-through
# ---------------------------------------------------------------------------


class TestPolicyDecisionPassthrough:
    def test_policy_passthrough(self):
        event = {
            "event_id": "e_pol",
            "step_id": 1,
            "action_type": "tool_call",
            "action_name": "send_email",
            "effect_type": "send",
            "target_resource": "email",
            "typed_args": {},
            "tool_output": None,
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "policy": {"policy_version": "policy_v0.1", "allowed_action_set": ["send_email"]},
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_pol")
        assert e["policy"]["policy_version"] == "policy_v0.1"

    def test_decision_passthrough(self):
        event = {
            "event_id": "e_dec",
            "step_id": 1,
            "action_type": "governance_action",
            "action_name": "approve_send_email",
            "effect_type": "approve",
            "target_resource": "email",
            "typed_args": {},
            "tool_output": None,
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "decision": {"verdict": "unknown", "route": "ask_user", "reason": "missing approval"},
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_dec")
        assert e["decision"]["verdict"] == "unknown"
        assert e["decision"]["route"] == "ask_user"


# ---------------------------------------------------------------------------
# Test 11 — Pre/post state pass-through
# ---------------------------------------------------------------------------


class TestStateSlots:
    def test_pre_state_passthrough(self):
        event = {
            "event_id": "e_state",
            "step_id": 1,
            "action_type": "tool_call",
            "action_name": "write_memory",
            "effect_type": "write",
            "target_resource": "memory",
            "typed_args": {"pre_state": {"key": "old"}, "post_state": {"key": "new"}},
            "tool_output": None,
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        e = _find_event(enriched, "e_state")
        assert e["pre_state"] == {"key": "old"}
        assert e["post_state"] == {"key": "new"}


# ---------------------------------------------------------------------------
# Test 12 — Reversibility heuristic
# ---------------------------------------------------------------------------


class TestReversibility:
    def test_send_is_hard(self):
        event = {
            "event_id": "e_r1",
            "step_id": 1,
            "action_type": "tool_call",
            "action_name": "send_email",
            "effect_type": "send",
            "target_resource": "email",
            "typed_args": {},
            "tool_output": None,
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        assert _find_event(enriched, "e_r1")["reversibility"] == "hard"

    def test_delete_is_irreversible(self):
        event = {
            "event_id": "e_r2",
            "step_id": 1,
            "action_type": "tool_call",
            "action_name": "delete_file",
            "effect_type": "delete",
            "target_resource": "file",
            "typed_args": {},
            "tool_output": None,
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        assert _find_event(enriched, "e_r2")["reversibility"] == "irreversible"

    def test_retrieve_is_reversible(self):
        event = {
            "event_id": "e_r3",
            "step_id": 1,
            "action_type": "retrieval",
            "action_name": "retrieve_document",
            "effect_type": "retrieve",
            "target_resource": "document",
            "typed_args": {"source": "internal_kb"},
            "tool_output": {},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        assert _find_event(enriched, "e_r3")["reversibility"] == "reversible"

    def test_existing_reversibility_not_overwritten(self):
        event = {
            "event_id": "e_r4",
            "step_id": 1,
            "action_type": "tool_call",
            "action_name": "send_email",
            "effect_type": "send",
            "target_resource": "email",
            "typed_args": {},
            "tool_output": None,
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "reversibility": "compensatable",  # explicitly set
            "metadata": {},
        }
        enriched = extract_evidence(_make_trace(event))
        assert _find_event(enriched, "e_r4")["reversibility"] == "compensatable"


# ---------------------------------------------------------------------------
# Test 13 — Input mutation guard
# ---------------------------------------------------------------------------


class TestInputNotMutated:
    def test_original_trace_unchanged(self):
        import copy
        event = {
            "event_id": "e_orig",
            "step_id": 1,
            "action_type": "retrieval",
            "action_name": "retrieve_document",
            "effect_type": "retrieve",
            "target_resource": "document",
            "typed_args": {"url": "https://external.com/data"},
            "tool_output": {},
            "output_ref": None,
            "status": "success",
            "input_refs": None,
            "parent_event": None,
            "metadata": {},
        }
        trace = _make_trace(event)
        original = copy.deepcopy(trace)
        extract_evidence(trace)
        assert trace == original, "Input trace must not be mutated"


# ---------------------------------------------------------------------------
# Test 14 — extract_evidence convenience function
# ---------------------------------------------------------------------------


class TestConvenienceFunction:
    def test_returns_dict(self):
        trace = _make_trace(
            {
                "event_id": "e_x",
                "step_id": 1,
                "action_type": "message",
                "action_name": "user_message",
                "effect_type": None,
                "target_resource": None,
                "typed_args": {},
                "tool_output": None,
                "output_ref": None,
                "status": "success",
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            }
        )
        result = extract_evidence(trace)
        assert isinstance(result, dict)
        assert "events" in result

    def test_evidence_extractor_version_stamp(self):
        trace = _make_trace(
            {
                "event_id": "e_stamp",
                "step_id": 1,
                "action_type": "message",
                "action_name": "user_message",
                "effect_type": None,
                "target_resource": None,
                "typed_args": {},
                "tool_output": None,
                "output_ref": None,
                "status": "success",
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            }
        )
        enriched = extract_evidence(trace)
        e = _find_event(enriched, "e_stamp")
        assert e["metadata"].get("evidence_extractor") == "v0.1"
