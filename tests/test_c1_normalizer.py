"""
tests/test_c1_normalizer.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for c1.normalizer:

    Vocabulary:
        test_vocabulary_loads_all_sections
        test_normalize_action_name_known_aliases
        test_normalize_action_name_canonical_self
        test_normalize_action_name_unknown_returns_unknown
        test_derive_action_type
        test_derive_effect_type
        test_derive_target_resource
        test_normalize_status_valid
        test_normalize_status_unknown_fallback
        test_normalize_error_type_dict
        test_normalize_error_type_none
        test_normalize_error_type_unknown_value
        test_normalize_reversibility

    Normalizer.normalize_raw_event:
        test_full_tool_call_event
        test_event_missing_action_name
        test_event_missing_status
        test_event_with_error_dict
        test_evidence_passthrough_taint_approval_provenance
        test_event_type_mapping_each_type
        test_raw_action_preserved_in_metadata
        test_unknown_action_preserved_in_metadata
        test_empty_references_becomes_none
        test_nonempty_references_become_input_refs
        test_output_ref_passthrough
"""

from __future__ import annotations

import sys
import warnings
from pathlib import Path

import pytest

# ── path surgery so tests can be run from the repo root without installing ──
REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src "
sys.path.insert(0, str(SRC_DIR))

from c1.normalizer import (  # noqa: E402
    Normalizer,
    Vocabulary,
    derive_action_type,
    derive_effect_type,
    derive_target_resource,
    normalize_action_name,
    normalize_error_type,
    normalize_raw_event,
    normalize_status,
)

VOCAB_PATH = REPO_ROOT / "phase_2" / "outputs" / "vocabulary.yaml"


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture(scope="module")
def vocab() -> Vocabulary:
    return Vocabulary(VOCAB_PATH)


@pytest.fixture(scope="module")
def norm(vocab: Vocabulary) -> Normalizer:
    return Normalizer(vocab)


# ===========================================================================
# Vocabulary tests
# ===========================================================================


class TestVocabularyLoad:
    def test_vocabulary_loads_all_sections(self, vocab: Vocabulary) -> None:
        assert len(vocab.phases) > 0,            "phase list empty"
        assert len(vocab.action_types) > 0,      "action_type list empty"
        assert len(vocab.effect_types) > 0,      "effect_type list empty"
        assert len(vocab.target_resources) > 0,  "target_resource list empty"
        assert len(vocab.statuses) > 0,          "status list empty"
        assert len(vocab.error_types) > 0,       "error_type list empty"
        assert len(vocab.taint_labels) > 0,      "taint_label list empty"
        assert len(vocab.approval_statuses) > 0, "approval_status list empty"
        assert len(vocab.reversibilities) > 0,   "reversibility list empty"
        assert len(vocab.decision_verdicts) > 0, "decision_verdict list empty"
        assert len(vocab.decision_routes) > 0,   "decision_route list empty"

    def test_known_canonical_values_in_sets(self, vocab: Vocabulary) -> None:
        assert "plan"          in vocab.phases
        assert "before_action" in vocab.phases
        assert "finish"        in vocab.phases
        assert "tool_call"     in vocab.action_types
        assert "send"          in vocab.effect_types
        assert "email"         in vocab.target_resources
        assert "success"       in vocab.statuses
        assert "permission_denied" in vocab.error_types


class TestNormalizeActionName:
    @pytest.mark.parametrize("raw, expected", [
        ("sendEmail",       "send_email"),
        ("gmail_send",      "send_email"),
        ("email.send",      "send_email"),
        ("mcp.gmail.send",  "send_email"),
        ("gmail.send_message", "send_email"),
        ("retrieve",        "retrieve_document"),
        ("rag.retrieve",    "retrieve_document"),
        ("deleteFile",      "delete_file"),
        ("file.delete",     "delete_file"),
        ("mcp.fs.delete",   "delete_file"),
        ("memory.write",    "write_memory"),
        ("save_memory",     "write_memory"),
        ("memory.read",     "read_memory"),
        ("load_memory",     "read_memory"),
        ("calendar.read",   "read_calendar"),
        ("readFile",        "read_file"),
        ("mcp.fs.read",     "read_file"),
        ("writeFile",       "write_file"),
        ("mcp.fs.write",    "write_file"),
        ("python.run",      "execute_code"),
        ("PythonREPL",      "execute_code"),
        ("httpGet",         "call_api"),
        ("api.call",        "call_api"),
        ("sql.query",       "query_database"),
        ("sendMessage",     "send_message"),
        ("slack.postMessage","send_message"),
        ("ask_approval",    "ask_user_approval"),
        ("human_review",    "ask_user_approval"),
        ("policy.update",   "update_policy"),
        ("set_policy",      "update_policy"),
    ])
    def test_known_aliases(self, vocab: Vocabulary, raw: str, expected: str) -> None:
        assert vocab.normalize_action_name(raw) == expected

    def test_canonical_name_maps_to_itself(self, vocab: Vocabulary) -> None:
        assert vocab.normalize_action_name("send_email") == "send_email"
        assert vocab.normalize_action_name("delete_file") == "delete_file"

    def test_unknown_returns_unknown(self, vocab: Vocabulary) -> None:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = vocab.normalize_action_name("some_totally_unknown_tool_xyz")
        assert result == "unknown"
        assert any("unknown" in str(warning.message).lower() for warning in w)

    def test_none_returns_unknown(self, vocab: Vocabulary) -> None:
        assert vocab.normalize_action_name(None) == "unknown"

    def test_empty_string_returns_unknown(self, vocab: Vocabulary) -> None:
        assert vocab.normalize_action_name("") == "unknown"

    # Module-level convenience function
    def test_module_level_function(self) -> None:
        assert normalize_action_name("gmail_send") == "send_email"
        assert normalize_action_name("mcp.gmail.send") == "send_email"
        assert normalize_action_name("email.send") == "send_email"


class TestDeriveActionType:
    @pytest.mark.parametrize("action, expected", [
        ("send_email",       "tool_call"),
        ("retrieve_document","retrieval"),
        ("delete_file",      "tool_call"),
        ("write_memory",     "memory_op"),
        ("read_memory",      "memory_op"),
        ("execute_code",     "code_execution"),
        ("call_api",         "external_api_call"),
        ("query_database",   "tool_call"),
        ("send_message",     "message"),
        ("ask_user_approval","governance_action"),  # alias: approval→governance_action
        ("update_policy",    "policy_decision"),    # alias: policy_update→policy_decision
    ])
    def test_known_mappings(self, vocab: Vocabulary, action: str, expected: str) -> None:
        assert vocab.derive_action_type(action) == expected

    def test_unknown_action_type(self, vocab: Vocabulary) -> None:
        assert vocab.derive_action_type("unknown") == "unknown"

    def test_module_level_function(self) -> None:
        assert derive_action_type("send_email") == "tool_call"


class TestDeriveEffectType:
    @pytest.mark.parametrize("action, expected", [
        ("send_email",       "send"),
        ("retrieve_document","retrieve"),
        ("delete_file",      "delete"),
        ("write_memory",     "write"),
        ("read_memory",      "read"),
        ("read_calendar",    "read"),
        ("write_calendar",   "write"),
        ("read_file",        "read"),
        ("write_file",       "write"),
        ("execute_code",     "execute"),
        ("call_api",         "connect"),
        ("query_database",   "read"),
        ("send_message",     "send"),
        ("ask_user_approval","approve"),
        ("update_policy",    "rewrite"),
    ])
    def test_known_mappings(self, vocab: Vocabulary, action: str, expected: str) -> None:
        assert vocab.derive_effect_type(action) == expected

    def test_unknown_returns_none(self, vocab: Vocabulary) -> None:
        assert vocab.derive_effect_type("unknown") is None

    def test_module_level_function(self) -> None:
        assert derive_effect_type("send_email") == "send"


class TestDeriveTargetResource:
    @pytest.mark.parametrize("action, expected", [
        ("send_email",       "email"),
        ("retrieve_document","web"),
        ("delete_file",      "file"),
        ("write_memory",     "memory"),
        ("read_memory",      "memory"),
        ("read_calendar",    "calendar"),
        ("write_calendar",   "calendar"),
        ("read_file",        "file"),
        ("write_file",       "file"),
        ("execute_code",     "system_command"),
        ("call_api",         "api"),
        ("query_database",   "database"),
        ("send_message",     "communication_edge"),
        ("ask_user_approval","user"),
        ("update_policy",    "agent_context"),  # alias: policy→agent_context
    ])
    def test_known_mappings(self, vocab: Vocabulary, action: str, expected: str) -> None:
        assert vocab.derive_target_resource(action) == expected

    def test_unknown_returns_none(self, vocab: Vocabulary) -> None:
        assert vocab.derive_target_resource("unknown") is None

    def test_module_level_function(self) -> None:
        assert derive_target_resource("send_email") == "email"


class TestNormalizeStatus:
    @pytest.mark.parametrize("raw", [
        "pending", "success", "failed", "blocked",
        "aborted", "rejected", "allowed", "rewritten", "unknown",
    ])
    def test_valid_statuses_passthrough(self, vocab: Vocabulary, raw: str) -> None:
        assert vocab.normalize_status(raw) == raw

    def test_none_returns_unknown(self, vocab: Vocabulary) -> None:
        assert vocab.normalize_status(None) == "unknown"

    def test_empty_string_returns_unknown(self, vocab: Vocabulary) -> None:
        assert vocab.normalize_status("") == "unknown"

    def test_unrecognised_returns_unknown(self, vocab: Vocabulary) -> None:
        assert vocab.normalize_status("flying") == "unknown"

    def test_module_level_function(self) -> None:
        assert normalize_status("success") == "success"
        assert normalize_status(None) == "unknown"


class TestNormalizeErrorType:
    def test_none_returns_none(self, vocab: Vocabulary) -> None:
        assert vocab.normalize_error_type(None) is None

    @pytest.mark.parametrize("raw", [
        "permission_denied", "missing_approval", "policy_violation",
        "runtime_exception", "tool_failure", "sandbox_violation",
        "taint_violation", "sink_reached", "anomaly_detected",
        "evidence_missing", "inconsistent_evidence", "timeout", "unknown",
    ])
    def test_known_error_types_from_string(self, vocab: Vocabulary, raw: str) -> None:
        assert vocab.normalize_error_type(raw) == raw

    def test_dict_with_error_type_key(self, vocab: Vocabulary) -> None:
        err = {"error_type": "permission_denied", "message": "No access"}
        assert vocab.normalize_error_type(err) == "permission_denied"

    def test_dict_with_type_key(self, vocab: Vocabulary) -> None:
        err = {"type": "tool_failure"}
        assert vocab.normalize_error_type(err) == "tool_failure"

    def test_unknown_dict_value_returns_unknown(self, vocab: Vocabulary) -> None:
        err = {"error_type": "some_made_up_error"}
        assert vocab.normalize_error_type(err) == "unknown"

    def test_module_level_function(self) -> None:
        assert normalize_error_type(None) is None
        assert normalize_error_type({"error_type": "permission_denied"}) == "permission_denied"


class TestNormalizeReversibility:
    @pytest.mark.parametrize("action, expected", [
        ("delete_file",      "hard"),
        ("send_email",       "hard"),
        ("send_message",     "hard"),
        ("read_memory",      "reversible"),
        ("read_file",        "reversible"),
        ("retrieve_document","reversible"),
        ("query_database",   "reversible"),
        ("write_memory",     "compensatable"),
        ("write_file",       "compensatable"),
        ("execute_code",     "compensatable"),
        ("call_api",         "compensatable"),
        ("update_policy",    "compensatable"),
    ])
    def test_known_reversibilities(self, vocab: Vocabulary, action: str, expected: str) -> None:
        assert vocab.normalize_reversibility(action) == expected

    def test_unknown_returns_none(self, vocab: Vocabulary) -> None:
        assert vocab.normalize_reversibility("unknown") is None


# ===========================================================================
# Normalizer.normalize_raw_event tests
# ===========================================================================


class TestNormalizeRawEvent:

    def test_full_tool_call_event(self, norm: Normalizer) -> None:
        """Case from spec: gmail_send → send_email with full field mapping."""
        raw = {
            "event_id":   "raw_001",
            "event_type": "tool_call",
            "step_id":    2,
            "tool_name":  "gmail_send",
            "action":     "some_action",
            "input":      {"recipient": "team@example.com", "subject": "Report"},
            "output":     None,
            "status":     "pending",
            "error":      None,
            "parent_event": None,
            "references": [],
        }
        ev = norm.normalize_raw_event(raw, "case_001")

        assert ev["event_id"]       == "raw_001"
        assert ev["trace_id"]       == "case_001"
        assert ev["step_id"]        == 2
        assert ev["timestamp"]      is None
        assert ev["parent_event"]   is None
        assert ev["phase"]          == "before_action"
        assert ev["action_type"]    == "tool_call"
        assert ev["action_name"]    == "send_email"
        assert ev["effect_type"]    == "send"
        assert ev["target_resource"]== "email"
        assert ev["typed_args"]     == {"recipient": "team@example.com", "subject": "Report"}
        assert ev["tool_output"]    is None
        assert ev["input_refs"]     is None   # empty list → None
        assert ev["output_ref"]     is None
        assert ev["pre_state"]      is None
        assert ev["post_state"]     is None
        assert ev["status"]         == "pending"
        assert ev["error_type"]     is None
        assert ev["reversibility"]  == "hard"
        assert ev["raw_event_ref"]  == "raw_001"

    def test_event_missing_action_name(self, norm: Normalizer) -> None:
        """No tool_name and no action → action_name='unknown', no crash."""
        raw = {
            "event_id":   "e_no_action",
            "event_type": "tool_call",
            "step_id":    1,
            "tool_name":  None,
            "action":     None,
            "input":      {},
            "output":     None,
            "status":     "pending",
            "error":      None,
            "parent_event": None,
            "references": None,
        }
        ev = norm.normalize_raw_event(raw, "trace_x")
        assert ev["action_name"] == "unknown"
        assert ev["effect_type"] is None or ev["effect_type"] == "unknown"
        assert ev["metadata"] is not None
        assert "missing_action_name" in str(ev["metadata"])

    def test_event_missing_status(self, norm: Normalizer) -> None:
        """Missing status falls back to 'unknown', not 'success'."""
        raw = {
            "event_id":   "e_no_status",
            "event_type": "tool_result",
            "step_id":    3,
            "tool_name":  "send_email",
            "action":     None,
            "input":      None,
            "output":     {"ok": True},
            "status":     None,
            "error":      None,
            "parent_event": "e_002",
            "references": ["e_002"],
        }
        ev = norm.normalize_raw_event(raw, "trace_x")
        assert ev["status"] == "unknown"

    def test_event_with_error_dict(self, norm: Normalizer) -> None:
        """error dict with error_type key is correctly normalized."""
        raw = {
            "event_id":   "e_err",
            "event_type": "tool_result",
            "step_id":    3,
            "tool_name":  "delete_file",
            "action":     None,
            "input":      {"tool_call_ref": "e_002"},
            "output":     {"ok": False},
            "status":     "failed",
            "error":      {"error_type": "permission_denied", "message": "denied"},
            "parent_event": "e_002",
            "references": ["e_002"],
        }
        ev = norm.normalize_raw_event(raw, "trace_y")
        assert ev["status"]      == "failed"
        assert ev["error_type"]  == "permission_denied"
        assert ev["action_name"] == "delete_file"
        assert ev["reversibility"] == "hard"

    def test_evidence_passthrough_taint_approval_provenance(self, norm: Normalizer) -> None:
        """Taint / approval / provenance pass through verbatim from raw event."""
        taint_val    = {"label": "untrusted", "source": "web_001"}
        approval_val = {"required": True, "exists": False, "status": "missing"}
        prov_val     = {"source_id": "web_001", "source_type": "web"}

        raw = {
            "event_id":   "e_ev",
            "event_type": "tool_call",
            "step_id":    4,
            "tool_name":  "delete_file",
            "action":     None,
            "input":      {"path": "/tmp/data.csv"},
            "output":     {"deleted": True},
            "status":     "success",
            "error":      None,
            "parent_event": "e_003",
            "references": ["e_002", "e_003"],
            "taint":      taint_val,
            "approval":   approval_val,
            "provenance": prov_val,
        }
        ev = norm.normalize_raw_event(raw, "trace_z")
        assert ev["taint"]      == taint_val
        assert ev["approval"]   == approval_val
        assert ev["provenance"] == prov_val

    @pytest.mark.parametrize("event_type, expected_phase, expected_action_type", [
        ("user_message",      "plan",          "message"),
        ("planner_step",      "plan",          "message"),
        ("retrieval",         "after_action",  "retrieval"),
        ("tool_call",         "before_action", "tool_call"),
        ("tool_result",       "after_action",  "tool_result"),
        ("approval_request",  "before_action", "governance_action"),
        ("approval_response", "after_action",  "governance_action"),
        ("memory_op",         "before_action", "memory_op"),
        ("final_response",    "finish",        "agent_response"),
        ("error",             "after_action",  "unknown"),
    ])
    def test_event_type_mapping(
        self,
        norm: Normalizer,
        event_type: str,
        expected_phase: str,
        expected_action_type: str,
    ) -> None:
        """Each raw event_type maps correctly to phase + action_type."""
        raw = {
            "event_id":   "e_map",
            "event_type": event_type,
            "step_id":    1,
            "tool_name":  None,
            "action":     None,
            "input":      None,
            "output":     None,
            "status":     "success",
            "error":      None,
            "parent_event": None,
            "references": None,
        }
        ev = norm.normalize_raw_event(raw, "trace_map")
        assert ev["phase"] == expected_phase, f"phase mismatch for {event_type}"
        # For tool_call/retrieval/memory_op, action_type from event_type mapping
        # is overridden only if vocab mapping produces something better; with
        # tool_name=None the vocab falls back to the event_type mapping.
        if event_type in ("approval_request", "approval_response", "final_response"):
            assert ev["action_type"] == expected_action_type
        else:
            assert ev["action_type"] == expected_action_type

    def test_raw_action_preserved_in_metadata_when_mapped(self, norm: Normalizer) -> None:
        """When raw alias maps to canonical, the original is still in metadata."""
        raw = {
            "event_id":   "e_meta",
            "event_type": "tool_call",
            "step_id":    2,
            "tool_name":  "gmail_send",
            "action":     None,
            "input":      {},
            "output":     None,
            "status":     "success",
            "error":      None,
            "parent_event": None,
            "references": None,
        }
        ev = norm.normalize_raw_event(raw, "trace_meta")
        assert ev["action_name"] == "send_email"
        # raw alias different from canonical → must appear in metadata
        meta = ev.get("metadata") or {}
        assert meta.get("raw_action_name") == "gmail_send"

    def test_unknown_action_preserved_in_metadata(self, norm: Normalizer) -> None:
        """Completely unknown action name is stored in metadata."""
        raw = {
            "event_id":   "e_unk",
            "event_type": "tool_call",
            "step_id":    5,
            "tool_name":  "totally_custom_tool_xyz",
            "action":     None,
            "input":      {},
            "output":     None,
            "status":     "success",
            "error":      None,
            "parent_event": None,
            "references": None,
        }
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            ev = norm.normalize_raw_event(raw, "trace_unk")
        assert ev["action_name"] == "unknown"
        meta = ev.get("metadata") or {}
        assert meta.get("raw_action_name") == "totally_custom_tool_xyz"
        assert "unknown_action_name" in str(meta.get("normalization_warnings", []))

    def test_empty_references_becomes_none(self, norm: Normalizer) -> None:
        raw = {
            "event_id": "e_ref",
            "event_type": "user_message",
            "step_id": 1,
            "tool_name": None,
            "action": "ask_user",
            "input": {"text": "hi"},
            "output": None,
            "status": "success",
            "error": None,
            "parent_event": None,
            "references": [],   # empty list
        }
        ev = norm.normalize_raw_event(raw, "trace_ref")
        assert ev["input_refs"] is None

    def test_nonempty_references_become_input_refs(self, norm: Normalizer) -> None:
        raw = {
            "event_id": "e_refs",
            "event_type": "tool_call",
            "step_id": 3,
            "tool_name": "delete_file",
            "action": None,
            "input": {"path": "/tmp/x"},
            "output": None,
            "status": "pending",
            "error": None,
            "parent_event": "e_001",
            "references": ["e_001", "e_002", "doc_abc"],
        }
        ev = norm.normalize_raw_event(raw, "trace_refs")
        assert ev["input_refs"] == ["e_001", "e_002", "doc_abc"]

    def test_output_ref_passthrough(self, norm: Normalizer) -> None:
        raw = {
            "event_id": "e_oref",
            "event_type": "tool_result",
            "step_id": 3,
            "tool_name": "delete_file",
            "action": None,
            "input": {"tool_call_ref": "e_002"},
            "output": {"ok": False},
            "status": "failed",
            "error": None,
            "parent_event": "e_002",
            "references": ["e_002"],
            "output_ref": "tool_result_failed_001",
        }
        ev = norm.normalize_raw_event(raw, "trace_oref")
        assert ev["output_ref"] == "tool_result_failed_001"

    def test_required_core_fields_always_present(self, norm: Normalizer) -> None:
        """Every required core field must be present even for a minimal event."""
        required_fields = [
            "event_id", "trace_id", "step_id", "timestamp", "parent_event",
            "phase", "action_type", "action_name", "effect_type", "target_resource",
            "typed_args", "tool_output", "input_refs", "output_ref",
            "pre_state", "post_state",
            "status", "error_type", "reversibility",
            "raw_event_ref",
        ]
        raw = {
            "event_id": "e_minimal",
            "event_type": "tool_call",
            "step_id": 1,
        }
        ev = norm.normalize_raw_event(raw, "trace_min")
        for field in required_fields:
            assert field in ev, f"Required field '{field}' missing from normalized event"

    def test_module_level_normalize_raw_event(self) -> None:
        raw = {
            "event_id":   "e_mod",
            "event_type": "tool_call",
            "step_id":    1,
            "tool_name":  "send_email",
            "status":     "success",
        }
        ev = normalize_raw_event(raw, "trace_mod")
        assert ev["action_name"] == "send_email"
        assert ev["effect_type"] == "send"


# ===========================================================================
# Extended tests — Tasks 4.3 / 4.4 / 4.5 done criteria
# ===========================================================================


class TestNormalizeRawEventExtended:
    """Covers the 7 specific test cases required by Tasks 4.3–4.5."""

    # ── Test 1: action alias mapping (module-level convenience functions) ──

    def test_action_alias_mapping(self) -> None:
        """Spec test 1 — gmail_send resolves correctly through all derives."""
        assert normalize_action_name("gmail_send") == "send_email"
        assert derive_action_type("send_email")    == "tool_call"
        assert derive_effect_type("send_email")    == "send"
        assert derive_target_resource("send_email")== "email"

    # ── Test 2: full tool_call event mapping ──────────────────────────────

    def test_normalize_tool_call_event(self, norm: Normalizer) -> None:
        """Spec test 2 — tool_call with gmail_send produces correct fields."""
        raw = {
            "event_id":   "raw_002",
            "event_type": "tool_call",
            "step_id":    2,
            "tool_name":  "gmail_send",
            "input":      {"recipient": "team@example.com"},
            "status":     "pending",
        }
        ev = norm.normalize_raw_event(raw, "trace_t2")

        assert ev["phase"]          == "before_action"
        assert ev["action_type"]    == "tool_call"
        assert ev["action_name"]    == "send_email"
        assert ev["effect_type"]    == "send"
        assert ev["target_resource"]== "email"
        assert ev["step_id"]        == 2
        assert isinstance(ev["metadata"], dict)
        assert ev["metadata"]["raw_action_name"] == "gmail_send"
        assert ev["metadata"]["raw_event_type"]  == "tool_call"

    # ── Test 3: missing step_id ───────────────────────────────────────────

    def test_missing_step_id_returns_zero(self, norm: Normalizer) -> None:
        """Spec test 3 — missing step_id → 0, warning recorded, no crash."""
        raw = {
            "event_id":   "raw_003",
            "event_type": "tool_call",
            "tool_name":  "delete_file",
            "status":     "pending",
            # step_id deliberately omitted
        }
        ev = norm.normalize_raw_event(raw, "trace_t3")

        assert ev["step_id"] == 0
        assert isinstance(ev["step_id"], int)
        warnings_field = ev["metadata"].get("normalization_warnings", [])
        assert "missing_step_id" in warnings_field

    # ── Test 4: invalid step_id ───────────────────────────────────────────

    def test_invalid_step_id_returns_zero(self, norm: Normalizer) -> None:
        """Spec test 4 — non-numeric step_id → 0, warning contains invalid_step_id."""
        raw = {
            "event_id":   "raw_004",
            "event_type": "tool_call",
            "step_id":    "abc",
            "tool_name":  "delete_file",
            "status":     "pending",
        }
        ev = norm.normalize_raw_event(raw, "trace_t4")

        assert ev["step_id"] == 0
        assert isinstance(ev["step_id"], int)
        warnings_field = ev["metadata"].get("normalization_warnings", [])
        assert any("invalid_step_id" in w for w in warnings_field)

    # ── Test 5: unknown event_type ────────────────────────────────────────

    def test_unknown_event_type_no_crash(self, norm: Normalizer) -> None:
        """Spec test 5 — unrecognised event_type → phase=unknown, warning, no crash.

        When action IS mappable, action_type/action_name still resolve correctly.
        """
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            raw = {
                "event_id":   "raw_x",
                "event_type": "function_invoke",
                "step_id":    1,
                "tool_name":  "gmail_send",
                "status":     "pending",
            }
            ev = norm.normalize_raw_event(raw, "trace_t5")

        assert ev["phase"]       == "unknown"
        assert ev["action_name"] == "send_email"
        # action_type still resolved from vocab (tool_call), not from event_type
        assert ev["action_type"] == "tool_call"
        warnings_field = ev["metadata"].get("normalization_warnings", [])
        assert "unknown_event_type:function_invoke" in warnings_field

    # ── Test 6: metadata always dict ─────────────────────────────────────

    def test_metadata_always_dict(self, norm: Normalizer) -> None:
        """Spec test 6 — metadata is always dict even for a perfectly clean event."""
        raw = {
            "event_id":   "raw_clean",
            "event_type": "tool_call",
            "step_id":    1,
            "tool_name":  "send_email",
            "status":     "success",
        }
        ev = norm.normalize_raw_event(raw, "trace_t6")
        assert isinstance(ev["metadata"], dict), (
            f"metadata should be dict, got {type(ev['metadata'])}: {ev['metadata']}"
        )

    # ── Test 7: policy and decision pass-through ──────────────────────────

    def test_policy_decision_passthrough(self, norm: Normalizer) -> None:
        """Spec test 7 — policy and decision pass through verbatim."""
        policy_val = {
            "policy_version": "v0.1",
            "allowed_action_set": ["send_email"],
        }
        decision_val = {
            "verdict": "unknown",
            "route": "ask_user",
            "missing_evidence": ["approval"],
        }
        raw = {
            "event_id":   "raw_t7",
            "event_type": "tool_call",
            "step_id":    4,
            "tool_name":  "send_email",
            "status":     "pending",
            "policy":     policy_val,
            "decision":   decision_val,
        }
        ev = norm.normalize_raw_event(raw, "trace_t7")

        assert ev["policy"]   == policy_val
        assert ev["decision"] == decision_val

    # ── Extended event_type coverage (memory_read, external_api_call …) ──

    @pytest.mark.parametrize("event_type, expected_phase, expected_action_type", [
        ("memory_read",       "before_action", "memory_op"),
        ("memory_write",      "before_action", "memory_op"),
        ("external_api_call", "before_action", "external_api_call"),
        ("resource_access",   "before_action", "resource_access"),
        ("policy_update",     "state_change",  "policy_decision"),
        ("state_change",      "state_change",  "environment_update"),
        ("environment_update","state_change",  "environment_update"),
    ])
    def test_extended_event_type_mapping(
        self,
        norm: Normalizer,
        event_type: str,
        expected_phase: str,
        expected_action_type: str,
    ) -> None:
        """Extended _EVENT_TYPE_MAP entries resolve phase + action_type correctly."""
        raw = {
            "event_id":   "e_ext",
            "event_type": event_type,
            "step_id":    1,
            "tool_name":  None,
            "action":     None,
            "status":     "success",
        }
        ev = norm.normalize_raw_event(raw, "trace_ext")
        assert ev["phase"]       == expected_phase,       f"phase mismatch for {event_type}"
        assert ev["action_type"] == expected_action_type, f"action_type mismatch for {event_type}"

    # ── No SAFE inference check ───────────────────────────────────────────

    def test_no_safe_inference_when_evidence_missing(self, norm: Normalizer) -> None:
        """C1 must never produce SAFE/VIOLATION labels; evidence fields stay None."""
        raw = {
            "event_id":   "raw_safe_check",
            "event_type": "tool_call",
            "step_id":    3,
            "tool_name":  "delete_file",
            "status":     "pending",
            # No approval, taint, provenance, policy, decision
        }
        ev = norm.normalize_raw_event(raw, "trace_safe")

        # None of these evidence fields should have been fabricated
        assert ev["approval"]   is None
        assert ev["taint"]      is None
        assert ev["provenance"] is None
        assert ev["policy"]     is None
        assert ev["decision"]   is None
        # No verdict-like key in the output
        assert "verdict"    not in ev
        assert "safe"       not in str(ev.get("decision", ""))
        assert "violation"  not in str(ev.get("decision", ""))

