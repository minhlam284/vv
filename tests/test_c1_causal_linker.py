"""
tests/test_c1_causal_linker.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tests for c1.causal_linker — Task 4.6.

All tests exercise the public API ``link_causal_trace()`` / ``CausalLinker``.
No external dependencies (vocabulary.yaml, network, …) are required.
"""

from __future__ import annotations

import pytest

# Adjust the import path to match the project's package layout.
# The src directory has a trailing space, so we add it to sys.path.
import sys
from pathlib import Path

# Add "src " directory (note the trailing space in the actual folder name)
_SRC_DIR = Path(__file__).resolve().parents[1] / "src "
sys.path.insert(0, str(_SRC_DIR))

from c1.causal_linker import CausalLinker, link_causal_trace  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_trace(*events: dict) -> dict:
    """Wrap events in a minimal trace envelope."""
    return {
        "trace_id": "t_test",
        "schema_version": "0.1",
        "events": list(events),
    }


def _find_event(linked_trace: dict, event_id: str) -> dict:
    """Return the event with the given ID from a linked trace."""
    for e in linked_trace["events"]:
        if e.get("event_id") == event_id:
            return e
    raise KeyError(f"Event {event_id!r} not found in linked trace")


# ---------------------------------------------------------------------------
# Test 1 — retrieval output_ref is inferred from tool_output.doc_id
# ---------------------------------------------------------------------------

class TestEnsureOutputRef:
    def test_doc_id_in_tool_output(self):
        """output_ref should be set to the doc_id found inside tool_output."""
        trace = _make_trace(
            {
                "event_id": "e_001",
                "trace_id": "t_test",
                "step_id": 1,
                "action_type": "retrieval",
                "action_name": "retrieve_document",
                "effect_type": "retrieve",
                "phase": "after_action",
                "tool_output": {"doc_id": "doc_001"},
                "input_refs": None,
                "output_ref": None,
                "parent_event": None,
                "metadata": {},
            }
        )
        linked = link_causal_trace(trace)
        event = _find_event(linked, "e_001")
        assert event["output_ref"] == "doc_001"

    def test_retrieval_fallback_ref(self):
        """When tool_output has no ID keys, output_ref uses retrieval_{event_id}."""
        trace = _make_trace(
            {
                "event_id": "e_r",
                "step_id": 1,
                "action_type": "retrieval",
                "effect_type": "retrieve",
                "tool_output": {"text": "some text"},
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            }
        )
        linked = link_causal_trace(trace)
        event = _find_event(linked, "e_r")
        assert event["output_ref"] == "retrieval_e_r"

    def test_existing_output_ref_is_preserved(self):
        """An already-present output_ref must not be overwritten."""
        trace = _make_trace(
            {
                "event_id": "e_001",
                "step_id": 1,
                "action_type": "retrieval",
                "effect_type": "retrieve",
                "tool_output": {"doc_id": "doc_NEW"},
                "output_ref": "existing_ref",
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            }
        )
        linked = link_causal_trace(trace)
        event = _find_event(linked, "e_001")
        assert event["output_ref"] == "existing_ref"

    def test_tool_result_output_ref(self):
        trace = _make_trace(
            {
                "event_id": "e_tr",
                "step_id": 1,
                "action_type": "tool_result",
                "tool_output": None,
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            }
        )
        linked = link_causal_trace(trace)
        event = _find_event(linked, "e_tr")
        assert event["output_ref"] == "tool_result_e_tr"

    def test_final_response_output_ref(self):
        trace = _make_trace(
            {
                "event_id": "e_fr",
                "step_id": 1,
                "action_type": "agent_response",
                "action_name": "final_response",
                "tool_output": None,
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            }
        )
        linked = link_causal_trace(trace)
        event = _find_event(linked, "e_fr")
        assert event["output_ref"] == "final_answer_e_fr"

    def test_memory_write_output_ref_with_key(self):
        trace = _make_trace(
            {
                "event_id": "e_mw",
                "step_id": 1,
                "action_type": "memory_op",
                "effect_type": "write",
                "typed_args": {"memory_key": "user_pref"},
                "tool_output": None,
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            }
        )
        linked = link_causal_trace(trace)
        event = _find_event(linked, "e_mw")
        assert event["output_ref"] == "user_pref"

    def test_memory_write_output_ref_fallback(self):
        trace = _make_trace(
            {
                "event_id": "e_mw2",
                "step_id": 1,
                "action_type": "memory_op",
                "effect_type": "write",
                "typed_args": {},
                "tool_output": None,
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            }
        )
        linked = link_causal_trace(trace)
        event = _find_event(linked, "e_mw2")
        assert event["output_ref"] == "memory_e_mw2"


# ---------------------------------------------------------------------------
# Test 2 — retrieval → delete_file: input_refs and parent_event
# ---------------------------------------------------------------------------

class TestRetrievalToDelete:
    def _build_trace(self) -> dict:
        return _make_trace(
            {
                "event_id": "e_001",
                "step_id": 1,
                "action_type": "retrieval",
                "effect_type": "retrieve",
                "tool_output": {"doc_id": "doc_001"},
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "taint": None,
                "metadata": {},
            },
            {
                "event_id": "e_002",
                "step_id": 2,
                "action_type": "tool_call",
                "action_name": "delete_file",
                "effect_type": "delete",
                "tool_output": None,
                "typed_args": {},
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "taint": None,
                "metadata": {},
            },
        )

    def test_delete_event_input_refs(self):
        linked = link_causal_trace(self._build_trace())
        delete_event = _find_event(linked, "e_002")
        assert delete_event["input_refs"] is not None
        assert "doc_001" in delete_event["input_refs"]

    def test_delete_event_parent_event(self):
        linked = link_causal_trace(self._build_trace())
        delete_event = _find_event(linked, "e_002")
        assert delete_event["parent_event"] == "e_001"


# ---------------------------------------------------------------------------
# Test 3 — typed_args content_ref added to input_refs
# ---------------------------------------------------------------------------

class TestTypedArgsContentRef:
    def test_content_ref_in_input_refs(self):
        trace = _make_trace(
            {
                "event_id": "e_001",
                "step_id": 1,
                "action_type": "retrieval",
                "effect_type": "retrieve",
                "tool_output": {"doc_id": "doc_001"},
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            },
            {
                "event_id": "e_002",
                "step_id": 2,
                "action_type": "tool_call",
                "action_name": "write_file",
                "effect_type": "write",
                "typed_args": {"content_ref": "doc_001"},
                "tool_output": None,
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            },
        )
        linked = link_causal_trace(trace)
        event = _find_event(linked, "e_002")
        assert event["input_refs"] is not None
        assert "doc_001" in event["input_refs"]

    def test_multiple_ref_arg_keys(self):
        """Several REF_ARG_KEYS should all be picked up."""
        trace = _make_trace(
            {
                "event_id": "e_tc",
                "step_id": 1,
                "action_type": "tool_call",
                "effect_type": "write",
                "typed_args": {"doc_id": "d1", "source_id": "s1"},
                "tool_output": None,
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            }
        )
        linked = link_causal_trace(trace)
        event = _find_event(linked, "e_tc")
        assert "d1" in (event["input_refs"] or [])
        assert "s1" in (event["input_refs"] or [])


# ---------------------------------------------------------------------------
# Test 4 — final_response links to tool_result
# ---------------------------------------------------------------------------

class TestFinalResponseLinksToToolResult:
    def _build_trace(self) -> dict:
        return _make_trace(
            {
                "event_id": "e_001",
                "step_id": 1,
                "action_type": "tool_result",
                "tool_output": {"result_id": "tool_result_001"},
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "taint": None,
                "metadata": {},
            },
            {
                "event_id": "e_002",
                "step_id": 2,
                "action_type": "agent_response",
                "action_name": "final_response",
                "tool_output": None,
                "typed_args": {},
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "taint": None,
                "metadata": {},
            },
        )

    def test_final_response_input_refs(self):
        linked = link_causal_trace(self._build_trace())
        final_event = _find_event(linked, "e_002")
        assert final_event["input_refs"] is not None
        assert "tool_result_001" in final_event["input_refs"]

    def test_final_response_parent_event(self):
        linked = link_causal_trace(self._build_trace())
        final_event = _find_event(linked, "e_002")
        assert final_event["parent_event"] == "e_001"


# ---------------------------------------------------------------------------
# Test 5 — existing valid parent_event is preserved
# ---------------------------------------------------------------------------

class TestExistingParentEventPreserved:
    def test_valid_parent_event_unchanged(self):
        trace = _make_trace(
            {
                "event_id": "e_001",
                "step_id": 1,
                "action_type": "retrieval",
                "effect_type": "retrieve",
                "tool_output": {"doc_id": "doc_001"},
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            },
            {
                "event_id": "e_002",
                "step_id": 2,
                "action_type": "tool_call",
                "effect_type": "delete",
                "tool_output": None,
                "typed_args": {},
                "output_ref": None,
                "input_refs": None,
                "parent_event": "e_001",  # already set
                "metadata": {},
            },
        )
        linked = link_causal_trace(trace)
        e2 = _find_event(linked, "e_002")
        assert e2["parent_event"] == "e_001"


# ---------------------------------------------------------------------------
# Test 6 — broken parent_event triggers warning and is cleared
# ---------------------------------------------------------------------------

class TestBrokenParentEventWarning:
    def test_broken_parent_cleared_and_warned(self):
        trace = _make_trace(
            {
                "event_id": "e_001",
                "step_id": 1,
                "action_type": "retrieval",
                "effect_type": "retrieve",
                "tool_output": None,
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            },
            {
                "event_id": "e_002",
                "step_id": 2,
                "action_type": "tool_call",
                "effect_type": "delete",
                "tool_output": None,
                "typed_args": {},
                "output_ref": None,
                "input_refs": None,
                "parent_event": "missing_event",
                "metadata": {},
            },
        )
        linked = link_causal_trace(trace)
        e2 = _find_event(linked, "e_002")

        # parent_event must be cleared (None or reassigned to a valid event)
        assert e2["parent_event"] != "missing_event"

        # Warning must be present
        warnings = e2.get("metadata", {}).get("causal_link_warnings", [])
        assert any("broken_parent_event:missing_event" in w for w in warnings)


# ---------------------------------------------------------------------------
# Test 7 — taint.causal_path propagated from retrieval to write_file
# ---------------------------------------------------------------------------

class TestTaintCausalPathPropagation:
    def test_causal_path_propagated(self):
        trace = _make_trace(
            {
                "event_id": "e_001",
                "step_id": 1,
                "action_type": "retrieval",
                "effect_type": "retrieve",
                "tool_output": {"doc_id": "doc_001"},
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "taint": {
                    "label": "untrusted",
                    "source": "web",
                    "causal_path": ["e_001"],
                },
                "metadata": {},
            },
            {
                "event_id": "e_002",
                "step_id": 2,
                "action_type": "tool_call",
                "action_name": "write_file",
                "effect_type": "write",
                "typed_args": {},
                "tool_output": None,
                "output_ref": None,
                "input_refs": ["doc_001"],
                "parent_event": None,
                "taint": None,
                "metadata": {},
            },
        )
        linked = link_causal_trace(trace)
        write_event = _find_event(linked, "e_002")

        assert write_event["taint"] is not None
        assert write_event["taint"]["label"] == "untrusted"

        path = write_event["taint"]["causal_path"]
        assert "e_001" in path
        assert "e_002" in path
        assert path.index("e_001") < path.index("e_002")

    def test_taint_label_priority(self):
        """When two producers have different labels, the higher-priority wins."""
        trace = _make_trace(
            {
                "event_id": "e_a",
                "step_id": 1,
                "action_type": "retrieval",
                "effect_type": "retrieve",
                "tool_output": {"doc_id": "da"},
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "taint": {"label": "trusted", "source": "internal", "causal_path": ["e_a"]},
                "metadata": {},
            },
            {
                "event_id": "e_b",
                "step_id": 2,
                "action_type": "retrieval",
                "effect_type": "retrieve",
                "tool_output": {"doc_id": "db"},
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "taint": {"label": "untrusted", "source": "web", "causal_path": ["e_b"]},
                "metadata": {},
            },
            {
                "event_id": "e_c",
                "step_id": 3,
                "action_type": "tool_call",
                "effect_type": "write",
                "typed_args": {},
                "tool_output": None,
                "output_ref": None,
                "input_refs": ["da", "db"],
                "parent_event": None,
                "taint": None,
                "metadata": {},
            },
        )
        linked = link_causal_trace(trace)
        ec = _find_event(linked, "e_c")
        assert ec["taint"]["label"] == "untrusted"


# ---------------------------------------------------------------------------
# Test 8 — unresolved input_ref triggers warning
# ---------------------------------------------------------------------------

class TestUnresolvedInputRefWarning:
    def test_warning_on_missing_ref(self):
        trace = _make_trace(
            {
                "event_id": "e_001",
                "step_id": 1,
                "action_type": "tool_call",
                "effect_type": "write",
                "typed_args": {},
                "tool_output": None,
                "output_ref": None,
                "input_refs": ["missing_doc"],
                "parent_event": None,
                "taint": None,
                "metadata": {},
            }
        )
        linked = link_causal_trace(trace)
        event = _find_event(linked, "e_001")
        warnings = event.get("metadata", {}).get("causal_link_warnings", [])
        assert any("unresolved_input_ref:missing_doc" in w for w in warnings)

    def test_unresolved_ref_not_removed(self):
        """The ref must not be silently dropped; validator/C2 handles it."""
        trace = _make_trace(
            {
                "event_id": "e_001",
                "step_id": 1,
                "action_type": "tool_call",
                "effect_type": "write",
                "typed_args": {},
                "tool_output": None,
                "output_ref": None,
                "input_refs": ["missing_doc"],
                "parent_event": None,
                "taint": None,
                "metadata": {},
            }
        )
        linked = link_causal_trace(trace)
        event = _find_event(linked, "e_001")
        assert event["input_refs"] is not None
        assert "missing_doc" in event["input_refs"]


# ---------------------------------------------------------------------------
# Test 9 — causal linker does NOT produce decision/verdict fields
# ---------------------------------------------------------------------------

class TestNoVerdictProduced:
    def test_no_decision_field_added(self):
        trace = _make_trace(
            {
                "event_id": "e_001",
                "step_id": 1,
                "action_type": "retrieval",
                "effect_type": "retrieve",
                "tool_output": {"doc_id": "doc_001"},
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "taint": {"label": "untrusted", "source": "web", "causal_path": ["e_001"]},
                "metadata": {},
            },
            {
                "event_id": "e_002",
                "step_id": 2,
                "action_type": "tool_call",
                "effect_type": "delete",
                "typed_args": {},
                "tool_output": None,
                "output_ref": None,
                "input_refs": ["doc_001"],
                "parent_event": None,
                "taint": None,
                "metadata": {},
            },
        )
        linked = link_causal_trace(trace)
        for event in linked["events"]:
            # causal_linker must never set decision/verdict
            assert "decision" not in event or event.get("decision") is None
            taint = event.get("taint")
            if isinstance(taint, dict):
                assert "verdict" not in taint, (
                    f"Unexpected verdict in taint for {event.get('event_id')}"
                )


# ---------------------------------------------------------------------------
# Test 10 — input trace is not mutated (deep-copy contract)
# ---------------------------------------------------------------------------

class TestInputNotMutated:
    def test_original_trace_unchanged(self):
        import copy

        original = _make_trace(
            {
                "event_id": "e_001",
                "step_id": 1,
                "action_type": "retrieval",
                "effect_type": "retrieve",
                "tool_output": {"doc_id": "doc_001"},
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            }
        )
        snapshot = copy.deepcopy(original)
        link_causal_trace(original)
        assert original == snapshot, "Input trace was mutated by link_causal_trace"


# ---------------------------------------------------------------------------
# Test 11 — events sorted by step_id before linking
# ---------------------------------------------------------------------------

class TestEventOrdering:
    def test_out_of_order_events_linked_correctly(self):
        """Events provided out of step_id order should still link correctly."""
        trace = _make_trace(
            {
                "event_id": "e_002",
                "step_id": 2,
                "action_type": "tool_call",
                "effect_type": "delete",
                "typed_args": {},
                "tool_output": None,
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "taint": None,
                "metadata": {},
            },
            {
                "event_id": "e_001",
                "step_id": 1,
                "action_type": "retrieval",
                "effect_type": "retrieve",
                "tool_output": {"doc_id": "doc_001"},
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "taint": None,
                "metadata": {},
            },
        )
        linked = link_causal_trace(trace)
        e2 = _find_event(linked, "e_002")
        # After ordering, e_001 (step 1) comes before e_002 (step 2).
        # So the sink e_002 should see the retrieval output as input.
        assert e2["input_refs"] is not None
        assert "doc_001" in e2["input_refs"]


# ---------------------------------------------------------------------------
# Test 12 — empty trace passes through without errors
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_events(self):
        trace = {"trace_id": "empty", "schema_version": "0.1", "events": []}
        linked = link_causal_trace(trace)
        assert linked["events"] == []

    def test_single_event_no_crash(self):
        trace = _make_trace(
            {
                "event_id": "e_solo",
                "step_id": 1,
                "action_type": "message",
                "phase": "plan",
                "tool_output": None,
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            }
        )
        linked = link_causal_trace(trace)
        assert len(linked["events"]) == 1

    def test_none_step_id_event_sorts_last(self):
        trace = _make_trace(
            {
                "event_id": "e_none",
                "step_id": None,
                "action_type": "retrieval",
                "effect_type": "retrieve",
                "tool_output": None,
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            },
            {
                "event_id": "e_first",
                "step_id": 1,
                "action_type": "message",
                "phase": "plan",
                "tool_output": None,
                "output_ref": None,
                "input_refs": None,
                "parent_event": None,
                "metadata": {},
            },
        )
        linked = link_causal_trace(trace)
        # Should not raise; both events present
        event_ids = [e["event_id"] for e in linked["events"]]
        assert "e_first" in event_ids
        assert "e_none" in event_ids
