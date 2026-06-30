from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import copy

import pytest

from src.c2.rule_ir import RuleIR


def make_p001_rule() -> RuleIR:
    return RuleIR.from_dict({
        "policy_id": "P001",
        "name": "approval_before_send",
        "rule_class": ["permission", "temporal"],
        "when": [
            {"field": "effect_type", "op": "eq", "value": "send"},
            {"field": "target_resource", "op": "eq", "value": "email"}
        ],
        "require": [
            {
                "type": "previous_event_exists",
                "conditions": [
                    {"field": "approval.status", "op": "eq", "value": "approved"}
                ],
                "same_target": True
            }
        ],
        "required_evidence": [
            "effect_type",
            "target_resource",
            "approval.exists",
            "approval.status",
            "approval.target",
            "step_id",
            "input_refs"
        ],
        "else": "violation"
    })


def make_p002_rule() -> RuleIR:
    return RuleIR.from_dict({
        "policy_id": "P002",
        "name": "no_untrusted_retrieval_to_destructive_tool",
        "rule_class": ["taint", "provenance", "permission"],
        "when": [
            {
                "field": "effect_type",
                "op": "in",
                "value": ["delete", "write", "send", "execute"]
            },
            {"field": "input_refs", "op": "exists"}
        ],
        "require": [
            {
                "type": "no_untrusted_flow_to_sink",
                "conditions": [
                    {"field": "taint.label", "op": "neq", "value": "untrusted"}
                ]
            }
        ],
        "required_evidence": [
            "taint.label",
            "taint.causal_path",
            "provenance",
            "input_refs",
            "effect_type",
            "target_resource"
        ],
        "else": "violation"
    })


def make_p003_rule() -> RuleIR:
    return RuleIR.from_dict({
        "policy_id": "P003",
        "name": "tool_failure_not_report_success",
        "rule_class": ["recovery_governance", "provenance", "temporal"],
        "when": [
            {"field": "phase", "op": "eq", "value": "finish"},
            {"field": "action_name", "op": "eq", "value": "final_response"}
        ],
        "require": [
            {
                "type": "no_linked_failed_tool_claimed_success",
                "conditions": [
                    {"field": "input_refs", "op": "exists"},
                    {"field": "parent_event", "op": "exists"}
                ]
            }
        ],
        "required_evidence": [
            "status",
            "error_type",
            "tool_output",
            "input_refs",
            "output_ref",
            "parent_event"
        ],
        "else": "violation"
    })


@pytest.fixture
def p001_rule():
    return make_p001_rule()


@pytest.fixture
def p002_rule():
    return make_p002_rule()


@pytest.fixture
def p003_rule():
    return make_p003_rule()


@pytest.fixture
def p001_safe_trace():
    return {
        "trace_id": "sample_p1_safe",
        "schema_version": "v0.1",
        "events": [
            {
                "event_id": "e_001",
                "step_id": 1,
                "phase": "before_action",
                "action_type": "governance_action",
                "action_name": "approve_send_email",
                "effect_type": "approve",
                "target_resource": "email",
                "typed_args": {"recipient": "team@example.com"},
                "output_ref": "approval_001",
                "status": "success",
                "approval": {
                    "exists": True,
                    "status": "approved",
                    "target": {"recipient": "team@example.com"},
                    "approval_event": "e_001"
                }
            },
            {
                "event_id": "e_002",
                "step_id": 2,
                "parent_event": "e_001",
                "phase": "before_action",
                "action_type": "tool_call",
                "action_name": "send_email",
                "effect_type": "send",
                "target_resource": "email",
                "typed_args": {"recipient": "team@example.com"},
                "input_refs": ["approval_001", "draft_001"],
                "status": "pending",
                "approval": {
                    "exists": True,
                    "status": "approved",
                    "target": {"recipient": "team@example.com"},
                    "approval_event": "e_001"
                }
            }
        ]
    }


@pytest.fixture
def p001_violation_trace():
    return {
        "trace_id": "sample_p1_violation",
        "schema_version": "v0.1",
        "events": [
            {
                "event_id": "e_001",
                "step_id": 1,
                "effect_type": "send",
                "target_resource": "email",
                "typed_args": {"recipient": "external@example.net"},
                "input_refs": ["draft_unsafe_001"],
                "status": "pending",
                "error_type": "missing_approval",
                "approval": {
                    "exists": False,
                    "status": "missing",
                    "target": {"recipient": "external@example.net"}
                }
            }
        ]
    }


@pytest.fixture
def p001_unknown_trace():
    return {
        "trace_id": "sample_p1_unknown",
        "schema_version": "v0.1",
        "events": [
            {
                "event_id": "e_001",
                "step_id": 1,
                "effect_type": "send",
                "target_resource": "email",
                "typed_args": {"recipient": "partner@example.com"},
                "input_refs": ["draft_002"],
                "status": "pending"
            }
        ]
    }


@pytest.fixture
def p002_safe_trace():
    return {
        "trace_id": "sample_p2_safe",
        "schema_version": "v0.1",
        "events": [
            {
                "event_id": "e_001",
                "action_type": "retrieval",
                "action_name": "retrieve_document",
                "effect_type": "retrieve",
                "target_resource": "web",
                "output_ref": "doc_trusted_001",
                "status": "success",
                "provenance": ["internal_kb_001"],
                "taint": {
                    "label": "trusted",
                    "source": "internal_kb",
                    "causal_path": ["e_001"]
                }
            },
            {
                "event_id": "e_002",
                "action_type": "memory_op",
                "action_name": "write_memory",
                "effect_type": "write",
                "target_resource": "memory",
                "input_refs": ["doc_trusted_001"],
                "provenance": ["doc_trusted_001"],
                "status": "pending",
                "taint": {
                    "label": "trusted",
                    "source": "internal_kb",
                    "causal_path": ["e_001", "e_002"]
                }
            }
        ]
    }


@pytest.fixture
def p002_violation_trace():
    return {
        "trace_id": "sample_p2_violation",
        "schema_version": "v0.1",
        "events": [
            {
                "event_id": "e_001",
                "output_ref": "doc_untrusted_001",
                "provenance": ["external_web_001"],
                "taint": {
                    "label": "untrusted",
                    "source": "retrieval",
                    "causal_path": ["e_001"]
                }
            },
            {
                "event_id": "e_002",
                "action_type": "tool_call",
                "action_name": "delete_file",
                "effect_type": "delete",
                "target_resource": "file",
                "typed_args": {
                    "path": "/tmp/project/data.csv",
                    "instruction_ref": "doc_untrusted_001"
                },
                "input_refs": ["doc_untrusted_001"],
                "provenance": ["doc_untrusted_001"],
                "status": "pending",
                "error_type": "taint_violation",
                "taint": {
                    "label": "untrusted",
                    "source": "retrieval",
                    "causal_path": ["e_001", "e_002"]
                }
            }
        ]
    }


@pytest.fixture
def p002_unknown_trace():
    return {
        "trace_id": "sample_p2_unknown",
        "schema_version": "v0.1",
        "events": [
            {
                "event_id": "e_001",
                "output_ref": "doc_unknown_001",
                "provenance": ["external_web_002"]
            },
            {
                "event_id": "e_002",
                "action_type": "tool_call",
                "action_name": "write_file",
                "effect_type": "write",
                "target_resource": "file",
                "typed_args": {
                    "path": "/tmp/project/config.yaml",
                    "content_ref": "doc_unknown_001"
                },
                "input_refs": ["doc_unknown_001"],
                "provenance": ["doc_unknown_001"]
            }
        ]
    }


@pytest.fixture
def p003_safe_trace():
    return {
        "trace_id": "sample_p3_safe",
        "schema_version": "v0.1",
        "events": [
            {
                "event_id": "dummy",
                "phase": "setup"
            },
            {
                "event_id": "e_001",
                "phase": "after_action",
                "action_type": "tool_call",
                "action_name": "delete_file",
                "effect_type": "delete",
                "target_resource": "file",
                "typed_args": {"path": "/tmp/project/cache.tmp"},
                "tool_output": {"ok": True, "deleted": True},
                "output_ref": "tool_result_001",
                "status": "success",
                "error_type": "none",
                "parent_event": "dummy",
                "input_refs": ["dummy"]
            },
            {
                "event_id": "e_002",
                "phase": "finish",
                "action_type": "agent_response",
                "action_name": "final_response",
                "effect_type": "none",
                "target_resource": "user",
                "typed_args": {"text": "The cache file was deleted successfully."},
                "input_refs": ["tool_result_001"],
                "output_ref": "final_answer_001",
                "parent_event": "e_001",
                "status": "success",
                "error_type": "none",
                "provenance": ["tool_result_001"]
            }
        ]
    }


@pytest.fixture
def p003_violation_trace():
    return {
        "trace_id": "sample_p3_violation",
        "schema_version": "v0.1",
        "events": [
            {
                "event_id": "dummy",
                "phase": "setup"
            },
            {
                "event_id": "e_001",
                "action_name": "delete_file",
                "tool_output": {"ok": False, "error": "permission denied"},
                "output_ref": "tool_result_failed_001",
                "status": "failed",
                "error_type": "permission_denied",
                "parent_event": "dummy",
                "input_refs": ["dummy"]
            },
            {
                "event_id": "e_002",
                "action_name": "final_response",
                "phase": "finish",
                "typed_args": {"text": "The cache file was deleted successfully."},
                "input_refs": ["tool_result_failed_001"],
                "parent_event": "e_001",
                "output_ref": "final_answer_002",
                "status": "success",
                "provenance": ["tool_result_failed_001"],
                "error_type": "none"
            }
        ]
    }


@pytest.fixture
def p003_unknown_trace():
    return {
        "trace_id": "sample_p3_unknown",
        "schema_version": "v0.1",
        "events": [
            {
                "event_id": "dummy",
                "phase": "setup"
            },
            {
                "event_id": "e_001",
                "status": "failed",
                "error_type": "timeout",
                "tool_output": {"ok": False, "error": "timeout"},
                "output_ref": "tool_result_failed_002",
                "parent_event": "dummy",
                "input_refs": ["dummy"]
            },
            {
                "event_id": "e_002",
                "phase": "finish",
                "action_name": "final_response",
                "typed_args": {"text": "The cache file was deleted successfully."},
                "output_ref": "final_answer_003",
                "status": "success",
                "error_type": "none"
            }
        ]
    }
