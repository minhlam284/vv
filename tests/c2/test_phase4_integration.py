import json
from pathlib import Path

import pytest

from src.c2.integration import (
    validate_normalized_trace,
    run_phase5_pipeline,
    main,
    TraceValidationIssue,
)

MINIMAL_VOCABULARY = {
    "phase": ["plan", "before_action", "after_action", "state_change", "finish", "unknown"],
    "action_type": ["tool_call", "memory_op", "retrieval", "external_api_call", "message", "approval", "policy_update", "unknown"],
    "effect_type": ["read", "write", "delete", "send", "execute", "approve", "none", "unknown"],
    "target_resource": ["file", "email", "calendar", "memory", "database", "none", "unknown"],
    "status": ["pending", "success", "failed", "blocked", "aborted", "allowed", "unknown"],
    "error_type": ["permission_denied", "missing_approval", "policy_violation", "unknown"],
    "taint_label": ["trusted", "untrusted", "sensitive", "unknown"],
    "approval_status": ["approved", "rejected", "missing", "unknown"],
    "reversibility": ["easy", "hard", "irreversible", "unknown"],
    "decision_verdict": ["safe", "violation", "unknown", "inconsistent"],
    "decision_route": ["allow", "block", "abort", "ask_user", "unknown"]
}

MINIMAL_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["trace_id", "schema_version", "events"],
    "properties": {
        "trace_id": {"type": "string"},
        "schema_version": {"const": "0.1"},
        "events": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "event_id",
                    "trace_id",
                    "step_id",
                    "phase",
                    "action_type",
                    "status"
                ],
                "properties": {
                    "event_id": {"type": "string"},
                    "trace_id": {"type": "string"},
                    "step_id": {"type": "integer"},
                    "phase": {"type": "string"},
                    "action_type": {"type": "string"},
                    "status": {"type": "string"}
                },
                "additionalProperties": True
            }
        }
    },
    "additionalProperties": True
}

def create_valid_trace() -> dict:
    return {
        "trace_id": "case_001",
        "schema_version": "0.1",
        "events": [
            {
                "event_id": "e_001",
                "trace_id": "case_001",
                "step_id": 1,
                "phase": "before_action",
                "action_type": "tool_call",
                "status": "success",
                "effect_type": "send",
                "target_resource": "email"
            }
        ]
    }

def test_a_validate_schema_invariants_valid_trace():
    trace = create_valid_trace()
    result = validate_normalized_trace(
        trace,
        schema=MINIMAL_SCHEMA,
        vocabulary=MINIMAL_VOCABULARY,
        trace_file="case_001.json"
    )
    
    assert result.valid is True
    assert all(issue.level != "ERROR" for issue in result.issues)

def test_b_duplicate_event_id_invalid():
    trace = create_valid_trace()
    trace["events"].append(trace["events"][0].copy())
    trace["events"][1]["step_id"] = 2  # To avoid INV-03 overriding focus on INV-01
    
    result = validate_normalized_trace(
        trace,
        schema=MINIMAL_SCHEMA,
        vocabulary=MINIMAL_VOCABULARY,
        trace_file="case_001.json"
    )
    
    assert result.valid is False
    assert any(issue.code == "INV-01" for issue in result.issues)

def test_c_event_trace_id_mismatch_invalid():
    trace = create_valid_trace()
    trace["events"][0]["trace_id"] = "case_other"
    
    result = validate_normalized_trace(
        trace,
        schema=MINIMAL_SCHEMA,
        vocabulary=MINIMAL_VOCABULARY,
        trace_file="case_001.json"
    )
    
    assert result.valid is False
    assert any(issue.code == "INV-02" for issue in result.issues)

def test_d_step_id_out_of_order_invalid():
    trace = create_valid_trace()
    ev1 = trace["events"][0].copy()
    ev1["step_id"] = 2
    ev2 = trace["events"][0].copy()
    ev2["event_id"] = "e_002"
    ev2["step_id"] = 1
    
    trace["events"] = [ev1, ev2]
    
    result = validate_normalized_trace(
        trace,
        schema=MINIMAL_SCHEMA,
        vocabulary=MINIMAL_VOCABULARY,
        trace_file="case_001.json"
    )
    
    assert result.valid is False
    assert any(issue.code == "INV-03" for issue in result.issues)

def test_e_broken_parent_event_invalid():
    trace = create_valid_trace()
    trace["events"][0]["parent_event"] = "missing_event"
    
    result = validate_normalized_trace(
        trace,
        schema=MINIMAL_SCHEMA,
        vocabulary=MINIMAL_VOCABULARY,
        trace_file="case_001.json"
    )
    
    assert result.valid is False
    assert any(issue.code == "INV-04" for issue in result.issues)

def test_f_unresolved_input_refs_warning_only():
    trace = create_valid_trace()
    trace["events"][0]["input_refs"] = ["doc_unknown"]
    
    result = validate_normalized_trace(
        trace,
        schema=MINIMAL_SCHEMA,
        vocabulary=MINIMAL_VOCABULARY,
        trace_file="case_001.json"
    )
    
    assert result.valid is True
    assert any(issue.level == "WARNING" and issue.code == "INV-04" for issue in result.issues)

def test_g_invalid_enum_invalid():
    trace = create_valid_trace()
    trace["events"][0]["effect_type"] = "bad_effect"
    
    result = validate_normalized_trace(
        trace,
        schema=MINIMAL_SCHEMA,
        vocabulary=MINIMAL_VOCABULARY,
        trace_file="case_001.json"
    )
    
    assert result.valid is False
    assert any(issue.code == "INV-07" for issue in result.issues)

@pytest.fixture
def workspace(tmp_path):
    trace_dir = tmp_path / "data" / "normalized_traces"
    trace_dir.mkdir(parents=True)
    rule_dir = tmp_path / "rule_ir"
    rule_dir.mkdir(parents=True)
    out_dir = tmp_path / "results" / "c2"
    
    schema_path = tmp_path / "normalized_event_schema.json"
    with open(schema_path, "w") as f:
        json.dump(MINIMAL_SCHEMA, f)
        
    vocab_path = tmp_path / "vocabulary.yaml"
    import yaml
    with open(vocab_path, "w") as f:
        yaml.dump(MINIMAL_VOCABULARY, f)
        
    return tmp_path, trace_dir, rule_dir, out_dir, schema_path, vocab_path

def test_h_missing_approval_is_schema_valid_but_c2_unknown(workspace):
    tmp_path, trace_dir, rule_dir, out_dir, schema_path, vocab_path = workspace
    
    trace = create_valid_trace()
    trace["events"][0]["input_refs"] = ["e_001"] # arbitrary input ref
    # Note: no approval slot in event
    
    with open(trace_dir / "case_001.json", "w") as f:
        json.dump(trace, f)
        
    p001_rule = {
        "policy_id": "P001",
        "name": "Require approval for send email",
        "rule_class": ["permission"],
        "required_evidence": ["approval.exists", "approval.status"],
        "when": [
            {"field": "effect_type", "op": "eq", "value": "send"},
            {"field": "target_resource", "op": "eq", "value": "email"}
        ],
        "require": [
            {
                "type": "evidence",
                "conditions": [
                    {"field": "approval.status", "op": "eq", "value": "approved"}
                ]
            }
        ]
    }
    
    with open(rule_dir / "p001.json", "w") as f:
        json.dump(p001_rule, f)
        
    summary = run_phase5_pipeline(
        trace_dir=trace_dir,
        rule_path=rule_dir,
        schema_path=schema_path,
        vocabulary_path=vocab_path,
        out_dir=out_dir,
    )
    
    assert summary["valid_trace_count"] == 1
    
    with open(out_dir / "verdicts.csv") as f:
        content = f.read()
        assert "UNKNOWN" in content
        assert "SAFE" not in content
        
    with open(out_dir / "missing_evidence.csv") as f:
        content = f.read()
        assert "approval.exists" in content
        assert "approval.status" in content

def test_i_full_pipeline_writes_required_reports(workspace):
    tmp_path, trace_dir, rule_dir, out_dir, schema_path, vocab_path = workspace
    
    with open(trace_dir / "case_001.json", "w") as f:
        json.dump(create_valid_trace(), f)
        
    p001_rule = {
        "policy_id": "P001",
        "name": "Simple safe rule",
        "rule_class": ["permission"],
        "required_evidence": ["dummy.evidence"],
        "when": [
            {"field": "effect_type", "op": "eq", "value": "send"}
        ],
        "require": []
    }
    
    with open(rule_dir / "p001.json", "w") as f:
        json.dump(p001_rule, f)
        
    summary = run_phase5_pipeline(
        trace_dir=trace_dir,
        rule_path=rule_dir,
        schema_path=schema_path,
        vocabulary_path=vocab_path,
        out_dir=out_dir,
    )
    
    assert (out_dir / "verdicts.csv").exists()
    assert (out_dir / "missing_evidence.csv").exists()
    assert (out_dir / "evidence_mapping.csv").exists()
    assert (out_dir / "c2_summary.json").exists()
    assert (out_dir / "validation_report.json").exists()
    assert (out_dir / "integration_summary.json").exists()
    
    assert summary["valid_trace_count"] == 1
    assert summary["rule_count"] == 1

def test_j_invalid_trace_skipped(workspace):
    tmp_path, trace_dir, rule_dir, out_dir, schema_path, vocab_path = workspace
    
    with open(trace_dir / "case_001.json", "w") as f:
        json.dump(create_valid_trace(), f)
        
    invalid_trace = create_valid_trace()
    invalid_trace["events"][0]["effect_type"] = "invalid_enum_value"
    with open(trace_dir / "case_invalid.json", "w") as f:
        json.dump(invalid_trace, f)
        
    with open(rule_dir / "p001.json", "w") as f:
        json.dump({
            "policy_id": "P001",
            "name": "Empty rule",
            "rule_class": ["permission"],
            "required_evidence": ["dummy.evidence"],
            "when": [],
            "require": []
        }, f)
        
    summary = run_phase5_pipeline(
        trace_dir=trace_dir,
        rule_path=rule_dir,
        schema_path=schema_path,
        vocabulary_path=vocab_path,
        out_dir=out_dir,
        skip_invalid=True
    )
    
    assert summary["trace_count"] == 2
    assert summary["valid_trace_count"] == 1
    assert summary["invalid_trace_count"] == 1

def test_k_fail_on_invalid_behavior(workspace):
    tmp_path, trace_dir, rule_dir, out_dir, schema_path, vocab_path = workspace
    
    invalid_trace = create_valid_trace()
    invalid_trace["events"][0]["effect_type"] = "invalid_enum_value"
    with open(trace_dir / "case_invalid.json", "w") as f:
        json.dump(invalid_trace, f)
        
    with open(rule_dir / "p001.json", "w") as f:
        json.dump({
            "policy_id": "P001",
            "name": "Empty rule",
            "rule_class": ["permission"],
            "required_evidence": ["dummy.evidence"],
            "when": [],
            "require": []
        }, f)
        
    with pytest.raises(ValueError):
        run_phase5_pipeline(
            trace_dir=trace_dir,
            rule_path=rule_dir,
            schema_path=schema_path,
            vocabulary_path=vocab_path,
            out_dir=out_dir,
            skip_invalid=False
        )

def test_l_cli_smoke_test(workspace):
    tmp_path, trace_dir, rule_dir, out_dir, schema_path, vocab_path = workspace
    
    with open(trace_dir / "case_001.json", "w") as f:
        json.dump(create_valid_trace(), f)
        
    with open(rule_dir / "p001.json", "w") as f:
        json.dump({
            "policy_id": "P001",
            "name": "Empty rule",
            "rule_class": ["permission"],
            "required_evidence": ["dummy.evidence"],
            "when": [],
            "require": []
        }, f)
        
    code = main([
        "--trace-dir", str(trace_dir),
        "--rules", str(rule_dir),
        "--schema", str(schema_path),
        "--vocabulary", str(vocab_path),
        "--out-dir", str(out_dir),
        "--quiet"
    ])
    
    assert code == 0
    assert (out_dir / "verdicts.csv").exists()
    assert (out_dir / "c2_summary.json").exists()
