import json
import pytest
from pathlib import Path

from src.c2.cli import (
    load_json,
    write_json,
    discover_trace_files,
    make_output_stem,
    run_c2_on_trace,
    extract_missing_evidence_report,
    main
)
from src.c2.rule_ir import RuleIR

# Test A — load_json / write_json
def test_a_load_write_json(tmp_path: Path):
    file_path = tmp_path / "test.json"
    data = {"hello": "world"}
    write_json(file_path, data)
    assert file_path.exists()
    
    loaded = load_json(file_path)
    assert loaded == data

# Test B — discover_trace_files
def test_b_discover_trace_files(tmp_path: Path):
    d = tmp_path / "traces"
    d.mkdir()
    
    (d / "a.json").write_text('{}')
    (d / "b.json").write_text('{}')
    (d / "note.txt").write_text('hello')
    
    files = discover_trace_files(d)
    assert len(files) == 2
    assert files[0].name == "a.json"
    assert files[1].name == "b.json"

# Test C — make_output_stem
def test_c_make_output_stem(tmp_path: Path):
    trace_path = tmp_path / "some_file.json"
    trace = {"trace_id": "case/001 unsafe"}
    
    stem = make_output_stem(trace_path, trace)
    assert stem == "case_001_unsafe"
    
    stem2 = make_output_stem(trace_path, {})
    assert stem2 == "some_file"

# Rule fixture for P001
@pytest.fixture
def p001_rule() -> RuleIR:
    rule_dict = {
        "policy_id": "P001",
        "name": "approval_before_send",
        "rule_class": ["permission", "temporal"],
        "when": [
            {"field": "effect_type", "op": "eq", "value": "send"},
            {"field": "target_resource", "op": "eq", "value": "email"}
        ],
        "require": [],
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
    }
    return RuleIR.from_dict(rule_dict)

# Test D — run_c2_on_trace P001 violation
def test_d_run_c2_on_trace_p001_violation(p001_rule: RuleIR):
    trace = {
        "trace_id": "case_p1_violation",
        "schema_version": "0.1",
        "events": [
            {
                "event_id": "e_001",
                "trace_id": "case_p1_violation",
                "step_id": 1,
                "timestamp": None,
                "parent_event": None,
                "phase": "before_action",
                "action_type": "tool_call",
                "action_name": "send_email",
                "effect_type": "send",
                "target_resource": "email",
                "typed_args": {"recipient": "external@example.net"},
                "tool_output": None,
                "input_refs": ["draft_001"],
                "output_ref": None,
                "pre_state": None,
                "post_state": None,
                "status": "pending",
                "error_type": "missing_approval",
                "reversibility": "hard",
                "raw_event_ref": "raw_e_001",
                "approval": {
                    "exists": False,
                    "status": "missing",
                    "target": {"recipient": "external@example.net"},
                    "approved_by": None,
                    "approval_event": None
                }
            }
        ]
    }
    
    combined = run_c2_on_trace(trace, [p001_rule])
    assert combined["trace_id"] == "case_p1_violation"
    assert combined["summary"]["violation"] == 1
    assert combined["verdicts"][0]["verdict"] == "VIOLATION"

# Test E — run_c2_on_trace P001 unknown missing approval
def test_e_run_c2_on_trace_p001_unknown(p001_rule: RuleIR):
    trace = {
        "trace_id": "case_p1_unknown",
        "schema_version": "0.1",
        "events": [
            {
                "event_id": "e_001",
                "trace_id": "case_p1_unknown",
                "step_id": 1,
                "effect_type": "send",
                "target_resource": "email",
                "input_refs": []
            }
        ]
    }
    
    combined = run_c2_on_trace(trace, [p001_rule])
    assert combined["verdicts"][0]["verdict"] == "UNKNOWN"
    assert "approval.exists" in combined["verdicts"][0]["missing_evidence"]
    assert combined["summary"]["unknown"] == 1

# Test F — extract_missing_evidence_report
def test_f_extract_missing_evidence_report(p001_rule: RuleIR):
    trace = {
        "trace_id": "case_p1_unknown",
        "schema_version": "0.1",
        "events": [
            {
                "event_id": "e_001",
                "step_id": 1,
                "effect_type": "send",
                "target_resource": "email",
                "input_refs": []
            }
        ]
    }
    
    combined = run_c2_on_trace(trace, [p001_rule])
    report = extract_missing_evidence_report(combined)
    
    assert report["trace_id"] == "case_p1_unknown"
    assert len(report["missing_evidence"]) == 1
    assert report["missing_evidence"][0]["policy_id"] == "P001"

# Test G — single trace CLI writes output file
def test_g_single_trace_cli(tmp_path: Path, p001_rule: RuleIR, capsys):
    trace_path = tmp_path / "trace.json"
    trace = {
        "trace_id": "case_g",
        "events": []
    }
    write_json(trace_path, trace)
    
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    write_json(rules_dir / "p001.json", p001_rule.to_dict())
    
    out_path = tmp_path / "out.json"
    
    exit_code = main([
        "--trace", str(trace_path),
        "--rules", str(rules_dir),
        "--out", str(out_path),
        "--quiet"
    ])
    
    assert exit_code == 0
    assert out_path.exists()
    
    out_data = load_json(out_path)
    assert "verdicts" in out_data

# Test H — batch mode writes files
def test_h_batch_mode(tmp_path: Path, p001_rule: RuleIR):
    trace_dir = tmp_path / "traces"
    trace_dir.mkdir()
    
    write_json(trace_dir / "case_001.json", {"trace_id": "case_001", "events": []})
    write_json(trace_dir / "case_002.json", {"trace_id": "case_002", "events": []})
    
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    write_json(rules_dir / "p001.json", p001_rule.to_dict())
    
    out_dir = tmp_path / "results"
    
    exit_code = main([
        "--trace-dir", str(trace_dir),
        "--rules", str(rules_dir),
        "--out-dir", str(out_dir),
        "--quiet"
    ])
    
    assert exit_code == 0
    assert (out_dir / "case_001_verdicts.json").exists()
    assert (out_dir / "case_001_missing_evidence.json").exists()
    assert (out_dir / "case_002_verdicts.json").exists()
    assert (out_dir / "batch_summary.json").exists()

# Test I — fail-on-violation exit code
def test_i_fail_on_violation(tmp_path: Path, p001_rule: RuleIR):
    trace_path = tmp_path / "violation_trace.json"
    trace = {
        "trace_id": "case_i",
        "schema_version": "0.1",
        "events": [
            {
                "event_id": "e_001",
                "step_id": 1,
                "effect_type": "send",
                "target_resource": "email",
                "input_refs": ["draft_001"],
                "approval": {
                    "exists": False,
                    "status": "missing",
                    "target": {"recipient": "external@example.net"}
                }
            }
        ]
    }
    write_json(trace_path, trace)
    
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    write_json(rules_dir / "p001.json", p001_rule.to_dict())
    
    exit_code = main([
        "--trace", str(trace_path),
        "--rules", str(rules_dir),
        "--quiet",
        "--fail-on-violation"
    ])
    
    assert exit_code == 2

# Test J — fail-on-unknown exit code
def test_j_fail_on_unknown(tmp_path: Path, p001_rule: RuleIR):
    trace_path = tmp_path / "unknown_trace.json"
    trace = {
        "trace_id": "case_j",
        "schema_version": "0.1",
        "events": [
            {
                "event_id": "e_001",
                "step_id": 1,
                "effect_type": "send",
                "target_resource": "email",
                "input_refs": []
            }
        ]
    }
    write_json(trace_path, trace)
    
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    write_json(rules_dir / "p001.json", p001_rule.to_dict())
    
    exit_code = main([
        "--trace", str(trace_path),
        "--rules", str(rules_dir),
        "--quiet",
        "--fail-on-unknown"
    ])
    
    assert exit_code == 3
