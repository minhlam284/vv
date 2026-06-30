import csv
import json
from pathlib import Path
import pytest

from src.c2.reports import (
    verdict_rows_from_result,
    missing_evidence_rows_from_result,
    evidence_mapping_rows_from_result,
    build_c2_summary,
    generate_reports,
    write_csv,
    load_c2_results,
    main
)

def test_verdict_rows_from_result():
    # Test A — verdict_rows_from_result
    result = {
        "trace_id": "case_001",
        "verdicts": [
            {
                "policy_id": "P001",
                "trace_id": "case_001",
                "verdict": "safe",
                "reason": "approval exists"
            },
            {
                "policy_id": "P002",
                "trace_id": "case_001",
                "verdict": "violation",
                "reason": "untrusted source"
            }
        ]
    }
    
    rows = verdict_rows_from_result(result)
    assert len(rows) == 2
    assert rows[0] == {
        "trace_id": "case_001",
        "policy_id": "P001",
        "verdict": "SAFE",
        "reason": "approval exists"
    }
    assert rows[1] == {
        "trace_id": "case_001",
        "policy_id": "P002",
        "verdict": "VIOLATION",
        "reason": "untrusted source"
    }

def test_missing_evidence_rows_from_result():
    # Test B — missing_evidence_rows_from_result
    result = {
        "trace_id": "case_003",
        "verdicts": [
            {
                "policy_id": "P001",
                "trace_id": "case_003",
                "verdict": "UNKNOWN",
                "reason": "approval evidence missing",
                "missing_evidence": ["approval.status", "approval.target"],
                "triggered_event_ids": ["e_002"]
            }
        ],
        "preservation": [
            {
                "policy_id": "P001",
                "trace_id": "case_003",
                "status": "INCOMPLETE",
                "missing_evidence": ["approval.status", "approval.target"],
                "triggered_event_ids": ["e_002"]
            }
        ]
    }
    
    rows = missing_evidence_rows_from_result(result)
    assert len(rows) == 2
    assert {"trace_id": "case_003", "policy_id": "P001", "missing_field": "approval.status", "event_id": "e_002"} in rows
    assert {"trace_id": "case_003", "policy_id": "P001", "missing_field": "approval.target", "event_id": "e_002"} in rows

def test_missing_evidence_with_no_event_id():
    # Test C — missing evidence with no event id
    result = {
        "trace_id": "case_003",
        "verdicts": [
            {
                "policy_id": "P001",
                "trace_id": "case_003",
                "verdict": "UNKNOWN",
                "missing_evidence": ["approval.status"],
                "triggered_event_ids": []
            }
        ]
    }
    rows = missing_evidence_rows_from_result(result)
    assert len(rows) == 1
    assert rows[0]["event_id"] == ""

def test_evidence_mapping_rows_from_result():
    # Test D — evidence_mapping_rows_from_result
    result = {
        "trace_id": "case_001",
        "verdicts": [
            {
                "policy_id": "P001",
                "trace_id": "case_001",
                "verdict": "SAFE",
                "evidence_map": {
                    "approval.status": ["e_001"],
                    "effect_type": ["e_002"]
                }
            }
        ]
    }
    
    rows = evidence_mapping_rows_from_result(result)
    assert len(rows) == 2
    
    # Check that both rows are present
    approval_row = next(r for r in rows if r["evidence_field"] == "approval.status")
    effect_row = next(r for r in rows if r["evidence_field"] == "effect_type")
    
    assert approval_row["event_ids"] == "e_001"
    assert effect_row["event_ids"] == "e_002"
    assert approval_row["value"] == ""
    assert effect_row["value"] == ""

def test_build_c2_summary():
    # Test E — build_c2_summary
    results = [
        {
            "trace_id": "case_001",
            "verdicts": [{"policy_id": "P001", "verdict": "SAFE"}]
        },
        {
            "trace_id": "case_002",
            "verdicts": [{"policy_id": "P001", "verdict": "UNKNOWN", "missing_evidence": ["approval.status"]}]
        },
        {
            "trace_id": "case_003",
            "verdicts": [{"policy_id": "P002", "verdict": "VIOLATION"}]
        }
    ]
    
    summary = build_c2_summary(results)
    assert summary["trace_count"] == 3
    assert summary["policy_count"] == 2
    assert summary["verdict_counts"]["SAFE"] == 1
    assert summary["verdict_counts"]["UNKNOWN"] == 1
    assert summary["verdict_counts"]["VIOLATION"] == 1
    assert summary["missing_evidence_count"] == 1
    assert summary["missing_evidence_by_field"]["approval.status"] == 1
    assert "case_002" in summary["traces_with_unknown"]
    assert "case_003" in summary["traces_with_violation"]

def test_generate_reports_writes_files(tmp_path):
    # Test F — generate_reports writes files
    results = [
        {
            "trace_id": "case_001",
            "verdicts": [
                {
                    "policy_id": "P001",
                    "trace_id": "case_001",
                    "verdict": "SAFE",
                    "reason": "approval exists before send",
                    "missing_evidence": [],
                    "evidence_map": {
                        "approval.status": ["e_001"]
                    },
                    "triggered_event_ids": ["e_002"]
                }
            ]
        }
    ]
    
    out_dir = tmp_path / "results"
    paths = generate_reports(results, out_dir)
    
    assert paths["verdicts"].exists()
    assert paths["missing_evidence"].exists()
    assert paths["evidence_mapping"].exists()
    assert paths["summary"].exists()
    
    # Read verdicts.csv
    with open(paths["verdicts"], "r", encoding="utf-8") as f:
        header = f.readline().strip()
        assert header == "trace_id,policy_id,verdict,reason"
        row = f.readline().strip()
        assert row == "case_001,P001,SAFE,approval exists before send"
        
    # Read summary JSON
    with open(paths["summary"], "r", encoding="utf-8") as f:
        summary = json.load(f)
        assert summary["trace_count"] == 1

def test_write_csv_handles_list_and_dict_values(tmp_path):
    # Test G — write_csv handles list and dict values
    rows = [
        {
            "trace_id": "case_001",
            "policy_id": "P001",
            "evidence_field": "approval.target",
            "event_ids": ["e_001", "e_002"],
            "value": {"recipient": "team@example.com"}
        }
    ]
    
    csv_file = tmp_path / "test.csv"
    write_csv(csv_file, rows, ["trace_id", "policy_id", "evidence_field", "event_ids", "value"])
    
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        row = next(reader)
        
    assert row["event_ids"] == "e_001|e_002"
    assert row["value"] == '{"recipient":"team@example.com"}'
    # Wait, the assertion from the prompt for dict values actually had `[team@example.com](mailto:team@example.com)` but my dict string contains standard json.
    # The prompt actually said: JSON string for recipient, so checking `{"recipient":"team@example.com"}` is correct.

def test_load_c2_results_from_directory(tmp_path):
    # Test H — load_c2_results from directory
    (tmp_path / "case_001_verdicts.json").write_text('{"trace_id": "case_001"}')
    (tmp_path / "case_001_missing_evidence.json").write_text('{"trace_id": "case_001"}')
    (tmp_path / "batch_summary.json").write_text('{"total": 2}')
    (tmp_path / "case_002_verdicts.json").write_text('{"trace_id": "case_002"}')
    
    results = load_c2_results(tmp_path)
    
    assert len(results) == 2
    assert results[0]["trace_id"] == "case_001"
    assert results[1]["trace_id"] == "case_002"

def test_main(tmp_path):
    # Test I — optional main
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    
    (input_dir / "case_001_verdicts.json").write_text('{"trace_id": "case_001", "verdicts": []}')
    
    out_dir = tmp_path / "out"
    
    exit_code = main(["--input", str(input_dir), "--out-dir", str(out_dir)])
    
    assert exit_code == 0
    assert (out_dir / "verdicts.csv").exists()
    assert (out_dir / "c2_summary.json").exists()
