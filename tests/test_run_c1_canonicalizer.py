import json
import pytest
from pathlib import Path

from scripts.run_c1_canonicalizer import main

def test_cli_single_mode_creates_output(tmp_path):
    raw_path = tmp_path / "raw.json"
    output_path = tmp_path / "normalized.json"
    report_path = tmp_path / "mapping_report.json"

    raw_path.write_text(
        json.dumps({
            "trace_id": "t1",
            "source": "custom_react",
            "events": [
                {
                    "event_id": "raw_001",
                    "event_type": "tool_call",
                    "step_id": 1,
                    "tool_name": "gmail_send",
                    "input": {"recipient": "team@example.com"},
                    "status": "pending",
                }
            ],
        }),
        encoding="utf-8",
    )

    code = main([
        "--input", str(raw_path),
        "--output", str(output_path),
        "--report", str(report_path),
        "--no-fail-on-validation-error",  # Because mock data doesn't conform to strict schema
    ])

    assert code == 0
    assert output_path.exists()
    assert report_path.exists()

def test_cli_batch_mode_creates_outputs(tmp_path):
    input_dir = tmp_path / "raw"
    output_dir = tmp_path / "normalized"
    report_dir = tmp_path / "reports"

    (input_dir / "synthetic").mkdir(parents=True)
    raw_path = input_dir / "synthetic" / "case_001.json"
    raw_path.write_text(
        json.dumps({
            "trace_id": "t2",
            "source": "custom_react",
            "events": [
                {
                    "event_id": "raw_001",
                    "event_type": "tool_call",
                    "step_id": 1,
                    "tool_name": "gmail_send",
                    "input": {"recipient": "team@example.com"},
                    "status": "pending",
                }
            ]
        }),
        encoding="utf-8",
    )

    code = main([
        "--input-dir", str(input_dir),
        "--output-dir", str(output_dir),
        "--report-dir", str(report_dir),
        "--no-fail-on-validation-error",  # Missing standard events, so it might fail validation
    ])

    assert code == 0
    assert (output_dir / "synthetic" / "case_001.json").exists()
    assert (report_dir / "synthetic" / "case_001_mapping_report.json").exists()

def test_cli_requires_output_for_single(tmp_path):
    raw_path = tmp_path / "raw.json"
    raw_path.write_text("{}", encoding="utf-8")

    with pytest.raises(SystemExit):
        main(["--input", str(raw_path)])

def test_batch_continue_on_error(tmp_path):
    input_dir = tmp_path / "raw"
    output_dir = tmp_path / "normalized"
    
    input_dir.mkdir(parents=True)
    
    # Valid file
    valid_path = input_dir / "valid.json"
    valid_path.write_text(
        json.dumps({
            "trace_id": "t3",
            "source": "custom_react",
            "events": [
                {
                    "event_id": "raw_001",
                    "event_type": "tool_call",
                    "step_id": 1,
                    "tool_name": "gmail_send",
                    "input": {"recipient": "team@example.com"},
                    "status": "pending",
                }
            ]
        }),
        encoding="utf-8",
    )
    
    # Invalid file (not JSON)
    invalid_path = input_dir / "invalid.json"
    invalid_path.write_text("this is not json", encoding="utf-8")
    
    # With continue-on-error, we expect exit code 1 because there was an error
    # but the valid file should still be processed
    code = main([
        "--input-dir", str(input_dir),
        "--output-dir", str(output_dir),
        "--continue-on-error",
        "--no-fail-on-validation-error",
        "--quiet",
    ])
    
    assert code == 1
    assert (output_dir / "valid.json").exists()
    assert not (output_dir / "invalid.json").exists()
