import argparse
import json
import logging
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# Import C2 functions
from src.c2.rule_ir import RuleIR, load_rule_irs
from src.c2.cli import run_c2_on_trace, extract_missing_evidence_report
from src.c2.reports import generate_reports

@dataclass
class TraceValidationIssue:
    trace_id: str
    trace_file: str
    level: str        # "ERROR" or "WARNING"
    code: str         # e.g. "SCHEMA_ERROR", "INV-01"
    message: str
    event_id: str | None = None
    field: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class TraceValidationResult:
    trace_id: str
    trace_file: str
    valid: bool
    issues: list[TraceValidationIssue]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["issues"] = [issue.to_dict() for issue in self.issues]
        return d

@dataclass
class PipelineResult:
    trace_id: str
    trace_file: str
    valid: bool
    validation: TraceValidationResult
    c2_result: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "trace_file": self.trace_file,
            "valid": self.valid,
            "validation": self.validation.to_dict(),
            "c2_result": self.c2_result
        }

def load_json(path: str | Path) -> Any:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"JSON file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e}")

def write_json(path: str | Path, data: Any, *, indent: int = 2) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)

def discover_json_files(path: str | Path, pattern: str = "*.json") -> list[Path]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {path}")
    if path.is_file():
        return [path]
    
    files = sorted(path.glob(pattern))
    if not files:
        raise ValueError(f"No JSON files found in {path}")
    return files

def load_schema(schema_path: str | Path) -> dict[str, Any]:
    return load_json(schema_path)

def load_vocabulary(vocabulary_path: str | Path) -> dict[str, Any]:
    path = Path(vocabulary_path)
    if not HAS_YAML:
        raise RuntimeError("PyYAML is required to load vocabulary.yaml.")
    
    if not path.is_file():
        raise FileNotFoundError(f"Vocabulary file not found: {path}")
        
    try:
        with open(path, "r", encoding="utf-8") as f:
            vocab = yaml.safe_load(f)
            if not isinstance(vocab, dict):
                raise ValueError("Vocabulary file must contain a YAML dictionary.")
            return vocab
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in {path}: {e}")

def validate_trace_schema(
    trace: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    trace_file: str = "<memory>"
) -> list[TraceValidationIssue]:
    
    if not HAS_JSONSCHEMA:
        # Expected to be handled by caller if skip_schema_validation=False
        return []
        
    issues = []
    trace_id = trace.get("trace_id", "<unknown_trace>")
    
    validator = jsonschema.Draft202012Validator(schema)
    errors = validator.iter_errors(trace)
    
    for err in errors:
        path = ".".join(str(p) for p in err.path)
        issues.append(TraceValidationIssue(
            trace_id=trace_id,
            trace_file=trace_file,
            level="ERROR",
            code="SCHEMA_ERROR",
            message=f"Path '{path}': {err.message}"
        ))
        
    return issues

def validate_trace_invariants(
    trace: Mapping[str, Any],
    vocabulary: Mapping[str, Any],
    *,
    trace_file: str = "<memory>"
) -> list[TraceValidationIssue]:
    
    issues = []
    trace_id = trace.get("trace_id")
    
    if not trace_id:
        issues.append(TraceValidationIssue(
            trace_id="<unknown_trace>",
            trace_file=trace_file,
            level="ERROR",
            code="INV-02",
            message="Root trace_id is missing."
        ))
        trace_id = "<unknown_trace>"
        
    events = trace.get("events", [])
    if not isinstance(events, list):
        return issues # Let schema validation handle this structural error
        
    event_ids = set()
    prev_step_id = -1
    
    # Check vocabulary presence
    req_vocab_keys = [
        "phase", "action_type", "effect_type", "target_resource",
        "status", "error_type", "reversibility", "taint_label",
        "approval_status", "decision_verdict", "decision_route"
    ]
    for key in req_vocab_keys:
        if key not in vocabulary:
            issues.append(TraceValidationIssue(
                trace_id=trace_id,
                trace_file=trace_file,
                level="ERROR",
                code="VOCAB_ERROR",
                message=f"Missing required vocabulary key: {key}"
            ))
            return issues
            
    # Gather all event IDs first for INV-04
    all_known_ids = set()
    for ev in events:
        if isinstance(ev, dict):
            eid = ev.get("event_id")
            if eid:
                all_known_ids.add(eid)
                
    for ev in events:
        if not isinstance(ev, dict):
            continue
            
        ev_id = ev.get("event_id", "<unknown_event>")
        
        # INV-01
        if ev_id in event_ids:
            issues.append(TraceValidationIssue(
                trace_id=trace_id,
                trace_file=trace_file,
                level="ERROR",
                code="INV-01",
                message=f"Duplicate event_id {ev_id}",
                event_id=ev_id,
                field="event_id"
            ))
        else:
            event_ids.add(ev_id)
            
        # INV-02
        ev_trace_id = ev.get("trace_id")
        if ev_trace_id != trace_id:
            issues.append(TraceValidationIssue(
                trace_id=trace_id,
                trace_file=trace_file,
                level="ERROR",
                code="INV-02",
                message=f"Event trace_id '{ev_trace_id}' does not match root trace_id '{trace_id}'",
                event_id=ev_id,
                field="trace_id"
            ))
            
        # INV-03
        step_id = ev.get("step_id")
        if isinstance(step_id, int) and step_id >= 0:
            if step_id < prev_step_id:
                issues.append(TraceValidationIssue(
                    trace_id=trace_id,
                    trace_file=trace_file,
                    level="ERROR",
                    code="INV-03",
                    message=f"step_id {step_id} is out of order (previous was {prev_step_id})",
                    event_id=ev_id,
                    field="step_id"
                ))
            elif step_id == prev_step_id:
                issues.append(TraceValidationIssue(
                    trace_id=trace_id,
                    trace_file=trace_file,
                    level="WARNING",
                    code="INV-03",
                    message=f"Duplicate step_id {step_id} (allowed but warned)",
                    event_id=ev_id,
                    field="step_id"
                ))
            prev_step_id = step_id
        else:
            issues.append(TraceValidationIssue(
                trace_id=trace_id,
                trace_file=trace_file,
                level="ERROR",
                code="INV-03",
                message=f"Invalid or negative step_id: {step_id}",
                event_id=ev_id,
                field="step_id"
            ))

        # INV-04
        parent_event = ev.get("parent_event")
        if parent_event is not None and parent_event not in all_known_ids:
            issues.append(TraceValidationIssue(
                trace_id=trace_id,
                trace_file=trace_file,
                level="ERROR",
                code="INV-04",
                message=f"parent_event '{parent_event}' not found in trace",
                event_id=ev_id,
                field="parent_event"
            ))
            
        approval = ev.get("approval", {})
        if isinstance(approval, dict):
            approval_event = approval.get("approval_event")
            if approval_event is not None and approval_event not in all_known_ids:
                issues.append(TraceValidationIssue(
                    trace_id=trace_id,
                    trace_file=trace_file,
                    level="ERROR",
                    code="INV-04",
                    message=f"approval.approval_event '{approval_event}' not found in trace",
                    event_id=ev_id,
                    field="approval.approval_event"
                ))
                
        input_refs = ev.get("input_refs", [])
        if isinstance(input_refs, list):
            for ref in input_refs:
                # input_refs may refer to output_ref, source_id etc, but if it is not in event_ids, we just emit WARNING.
                if ref not in all_known_ids:
                    # In real code, we might want to collect all output_refs, but per spec, unresolved is WARNING.
                    issues.append(TraceValidationIssue(
                        trace_id=trace_id,
                        trace_file=trace_file,
                        level="WARNING",
                        code="INV-04",
                        message=f"input_ref '{ref}' not explicitly found in event_ids (may be an external or adapter ID)",
                        event_id=ev_id,
                        field="input_refs"
                    ))
        
        # Enums checking helpers
        def check_enum(field: str, val: Any, vocab_list: list, code: str, allow_null: bool = False):
            if val is None:
                if not allow_null:
                    issues.append(TraceValidationIssue(
                        trace_id=trace_id, trace_file=trace_file, level="ERROR",
                        code=code, message=f"{field} must not be null", event_id=ev_id, field=field
                    ))
                return
            if val not in vocab_list:
                issues.append(TraceValidationIssue(
                    trace_id=trace_id, trace_file=trace_file, level="ERROR",
                    code=code, message=f"Invalid {field}: '{val}'. Must be one of {vocab_list}",
                    event_id=ev_id, field=field
                ))
                
        # INV-05 to INV-09 and others
        check_enum("phase", ev.get("phase"), vocabulary["phase"], "INV-05")
        check_enum("action_type", ev.get("action_type"), vocabulary["action_type"], "INV-06")
        check_enum("effect_type", ev.get("effect_type"), vocabulary["effect_type"], "INV-07", allow_null=True)
        check_enum("target_resource", ev.get("target_resource"), vocabulary["target_resource"], "INV-08", allow_null=True)
        check_enum("status", ev.get("status"), vocabulary["status"], "INV-09")
        
        check_enum("error_type", ev.get("error_type"), vocabulary["error_type"], "INV-07", allow_null=True)
        check_enum("reversibility", ev.get("reversibility"), vocabulary["reversibility"], "INV-07", allow_null=True)
        
        if isinstance(approval, dict):
            check_enum("approval.status", approval.get("status"), vocabulary["approval_status"], "INV-07", allow_null=True)
            
        taint = ev.get("taint", {})
        if isinstance(taint, dict):
            check_enum("taint.label", taint.get("label"), vocabulary["taint_label"], "INV-07", allow_null=True)
            
        decision = ev.get("decision", {})
        if isinstance(decision, dict):
            check_enum("decision.verdict", decision.get("verdict"), vocabulary["decision_verdict"], "INV-07", allow_null=True)
            check_enum("decision.route", decision.get("route"), vocabulary["decision_route"], "INV-07", allow_null=True)
            
    return issues

def validate_normalized_trace(
    trace: Mapping[str, Any],
    *,
    schema: Mapping[str, Any] | None,
    vocabulary: Mapping[str, Any],
    trace_file: str = "<memory>",
    skip_schema_validation: bool = False
) -> TraceValidationResult:
    
    trace_id = trace.get("trace_id", "<unknown_trace>")
    issues = []
    
    if not skip_schema_validation:
        if not HAS_JSONSCHEMA:
            raise RuntimeError("jsonschema is required for schema validation. Install it or run with --skip-schema-validation.")
        if schema:
            issues.extend(validate_trace_schema(trace, schema, trace_file=trace_file))
            
    issues.extend(validate_trace_invariants(trace, vocabulary, trace_file=trace_file))
    
    valid = not any(issue.level == "ERROR" for issue in issues)
    
    return TraceValidationResult(
        trace_id=trace_id,
        trace_file=trace_file,
        valid=valid,
        issues=issues
    )

def safe_stem(value: str) -> str:
    stem = re.sub(r'[^a-zA-Z0-9\-\._]', '_', str(value))
    if not stem:
        stem = "unknown_trace"
    return stem

def run_c2_for_valid_trace(
    trace: Mapping[str, Any],
    rules: Sequence[RuleIR],
    *,
    include_preservation: bool = True
) -> dict[str, Any]:
    # We just delegate to the CLI logic which handles preservation -> verdict -> missing logic correctly
    return run_c2_on_trace(trace, rules, include_preservation=include_preservation)

def run_phase5_pipeline(
    *,
    trace_dir: str | Path,
    rule_path: str | Path,
    schema_path: str | Path,
    vocabulary_path: str | Path,
    out_dir: str | Path,
    mapping_report_path: str | Path | None = None,
    c1_metrics_path: str | Path | None = None,
    skip_schema_validation: bool = False,
    skip_invalid: bool = True,
    include_preservation: bool = True
) -> dict[str, Any]:
    
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    trace_files = discover_json_files(trace_dir, "*.json")
    rules = load_rule_irs(rule_path)
    
    schema = None
    if not skip_schema_validation:
        schema = load_schema(schema_path)
        
    vocabulary = load_vocabulary(vocabulary_path)
    
    valid_c2_results = []
    validation_traces = []
    
    valid_count = 0
    invalid_count = 0
    warning_count = 0
    error_count = 0
    
    for trace_file in trace_files:
        trace = load_json(trace_file)
        val_res = validate_normalized_trace(
            trace,
            schema=schema,
            vocabulary=vocabulary,
            trace_file=str(trace_file),
            skip_schema_validation=skip_schema_validation
        )
        
        validation_traces.append(val_res.to_dict())
        
        for issue in val_res.issues:
            if issue.level == "WARNING":
                warning_count += 1
            else:
                error_count += 1
                
        if not val_res.valid:
            invalid_count += 1
            if not skip_invalid:
                raise ValueError(f"Trace {trace_file} is invalid and skip_invalid=False.")
            continue
            
        valid_count += 1
        
        # Run C2
        c2_result = run_c2_for_valid_trace(trace, rules, include_preservation=include_preservation)
        valid_c2_results.append(c2_result)
        
        # Write per-trace outputs
        t_id_safe = safe_stem(c2_result.get("trace_id", trace_file.stem))
        verdicts_file = out_dir / f"{t_id_safe}_verdicts.json"
        missing_file = out_dir / f"{t_id_safe}_missing_evidence.json"
        
        write_json(verdicts_file, c2_result)
        missing_report = extract_missing_evidence_report(c2_result)
        write_json(missing_file, missing_report)

    # Generate Reports
    report_files = {}
    if valid_c2_results:
        # returns dict of paths
        report_files_paths = generate_reports(valid_c2_results, out_dir)
        report_files = {k: str(v) for k, v in report_files_paths.items()}
    
    # Write validation_report.json
    val_report = {
        "trace_count": len(trace_files),
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "warning_count": warning_count,
        "error_count": error_count,
        "traces": validation_traces
    }
    
    val_report_path = out_dir / "validation_report.json"
    write_json(val_report_path, val_report)
    
    # Write integration_summary.json
    integration_summary = {
        "trace_dir": str(trace_dir),
        "rule_path": str(rule_path),
        "schema_path": str(schema_path),
        "vocabulary_path": str(vocabulary_path),
        "out_dir": str(out_dir),
        "trace_count": len(trace_files),
        "valid_trace_count": valid_count,
        "invalid_trace_count": invalid_count,
        "rule_count": len(rules),
        "c2_result_count": len(valid_c2_results),
        "report_files": report_files,
        "validation_report": str(val_report_path),
        "phase4_artifacts": {
            "mapping_report": str(mapping_report_path) if mapping_report_path else None,
            "c1_metrics": str(c1_metrics_path) if c1_metrics_path else None
        }
    }
    
    summary_path = out_dir / "integration_summary.json"
    write_json(summary_path, integration_summary)
    
    return integration_summary

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Phase 5 Integration Pipeline")
    
    parser.add_argument("--trace-dir", type=str, default="data/normalized_traces", help="Directory containing normalized trace JSON files")
    parser.add_argument("--rules", type=str, default="rule_ir", help="Rule IR directory or file")
    parser.add_argument("--schema", type=str, default="normalized_event_schema.json", help="Path to JSON Schema file")
    parser.add_argument("--vocabulary", type=str, default="vocabulary.yaml", help="Path to Vocabulary YAML file")
    parser.add_argument("--out-dir", type=str, default="results/c2", help="Output directory")
    parser.add_argument("--mapping-report", type=str, default=None, help="Path to Phase 4 mapping report JSON (optional)")
    parser.add_argument("--c1-metrics", type=str, default=None, help="Path to Phase 4 metrics JSON (optional)")
    parser.add_argument("--skip-schema-validation", action="store_true", help="Skip jsonschema validation")
    parser.add_argument("--fail-on-invalid", action="store_true", help="Fail and exit on structurally invalid traces instead of skipping")
    parser.add_argument("--quiet", action="store_true", help="Suppress stdout output")
    
    return parser

def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    
    try:
        summary = run_phase5_pipeline(
            trace_dir=args.trace_dir,
            rule_path=args.rules,
            schema_path=args.schema,
            vocabulary_path=args.vocabulary,
            out_dir=args.out_dir,
            mapping_report_path=args.mapping_report,
            c1_metrics_path=args.c1_metrics,
            skip_schema_validation=args.skip_schema_validation,
            skip_invalid=not args.fail_on_invalid,
            include_preservation=True
        )
        
        if not args.quiet:
            print(f"Integration pipeline completed successfully.")
            print(f"Traces: {summary['trace_count']} total, {summary['valid_trace_count']} valid, {summary['invalid_trace_count']} invalid.")
            print(f"Outputs written to: {summary['out_dir']}")
            
        if summary['valid_trace_count'] == 0:
            return 2
            
        return 0
    except Exception as e:
        if not args.quiet:
            sys.stderr.write(f"Error: {e}\n")
        return 1

if __name__ == "__main__":
    sys.exit(main())
