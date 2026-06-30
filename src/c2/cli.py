import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.c2.rule_ir import RuleIR, load_rule_irs
from src.c2.preservation_checker import run_preservation_check
from src.c2.verdict_engine import evaluate_rule
from src.c2.evidence_requirements import get_trace_id

def load_json(path: str | Path) -> dict[str, Any]:
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

def discover_trace_files(trace_dir: str | Path) -> list[Path]:
    trace_dir = Path(trace_dir)
    if not trace_dir.is_dir():
        raise FileNotFoundError(f"Trace directory not found: {trace_dir}")
    
    files = sorted([f for f in trace_dir.iterdir() if f.is_file() and f.suffix.lower() == ".json"])
    if not files:
        raise ValueError(f"No JSON files found in {trace_dir}")
    return files

def make_output_stem(trace_path: Path, trace: Mapping[str, Any]) -> str:
    stem = trace.get("trace_id", "")
    if not stem:
        stem = trace_path.stem
    stem = re.sub(r'[^a-zA-Z0-9\-\.]', '_', str(stem))
    if not stem:
        stem = trace_path.stem
    return stem

def run_c2_on_trace(
    trace: Mapping[str, Any],
    rules: Sequence[RuleIR],
    *,
    include_preservation: bool = True
) -> dict[str, Any]:
    
    trace_id = get_trace_id(trace)
    
    verdicts = []
    preservation_results = []
    
    for rule in rules:
        pres_res = run_preservation_check(trace, rule)
        preservation_results.append(pres_res.to_dict())
        
        verdict_res = evaluate_rule(trace, rule, preservation_result=pres_res)
        verdicts.append(verdict_res.to_dict())
        
    summary = build_summary(verdicts, preservation_results)
    
    out = {
        "trace_id": trace_id,
        "schema_version": "0.1",
        "rule_count": len(rules),
        "verdicts": verdicts,
        "summary": summary
    }
    
    if include_preservation:
        out["preservation"] = preservation_results
        
    return out

def build_summary(
    verdict_rows: Sequence[Mapping[str, Any]],
    preservation_rows: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    
    summary = {
        "safe": 0,
        "violation": 0,
        "unknown": 0,
        "inconsistent": 0,
        "not_applicable": 0,
        "total_verdicts": len(verdict_rows),
        "total_preservation_checks": len(preservation_rows),
        "incomplete_preservation": 0,
        "missing_evidence_count": 0
    }
    
    for v in verdict_rows:
        verdict = v.get("verdict", "")
        if verdict == "SAFE":
            summary["safe"] += 1
        elif verdict == "VIOLATION":
            summary["violation"] += 1
        elif verdict == "UNKNOWN":
            summary["unknown"] += 1
        elif verdict == "INCONSISTENT":
            summary["inconsistent"] += 1
        elif verdict == "NOT_APPLICABLE":
            summary["not_applicable"] += 1
            
    for p in preservation_rows:
        if p.get("status") == "INCOMPLETE":
            summary["incomplete_preservation"] += 1
            
    unique_missing = {}
    
    for p in preservation_rows:
        policy_id = p.get("policy_id")
        me = p.get("missing_evidence", [])
        if me:
            unique_missing[policy_id] = len(me)
            
    for v in verdict_rows:
        policy_id = v.get("policy_id")
        me = v.get("missing_evidence", [])
        if me:
            unique_missing[policy_id] = len(me)
            
    summary["missing_evidence_count"] = sum(unique_missing.values())
    
    return summary

def extract_missing_evidence_report(combined_result: Mapping[str, Any]) -> dict[str, Any]:
    trace_id = combined_result.get("trace_id", "")
    
    verdicts = combined_result.get("verdicts", [])
    preservations = combined_result.get("preservation", [])
    
    policies = {}
    
    for p in preservations:
        if p.get("status") == "INCOMPLETE" and p.get("missing_evidence"):
            policies[p.get("policy_id")] = {
                "policy_id": p.get("policy_id"),
                "status": p.get("status"),
                "missing_evidence": p.get("missing_evidence"),
                "triggered_event_ids": p.get("triggered_event_ids", []),
                "reason": p.get("reason", "")
            }
            
    for v in verdicts:
        if v.get("verdict") == "UNKNOWN" and v.get("missing_evidence"):
            policies[v.get("policy_id")] = {
                "policy_id": v.get("policy_id"),
                "status": v.get("verdict"),
                "missing_evidence": v.get("missing_evidence"),
                "triggered_event_ids": v.get("triggered_event_ids", []),
                "reason": v.get("reason", "")
            }
            
    return {
        "trace_id": trace_id,
        "missing_evidence": list(policies.values())
    }

def compute_exit_code(
    summaries: Sequence[Mapping[str, Any]],
    *,
    fail_on_violation: bool = False,
    fail_on_unknown: bool = False
) -> int:
    
    total_violation = sum(s.get("violation", 0) for s in summaries)
    total_unknown = sum(s.get("unknown", 0) for s in summaries)
    total_inconsistent = sum(s.get("inconsistent", 0) for s in summaries)
    
    if fail_on_violation and total_violation > 0:
        return 2
    elif fail_on_unknown and (total_unknown + total_inconsistent) > 0:
        return 3
    return 0

def run_single_trace(args: argparse.Namespace) -> int:
    try:
        trace = load_json(args.trace)
        rules = load_rule_irs(args.rules)
        combined = run_c2_on_trace(trace, rules, include_preservation=args.include_preservation)
        
        if args.out:
            write_json(args.out, combined, indent=2 if args.pretty else 2)
            if not args.quiet:
                sys.stderr.write(f"Processed 1 trace with {len(rules)} rules.\n")
                sys.stderr.write(f"Output written to {args.out}\n")
                sys.stderr.write(json.dumps(combined["summary"], indent=2) + "\n")
        else:
            indent = 2 if args.pretty else 2
            print(json.dumps(combined, indent=indent))
            
            if not args.quiet:
                sys.stderr.write(f"Processed 1 trace with {len(rules)} rules.\n")
                sys.stderr.write(json.dumps(combined["summary"], indent=2) + "\n")
            
        return compute_exit_code([combined["summary"]], fail_on_violation=args.fail_on_violation, fail_on_unknown=args.fail_on_unknown)
    except Exception as e:
        if not args.quiet:
            sys.stderr.write(f"Error: {e}\n")
        return 1

def run_batch(args: argparse.Namespace) -> int:
    try:
        if not args.out_dir:
            raise ValueError("--out-dir is required for batch mode")
            
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        
        trace_files = discover_trace_files(args.trace_dir)
        rules = load_rule_irs(args.rules)
        
        outputs = []
        aggregate = {
            "safe": 0,
            "violation": 0,
            "unknown": 0,
            "inconsistent": 0,
            "missing_evidence_count": 0
        }
        
        for trace_path in trace_files:
            trace = load_json(trace_path)
            combined = run_c2_on_trace(trace, rules, include_preservation=args.include_preservation)
            
            stem = make_output_stem(trace_path, trace)
            
            verdicts_file = out_dir / f"{stem}_verdicts.json"
            missing_evidence_file = out_dir / f"{stem}_missing_evidence.json"
            
            write_json(verdicts_file, combined, indent=2 if args.pretty else 2)
            
            missing_report = extract_missing_evidence_report(combined)
            write_json(missing_evidence_file, missing_report, indent=2 if args.pretty else 2)
            
            summary = combined["summary"]
            outputs.append({
                "trace_id": combined["trace_id"],
                "trace_file": str(trace_path),
                "verdicts_file": str(verdicts_file),
                "missing_evidence_file": str(missing_evidence_file),
                "summary": {
                    "safe": summary.get("safe", 0),
                    "violation": summary.get("violation", 0),
                    "unknown": summary.get("unknown", 0),
                    "inconsistent": summary.get("inconsistent", 0)
                }
            })
            
            aggregate["safe"] += summary.get("safe", 0)
            aggregate["violation"] += summary.get("violation", 0)
            aggregate["unknown"] += summary.get("unknown", 0)
            aggregate["inconsistent"] += summary.get("inconsistent", 0)
            aggregate["missing_evidence_count"] += summary.get("missing_evidence_count", 0)
            
        batch_summary = {
            "trace_count": len(trace_files),
            "rule_count": len(rules),
            "outputs": outputs,
            "aggregate": aggregate
        }
        
        write_json(out_dir / "batch_summary.json", batch_summary, indent=2 if args.pretty else 2)
        
        if not args.quiet:
            sys.stderr.write(f"Processed {len(trace_files)} traces with {len(rules)} rules.\n")
            sys.stderr.write(f"Outputs written to {out_dir}\n")
            sys.stderr.write(json.dumps(aggregate, indent=2) + "\n")
            
        return compute_exit_code([batch_summary["aggregate"]], fail_on_violation=args.fail_on_violation, fail_on_unknown=args.fail_on_unknown)
        
    except Exception as e:
        if not args.quiet:
            sys.stderr.write(f"Error: {e}\n")
        return 1

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="C2 CLI")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--trace", type=str, help="Run C2 on one normalized trace JSON file")
    group.add_argument("--trace-dir", type=str, help="Run C2 on every *.json file in a directory")
    
    parser.add_argument("--rules", type=str, required=True, help="Single Rule IR JSON file or a directory containing *.json")
    parser.add_argument("--out", type=str, help="Output JSON file for single-trace mode")
    parser.add_argument("--out-dir", type=str, help="Output directory for batch mode")
    
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    parser.add_argument("--fail-on-violation", action="store_true", help="Exit code 2 if any verdict is VIOLATION")
    parser.add_argument("--fail-on-unknown", action="store_true", help="Exit code 3 if any verdict is UNKNOWN or INCONSISTENT")
    
    # Python 3.9+ BooleanOptionalAction
    parser.add_argument("--include-preservation", action=argparse.BooleanOptionalAction, default=True, help="Include raw preservation results in combined output")
    parser.add_argument("--quiet", action="store_true", help="Do not print summary logs to stderr/stdout except errors")
    
    args = parser.parse_args(argv)
    
    if args.trace:
        return run_single_trace(args)
    else:
        return run_batch(args)

if __name__ == "__main__":
    sys.exit(main())
