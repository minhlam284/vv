import csv
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from collections import Counter
import sys
import argparse

def load_json(path: str | Path) -> Any:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in file {path}: {e}")

def write_json(path: str | Path, data: Any, *, indent: int = 2) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)

def write_csv(
    path: str | Path,
    rows: Sequence[Mapping[str, Any]],
    fieldnames: Sequence[str]
) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            processed_row = {}
            for k in fieldnames:
                val = row.get(k)
                if val is None:
                    processed_row[k] = ""
                elif isinstance(val, (list, tuple, set)):
                    processed_row[k] = "|".join(str(v) for v in val)
                elif isinstance(val, dict):
                    processed_row[k] = json.dumps(val, ensure_ascii=False, separators=(',', ':'))
                else:
                    processed_row[k] = str(val)
            writer.writerow(processed_row)

def normalize_verdict(verdict: Any) -> str:
    if not verdict:
        return "UNKNOWN"
    return str(verdict).upper()

def normalize_status(status: Any) -> str:
    if not status:
        return "UNKNOWN"
    return str(status).upper()

def join_values(values: Any) -> str:
    if values is None:
        return ""
    if isinstance(values, (list, tuple, set)):
        return "|".join(str(v) for v in values)
    if isinstance(values, dict):
        return json.dumps(values, ensure_ascii=False, separators=(',', ':'))
    return str(values)

def verdict_rows_from_result(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    base_trace_id = result.get("trace_id", "")
    for v in result.get("verdicts", []):
        trace_id = v.get("trace_id", base_trace_id)
        verdict = normalize_verdict(v.get("verdict"))
        reason = v.get("reason") or ""
        rows.append({
            "trace_id": trace_id,
            "policy_id": v.get("policy_id", ""),
            "verdict": verdict,
            "reason": reason
        })
    return rows

def collect_verdict_rows(results: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        rows.extend(verdict_rows_from_result(r))
    return rows

def missing_evidence_rows_from_result(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    seen = set()
    base_trace_id = result.get("trace_id", "")
    
    def add_missing(item, is_verdict):
        trace_id = item.get("trace_id", base_trace_id)
        policy_id = item.get("policy_id", "")
        missing_evidence = item.get("missing_evidence", [])
        triggered_event_ids = item.get("triggered_event_ids", [])
        
        if not missing_evidence:
            return
            
        if is_verdict:
            status = normalize_verdict(item.get("verdict"))
            if status not in ("UNKNOWN", "INCONSISTENT"):
                return
        else:
            status = normalize_status(item.get("status"))
            if status not in ("INCOMPLETE", "INCONSISTENT"):
                return
                
        event_ids = triggered_event_ids if triggered_event_ids else [""]
        
        for field in missing_evidence:
            for eid in event_ids:
                key = (trace_id, policy_id, field, eid)
                if key not in seen:
                    seen.add(key)
                    rows.append({
                        "trace_id": trace_id,
                        "policy_id": policy_id,
                        "missing_field": field,
                        "event_id": eid
                    })

    for v in result.get("verdicts", []):
        add_missing(v, True)
    for p in result.get("preservation", []):
        add_missing(p, False)
        
    return rows

def collect_missing_evidence_rows(results: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        rows.extend(missing_evidence_rows_from_result(r))
    return rows

def evidence_mapping_rows_from_result(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    base_trace_id = result.get("trace_id", "")
    
    has_resolver = False
    get_any_field = None
    MISSING = None
    try:
        from src.c2.field_resolver import get_any_field, MISSING
        has_resolver = True
    except ImportError:
        pass

    events_list = []
    if "events" in result:
        events_list = result["events"]
    elif "trace" in result and isinstance(result["trace"], dict) and "events" in result["trace"]:
        events_list = result["trace"]["events"]
        
    events_by_id = {}
    if isinstance(events_list, list):
        for ev in events_list:
            if isinstance(ev, dict) and "event_id" in ev:
                events_by_id[ev["event_id"]] = ev

    policy_maps = {}
    
    for p in result.get("preservation", []):
        pid = p.get("policy_id")
        if pid and p.get("evidence_map"):
            policy_maps[pid] = p["evidence_map"]
            
    for v in result.get("verdicts", []):
        pid = v.get("policy_id")
        if pid and v.get("evidence_map"):
            # verdict takes precedence
            policy_maps[pid] = v["evidence_map"]

    for policy_id, emap in policy_maps.items():
        for field, eids in emap.items():
            trace_id = base_trace_id
            
            value_parts = []
            
            ev_vals = result.get("evidence_values", {})
            if field in ev_vals:
                if isinstance(ev_vals[field], list):
                    value_parts = ev_vals[field]
                else:
                    value_parts = [ev_vals[field]]
            elif has_resolver and events_by_id:
                for eid in eids:
                    ev = events_by_id.get(eid)
                    if ev:
                        val = get_any_field(ev, field)
                        if val is not MISSING:
                            value_parts.append(val)
                            continue
                    value_parts.append("")
                    
            if not value_parts:
                val_str = ""
            else:
                val_str = "|".join(join_values(v) for v in value_parts)
                
            rows.append({
                "trace_id": trace_id,
                "policy_id": policy_id,
                "evidence_field": field,
                "event_ids": "|".join(eids) if isinstance(eids, list) else str(eids),
                "value": val_str
            })
            
    return rows

def collect_evidence_mapping_rows(results: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        rows.extend(evidence_mapping_rows_from_result(r))
    return rows

def build_c2_summary(results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    trace_ids = set()
    policy_ids = set()
    verdict_counts = Counter()
    preservation_counts = Counter()
    
    missing_evidence_count = 0
    missing_evidence_by_field = Counter()
    missing_evidence_by_policy = Counter()
    
    verdicts_by_policy = {}
    
    traces_with_unknown = set()
    traces_with_violation = set()
    
    unknown_count = 0
    incomplete_preservation_count = 0
    
    for r in results:
        tid = r.get("trace_id", "")
        if tid:
            trace_ids.add(tid)
            
        for v in r.get("verdicts", []):
            pid = v.get("policy_id")
            if pid:
                policy_ids.add(pid)
            
            verdict = normalize_verdict(v.get("verdict"))
            verdict_counts[verdict] += 1
            
            if pid not in verdicts_by_policy:
                verdicts_by_policy[pid] = Counter()
            verdicts_by_policy[pid][verdict] += 1
            
            if verdict == "UNKNOWN":
                traces_with_unknown.add(tid)
                unknown_count += 1
            elif verdict == "VIOLATION":
                traces_with_violation.add(tid)
                
        for p in r.get("preservation", []):
            status = normalize_status(p.get("status"))
            preservation_counts[status] += 1
            if status == "INCOMPLETE":
                incomplete_preservation_count += 1

        me_rows = missing_evidence_rows_from_result(r)
        missing_evidence_count += len(me_rows)
        for row in me_rows:
            missing_evidence_by_field[row["missing_field"]] += 1
            missing_evidence_by_policy[row["policy_id"]] += 1

    return {
        "trace_count": len(trace_ids),
        "policy_count": len(policy_ids),
        "verdict_counts": {
            "SAFE": verdict_counts.get("SAFE", 0),
            "VIOLATION": verdict_counts.get("VIOLATION", 0),
            "UNKNOWN": verdict_counts.get("UNKNOWN", 0),
            "INCONSISTENT": verdict_counts.get("INCONSISTENT", 0)
        },
        "preservation_counts": {
            "COMPLETE": preservation_counts.get("COMPLETE", 0),
            "INCOMPLETE": preservation_counts.get("INCOMPLETE", 0),
            "NOT_APPLICABLE": preservation_counts.get("NOT_APPLICABLE", 0),
            "INCONSISTENT": preservation_counts.get("INCONSISTENT", 0)
        },
        "missing_evidence_count": missing_evidence_count,
        "missing_evidence_by_field": dict(missing_evidence_by_field),
        "missing_evidence_by_policy": dict(missing_evidence_by_policy),
        "verdicts_by_policy": {k: dict(v) for k, v in verdicts_by_policy.items()},
        "traces_with_unknown": sorted(list(traces_with_unknown)),
        "traces_with_violation": sorted(list(traces_with_violation)),
        "false_safe_guard": {
            "unknown_count": unknown_count,
            "incomplete_preservation_count": incomplete_preservation_count,
            "note": "Missing required evidence should be UNKNOWN/INCOMPLETE, not SAFE."
        }
    }

def generate_reports(
    results: Sequence[Mapping[str, Any]],
    out_dir: str | Path
) -> dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    verdicts_path = out_dir / "verdicts.csv"
    missing_evidence_path = out_dir / "missing_evidence.csv"
    evidence_mapping_path = out_dir / "evidence_mapping.csv"
    summary_path = out_dir / "c2_summary.json"
    
    write_csv(
        verdicts_path,
        collect_verdict_rows(results),
        ["trace_id", "policy_id", "verdict", "reason"]
    )
    
    write_csv(
        missing_evidence_path,
        collect_missing_evidence_rows(results),
        ["trace_id", "policy_id", "missing_field", "event_id"]
    )
    
    write_csv(
        evidence_mapping_path,
        collect_evidence_mapping_rows(results),
        ["trace_id", "policy_id", "evidence_field", "event_ids", "value"]
    )
    
    write_json(
        summary_path,
        build_c2_summary(results)
    )
    
    return {
        "verdicts": verdicts_path,
        "missing_evidence": missing_evidence_path,
        "evidence_mapping": evidence_mapping_path,
        "summary": summary_path
    }

def load_c2_results(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {path}")
        
    if path.is_file():
        return [load_json(path)]
        
    # Directory
    results = []
    verdict_files = sorted(path.glob("*_verdicts.json"))
    
    if verdict_files:
        for f in verdict_files:
            results.append(load_json(f))
        return results
        
    # Fallback
    all_json = sorted(path.glob("*.json"))
    for f in all_json:
        if f.name == "batch_summary.json" or f.name.endswith("_missing_evidence.json"):
            continue
        results.append(load_json(f))
        
    if not results:
        raise ValueError(f"No result JSON files found in directory {path}")
        
    return results

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate C2 reports")
    parser.add_argument("--input", required=True, help="Input file or directory")
    parser.add_argument("--out-dir", required=True, help="Output directory")
    args = parser.parse_args(argv)
    
    try:
        results = load_c2_results(args.input)
        generate_reports(results, args.out_dir)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
