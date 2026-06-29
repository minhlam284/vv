import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.c1.metrics import (
    C1DatasetMetrics,
    compute_c1_metrics_for_dataset,
    compute_c1_trace_metrics,
    load_json,
    write_c1_dataset_metrics,
    write_c1_trace_metrics,
)


def run_single(
    raw_path: Path,
    normalized_path: Path,
    output_path: Path,
    mapping_report_path: Path | None = None,
    validation_report_path: Path | None = None,
) -> None:
    raw_trace = load_json(raw_path) if raw_path.exists() else {"trace_id": "unknown", "events": []}
    normalized_trace = load_json(normalized_path) if normalized_path.exists() else {"trace_id": "unknown", "events": []}
    
    mapping_report = None
    if mapping_report_path and mapping_report_path.exists():
        mapping_report = load_json(mapping_report_path)
        
    validation_report = None
    if validation_report_path and validation_report_path.exists():
        validation_report = load_json(validation_report_path)

    metrics = compute_c1_trace_metrics(
        raw_trace=raw_trace,
        normalized_trace=normalized_trace,
        mapping_report=mapping_report,
        validation_report=validation_report,
    )
    
    write_c1_trace_metrics(metrics, output_path)
    print(f"Metrics written to {output_path}")


def run_dataset(
    raw_dir: Path,
    normalized_dir: Path,
    output_path: Path,
    mapping_report_dir: Path | None = None,
    validation_report_dir: Path | None = None,
) -> None:
    items: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]] = []

    if raw_dir.exists():
        for raw_path in raw_dir.rglob("*.json"):
            stem = raw_path.stem
            rel_path = raw_path.relative_to(raw_dir)
            normalized_path = normalized_dir / rel_path
            
            raw_trace = load_json(raw_path)
            normalized_trace = load_json(normalized_path) if normalized_path.exists() else {"trace_id": stem, "events": []}
            
            mapping_report = None
            if mapping_report_dir and (mapping_report_dir / f"{stem}_mapping_report.json").exists():
                mapping_report = load_json(mapping_report_dir / f"{stem}_mapping_report.json")
                
            validation_report = None
            if validation_report_dir and (validation_report_dir / f"{stem}_validation_report.json").exists():
                validation_report = load_json(validation_report_dir / f"{stem}_validation_report.json")
                
            items.append((raw_trace, normalized_trace, mapping_report, validation_report))

    if not items:
        print("No traces found to process.")
        # Just generate empty dataset metrics
        write_c1_dataset_metrics(C1DatasetMetrics(), output_path)
        return

    dataset_metrics = compute_c1_metrics_for_dataset(items)
    write_c1_dataset_metrics(dataset_metrics, output_path)
    print(f"Dataset metrics written to {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate C1 metrics")
    
    # Single trace mode
    parser.add_argument("--raw", type=Path, help="Path to raw trace")
    parser.add_argument("--normalized", type=Path, help="Path to normalized trace")
    parser.add_argument("--mapping-report", type=Path, help="Path to mapping report")
    parser.add_argument("--validation-report", type=Path, help="Path to validation report")
    
    # Dataset mode
    parser.add_argument("--raw-dir", type=Path, help="Path to raw traces directory")
    parser.add_argument("--normalized-dir", type=Path, help="Path to normalized traces directory")
    parser.add_argument("--mapping-report-dir", type=Path, help="Path to mapping reports directory")
    parser.add_argument("--validation-report-dir", type=Path, help="Path to validation reports directory")
    
    # Common
    parser.add_argument("--output", type=Path, required=True, help="Path to write output metrics")
    
    args = parser.parse_args()
    
    # Determine mode
    if args.raw_dir and args.normalized_dir:
        run_dataset(
            raw_dir=args.raw_dir,
            normalized_dir=args.normalized_dir,
            output_path=args.output,
            mapping_report_dir=args.mapping_report_dir,
            validation_report_dir=args.validation_report_dir,
        )
    elif args.raw and args.normalized:
        run_single(
            raw_path=args.raw,
            normalized_path=args.normalized,
            output_path=args.output,
            mapping_report_path=args.mapping_report,
            validation_report_path=args.validation_report,
        )
    else:
        print("Error: Must provide either --raw/--normalized OR --raw-dir/--normalized-dir", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
