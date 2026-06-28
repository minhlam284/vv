from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

# Allow running from project root without installing package.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.c1.canonicalizer import Canonicalizer, load_json, write_json
from src.c1.mapping_report import generate_mapping_report, write_mapping_report
from src.c1.metrics import compute_c1_trace_metrics, write_c1_trace_metrics


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run C1 canonicalizer on raw trace JSON files.",
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--input", type=Path, help="Single raw trace JSON file.")
    input_group.add_argument("--input-dir", type=Path, help="Directory of raw trace JSON files.")

    parser.add_argument("--output", type=Path, help="Output normalized trace JSON file.")
    parser.add_argument("--output-dir", type=Path, help="Output directory for normalized traces.")

    parser.add_argument("--report", type=Path, help="Output mapping report JSON file.")
    parser.add_argument("--report-dir", type=Path, help="Output directory for mapping reports.")

    parser.add_argument("--canonical-report", type=Path, help="Output canonicalization report JSON file.")
    parser.add_argument("--canonical-report-dir", type=Path, help="Output directory for canonicalization reports.")

    parser.add_argument("--metrics", type=Path, help="Output C1 metrics JSON file.")
    parser.add_argument("--metrics-dir", type=Path, help="Output directory for C1 metrics files.")

    parser.add_argument("--summary", type=Path, help="Output batch summary JSON file.")
    parser.add_argument("--glob", default="*.json", help="Glob pattern for batch mode. Default: *.json")

    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue batch processing even if one file fails.",
    )

    parser.add_argument(
        "--no-fail-on-validation-error",
        action="store_true",
        help="Do not raise when normalized trace validation fails.",
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce terminal output.",
    )

    return parser


def validate_args(args: argparse.Namespace) -> None:
    if args.input is not None:
        if args.output is None:
            raise SystemExit("--output is required when using --input")
        if args.output_dir is not None:
            raise SystemExit("--output-dir cannot be used with --input")
        if args.report_dir is not None:
            raise SystemExit("--report-dir cannot be used with --input")
        if args.metrics_dir is not None:
            raise SystemExit("--metrics-dir cannot be used with --input")
        if args.canonical_report_dir is not None:
            raise SystemExit("--canonical-report-dir cannot be used with --input")

    if args.input_dir is not None:
        if args.output_dir is None:
            raise SystemExit("--output-dir is required when using --input-dir")
        if args.output is not None:
            raise SystemExit("--output cannot be used with --input-dir")
        if args.report is not None:
            raise SystemExit("--report cannot be used with --input-dir")
        if args.metrics is not None:
            raise SystemExit("--metrics cannot be used with --input-dir")
        if args.canonical_report is not None:
            raise SystemExit("--canonical-report cannot be used with --input-dir")


def build_output_path(
    input_file: Path,
    input_root: Path,
    output_root: Path,
    suffix: str | None = None,
) -> Path:
    rel = input_file.relative_to(input_root)

    if suffix is None:
        return output_root / rel

    return output_root / rel.with_name(rel.stem + suffix + rel.suffix)


def process_one_file(
    input_path: Path,
    output_path: Path,
    *,
    mapping_report_path: Path | None = None,
    canonical_report_path: Path | None = None,
    metrics_path: Path | None = None,
    fail_on_validation_error: bool = True,
) -> dict[str, Any]:
    raw_trace = load_json(input_path)

    canonicalizer = Canonicalizer(
        fail_on_validation_error=fail_on_validation_error,
    )

    result = canonicalizer.canonicalize_with_report(raw_trace)

    write_json(result.trace, output_path)

    if canonical_report_path is not None:
        write_json(result.report.to_dict(), canonical_report_path)

    mapping_report_dict = None

    if mapping_report_path is not None or metrics_path is not None:
        mapping_report = generate_mapping_report(
            result.trace,
            source=str(raw_trace.get("source") or raw_trace.get("trace_source") or "unknown"),
        )
        mapping_report_dict = mapping_report.to_dict()

        if mapping_report_path is not None:
            write_mapping_report(mapping_report, mapping_report_path)

    if metrics_path is not None:
        metrics = compute_c1_trace_metrics(
            raw_trace,
            result.trace,
            mapping_report=mapping_report_dict,
            validation_report=result.report.validation_report,
        )
        write_c1_trace_metrics(metrics, metrics_path)

    return {
        "input": str(input_path),
        "output": str(output_path),
        "ok": True,
        "trace_id": result.trace.get("trace_id"),
        "normalized_events": len(result.trace.get("events", [])),
        "schema_valid": result.report.schema_valid,
    }


def run_single(args: argparse.Namespace) -> int:
    try:
        item = process_one_file(
            input_path=args.input,
            output_path=args.output,
            mapping_report_path=args.report,
            canonical_report_path=args.canonical_report,
            metrics_path=args.metrics,
            fail_on_validation_error=not args.no_fail_on_validation_error,
        )

        if not args.quiet:
            print(
                f"[OK] {item['input']} -> {item['output']} "
                f"(events={item['normalized_events']}, schema_valid={item['schema_valid']})"
            )

        return 0

    except Exception as exc:
        print(f"[ERROR] {args.input}: {exc}", file=sys.stderr)
        return 1


def run_batch(args: argparse.Namespace) -> int:
    input_dir = args.input_dir
    files = sorted(p for p in input_dir.rglob(args.glob) if p.is_file())

    summary: dict[str, Any] = {
        "total": len(files),
        "success": 0,
        "failed": 0,
        "outputs": [],
        "errors": [],
    }

    if not files:
        print(f"[WARN] No files matched {args.glob!r} under {input_dir}", file=sys.stderr)

    for input_file in files:
        output_path = build_output_path(
            input_file,
            input_dir,
            args.output_dir,
            suffix=None,
        )

        mapping_report_path = None
        if args.report_dir is not None:
            mapping_report_path = build_output_path(
                input_file,
                input_dir,
                args.report_dir,
                suffix="_mapping_report",
            )

        canonical_report_path = None
        if args.canonical_report_dir is not None:
            canonical_report_path = build_output_path(
                input_file,
                input_dir,
                args.canonical_report_dir,
                suffix="_canonicalization_report",
            )

        metrics_path = None
        if args.metrics_dir is not None:
            metrics_path = build_output_path(
                input_file,
                input_dir,
                args.metrics_dir,
                suffix="_c1_metrics",
            )

        try:
            item = process_one_file(
                input_path=input_file,
                output_path=output_path,
                mapping_report_path=mapping_report_path,
                canonical_report_path=canonical_report_path,
                metrics_path=metrics_path,
                fail_on_validation_error=not args.no_fail_on_validation_error,
            )

            summary["success"] += 1
            summary["outputs"].append(item)

            if not args.quiet:
                print(f"[OK] {input_file} -> {output_path}")

        except Exception as exc:
            summary["failed"] += 1
            error_item = {
                "input": str(input_file),
                "error": str(exc),
            }
            summary["errors"].append(error_item)

            print(f"[ERROR] {input_file}: {exc}", file=sys.stderr)

            if not args.continue_on_error:
                break

    if args.summary is not None:
        write_json(summary, args.summary)

    if not args.quiet:
        print(
            f"[SUMMARY] total={summary['total']} "
            f"success={summary['success']} failed={summary['failed']}"
        )

    return 0 if summary["failed"] == 0 else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(args)

    if args.input is not None:
        return run_single(args)

    return run_batch(args)


if __name__ == "__main__":
    raise SystemExit(main())
