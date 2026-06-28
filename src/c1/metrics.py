from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def safe_div(numerator: int | float, denominator: int | float) -> float:
    if denominator == 0:
        return 0.0
    return round(float(numerator) / float(denominator), 6)


def json_size_bytes(obj: Any) -> int:
    payload = json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return len(payload.encode("utf-8"))


def is_unknown(value: Any) -> bool:
    return value is None or value == "unknown"


def count_mapped_events(normalized_trace: dict[str, Any]) -> int:
    count = 0

    for event in normalized_trace.get("events", []):
        if not event.get("raw_event_ref"):
            continue
        if not event.get("event_id"):
            continue
        if event.get("action_name") in {None, "unknown"}:
            continue
        if event.get("action_type") in {None, "unknown"}:
            continue
        count += 1

    return count


def count_ambiguous_events(normalized_trace: dict[str, Any]) -> int:
    count = 0

    for event in normalized_trace.get("events", []):
        metadata = event.get("metadata") or {}
        warnings = metadata.get("normalization_warnings", [])
        if any("ambiguous" in str(w) for w in warnings):
            count += 1

    return count


@dataclass
class C1TraceMetrics:
    trace_id: str
    source: str = "unknown"

    total_raw_events: int = 0
    total_normalized_events: int = 0

    mapped_events: int = 0
    unmapped_events: int = 0
    mapping_coverage: float = 0.0

    ambiguous_events: int = 0
    mapping_ambiguity: float = 0.0

    unknown_action_count: int = 0
    unknown_effect_count: int = 0
    unknown_target_count: int = 0

    schema_valid: bool | None = None

    raw_trace_bytes: int = 0
    normalized_trace_bytes: int = 0
    trace_reduction_ratio: float | None = None
    trace_reduction_percent: float | None = None

    warnings_count: int = 0
    errors_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "source": self.source,
            "total_raw_events": self.total_raw_events,
            "total_normalized_events": self.total_normalized_events,
            "mapped_events": self.mapped_events,
            "unmapped_events": self.unmapped_events,
            "mapping_coverage": self.mapping_coverage,
            "ambiguous_events": self.ambiguous_events,
            "mapping_ambiguity": self.mapping_ambiguity,
            "unknown_action_count": self.unknown_action_count,
            "unknown_effect_count": self.unknown_effect_count,
            "unknown_target_count": self.unknown_target_count,
            "schema_valid": self.schema_valid,
            "raw_trace_bytes": self.raw_trace_bytes,
            "normalized_trace_bytes": self.normalized_trace_bytes,
            "trace_reduction_ratio": self.trace_reduction_ratio,
            "trace_reduction_percent": self.trace_reduction_percent,
            "warnings_count": self.warnings_count,
            "errors_count": self.errors_count,
        }


@dataclass
class C1DatasetMetrics:
    traces: list[C1TraceMetrics] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        trace_dicts = [m.to_dict() for m in self.traces]

        total_raw_events = sum(m.total_raw_events for m in self.traces)
        total_normalized_events = sum(m.total_normalized_events for m in self.traces)
        mapped_events = sum(m.mapped_events for m in self.traces)
        ambiguous_events = sum(m.ambiguous_events for m in self.traces)

        ratios = [
            m.trace_reduction_ratio
            for m in self.traces
            if m.trace_reduction_ratio is not None
        ]

        reduction_percents = [
            m.trace_reduction_percent
            for m in self.traces
            if m.trace_reduction_percent is not None
        ]

        dataset_summary = {
            "trace_count": len(self.traces),
            "schema_valid_traces": sum(1 for m in self.traces if m.schema_valid is True),
            "schema_invalid_traces": sum(1 for m in self.traces if m.schema_valid is False),
            "total_raw_events": total_raw_events,
            "total_normalized_events": total_normalized_events,
            "mapped_events": mapped_events,
            "unmapped_events": max(total_raw_events - mapped_events, 0),
            "mapping_coverage": safe_div(mapped_events, total_raw_events),
            "ambiguous_events": ambiguous_events,
            "mapping_ambiguity": safe_div(ambiguous_events, total_raw_events),
            "unknown_action_count": sum(m.unknown_action_count for m in self.traces),
            "unknown_effect_count": sum(m.unknown_effect_count for m in self.traces),
            "unknown_target_count": sum(m.unknown_target_count for m in self.traces),
            "avg_trace_reduction_ratio": round(sum(ratios) / len(ratios), 6) if ratios else None,
            "avg_trace_reduction_percent": round(sum(reduction_percents) / len(reduction_percents), 2) if reduction_percents else None,
            "warnings_count": sum(m.warnings_count for m in self.traces),
            "errors_count": sum(m.errors_count for m in self.traces),
        }

        return {
            "dataset": dataset_summary,
            "traces": trace_dicts,
        }


def compute_c1_trace_metrics(
    raw_trace: dict[str, Any],
    normalized_trace: dict[str, Any],
    *,
    mapping_report: dict[str, Any] | None = None,
    validation_report: dict[str, Any] | None = None,
) -> C1TraceMetrics:
    trace_id = str(
        normalized_trace.get("trace_id")
        or raw_trace.get("trace_id")
        or "unknown"
    )

    source = str(
        raw_trace.get("source")
        or raw_trace.get("trace_source")
        or (mapping_report or {}).get("source")
        or "unknown"
    )

    raw_events = raw_trace.get("events", [])
    normalized_events = normalized_trace.get("events", [])

    total_raw_events = len(raw_events)
    total_normalized_events = len(normalized_events)

    if mapping_report is not None:
        mapped_events = int(mapping_report.get("mapped_events", 0))
        ambiguous_events = len(mapping_report.get("ambiguous_events", []))
    else:
        mapped_events = count_mapped_events(normalized_trace)
        ambiguous_events = count_ambiguous_events(normalized_trace)

    unmapped_events = max(total_raw_events - mapped_events, 0)

    unknown_action_count = sum(
        1 for event in normalized_events if is_unknown(event.get("action_name"))
    )
    unknown_effect_count = sum(
        1 for event in normalized_events if is_unknown(event.get("effect_type"))
    )
    unknown_target_count = sum(
        1 for event in normalized_events if is_unknown(event.get("target_resource"))
    )

    schema_valid = None
    warnings_count = 0
    errors_count = 0

    if validation_report is not None:
        schema_valid = validation_report.get("valid")
        if schema_valid is not None:
            schema_valid = bool(schema_valid)
        warnings_count = len(validation_report.get("warnings", []))
        errors_count = len(validation_report.get("errors", []))

    raw_trace_bytes = json_size_bytes(raw_trace)
    normalized_trace_bytes = json_size_bytes(normalized_trace)

    if raw_trace_bytes > 0:
        trace_reduction_ratio = round(
            normalized_trace_bytes / raw_trace_bytes,
            6,
        )
        trace_reduction_percent = round(
            (1.0 - trace_reduction_ratio) * 100.0,
            2,
        )
    else:
        trace_reduction_ratio = None
        trace_reduction_percent = None

    return C1TraceMetrics(
        trace_id=trace_id,
        source=source,
        total_raw_events=total_raw_events,
        total_normalized_events=total_normalized_events,
        mapped_events=mapped_events,
        unmapped_events=unmapped_events,
        mapping_coverage=safe_div(mapped_events, total_raw_events),
        ambiguous_events=ambiguous_events,
        mapping_ambiguity=safe_div(ambiguous_events, total_raw_events),
        unknown_action_count=unknown_action_count,
        unknown_effect_count=unknown_effect_count,
        unknown_target_count=unknown_target_count,
        schema_valid=schema_valid,
        raw_trace_bytes=raw_trace_bytes,
        normalized_trace_bytes=normalized_trace_bytes,
        trace_reduction_ratio=trace_reduction_ratio,
        trace_reduction_percent=trace_reduction_percent,
        warnings_count=warnings_count,
        errors_count=errors_count,
    )


def compute_c1_dataset_metrics(
    trace_metrics: list[C1TraceMetrics],
) -> C1DatasetMetrics:
    return C1DatasetMetrics(traces=trace_metrics)


def compute_c1_metrics_for_dataset(
    items: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]],
) -> C1DatasetMetrics:
    metrics = []

    for raw_trace, normalized_trace, mapping_report, validation_report in items:
        metrics.append(
            compute_c1_trace_metrics(
                raw_trace,
                normalized_trace,
                mapping_report=mapping_report,
                validation_report=validation_report,
            )
        )

    return C1DatasetMetrics(traces=metrics)


def load_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(obj: dict[str, Any], path: str | Path) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def write_c1_trace_metrics(
    metrics: C1TraceMetrics,
    output_path: str | Path,
) -> None:
    write_json(metrics.to_dict(), output_path)


def write_c1_dataset_metrics(
    metrics: C1DatasetMetrics,
    output_path: str | Path,
) -> None:
    write_json(metrics.to_dict(), output_path)
