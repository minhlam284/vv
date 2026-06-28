# src/c1/mapping_report.py

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json


CORE_MAPPING_FIELDS = [
    "phase",
    "action_type",
    "action_name",
    "effect_type",
    "target_resource",
    "status",
]


@dataclass
class MappingReport:
    trace_id: str
    source: str
    mapped_events: int = 0
    unmapped_events: int = 0
    ambiguous_events: list[dict[str, Any]] = field(default_factory=list)
    unknown_fields: list[dict[str, Any]] = field(default_factory=list)
    raw_to_normalized: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "source": self.source,
            "mapped_events": self.mapped_events,
            "unmapped_events": self.unmapped_events,
            "ambiguous_events": self.ambiguous_events,
            "unknown_fields": self.unknown_fields,
            "raw_to_normalized": self.raw_to_normalized,
        }


def generate_mapping_report(
    normalized_trace: dict[str, Any],
    *,
    source: str = "unknown",
) -> MappingReport:
    trace_id = normalized_trace.get("trace_id", "unknown")
    events = normalized_trace.get("events", [])

    report = MappingReport(
        trace_id=trace_id,
        source=source,
    )

    for event in events:
        record = _build_event_mapping_record(event)
        report.raw_to_normalized.append(record)

        if _is_mapped_event(event):
            report.mapped_events += 1
        else:
            report.unmapped_events += 1

        unknowns = _collect_unknown_fields(event)
        if unknowns:
            report.unknown_fields.append(
                {
                    "event_id": event.get("event_id"),
                    "raw_event_ref": event.get("raw_event_ref"),
                    "fields": unknowns,
                }
            )

        ambiguous = _collect_ambiguity(event)
        if ambiguous:
            report.ambiguous_events.append(
                {
                    "event_id": event.get("event_id"),
                    "raw_event_ref": event.get("raw_event_ref"),
                    "reason": ambiguous,
                }
            )

    return report


def _build_event_mapping_record(event: dict[str, Any]) -> dict[str, Any]:
    metadata = event.get("metadata") or {}

    return {
        "raw_event_ref": event.get("raw_event_ref"),
        "event_id": event.get("event_id"),
        "raw_event_type": metadata.get("raw_event_type"),
        "raw_action_name": metadata.get("raw_action_name"),
        "phase": event.get("phase"),
        "action_type": event.get("action_type"),
        "action_name": event.get("action_name"),
        "effect_type": event.get("effect_type"),
        "target_resource": event.get("target_resource"),
        "status": event.get("status"),
    }


def _is_mapped_event(event: dict[str, Any]) -> bool:
    if not event.get("raw_event_ref"):
        return False

    if not event.get("event_id"):
        return False

    if event.get("action_name") in {None, "unknown"}:
        return False

    if event.get("action_type") in {None, "unknown"}:
        return False

    return True


def _collect_unknown_fields(event: dict[str, Any]) -> list[str]:
    unknowns: list[str] = []

    for field in CORE_MAPPING_FIELDS:
        value = event.get(field)
        if value is None or value == "unknown":
            unknowns.append(field)

    metadata = event.get("metadata") or {}
    for warning in metadata.get("normalization_warnings", []):
        if "unknown" in str(warning) or "missing" in str(warning):
            unknowns.append(f"metadata.warning:{warning}")

    return sorted(set(unknowns))


def _collect_ambiguity(event: dict[str, Any]) -> list[str]:
    metadata = event.get("metadata") or {}
    warnings = metadata.get("normalization_warnings", [])

    ambiguous = [
        str(w)
        for w in warnings
        if "ambiguous" in str(w)
    ]

    return ambiguous


def write_mapping_report(report: MappingReport, output_path: str | Path) -> None:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)