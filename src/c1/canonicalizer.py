# src/c1/canonicalizer.py

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json

from .normalizer import Normalizer
from .causal_linker import CausalLinker
from .evidence_extractor import EvidenceExtractor
from .validator import NormalizedTraceValidator
from .adapters.custom_react_adapter import CustomReActAdapter
from .mapping_report import generate_mapping_report


class CanonicalizationError(Exception):
    pass


class AdapterSelectionError(CanonicalizationError):
    pass


class RawTraceFormatError(CanonicalizationError):
    pass


class NormalizedTraceValidationError(CanonicalizationError):
    pass


@dataclass
class CanonicalizationReport:
    trace_id: str
    source: str
    adapter_name: str | None = None
    raw_event_count: int = 0
    normalized_event_count: int = 0
    schema_valid: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw_to_normalized: list[dict[str, Any]] = field(default_factory=list)
    validation_report: dict[str, Any] | None = None
    mapping_report: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "source": self.source,
            "adapter_name": self.adapter_name,
            "raw_event_count": self.raw_event_count,
            "normalized_event_count": self.normalized_event_count,
            "schema_valid": self.schema_valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "raw_to_normalized": self.raw_to_normalized,
            "validation_report": self.validation_report,
            "mapping_report": self.mapping_report,
        }


@dataclass
class CanonicalizationResult:
    trace: dict[str, Any]
    report: CanonicalizationReport


DEFAULT_ADAPTER_REGISTRY = {
    "custom_react": CustomReActAdapter,
    "synthetic": CustomReActAdapter,
}


class Canonicalizer:
    def __init__(
        self,
        *,
        adapter_registry: dict[str, type] | None = None,
        normalizer: Normalizer | None = None,
        causal_linker: CausalLinker | None = None,
        evidence_extractor: EvidenceExtractor | None = None,
        validator: NormalizedTraceValidator | None = None,
        fail_on_validation_error: bool = True,
    ) -> None:
        self.adapter_registry = adapter_registry or DEFAULT_ADAPTER_REGISTRY
        self.normalizer = normalizer or Normalizer()
        self.causal_linker = causal_linker or CausalLinker()
        self.evidence_extractor = evidence_extractor or EvidenceExtractor()
        self.validator = validator or NormalizedTraceValidator()
        self.fail_on_validation_error = fail_on_validation_error

    def canonicalize(self, raw_trace: dict[str, Any]) -> dict[str, Any]:
        return self.canonicalize_with_report(raw_trace).trace

    def canonicalize_with_report(
        self,
        raw_trace: dict[str, Any],
    ) -> CanonicalizationResult:
        self._validate_raw_trace_minimal(raw_trace)

        raw_trace_copy = deepcopy(raw_trace)

        trace_id = str(raw_trace_copy["trace_id"])
        source = str(
            raw_trace_copy.get("source")
            or raw_trace_copy.get("trace_source")
            or "custom_react"
        )

        report = CanonicalizationReport(
            trace_id=trace_id,
            source=source,
        )

        adapter = self._select_adapter(source)
        report.adapter_name = adapter.__class__.__name__

        try:
            raw_events = adapter.parse(raw_trace_copy)
        except Exception as exc:
            raise CanonicalizationError(f"Adapter parse failed: {exc}") from exc

        if not raw_events:
            raise RawTraceFormatError("Adapter returned no events")

        report.raw_event_count = len(raw_events)

        normalized_events = []

        for raw_event in raw_events:
            try:
                normalized_event = self.normalizer.normalize_raw_event(
                    raw_event,
                    trace_id,
                )
            except Exception as exc:
                raw_id = raw_event.get("event_id") or raw_event.get("raw_event_id")
                raise CanonicalizationError(
                    f"Normalization failed for raw_event={raw_id!r}: {exc}"
                ) from exc

            normalized_events.append(normalized_event)
            report.raw_to_normalized.append(
                self._build_mapping_record(normalized_event)
            )

        report.normalized_event_count = len(normalized_events)

        trace = {
            "trace_id": trace_id,
            "schema_version": "0.1",
            "events": normalized_events,
        }

        try:
            trace = self.causal_linker.link_trace(trace)
        except Exception as exc:
            raise CanonicalizationError(f"Causal linking failed: {exc}") from exc

        try:
            trace = self.evidence_extractor.extract_trace(trace)
        except Exception as exc:
            raise CanonicalizationError(f"Evidence extraction failed: {exc}") from exc

        validation_report = self.validator.validate_trace(trace)
        report.schema_valid = bool(validation_report.valid)
        report.validation_report = validation_report.to_dict()

        if getattr(validation_report, "warnings", None):
            report.warnings.extend(
                f"{issue.code}:{issue.message}"
                for issue in validation_report.warnings
            )

        if not validation_report.valid:
            report.errors.extend(
                f"{issue.code}:{issue.message}"
                for issue in validation_report.errors
            )

            if self.fail_on_validation_error:
                raise NormalizedTraceValidationError(str(report.to_dict()))

        mapping_report = generate_mapping_report(trace, source=source)
        report.mapping_report = mapping_report.to_dict()

        return CanonicalizationResult(trace=trace, report=report)

    def _select_adapter(self, source: str):
        lookup_source = "synthetic" if source == "synthetic_mutation" else source
        adapter_cls = self.adapter_registry.get(lookup_source)
        if adapter_cls is None:
            raise AdapterSelectionError(
                f"Unsupported raw trace source={source!r}. "
                f"Available sources={sorted(self.adapter_registry)}"
            )
        return adapter_cls()

    @staticmethod
    def _validate_raw_trace_minimal(raw_trace: dict[str, Any]) -> None:
        if not isinstance(raw_trace, dict):
            raise RawTraceFormatError("raw_trace must be a dict")

        if not raw_trace.get("trace_id"):
            raise RawTraceFormatError("raw_trace must contain trace_id")

        if "events" not in raw_trace:
            raise RawTraceFormatError("raw_trace must contain events")

        if not isinstance(raw_trace["events"], list):
            raise RawTraceFormatError("raw_trace.events must be a list")

    @staticmethod
    def _build_mapping_record(event: dict[str, Any]) -> dict[str, Any]:
        metadata = event.get("metadata") or {}
        return {
            "raw_event_ref": event.get("raw_event_ref"),
            "event_id": event.get("event_id"),
            "raw_event_type": metadata.get("raw_event_type"),
            "raw_action_name": metadata.get("raw_action_name"),
            "action_name": event.get("action_name"),
            "action_type": event.get("action_type"),
            "effect_type": event.get("effect_type"),
            "target_resource": event.get("target_resource"),
            "status": event.get("status"),
        }


def canonicalize(raw_trace: dict[str, Any]) -> dict[str, Any]:
    return Canonicalizer().canonicalize(raw_trace)


def canonicalize_with_report(
    raw_trace: dict[str, Any],
) -> CanonicalizationResult:
    return Canonicalizer().canonicalize_with_report(raw_trace)


def load_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(obj: dict[str, Any], path: str | Path) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def canonicalize_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    report_path: str | Path | None = None,
    *,
    fail_on_validation_error: bool = True,
) -> CanonicalizationResult:
    raw_trace = load_json(input_path)

    result = Canonicalizer(
        fail_on_validation_error=fail_on_validation_error,
    ).canonicalize_with_report(raw_trace)

    if output_path is not None:
        write_json(result.trace, output_path)

    if report_path is not None:
        write_json(result.report.to_dict(), report_path)

    return result