"""
c1.validator
~~~~~~~~~~~~
C1 Schema Validator: validate normalized trace against JSON Schema and
structural invariants.

Pipeline position::

    raw_trace (JSON)
        ──► TraceAdapter.parse()
        ──► Normalizer.normalize_raw_event()
        ──► CausalLinker.link_trace()
        ──► EvidenceExtractor.extract_trace()
        ──► Validator.validate_trace()           ← this module

**Responsibilities** (and *only* these):

1. JSON Schema validity (Draft 2020-12 via ``jsonschema``).
2. Structural invariants of the normalized trace:

   - INV-01: unique ``event_id`` within a trace.
   - INV-02: every ``event.trace_id`` matches the root ``trace_id``.
   - INV-03: ``step_id`` is non-negative and events are ordered
     non-decreasing by ``step_id``.
   - INV-04: ``parent_event`` (if non-null) refers to an existing
     ``event_id``.
   - INV-05: ``approval.approval_event`` (if non-null) refers to an
     existing ``event_id``.
   - INV-06: unresolved ``input_refs`` emit *warnings* only (not errors).
   - INV-07: enum values align with ``vocabulary.yaml``.
   - INV-08: ``metadata`` is an object or absent.
   - INV-09: optional evidence slots (``approval``, ``taint``, etc.)
     may be absent without making the trace invalid.

**Not in scope**: verdict engine (SAFE / VIOLATION / UNKNOWN), rule IR,
policy-violation detection, C2 preservation checker.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json
import yaml

from jsonschema import Draft202012Validator


REFERENCE_KEYS = [
    "doc_id",
    "document_id",
    "result_id",
    "tool_result_id",
    "id",
    "memory_id",
    "approval_request_id",
    "approval_id",
    "tool_call_id",
    "message_id",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ValidationIssue:
    """A single validation finding (error or warning)."""

    code: str
    message: str
    path: str | None = None
    event_id: str | None = None
    severity: str = "error"  # "error" or "warning"


@dataclass
class ValidationReport:
    """Aggregate result of a trace validation run."""

    valid: bool
    errors: list[ValidationIssue] = field(default_factory=list)
    warnings: list[ValidationIssue] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": [issue.__dict__ for issue in self.errors],
            "warnings": [issue.__dict__ for issue in self.warnings],
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
        }


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class InvalidTraceError(Exception):
    """Raised by ``assert_valid_trace`` when validation fails."""

    def __init__(self, report: ValidationReport) -> None:
        self.report = report
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        first_errors = self.report.errors[:5]
        detail = "; ".join(f"{e.code}: {e.message}" for e in first_errors)
        return f"Invalid normalized trace: {detail}"


# ---------------------------------------------------------------------------
# Path resolver
# ---------------------------------------------------------------------------


def _resolve_project_file(
    filename: str,
    explicit_path: str | Path | None = None,
) -> Path:
    """Return path to *filename*, searching project-standard locations.

    Parameters
    ----------
    filename:
        Bare filename to look for (e.g. ``"vocabulary.yaml"``).
    explicit_path:
        If given, use this exact path and raise if not found.
    """
    if explicit_path is not None:
        path = Path(explicit_path)
        if not path.exists():
            raise FileNotFoundError(f"{filename} not found at: {path}")
        return path

    # Repo root is two levels above this file: src /c1/validator.py
    # src / → src /c1/../.. → repo root
    repo_root = Path(__file__).resolve().parents[2]

    candidates = [
        repo_root / filename,
        repo_root / "phase_2" / "outputs" / filename,
        repo_root / "outputs" / filename,
        repo_root / "config" / filename,
    ]

    for path in candidates:
        if path.exists():
            return path

    raise FileNotFoundError(
        f"Cannot find {filename}. Tried: "
        + ", ".join(str(p) for p in candidates)
    )


# ---------------------------------------------------------------------------
# Validator class
# ---------------------------------------------------------------------------


class NormalizedTraceValidator:
    """Validates a normalized trace for schema and structural correctness."""

    def __init__(
        self,
        schema_path: str | Path | None = None,
        vocabulary_path: str | Path | None = None,
    ) -> None:
        self.schema_path = _resolve_project_file(
            "normalized_event_schema.json",
            schema_path,
        )
        self.vocabulary_path = _resolve_project_file(
            "vocabulary.yaml",
            vocabulary_path,
        )

        self.schema: dict[str, Any] = self._load_json(self.schema_path)
        self.vocabulary: dict[str, Any] = self._load_yaml(self.vocabulary_path)
        self.jsonschema_validator = Draft202012Validator(self.schema)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_trace(self, trace: dict[str, Any]) -> ValidationReport:
        """Validate *trace* and return a :class:`ValidationReport`.

        Errors make ``report.valid = False``.
        Warnings are informational and do *not* affect ``valid``.
        """
        errors: list[ValidationIssue] = []
        warnings: list[ValidationIssue] = []

        # JSON Schema check first — catches type / enum / required-field issues
        errors.extend(self._validate_json_schema(trace))

        # Structural invariants
        errors.extend(self._check_unique_event_id(trace))
        errors.extend(self._check_trace_id_consistency(trace))
        errors.extend(self._check_step_id_order(trace))
        errors.extend(self._check_parent_event_refs(trace))
        errors.extend(self._check_approval_event_refs(trace))
        errors.extend(self._check_enum_alignment(trace))
        errors.extend(self._check_metadata_shape(trace))

        # Warnings only (do NOT affect valid)
        warnings.extend(self._check_input_refs_resolvable(trace))
        warnings.extend(self._check_optional_evidence_boundary(trace))

        return ValidationReport(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
        )

    def assert_valid_trace(self, trace: dict[str, Any]) -> None:
        """Validate *trace* and raise :class:`InvalidTraceError` if invalid."""
        report = self.validate_trace(trace)
        if not report.valid:
            raise InvalidTraceError(report)

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any]:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    # ------------------------------------------------------------------
    # 1. JSON Schema validation
    # ------------------------------------------------------------------

    def _validate_json_schema(self, trace: dict[str, Any]) -> list[ValidationIssue]:
        """Check trace against normalized_event_schema.json (Draft 2020-12)."""
        issues: list[ValidationIssue] = []

        for error in sorted(self.jsonschema_validator.iter_errors(trace), key=str):
            path = "$"
            if error.absolute_path:
                path += "." + ".".join(str(p) for p in error.absolute_path)

            issues.append(
                ValidationIssue(
                    code="JSON_SCHEMA_ERROR",
                    message=error.message,
                    path=path,
                    severity="error",
                )
            )

        return issues

    # ------------------------------------------------------------------
    # 2. INV-01 — unique event_id
    # ------------------------------------------------------------------

    def _check_unique_event_id(self, trace: dict[str, Any]) -> list[ValidationIssue]:
        """Each event_id must be unique within the trace."""
        issues: list[ValidationIssue] = []
        seen: dict[str, int] = {}

        for idx, event in enumerate(trace.get("events", [])):
            event_id = event.get("event_id")
            if not event_id:
                continue

            if event_id in seen:
                issues.append(
                    ValidationIssue(
                        code="DUPLICATE_EVENT_ID",
                        message=(
                            f"Duplicate event_id {event_id!r}; "
                            f"first seen at index {seen[event_id]}, "
                            f"duplicated at index {idx}"
                        ),
                        path=f"$.events[{idx}].event_id",
                        event_id=event_id,
                    )
                )
            else:
                seen[event_id] = idx

        return issues

    # ------------------------------------------------------------------
    # 3. INV-02 — event.trace_id == root trace_id
    # ------------------------------------------------------------------

    def _check_trace_id_consistency(
        self, trace: dict[str, Any]
    ) -> list[ValidationIssue]:
        """Every event.trace_id must equal the root trace_id."""
        issues: list[ValidationIssue] = []
        root_trace_id = trace.get("trace_id")

        for idx, event in enumerate(trace.get("events", [])):
            event_trace_id = event.get("trace_id")

            if event_trace_id != root_trace_id:
                issues.append(
                    ValidationIssue(
                        code="TRACE_ID_MISMATCH",
                        message=(
                            f"event.trace_id={event_trace_id!r} "
                            f"does not match root trace_id={root_trace_id!r}"
                        ),
                        path=f"$.events[{idx}].trace_id",
                        event_id=event.get("event_id"),
                    )
                )

        return issues

    # ------------------------------------------------------------------
    # 4. INV-03 — step_id non-negative and ordered non-decreasing
    # ------------------------------------------------------------------

    def _check_step_id_order(self, trace: dict[str, Any]) -> list[ValidationIssue]:
        """step_id must be >= 0 and events must be ordered non-decreasingly."""
        issues: list[ValidationIssue] = []
        prev_step: int | None = None

        for idx, event in enumerate(trace.get("events", [])):
            step_id = event.get("step_id")

            if not isinstance(step_id, int):
                # Type errors are already caught by JSON Schema; skip here.
                continue

            if step_id < 0:
                issues.append(
                    ValidationIssue(
                        code="NEGATIVE_STEP_ID",
                        message=f"step_id must be non-negative, got {step_id}",
                        path=f"$.events[{idx}].step_id",
                        event_id=event.get("event_id"),
                    )
                )

            if prev_step is not None and step_id < prev_step:
                issues.append(
                    ValidationIssue(
                        code="STEP_ID_NOT_ORDERED",
                        message=(
                            "events must be ordered by non-decreasing step_id; "
                            f"got {step_id} after {prev_step}"
                        ),
                        path=f"$.events[{idx}].step_id",
                        event_id=event.get("event_id"),
                    )
                )

            prev_step = step_id

        return issues

    # ------------------------------------------------------------------
    # Helper: build event_id set
    # ------------------------------------------------------------------

    def _event_id_set(self, trace: dict[str, Any]) -> set[str]:
        return {
            str(event.get("event_id"))
            for event in trace.get("events", [])
            if event.get("event_id")
        }

    # ------------------------------------------------------------------
    # 5. INV-04 — parent_event reference exists
    # ------------------------------------------------------------------

    def _check_parent_event_refs(
        self, trace: dict[str, Any]
    ) -> list[ValidationIssue]:
        """If parent_event is non-null it must point to an existing event_id."""
        issues: list[ValidationIssue] = []
        event_ids = self._event_id_set(trace)

        for idx, event in enumerate(trace.get("events", [])):
            parent = event.get("parent_event")
            if parent is None:
                continue

            if str(parent) not in event_ids:
                issues.append(
                    ValidationIssue(
                        code="BROKEN_PARENT_EVENT_REF",
                        message=(
                            f"parent_event {parent!r} does not refer to "
                            "an existing event_id"
                        ),
                        path=f"$.events[{idx}].parent_event",
                        event_id=event.get("event_id"),
                    )
                )

        return issues

    # ------------------------------------------------------------------
    # 6. INV-05 — approval.approval_event reference exists
    # ------------------------------------------------------------------

    def _check_approval_event_refs(
        self, trace: dict[str, Any]
    ) -> list[ValidationIssue]:
        """approval.approval_event (if non-null) must point to an existing event_id."""
        issues: list[ValidationIssue] = []
        event_ids = self._event_id_set(trace)

        for idx, event in enumerate(trace.get("events", [])):
            approval = event.get("approval")

            if not isinstance(approval, dict):
                continue

            approval_event = approval.get("approval_event")
            if approval_event is None:
                continue

            if str(approval_event) not in event_ids:
                issues.append(
                    ValidationIssue(
                        code="BROKEN_APPROVAL_EVENT_REF",
                        message=(
                            f"approval.approval_event {approval_event!r} "
                            "does not refer to an existing event_id"
                        ),
                        path=f"$.events[{idx}].approval.approval_event",
                        event_id=event.get("event_id"),
                    )
                )

        return issues

    # ------------------------------------------------------------------
    # 7. INV-06 — unresolved input_refs → warning only
    # ------------------------------------------------------------------

    def _build_reference_index(self, trace: dict[str, Any]) -> set[str]:
        """Build the set of all resolvable reference IDs in the trace."""
        refs: set[str] = set()

        for event in trace.get("events", []):
            for key in ("event_id", "output_ref"):
                value = event.get(key)
                if value:
                    refs.add(str(value))

            tool_output = event.get("tool_output")
            if isinstance(tool_output, dict):
                for key in REFERENCE_KEYS:
                    value = tool_output.get(key)
                    if value:
                        refs.add(str(value))

            provenance = event.get("provenance")
            if isinstance(provenance, list):
                for item in provenance:
                    if isinstance(item, str):
                        refs.add(item)
                    elif isinstance(item, dict):
                        for key in ("source_id", "doc_id", "id"):
                            value = item.get(key)
                            if value:
                                refs.add(str(value))
            elif isinstance(provenance, dict):
                for key in ("source_id", "doc_id", "id"):
                    value = provenance.get(key)
                    if value:
                        refs.add(str(value))

        return refs

    def _check_input_refs_resolvable(
        self, trace: dict[str, Any]
    ) -> list[ValidationIssue]:
        """Unresolvable input_refs emit warnings (not errors)."""
        warnings: list[ValidationIssue] = []
        ref_index = self._build_reference_index(trace)

        for idx, event in enumerate(trace.get("events", [])):
            input_refs = event.get("input_refs") or []
            if not isinstance(input_refs, list):
                continue

            for ref in input_refs:
                if str(ref) not in ref_index:
                    warnings.append(
                        ValidationIssue(
                            code="UNRESOLVED_INPUT_REF",
                            message=(
                                f"input_ref {ref!r} cannot be resolved "
                                "in current trace reference index"
                            ),
                            path=f"$.events[{idx}].input_refs",
                            event_id=event.get("event_id"),
                            severity="warning",
                        )
                    )

        return warnings

    # ------------------------------------------------------------------
    # 8. INV-07 — enum alignment with vocabulary.yaml
    # ------------------------------------------------------------------

    def _check_enum_alignment(self, trace: dict[str, Any]) -> list[ValidationIssue]:
        """Cross-check enum values against vocabulary.yaml for drift detection."""
        issues: list[ValidationIssue] = []

        top_level_mapping = {
            "phase": "phase",
            "action_type": "action_type",
            "effect_type": "effect_type",
            "target_resource": "target_resource",
            "status": "status",
            "error_type": "error_type",
            "reversibility": "reversibility",
        }

        for idx, event in enumerate(trace.get("events", [])):
            event_id = event.get("event_id")

            # Top-level fields
            for field_name, vocab_key in top_level_mapping.items():
                value = event.get(field_name)
                if value is None:
                    continue

                allowed = set(self.vocabulary.get(vocab_key, []))
                if allowed and value not in allowed:
                    issues.append(
                        ValidationIssue(
                            code="VOCAB_ENUM_MISMATCH",
                            message=(
                                f"{field_name}={value!r} "
                                f"is not in vocabulary.{vocab_key}"
                            ),
                            path=f"$.events[{idx}].{field_name}",
                            event_id=event_id,
                        )
                    )

            # taint.label
            taint = event.get("taint")
            if isinstance(taint, dict):
                value = taint.get("label")
                allowed = set(self.vocabulary.get("taint_label", []))
                if value is not None and allowed and value not in allowed:
                    issues.append(
                        ValidationIssue(
                            code="VOCAB_ENUM_MISMATCH",
                            message=(
                                f"taint.label={value!r} "
                                "is not in vocabulary.taint_label"
                            ),
                            path=f"$.events[{idx}].taint.label",
                            event_id=event_id,
                        )
                    )

            # approval.status
            approval = event.get("approval")
            if isinstance(approval, dict):
                value = approval.get("status")
                allowed = set(self.vocabulary.get("approval_status", []))
                if value is not None and allowed and value not in allowed:
                    issues.append(
                        ValidationIssue(
                            code="VOCAB_ENUM_MISMATCH",
                            message=(
                                f"approval.status={value!r} "
                                "is not in vocabulary.approval_status"
                            ),
                            path=f"$.events[{idx}].approval.status",
                            event_id=event_id,
                        )
                    )

            # decision.verdict and decision.route
            decision = event.get("decision")
            if isinstance(decision, dict):
                verdict = decision.get("verdict")
                allowed_verdicts = set(self.vocabulary.get("decision_verdict", []))
                if (
                    verdict is not None
                    and allowed_verdicts
                    and verdict not in allowed_verdicts
                ):
                    issues.append(
                        ValidationIssue(
                            code="VOCAB_ENUM_MISMATCH",
                            message=(
                                f"decision.verdict={verdict!r} "
                                "is not in vocabulary.decision_verdict"
                            ),
                            path=f"$.events[{idx}].decision.verdict",
                            event_id=event_id,
                        )
                    )

                route = decision.get("route")
                allowed_routes = set(self.vocabulary.get("decision_route", []))
                if (
                    route is not None
                    and allowed_routes
                    and route not in allowed_routes
                ):
                    issues.append(
                        ValidationIssue(
                            code="VOCAB_ENUM_MISMATCH",
                            message=(
                                f"decision.route={route!r} "
                                "is not in vocabulary.decision_route"
                            ),
                            path=f"$.events[{idx}].decision.route",
                            event_id=event_id,
                        )
                    )

        return issues

    # ------------------------------------------------------------------
    # 9. INV-08 — metadata shape
    # ------------------------------------------------------------------

    def _check_metadata_shape(self, trace: dict[str, Any]) -> list[ValidationIssue]:
        """metadata must be an object (or absent), never a scalar or list."""
        issues: list[ValidationIssue] = []

        for idx, event in enumerate(trace.get("events", [])):
            metadata = event.get("metadata", {})

            if metadata is not None and not isinstance(metadata, dict):
                issues.append(
                    ValidationIssue(
                        code="INVALID_METADATA_SHAPE",
                        message=(
                            "metadata must be object or absent, "
                            f"got {type(metadata).__name__}"
                        ),
                        path=f"$.events[{idx}].metadata",
                        event_id=event.get("event_id"),
                    )
                )

        return issues

    # ------------------------------------------------------------------
    # 10. INV-09 — optional evidence boundary (warnings only)
    # ------------------------------------------------------------------

    def _check_optional_evidence_boundary(
        self, trace: dict[str, Any]
    ) -> list[ValidationIssue]:
        """Warn when optional evidence slots are absent on high-risk events.

        Missing optional evidence does *not* invalidate the trace —
        C2 will return UNKNOWN when it needs evidence that is absent.
        """
        warnings: list[ValidationIssue] = []

        for idx, event in enumerate(trace.get("events", [])):
            effect_type = event.get("effect_type")
            target_resource = event.get("target_resource")
            event_id = event.get("event_id")

            # send/email without approval slot
            if (
                effect_type == "send"
                and target_resource == "email"
                and "approval" not in event
            ):
                warnings.append(
                    ValidationIssue(
                        code="OPTIONAL_APPROVAL_EVIDENCE_ABSENT",
                        message=(
                            "send/email event has no approval slot; "
                            "C2 should return UNKNOWN if approval rule requires it"
                        ),
                        path=f"$.events[{idx}].approval",
                        event_id=event_id,
                        severity="warning",
                    )
                )

            # sink/destructive event without taint slot
            if effect_type in {"write", "delete", "execute", "send"} and "taint" not in event:
                warnings.append(
                    ValidationIssue(
                        code="OPTIONAL_TAINT_EVIDENCE_ABSENT",
                        message=(
                            "sink/destructive event has no taint slot; "
                            "C2 should return UNKNOWN if taint rule requires it"
                        ),
                        path=f"$.events[{idx}].taint",
                        event_id=event_id,
                        severity="warning",
                    )
                )

        return warnings


# ---------------------------------------------------------------------------
# Convenience module-level functions
# ---------------------------------------------------------------------------


def validate_trace(
    trace: dict[str, Any],
    schema_path: str | Path | None = None,
    vocabulary_path: str | Path | None = None,
) -> ValidationReport:
    """Validate *trace* and return a :class:`ValidationReport`.

    Parameters
    ----------
    trace:
        Normalized trace dict produced by the C1 pipeline.
    schema_path:
        Override path to ``normalized_event_schema.json``.
    vocabulary_path:
        Override path to ``vocabulary.yaml``.
    """
    return NormalizedTraceValidator(
        schema_path=schema_path,
        vocabulary_path=vocabulary_path,
    ).validate_trace(trace)


def assert_valid_trace(
    trace: dict[str, Any],
    schema_path: str | Path | None = None,
    vocabulary_path: str | Path | None = None,
) -> None:
    """Validate *trace* and raise :class:`InvalidTraceError` if invalid.

    Parameters
    ----------
    trace:
        Normalized trace dict produced by the C1 pipeline.
    schema_path:
        Override path to ``normalized_event_schema.json``.
    vocabulary_path:
        Override path to ``vocabulary.yaml``.
    """
    NormalizedTraceValidator(
        schema_path=schema_path,
        vocabulary_path=vocabulary_path,
    ).assert_valid_trace(trace)
