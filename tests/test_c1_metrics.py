import pytest
from src.c1.metrics import (
    C1TraceMetrics,
    compute_c1_dataset_metrics,
    compute_c1_trace_metrics,
)


def test_compute_metrics_all_mapped():
    raw_trace = {
        "trace_id": "t1",
        "source": "custom_react",
        "events": [
            {"event_id": "raw_001"},
            {"event_id": "raw_002"},
        ],
    }

    normalized_trace = {
        "trace_id": "t1",
        "schema_version": "0.1",
        "events": [
            {
                "event_id": "e_001",
                "raw_event_ref": "raw_001",
                "action_name": "send_email",
                "action_type": "tool_call",
                "effect_type": "send",
                "target_resource": "email",
                "metadata": {},
            },
            {
                "event_id": "e_002",
                "raw_event_ref": "raw_002",
                "action_name": "retrieve_document",
                "action_type": "retrieval",
                "effect_type": "retrieve",
                "target_resource": "web",
                "metadata": {},
            },
        ],
    }

    metrics = compute_c1_trace_metrics(raw_trace, normalized_trace)

    assert metrics.total_raw_events == 2
    assert metrics.mapped_events == 2
    assert metrics.mapping_coverage == 1.0
    assert metrics.unknown_action_count == 0


def test_unknown_counts():
    raw_trace = {
        "trace_id": "t1",
        "events": [{"event_id": "raw_001"}],
    }

    normalized_trace = {
        "trace_id": "t1",
        "schema_version": "0.1",
        "events": [
            {
                "event_id": "e_001",
                "raw_event_ref": "raw_001",
                "action_name": "unknown",
                "action_type": "unknown",
                "effect_type": None,
                "target_resource": None,
                "metadata": {},
            }
        ],
    }

    metrics = compute_c1_trace_metrics(raw_trace, normalized_trace)

    assert metrics.mapped_events == 0
    assert metrics.mapping_coverage == 0.0
    assert metrics.unknown_action_count == 1
    assert metrics.unknown_effect_count == 1
    assert metrics.unknown_target_count == 1


def test_mapping_report_overrides_counts():
    raw_trace = {
        "trace_id": "t1",
        "events": [{"event_id": "raw_001"}],
    }

    normalized_trace = {
        "trace_id": "t1",
        "schema_version": "0.1",
        "events": [],
    }

    mapping_report = {
        "mapped_events": 1,
        "ambiguous_events": [{"event_id": "e_001"}],
    }

    metrics = compute_c1_trace_metrics(
        raw_trace,
        normalized_trace,
        mapping_report=mapping_report,
    )

    assert metrics.mapped_events == 1
    assert metrics.ambiguous_events == 1
    assert metrics.mapping_ambiguity == 1.0


def test_validation_report_schema_valid():
    raw_trace = {"trace_id": "t1", "events": []}
    normalized_trace = {"trace_id": "t1", "schema_version": "0.1", "events": []}

    validation_report = {
        "valid": True,
        "errors": [],
        "warnings": [{"code": "UNRESOLVED_INPUT_REF"}],
    }

    metrics = compute_c1_trace_metrics(
        raw_trace,
        normalized_trace,
        validation_report=validation_report,
    )

    assert metrics.schema_valid is True
    assert metrics.warnings_count == 1
    assert metrics.errors_count == 0


def test_dataset_aggregate():
    m1 = C1TraceMetrics(
        trace_id="t1",
        total_raw_events=2,
        mapped_events=2,
        mapping_coverage=1.0,
        schema_valid=True,
    )
    m2 = C1TraceMetrics(
        trace_id="t2",
        total_raw_events=2,
        mapped_events=1,
        mapping_coverage=0.5,
        schema_valid=False,
    )

    dataset = compute_c1_dataset_metrics([m1, m2]).to_dict()

    assert dataset["dataset"]["trace_count"] == 2
    assert dataset["dataset"]["schema_valid_traces"] == 1
    assert dataset["dataset"]["schema_invalid_traces"] == 1
    assert dataset["dataset"]["mapping_coverage"] == 0.75
