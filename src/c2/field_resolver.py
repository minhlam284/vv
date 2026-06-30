from collections.abc import Mapping, Sequence, Iterator
from typing import Any


class MissingType:
    """Sentinel type for missing values."""
    def __repr__(self) -> str:
        return "MISSING"

    def __str__(self) -> str:
        return "MISSING"


MISSING = MissingType()


def is_missing(value: Any, *, missing_if_empty: bool = True) -> bool:
    """Check if a value is considered missing."""
    if value is MISSING:
        return True
    if value is None:
        return True
    if value == "":
        return True
    if missing_if_empty and (value == [] or value == {}):
        return True
    return False


def split_field_path(field_path: str) -> list[str]:
    """Split a dot-separated field path into segments."""
    field_path = field_path.strip()
    if not field_path:
        raise ValueError("Field path cannot be empty")
    
    segments = field_path.split(".")
    for segment in segments:
        if not segment:
            raise ValueError(f"Invalid field path (empty segment): {field_path!r}")
            
    return segments


def get_field(
    event: Mapping[str, Any],
    field_path: str,
    *,
    default: Any = MISSING,
    missing_if_null: bool = True,
    missing_if_empty: bool = True
) -> Any:
    """Resolve a dot-separated nested field path within an event mapping."""
    if not isinstance(event, Mapping):
        raise TypeError("Event must be a mapping")
        
    segments = split_field_path(field_path)
    current = event
    
    for segment in segments:
        if isinstance(current, Mapping):
            if segment not in current:
                return default
            current = current[segment]
        elif isinstance(current, list):
            try:
                idx = int(segment)
                if idx < 0 or idx >= len(current):
                    return default
                current = current[idx]
            except ValueError:
                return default
        else:
            return default
            
    if missing_if_null and current is None:
        return default
    if missing_if_empty and (current == "" or current == [] or current == {}):
        return default
        
    return current


def has_field(
    event: Mapping[str, Any],
    field_path: str,
    *,
    missing_if_null: bool = True,
    missing_if_empty: bool = True
) -> bool:
    """Check if a field exists and is not considered missing."""
    val = get_field(
        event,
        field_path,
        default=MISSING,
        missing_if_null=missing_if_null,
        missing_if_empty=missing_if_empty
    )
    return val is not MISSING


class MissingFieldError(KeyError):
    """Exception raised when a required field is missing."""
    def __init__(self, field_path: str, event_id: str | None = None):
        self.field_path = field_path
        self.event_id = event_id
        
        msg = f"Missing required field {field_path!r}"
        if event_id:
            msg += f" in event {event_id!r}"
        super().__init__(msg)


def get_required_field(
    event: Mapping[str, Any],
    field_path: str
) -> Any:
    """Get a field, raising MissingFieldError if missing."""
    val = get_field(event, field_path)
    if val is MISSING:
        event_id = event.get("event_id")
        raise MissingFieldError(field_path, event_id)
    return val


def iter_events(trace_or_events: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> Iterator[Mapping[str, Any]]:
    """Iterate over events in a trace dict or a list of events."""
    if isinstance(trace_or_events, Mapping) and "events" in trace_or_events:
        items = trace_or_events["events"]
        if not isinstance(items, (list, tuple)):
             raise TypeError("Trace 'events' key must contain a sequence")
        yield from items
    elif isinstance(trace_or_events, (list, tuple)):
        yield from trace_or_events
    else:
        raise TypeError("Input must be a trace dict with 'events' or a sequence of events")


def find_events_with_field(
    trace_or_events: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    field_path: str,
    *,
    missing_if_null: bool = True,
    missing_if_empty: bool = True
) -> list[Mapping[str, Any]]:
    """Find all events containing a specific field."""
    return [
        event for event in iter_events(trace_or_events)
        if has_field(
            event, 
            field_path, 
            missing_if_null=missing_if_null, 
            missing_if_empty=missing_if_empty
        )
    ]


def find_field_locations(
    trace_or_events: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    field_path: str,
    *,
    missing_if_null: bool = True,
    missing_if_empty: bool = True
) -> list[str]:
    """Find event IDs of events containing a specific field."""
    locations = []
    for event in find_events_with_field(
        trace_or_events, 
        field_path, 
        missing_if_null=missing_if_null, 
        missing_if_empty=missing_if_empty
    ):
        locations.append(event.get("event_id", "<unknown_event>"))
    return locations


def collect_field_values(
    trace_or_events: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    field_path: str,
    *,
    missing_if_null: bool = True,
    missing_if_empty: bool = True
) -> list[tuple[str, Any]]:
    """Collect (event_id, value) for events containing a specific field."""
    results = []
    for event in iter_events(trace_or_events):
        val = get_field(
            event, 
            field_path, 
            default=MISSING, 
            missing_if_null=missing_if_null, 
            missing_if_empty=missing_if_empty
        )
        if val is not MISSING:
            event_id = event.get("event_id", "<unknown_event>")
            results.append((event_id, val))
    return results


FIELD_ALIASES = {
    "causal_path": ["taint.causal_path", "provenance.causal_path"],
    "source_id": ["taint.source", "provenance.source_id"],
    "allowed_action_set": ["policy.allowed_action_set"],
    "policy_version": ["policy.policy_version"],
    "approval_state": ["approval.status"],
    "verdict": ["decision.verdict"],
    "missing_evidence": ["decision.missing_evidence"]
}


def resolve_field_candidates(field_path: str) -> list[str]:
    """Resolve a field path to a list of alias candidates."""
    candidates = list(FIELD_ALIASES.get(field_path, []))
    if field_path not in candidates:
        candidates.append(field_path)
    return candidates


def get_any_field(
    event: Mapping[str, Any],
    field_path: str,
    *,
    default: Any = MISSING,
    missing_if_null: bool = True,
    missing_if_empty: bool = True
) -> Any:
    """Get the first non-missing value from alias candidates."""
    for candidate in resolve_field_candidates(field_path):
        val = get_field(
            event, 
            candidate,
            default=MISSING,
            missing_if_null=missing_if_null,
            missing_if_empty=missing_if_empty
        )
        if val is not MISSING:
            return val
    return default


def find_any_field_locations(
    trace_or_events: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    field_path: str,
    *,
    missing_if_null: bool = True,
    missing_if_empty: bool = True
) -> list[str]:
    """Find event IDs containing any of the alias candidates, deduplicated."""
    locations = []
    seen = set()
    
    for event in iter_events(trace_or_events):
        val = get_any_field(
            event, 
            field_path,
            default=MISSING,
            missing_if_null=missing_if_null,
            missing_if_empty=missing_if_empty
        )
        if val is not MISSING:
            event_id = event.get("event_id", "<unknown_event>")
            if event_id not in seen:
                seen.add(event_id)
                locations.append(event_id)
                
    return locations
