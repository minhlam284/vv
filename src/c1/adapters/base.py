"""
c1.adapters.base
~~~~~~~~~~~~~~~~
Base adapter interface for the C1 canonicalizer.

Every runtime source (custom ReAct, LangChain, MCP, OpenAI Agents …) must
subclass TraceAdapter and implement :meth:`parse`.  The contract is:

    raw_trace  (dict)   ──►  parse()  ──►  list[dict]   (intermediate raw events)

The returned list contains *intermediate* raw-event dicts — one dict per
observed runtime event — that are later handed to ``c1.normalize`` for
full normalization into the ``normalized_event_schema v0.1`` format.

Design rules (see ``data/raw_traces/raw_trace_format.md`` §7):
- Adapters MUST NOT silently drop events that carry evidence needed by C2.
- Adapters MUST preserve the raw alias (``tool_name``, ``action``) in each
  intermediate event so that the normalizer can store it in ``raw_event_ref``
  / ``metadata``.
- Adapters MUST NOT map missing evidence to SAFE; leave fields as ``None`` so
  that C2 returns UNKNOWN.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AdapterError(Exception):
    """Raised when a TraceAdapter encounters an unrecoverable parse error."""


class TraceAdapter(ABC):
    """Abstract base class for all C1 trace adapters.

    Subclasses declare :attr:`source_name` (a short identifier that matches
    the ``source`` field of an incoming raw trace) and implement
    :meth:`parse`.

    Example::

        class MyAdapter(TraceAdapter):
            source_name = "my_runtime"

            def parse(self, raw_trace: dict) -> list[dict]:
                events = []
                for raw_ev in raw_trace.get("events", []):
                    events.append(self._extract(raw_ev))
                return events

            def _extract(self, raw_ev: dict) -> dict:
                ...
    """

    # ------------------------------------------------------------------
    # Class-level identity
    # ------------------------------------------------------------------

    #: Short identifier that matches the ``source`` field of a raw trace
    #: (e.g. ``"custom_react"``, ``"langchain"``, ``"mcp"``).
    #: Subclasses MUST set this to a non-empty string.
    source_name: str = ""

    # ------------------------------------------------------------------
    # Constructor
    # ------------------------------------------------------------------

    def __init__(self, *, strict: bool = False) -> None:
        """
        Args:
            strict: When *True*, raise :class:`AdapterError` on any
                    validation failure instead of falling back to
                    ``"unknown"`` / ``None``.  Defaults to *False*.
        """
        if not self.source_name:
            raise TypeError(
                f"{type(self).__name__} must define a non-empty 'source_name'."
            )
        self.strict = strict

    # ------------------------------------------------------------------
    # Abstract interface — subclasses must implement this
    # ------------------------------------------------------------------

    @abstractmethod
    def parse(self, raw_trace: dict) -> list[dict]:
        """Parse a raw trace dict into a list of intermediate raw-event dicts.

        Each returned dict is a *runtime-neutral* intermediate representation
        that preserves all raw fields needed by the C1 normalizer and by C2
        evidence checkers.  The exact schema of intermediate events is defined
        in ``data/raw_traces/raw_trace_format.md``.

        Subclasses are responsible for:

        1. Iterating over ``raw_trace["events"]`` (or the framework-specific
           equivalent).
        2. Extracting at least the fields listed in the raw trace format
           (``event_id``, ``step_id``, ``timestamp``, ``event_type``,
           ``source``, ``action``, ``tool_name``, ``input``, ``output``,
           ``status``, ``error``, ``parent_event``, ``references``).
        3. Preserving raw aliases — never overwrite the raw ``tool_name`` /
           ``action`` value before the normalizer has saved it.
        4. Setting missing evidence fields to ``None`` (not ``"safe"`` or
           ``"success"``).

        Args:
            raw_trace: The raw trace JSON object loaded from disk or a
                       runtime hook.

        Returns:
            A list of intermediate raw-event dicts, one per observed event,
            in the original runtime order (sorted by ``step_id`` when
            possible).

        Raises:
            AdapterError: If the trace is structurally invalid and
                          ``self.strict`` is *True*, or if a non-recoverable
                          error occurs.
        """
        raise NotImplementedError  # pragma: no cover

    # ------------------------------------------------------------------
    # Shared validation helpers (available to all subclasses)
    # ------------------------------------------------------------------

    # Required top-level fields in every raw trace (RAW-TRACE-01..03)
    _REQUIRED_TRACE_FIELDS: frozenset[str] = frozenset({"trace_id", "source", "events"})

    # Allowed raw event_type values (RAW-EVENT-02)
    _ALLOWED_EVENT_TYPES: frozenset[str] = frozenset(
        {
            "user_message",
            "planner_step",
            "retrieval",
            "tool_call",
            "tool_result",
            "approval_request",
            "approval_response",
            "memory_op",
            "final_response",
            "error",
        }
    )

    # Allowed raw status values (RAW-EVENT-03)
    _ALLOWED_STATUSES: frozenset[str] = frozenset(
        {"pending", "success", "failed", "blocked", "unknown"}
    )

    def validate_trace(self, raw_trace: Any) -> None:
        """Validate trace-level structure.

        Checks RAW-TRACE-01, RAW-TRACE-02, RAW-TRACE-03, and RAW-TRACE-04
        (unique event_ids).

        Args:
            raw_trace: The raw trace object to validate.

        Raises:
            AdapterError: If any required field is missing or ``events`` is
                          not a list, or if ``event_id`` values are not unique.
        """
        if not isinstance(raw_trace, dict):
            raise AdapterError(
                f"[{self.source_name}] raw_trace must be a dict, "
                f"got {type(raw_trace).__name__}."
            )

        missing = self._REQUIRED_TRACE_FIELDS - raw_trace.keys()
        if missing:
            raise AdapterError(
                f"[{self.source_name}] raw_trace missing required fields: "
                f"{sorted(missing)}."
            )

        trace_id = raw_trace.get("trace_id")
        if not trace_id:
            raise AdapterError(
                f"[{self.source_name}] 'trace_id' must be a non-empty string."
            )

        events = raw_trace.get("events")
        if not isinstance(events, list):
            raise AdapterError(
                f"[{self.source_name}] 'events' must be a list, "
                f"got {type(events).__name__}."
            )

        # RAW-TRACE-04: unique event_ids
        seen_ids: set[str] = set()
        for ev in events:
            if isinstance(ev, dict):
                eid = ev.get("event_id")
                if eid in seen_ids:
                    raise AdapterError(
                        f"[{self.source_name}] Duplicate event_id '{eid}' "
                        f"in trace '{trace_id}'."
                    )
                if eid is not None:
                    seen_ids.add(eid)

    def normalize_event_type(self, raw_event_type: str | None) -> str:
        """Return the raw event_type if it is in the allowed set, else ``"error"``.

        Args:
            raw_event_type: The ``event_type`` string from the raw event.

        Returns:
            The same value if allowed, otherwise ``"error"``.
        """
        if raw_event_type in self._ALLOWED_EVENT_TYPES:
            return raw_event_type
        if self.strict:
            raise AdapterError(
                f"[{self.source_name}] Unknown event_type: '{raw_event_type}'."
            )
        return "error"

    def normalize_status(self, raw_status: str | None) -> str:
        """Return the raw status if it is in the allowed set, else ``"unknown"``.

        Args:
            raw_status: The ``status`` string from the raw event.

        Returns:
            The same value if allowed, otherwise ``"unknown"``.
        """
        if raw_status in self._ALLOWED_STATUSES:
            return raw_status
        if self.strict:
            raise AdapterError(
                f"[{self.source_name}] Unknown status: '{raw_status}'."
            )
        return "unknown"

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<{type(self).__name__} source_name={self.source_name!r} "
            f"strict={self.strict}>"
        )
