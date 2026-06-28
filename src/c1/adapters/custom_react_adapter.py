"""
c1.adapters.custom_react_adapter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Adapter for traces produced by the custom ReAct / synthetic agent runtime.

This adapter handles every file currently in:
    data/raw_traces/synthetic/   (case_001 – case_005)
    data/raw_traces/mutated/     (case_006 – case_010)

Both trace-level ``source`` values seen in the dataset are accepted:
    "synthetic"           – standard synthetic traces
    "synthetic_mutation"  – mutated variants (e.g. case_010)

**Contract**
The adapter maps each raw event to a *canonical intermediate dict* that:

1. Always contains every required key (``None`` when absent, never omitted).
2. Preserves raw ``tool_name`` and ``action`` aliases verbatim so the
   normalizer can store them in ``raw_event_ref`` / ``metadata``.
3. Passes through evidence slots (``approval``, ``taint``, ``provenance``,
   ``effect_type``, ``target_resource``, ``output_ref``) exactly as written
   in the raw trace — present or absent reflects what the runtime logged.
4. Never maps missing evidence to a safe/positive default (RAW-C1-02).

**Output keys** (one dict per event)
    _adapter_source   str   identifier of this adapter
    trace_id          str   from parent trace
    raw_event_id      str   original event_id (alias kept for normalizer)
    event_id          str   same as raw_event_id
    step_id           int|str|None
    timestamp         str|number|None
    event_type        str   coerced to allowed set (→ "error" if unknown)
    source            str|None
    action            str|None   raw action alias, verbatim
    tool_name         str|None   raw tool alias, verbatim
    input             any
    output            any
    status            str   coerced to allowed set (→ "unknown" if missing)
    error             any
    parent_event      str|None
    references        list|None
    output_ref        str|None   pass-through if present
    effect_type       str|None   pass-through if present
    target_resource   str|None   pass-through if present
    approval          dict|None  pass-through if present
    taint             dict|None  pass-through if present
    provenance        dict|None  pass-through if present
    _raw              dict   full original event for normalizer bookkeeping
"""

from __future__ import annotations

from typing import Any

from .base import AdapterError, TraceAdapter


# Trace-level ``source`` values this adapter accepts.
_ACCEPTED_SOURCES: frozenset[str] = frozenset(
    {"synthetic", "synthetic_mutation", "custom_react", "custom_agent"}
)


class CustomReActAdapter(TraceAdapter):
    """Adapter for the custom ReAct / synthetic agent runtime.

    Handles all files in ``data/raw_traces/synthetic/`` and
    ``data/raw_traces/mutated/`` out of the box.

    Usage::

        from c1.adapters.custom_react_adapter import CustomReActAdapter

        adapter = CustomReActAdapter()
        events = adapter.parse(raw_trace_dict)   # list[dict]

    In lenient mode (default), malformed individual events are emitted as
    ``event_type="error"`` / ``status="unknown"`` stubs rather than raising,
    so the normalizer always receives a complete (possibly partial) list.

    In strict mode (``strict=True``), any structural violation raises
    :class:`~c1.adapters.base.AdapterError`.
    """

    source_name: str = "custom_react"

    # Evidence pass-through keys: present verbatim when the raw event has them,
    # None when absent.  These must never be defaulted to a positive value.
    _EVIDENCE_KEYS: tuple[str, ...] = (
        "approval",
        "taint",
        "provenance",
        "effect_type",
        "target_resource",
        "output_ref",
    )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def parse(self, raw_trace: dict) -> list[dict]:
        """Parse a synthetic/custom-ReAct raw trace into intermediate events.

        Accepts both ``source="synthetic"`` and
        ``source="synthetic_mutation"`` at the trace level.

        Args:
            raw_trace: Raw trace JSON object loaded from disk.  Must contain
                       ``trace_id``, ``source``, and ``events`` (list).

        Returns:
            List of intermediate event dicts, one per entry in
            ``raw_trace["events"]``, in original runtime order.

        Raises:
            AdapterError: Always in strict mode; only for unrecoverable
                          trace-level errors in lenient mode.
        """
        self.validate_trace(raw_trace)

        trace_id: str = raw_trace["trace_id"]
        intermediate: list[dict] = []

        for idx, raw_ev in enumerate(raw_trace["events"]):
            try:
                ev = self._extract_event(raw_ev, trace_id=trace_id, idx=idx)
            except AdapterError:
                if self.strict:
                    raise
                # Lenient: emit a stub so downstream never sees a gap.
                ev = self._fallback_event(raw_ev, trace_id=trace_id, idx=idx)
            intermediate.append(ev)

        return intermediate

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_event(
        self, raw_ev: Any, *, trace_id: str, idx: int
    ) -> dict:
        """Extract a single well-formed raw event into a canonical dict.

        Args:
            raw_ev:   One element from ``raw_trace["events"]``.
            trace_id: Parent trace ID (used in error messages).
            idx:      Position index in the events list.

        Returns:
            Canonical intermediate dict with all required keys present.

        Raises:
            AdapterError: If ``raw_ev`` is not a dict, or is missing
                          ``event_id``.
        """
        if not isinstance(raw_ev, dict):
            raise AdapterError(
                f"[{self.source_name}] trace='{trace_id}' events[{idx}] "
                f"is not a dict (got {type(raw_ev).__name__})."
            )

        event_id: str | None = raw_ev.get("event_id")
        if not event_id:
            raise AdapterError(
                f"[{self.source_name}] trace='{trace_id}' events[{idx}] "
                f"is missing required 'event_id'."
            )

        # Build the canonical intermediate event.
        ev: dict[str, Any] = {
            # ── adapter provenance ──────────────────────────────────────
            "_adapter_source": self.source_name,
            # ── trace-level identity ────────────────────────────────────
            "trace_id": trace_id,
            # ── event identity ──────────────────────────────────────────
            "raw_event_id": event_id,       # canonical alias for normalizer
            "event_id": event_id,
            "step_id": raw_ev.get("step_id"),
            "timestamp": raw_ev.get("timestamp"),
            # ── classification ──────────────────────────────────────────
            "event_type": self.normalize_event_type(raw_ev.get("event_type")),
            "source": raw_ev.get("source"),
            # ── action identity (raw aliases preserved verbatim) ────────
            "action": raw_ev.get("action"),
            "tool_name": raw_ev.get("tool_name"),
            # ── payload ─────────────────────────────────────────────────
            "input": raw_ev.get("input"),
            "output": raw_ev.get("output"),
            # ── outcome ─────────────────────────────────────────────────
            "status": self.normalize_status(raw_ev.get("status")),
            "error": raw_ev.get("error"),
            # ── causal chain ─────────────────────────────────────────────
            "parent_event": raw_ev.get("parent_event"),
            "references": raw_ev.get("references"),
        }

        # ── evidence pass-throughs (present iff in raw event) ───────────
        # Use sentinel to distinguish "key absent" from "key = None".
        _MISSING = object()
        for key in self._EVIDENCE_KEYS:
            value = raw_ev.get(key, _MISSING)
            ev[key] = None if value is _MISSING else value

        # ── full raw event for normalizer bookkeeping (RAW-C1-01) ───────
        ev["_raw"] = raw_ev

        return ev

    def _fallback_event(
        self, raw_ev: Any, *, trace_id: str, idx: int
    ) -> dict:
        """Build a minimal stub for a malformed event (lenient mode only).

        The stub is marked ``event_type="error"`` / ``status="unknown"`` so
        that C2 returns UNKNOWN rather than SAFE (RAW-C1-02 / RAW-C1-05).

        Args:
            raw_ev:   The problematic event (may not be a dict).
            trace_id: Parent trace ID.
            idx:      Position index.

        Returns:
            Minimal intermediate dict with all keys present.
        """
        raw_dict: dict = raw_ev if isinstance(raw_ev, dict) else {}
        stub: dict[str, Any] = {
            "_adapter_source": self.source_name,
            "trace_id": trace_id,
            "raw_event_id": raw_dict.get("event_id", f"_malformed_{idx}"),
            "event_id": raw_dict.get("event_id", f"_malformed_{idx}"),
            "step_id": raw_dict.get("step_id", idx),
            "timestamp": raw_dict.get("timestamp"),
            "event_type": "error",
            "source": raw_dict.get("source"),
            "action": raw_dict.get("action"),
            "tool_name": raw_dict.get("tool_name"),
            "input": raw_dict.get("input"),
            "output": None,
            "status": "unknown",
            "error": {"message": "Malformed raw event — adapter could not extract"},
            "parent_event": raw_dict.get("parent_event"),
            "references": raw_dict.get("references"),
        }
        # Evidence slots → None (not a safe default, just absent)
        for key in self._EVIDENCE_KEYS:
            stub[key] = None
        stub["_raw"] = raw_ev
        return stub
