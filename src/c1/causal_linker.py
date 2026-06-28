"""
c1.causal_linker
~~~~~~~~~~~~~~~~
C1 Causal Linker: enrich normalized trace events with causal links.

Pipeline position::

    raw_trace (JSON)
        ──► TraceAdapter.parse()
        ──► Normalizer.normalize_raw_event()
        ──► CausalLinker.link_trace()          ← this module
        ──► EvidenceExtractor.extract_trace()
        ──► Validator.validate_trace()

**Responsibilities** (and *only* these):

- Infer ``output_ref`` for events that produce named artifacts.
- Build an output index keyed by ``event_id``, ``output_ref``, and
  ``tool_output`` artifact IDs.
- Fill ``parent_event`` according to a sequential event-chain heuristic.
- Fill ``input_refs`` from ``typed_args`` reference keys and heuristic
  consumption rules.
- Propagate ``taint`` objects and build ``taint.causal_path`` lists.
- Record ``metadata.causal_link_warnings`` for every ambiguity.

**Not in scope**: policy decisions, verdicts (SAFE/VIOLATION/UNKNOWN),
approval matching, trust classification, schema validation, full data-flow
graphs.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# typed_args keys that carry reference IDs to other artifacts/events.
REF_ARG_KEYS: frozenset[str] = frozenset(
    {
        "content_ref",
        "body_ref",
        "instruction_ref",
        "doc_id",
        "document_id",
        "source_id",
        "memory_key",
        "tool_result_id",
        "result_id",
    }
)

# Priority order for merging taint labels (most-dangerous first).
TAINT_PRIORITY: list[str] = [
    "untrusted",
    "prompt_derived",
    "user_controlled",
    "retrieval_derived",
    "classified",
    "sensitive",
    "unknown",
    "trusted",
    "sanitized",
]

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


# ===========================================================================
# CausalLinker
# ===========================================================================


class CausalLinker:
    """Enrich a normalized trace with causal links.

    Usage::

        linker = CausalLinker()
        linked_trace = linker.link_trace(trace)

    The input *trace* is never mutated; a deep-copy is returned.
    """

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def link_trace(self, trace: dict[str, Any]) -> dict[str, Any]:
        """Return an enriched copy of *trace* with causal links filled in.

        Steps
        -----
        1. Deep-copy the input trace.
        2. Sort events by ``step_id`` (ascending; missing step_id sorts last).
        3. Ensure every event has a ``metadata`` dict.
        4. Infer ``output_ref`` where missing.
        5. Build an output index (event_id / output_ref / tool_output IDs).
        6. Fill ``parent_event`` via a sequential chain heuristic.
        7. Fill ``input_refs`` from typed_args keys and consumption heuristics.
        8. Rebuild the output index (output_refs may have been added in step 4).
        9. Propagate taint objects and build ``taint.causal_path``.

        Args:
            trace: Normalized trace dict (``schema_version`` 0.1).

        Returns:
            New enriched trace dict; the input is not modified.
        """
        linked: dict[str, Any] = deepcopy(trace)
        events: list[dict[str, Any]] = linked.get("events", [])

        # Sort by step_id; events without a step_id go to the end.
        events.sort(
            key=lambda e: (
                e.get("step_id") if e.get("step_id") is not None else 10**9
            )
        )

        self._ensure_metadata(events)
        self._ensure_output_refs(events)

        output_index = self._build_output_index(events)

        self._link_parent_events(events, output_index)
        self._link_input_refs(events, output_index)

        # Rebuild after input_refs may have introduced new resolution targets.
        output_index = self._build_output_index(events)
        self._link_taint_causal_paths(events, output_index)

        return linked

    # ------------------------------------------------------------------
    # Internal helpers: metadata
    # ------------------------------------------------------------------

    def _ensure_metadata(self, events: list[dict[str, Any]]) -> None:
        """Guarantee every event has a non-None ``metadata`` dict."""
        for event in events:
            if not isinstance(event.get("metadata"), dict):
                event["metadata"] = {}

    def _warn(self, event: dict[str, Any], message: str) -> None:
        """Append *message* to ``event['metadata']['causal_link_warnings']``."""
        metadata = event.setdefault("metadata", {})
        if metadata is None:  # belt-and-suspenders
            metadata = {}
            event["metadata"] = metadata
        metadata.setdefault("causal_link_warnings", []).append(message)

    # ------------------------------------------------------------------
    # Step 1: ensure output_ref
    # ------------------------------------------------------------------

    def _ensure_output_refs(self, events: list[dict[str, Any]]) -> None:
        """Infer ``output_ref`` for events that produce named artifacts."""
        for event in events:
            if event.get("output_ref"):
                continue
            output_ref = self._infer_output_ref(event)
            if output_ref:
                event["output_ref"] = output_ref

    def _infer_output_ref(self, event: dict[str, Any]) -> str | None:
        """Return an inferred ``output_ref`` string, or ``None``.

        Resolution order:
        1. Well-known ID keys inside ``tool_output``.
        2. ``action_type`` / ``effect_type`` patterns.
        """
        event_id = event.get("event_id")
        action_type = event.get("action_type")
        effect_type = event.get("effect_type")
        action_name = event.get("action_name")
        tool_output = event.get("tool_output")
        typed_args = event.get("typed_args") or {}

        # 1. Prefer explicit artifact IDs in tool_output.
        if isinstance(tool_output, dict):
            for key in REFERENCE_KEYS:
                value = tool_output.get(key)
                if value:
                    return str(value)

        # 2. Action-type heuristics.
        if action_type == "retrieval" or effect_type == "retrieve":
            return f"retrieval_{event_id}"

        if action_type == "tool_result":
            return f"tool_result_{event_id}"

        if action_type == "tool_call" and tool_output is not None:
            return f"tool_result_{event_id}"

        if action_type == "memory_op" and effect_type == "write":
            memory_key = typed_args.get("memory_key") or typed_args.get("key")
            if memory_key:
                return str(memory_key)
            return f"memory_{event_id}"

        if action_type in {"agent_response", "final_response"} or action_name == "final_response":
            return f"final_answer_{event_id}"

        if action_type == "governance_action" and effect_type == "approve":
            return f"approval_{event_id}"

        return None

    # ------------------------------------------------------------------
    # Step 2: build output index
    # ------------------------------------------------------------------

    def _build_output_index(
        self, events: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        """Return a mapping from any reference key to its producer event.

        Keys indexed:
        - ``event_id``
        - ``output_ref``
        - ``tool_output`` artifact IDs (doc_id, result_id, ...)
        """
        index: dict[str, dict[str, Any]] = {}

        for event in events:
            event_id = event.get("event_id")
            output_ref = event.get("output_ref")

            if event_id:
                index[str(event_id)] = event

            if output_ref:
                index[str(output_ref)] = event

            tool_output = event.get("tool_output")
            if isinstance(tool_output, dict):
                for key in REFERENCE_KEYS:
                    value = tool_output.get(key)
                    if value:
                        index[str(value)] = event

        return index

    # ------------------------------------------------------------------
    # Step 3: link parent_event
    # ------------------------------------------------------------------

    def _link_parent_events(
        self,
        events: list[dict[str, Any]],
        output_index: dict[str, dict[str, Any]],
    ) -> None:
        """Fill ``parent_event`` for events where it is absent or broken."""
        last_user: str | None = None
        last_plan: str | None = None
        last_retrieval: str | None = None
        last_tool_call: str | None = None
        last_tool_result: str | None = None
        last_memory: str | None = None
        last_approval_request: str | None = None
        last_meaningful: str | None = None

        event_ids: set[str] = {
            str(e.get("event_id")) for e in events if e.get("event_id")
        }

        for event in events:
            event_id = event.get("event_id")
            action_type = event.get("action_type")
            action_name = event.get("action_name")
            phase = event.get("phase")
            effect_type = event.get("effect_type")

            # Validate existing parent_event.
            parent = event.get("parent_event")
            if parent is not None:
                if str(parent) in event_ids:
                    pass  # valid — keep as-is
                else:
                    self._warn(event, f"broken_parent_event:{parent}")
                    event["parent_event"] = None

            # Infer parent_event when absent.
            if not event.get("parent_event"):
                inferred = self._infer_parent_event(
                    event,
                    output_index=output_index,
                    last_user=last_user,
                    last_plan=last_plan,
                    last_retrieval=last_retrieval,
                    last_tool_call=last_tool_call,
                    last_tool_result=last_tool_result,
                    last_memory=last_memory,
                    last_approval_request=last_approval_request,
                    last_meaningful=last_meaningful,
                )
                if inferred and inferred != str(event_id):
                    event["parent_event"] = inferred

            # Advance chain pointers.
            if action_type == "message" and phase == "plan":
                last_user = str(event_id)
            if phase == "plan":
                last_plan = str(event_id)
            if action_type == "retrieval":
                last_retrieval = str(event_id)
            if action_type == "tool_call":
                last_tool_call = str(event_id)
            if action_type == "tool_result" or (
                action_type == "tool_call" and phase == "after_action"
            ):
                last_tool_result = str(event_id)
            if action_type == "memory_op":
                last_memory = str(event_id)
            if action_type == "governance_action" and "approval" in str(action_name):
                last_approval_request = str(event_id)
            if action_type != "unknown":
                last_meaningful = str(event_id)

    def _infer_parent_event(
        self,
        event: dict[str, Any],
        **ctx: Any,
    ) -> str | None:
        """Return the best inferred ``parent_event`` ID, or ``None``."""
        action_type = event.get("action_type")
        action_name = event.get("action_name")
        phase = event.get("phase")

        output_index: dict[str, dict[str, Any]] = ctx["output_index"]

        # Input refs take highest priority — trace back to their producer.
        for ref in event.get("input_refs") or []:
            producer = output_index.get(str(ref))
            if producer:
                return str(producer.get("event_id"))

        if phase == "plan":
            return ctx["last_user"]

        if action_type == "retrieval":
            return ctx["last_plan"] or ctx["last_user"]

        if action_type == "tool_call":
            return ctx["last_plan"] or ctx["last_retrieval"] or ctx["last_user"]

        if action_type == "tool_result":
            return ctx["last_tool_call"]

        if action_type == "memory_op":
            return (
                ctx["last_retrieval"]
                or ctx["last_tool_result"]
                or ctx["last_plan"]
            )

        if action_type in {"agent_response", "final_response"} or action_name == "final_response":
            return (
                ctx["last_tool_result"]
                or ctx["last_memory"]
                or ctx["last_retrieval"]
                or ctx["last_plan"]
            )

        if action_type == "governance_action" and "response" in str(action_name):
            return ctx["last_approval_request"]

        if action_type == "unknown":
            return ctx["last_meaningful"]

        return None

    # ------------------------------------------------------------------
    # Step 4: link input_refs
    # ------------------------------------------------------------------

    def _link_input_refs(
        self,
        events: list[dict[str, Any]],
        output_index: dict[str, dict[str, Any]],
    ) -> None:
        """Fill ``input_refs`` from typed_args keys, parent output, and heuristics."""
        latest_retrieval_output: str | None = None
        latest_tool_result_output: str | None = None
        latest_memory_output: str | None = None

        for event in events:
            refs = self._normalize_refs(event.get("input_refs"))

            # 1. typed_args reference keys.
            typed_args = event.get("typed_args") or {}
            if isinstance(typed_args, dict):
                for key in REF_ARG_KEYS:
                    value = typed_args.get(key)
                    if isinstance(value, str):
                        refs.append(value)
                    elif isinstance(value, list):
                        refs.extend(str(v) for v in value if isinstance(v, str))

            # 2. Parent event's output_ref (when the action should consume it).
            parent_id = event.get("parent_event")
            if parent_id:
                parent = output_index.get(str(parent_id))
                if parent and parent.get("output_ref"):
                    if self._should_consume_parent_output(event, parent):
                        refs.append(parent["output_ref"])

            # 3. Heuristic chain refs.
            action_type = event.get("action_type")
            effect_type = event.get("effect_type")
            action_name = event.get("action_name")

            if self._is_sink_action(event) and latest_retrieval_output:
                refs.append(latest_retrieval_output)

            if (
                action_type in {"agent_response", "final_response"}
                or action_name == "final_response"
            ):
                if latest_tool_result_output:
                    refs.append(latest_tool_result_output)
                elif latest_memory_output:
                    refs.append(latest_memory_output)
                elif latest_retrieval_output:
                    refs.append(latest_retrieval_output)

            refs = self._unique(refs)
            event["input_refs"] = refs if refs else None

            # Advance latest-output trackers *after* processing current event.
            if action_type == "retrieval" and event.get("output_ref"):
                latest_retrieval_output = event["output_ref"]

            if (
                action_type in {"tool_result", "tool_call"}
                and event.get("tool_output") is not None
                and event.get("output_ref")
            ):
                latest_tool_result_output = event["output_ref"]

            if (
                action_type == "memory_op"
                and effect_type == "write"
                and event.get("output_ref")
            ):
                latest_memory_output = event["output_ref"]

    def _is_sink_action(self, event: dict[str, Any]) -> bool:
        """Return True if the event *consumes* data (write, delete, send, ...)."""
        return event.get("effect_type") in {"write", "delete", "send", "execute", "connect"}

    def _should_consume_parent_output(
        self, event: dict[str, Any], parent: dict[str, Any]
    ) -> bool:
        """Return True when the event is expected to consume its parent's output."""
        if event.get("action_type") in {"tool_call", "memory_op", "agent_response"}:
            return True
        if event.get("effect_type") in {"write", "delete", "send", "execute", "connect"}:
            return True
        return False

    # ------------------------------------------------------------------
    # Step 5: link taint.causal_path
    # ------------------------------------------------------------------

    def _link_taint_causal_paths(
        self,
        events: list[dict[str, Any]],
        output_index: dict[str, dict[str, Any]],
    ) -> None:
        """Propagate taint objects and build ``taint.causal_path`` lists."""
        for event in events:
            event_id = event.get("event_id")
            refs = event.get("input_refs") or []

            # Resolve producer events (warn on unresolvable refs).
            producer_events: list[dict[str, Any]] = []
            for ref in refs:
                producer = output_index.get(str(ref))
                if producer:
                    producer_events.append(producer)
                else:
                    self._warn(event, f"unresolved_input_ref:{ref}")

            producer_taints = [
                p.get("taint")
                for p in producer_events
                if isinstance(p.get("taint"), dict)
            ]

            # Propagate taint from producers if the event itself has none.
            if not event.get("taint") and producer_taints:
                event["taint"] = self._merge_taints(producer_taints)

            # Build / update causal_path for any tainted event.
            taint = event.get("taint")
            if isinstance(taint, dict):
                path: list[str] = []

                for producer in producer_events:
                    producer_taint = producer.get("taint")
                    if isinstance(producer_taint, dict):
                        path.extend(producer_taint.get("causal_path") or [])
                    else:
                        pid = producer.get("event_id")
                        if pid:
                            path.append(str(pid))

                parent_id = event.get("parent_event")
                if parent_id:
                    path.append(str(parent_id))

                if event_id:
                    path.append(str(event_id))

                taint["causal_path"] = self._unique([p for p in path if p])

    # ------------------------------------------------------------------
    # Reference validation (warn only - do not remove refs)
    # ------------------------------------------------------------------

    def _warn_unresolved_refs(
        self, event: dict[str, Any], output_index: dict[str, dict[str, Any]]
    ) -> None:
        """Warn for every ``input_ref`` that cannot be resolved in *output_index*."""
        for ref in event.get("input_refs") or []:
            if str(ref) not in output_index:
                self._warn(event, f"unresolved_input_ref:{ref}")

    # ------------------------------------------------------------------
    # Taint merging
    # ------------------------------------------------------------------

    def _merge_taints(self, taints: list[dict[str, Any]]) -> dict[str, Any]:
        """Merge multiple taint objects into one, picking the highest-priority label."""
        labels = [t.get("label") for t in taints if isinstance(t, dict)]

        label = "unknown"
        for candidate in TAINT_PRIORITY:
            if candidate in labels:
                label = candidate
                break

        sources: list[str] = []
        reasons: list[str] = []
        for t in taints:
            if t.get("source"):
                sources.append(str(t["source"]))
            if t.get("reason"):
                reasons.append(str(t["reason"]))

        return {
            "label": label,
            "source": ",".join(self._unique(sources)) if sources else None,
            "reason": "propagated via input_refs",
            "sanitizer_status": None,
            "validator_status": None,
            "declassification_event": None,
            "causal_path": None,
        }

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_refs(raw: Any) -> list[str]:
        """Return a mutable list of string refs from *raw* (list or None)."""
        if isinstance(raw, list):
            return [str(r) for r in raw if r is not None]
        return []

    @staticmethod
    def _unique(items: list[str]) -> list[str]:
        """Return *items* with duplicates removed, preserving first-seen order."""
        seen: set[str] = set()
        result: list[str] = []
        for item in items:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result


# ===========================================================================
# Module-level convenience function
# ===========================================================================


def link_causal_trace(trace: dict[str, Any]) -> dict[str, Any]:
    """Convenience wrapper around :class:`CausalLinker`.

    Example::

        from src.c1.causal_linker import link_causal_trace

        linked_trace = link_causal_trace(trace)

    Args:
        trace: Normalized trace dict produced by the normalizer.

    Returns:
        Enriched trace dict with causal links filled in.
    """
    return CausalLinker().link_trace(trace)
