"""
c1.evidence_extractor
~~~~~~~~~~~~~~~~~~~~~
C1 Evidence Extractor: enrich normalized trace events with evidence slots.

Pipeline position::

    raw_trace (JSON)
        ──► TraceAdapter.parse()
        ──► Normalizer.normalize_raw_event()
        ──► CausalLinker.link_trace()
        ──► EvidenceExtractor.extract_trace()    ← this module
        ──► Validator.validate_trace()

**Responsibilities** (and *only* these):

- Extract / preserve ``approval`` slots from governance events.
- Propagate approval to matching sensitive actions (P001).
- Classify retrieval ``taint`` (trusted / untrusted / unknown).
- Propagate ``taint`` and ``provenance`` via ``input_refs`` (P002).
- Normalize ``status`` / ``error_type`` for failed tool calls (P003).
- Infer ``output_ref`` for retrieval / tool-result events.
- Pass-through ``policy``, ``decision``, ``pre_state``, ``post_state``.
- Fill ``reversibility`` heuristic when absent.
- Emit ``metadata.evidence_warnings`` for every ambiguity.

**Not in scope**: verdict engine (SAFE / VIOLATION / UNKNOWN), rule IR,
policy-violation detection, claim extraction from natural language,
full data-flow graphs, full symbolic state.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TRUSTED_HINTS: frozenset[str] = frozenset(
    {"internal", "trusted", "approved", "local", "company", "private_kb"}
)
UNTRUSTED_HINTS: frozenset[str] = frozenset(
    {"external", "web", "public", "internet", "http", "https", "url"}
)

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

APPROVAL_ACTION_NAMES: frozenset[str] = frozenset(
    {
        "ask_user_approval",
        "approve_send_email",
        "approval_response",
        "request_user_confirmation",
    }
)
APPROVAL_ACTION_TYPES: frozenset[str] = frozenset(
    {"governance_action", "policy_decision"}
)

APPROVAL_REQUEST_EVENT_TYPES: frozenset[str] = frozenset({"approval_request"})
APPROVAL_RESPONSE_EVENT_TYPES: frozenset[str] = frozenset({"approval_response"})

SENSITIVE_EFFECT_TYPES: frozenset[str] = frozenset(
    {"send", "delete", "write", "execute", "connect"}
)

APPROVAL_KEYS = {
    "exists",
    "status",
    "target",
    "approved_by",
    "approval_event",
}

_ERROR_KEYWORD_MAP: list[tuple[str, str]] = [
    ("permission denied", "permission_denied"),
    ("permission_denied", "permission_denied"),
    ("timeout", "timeout"),
    ("timed out", "timeout"),
    ("policy violation", "policy_violation"),
    ("policy_violation", "policy_violation"),
    ("sandbox", "sandbox_violation"),
    ("taint", "taint_violation"),
]

PROVENANCE_ARG_KEYS: tuple[str, ...] = (
    "source",
    "source_id",
    "doc_id",
    "url",
    "host",
)
PROVENANCE_OUTPUT_KEYS: tuple[str, ...] = (
    "source",
    "source_id",
    "doc_id",
    "result_id",
    "tool_result_id",
)

FINAL_RESPONSE_TYPES: frozenset[str] = frozenset(
    {"agent_response", "final_response"}
)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    if isinstance(value, str) and value:
        return [value]
    return []


def _lower_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).lower()


def _infer_target_binding(event: dict[str, Any]) -> dict[str, Any] | None:
    args = event.get("typed_args") or {}
    target: dict[str, Any] = {}
    for key in (
        "recipient",
        "email",
        "path",
        "url",
        "host",
        "resource",
        "target",
        "memory_key",
        "calendar_id",
    ):
        if args.get(key) is not None:
            target[key] = args[key]
    if event.get("target_resource"):
        target["target_resource"] = event["target_resource"]
    if event.get("action_name"):
        target["action_name"] = event["action_name"]
    return target if target else None


def _approval_target_key(target: Any) -> str:
    """Derive a stable key for approval matching.

    Intentionally excludes ``action_name`` so that a governance-action event
    (action_name="ask_user_approval") can match a sink event
    (action_name="send_email") when they share the same recipient /
    target_resource.  The meaningful dimensions are the *resource address*,
    not the name of the governance or sink action.
    """
    if not isinstance(target, dict):
        return "unknown"
    recipient = target.get("recipient") or target.get("email")
    path = target.get("path")
    host = target.get("host") or target.get("url")
    target_resource = target.get("target_resource")
    return "|".join(
        str(x)
        for x in [
            target_resource or "",
            recipient or "",
            path or "",
            host or "",
        ]
    )


# ===========================================================================
# EvidenceExtractor
# ===========================================================================


class EvidenceExtractor:
    """Enrich a normalized trace with evidence slots.

    Usage::

        extractor = EvidenceExtractor()
        enriched_trace = extractor.extract_trace(trace)

    The input *trace* is never mutated; a deep-copy is returned.
    """

    def extract_trace(self, trace: dict[str, Any]) -> dict[str, Any]:
        """Return an enriched copy of *trace* with evidence slots filled in."""
        enriched: dict[str, Any] = deepcopy(trace)
        events: list[dict[str, Any]] = enriched.get("events", [])

        events.sort(
            key=lambda e: (
                e.get("step_id") if e.get("step_id") is not None else 10**9
            )
        )

        self._ensure_metadata(events)

        # Pass 1 — local evidence extraction.
        for event in events:
            self._extract_local_evidence(event)

        # Build approval index after local extraction.
        approval_index = self._build_approval_index(events)

        # Rebuild output index after output_refs may have been generated.
        output_index = self._build_output_index(events)

        # Pass 2 — cross-event propagation and finalization.
        for event in events:
            self._propagate_input_evidence(event, output_index)
            self._attach_matching_approval(event, approval_index)
            self._finalize_event_defaults(event)

        return enriched

    def extract_event(
        self,
        event: dict[str, Any],
        *,
        events: list[dict[str, Any]],
        output_index: dict[str, dict[str, Any]],
        approval_index: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        """Enrich a single event in context of the full trace."""
        e = deepcopy(event)
        self._extract_local_evidence(e)
        self._propagate_input_evidence(e, output_index)
        self._attach_matching_approval(e, approval_index)
        self._finalize_event_defaults(e)
        return e

    # ------------------------------------------------------------------
    # metadata / warnings
    # ------------------------------------------------------------------

    def _ensure_metadata(self, events: list[dict[str, Any]]) -> None:
        for event in events:
            if not isinstance(event.get("metadata"), dict):
                event["metadata"] = {}

    def _warn(self, event: dict[str, Any], message: str) -> None:
        metadata = event.setdefault("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
            event["metadata"] = metadata
        metadata.setdefault("evidence_warnings", []).append(message)

    # ------------------------------------------------------------------
    # Output index
    # ------------------------------------------------------------------

    def _build_output_index(
        self, events: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
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
                for key in ("doc_id", "result_id", "tool_result_id", "id"):
                    value = tool_output.get(key)
                    if value:
                        index[str(value)] = event
        return index

    # ------------------------------------------------------------------
    # Pass 1 — local evidence extraction
    # ------------------------------------------------------------------

    def _extract_local_evidence(self, event: dict[str, Any]) -> None:
        self._extract_tool_output_and_output_ref(event)
        self._extract_status_error(event)
        self._extract_approval_slot(event)
        self._extract_retrieval_taint_and_provenance(event)
        self._extract_provenance_from_event(event)
        self._extract_policy_slot(event)
        self._extract_decision_slot(event)
        self._extract_state_slots(event)
        self._extract_reversibility(event)

    # 1a. tool_output / output_ref

    def _extract_tool_output_and_output_ref(self, event: dict[str, Any]) -> None:
        if event.get("output_ref"):
            return
        event_id = event.get("event_id")
        if not event_id:
            return
        action_type = event.get("action_type")
        effect_type = event.get("effect_type")
        action_name = event.get("action_name")
        tool_output = event.get("tool_output")
        typed_args = event.get("typed_args") or {}

        if isinstance(tool_output, dict):
            for key in ("doc_id", "result_id", "tool_result_id", "id"):
                value = tool_output.get(key)
                if value:
                    event["output_ref"] = str(value)
                    return

        if action_type == "retrieval" or effect_type == "retrieve":
            event["output_ref"] = f"retrieval_{event_id}"
            return
        if action_type == "tool_result":
            event["output_ref"] = f"tool_result_{event_id}"
            return
        if action_type == "tool_call" and tool_output is not None:
            event["output_ref"] = f"tool_result_{event_id}"
            return
        if action_type == "memory_op" and effect_type == "write":
            memory_key = typed_args.get("memory_key") or typed_args.get("key")
            if memory_key:
                event["output_ref"] = str(memory_key)
            else:
                event["output_ref"] = f"memory_{event_id}"
            return
        if action_type in FINAL_RESPONSE_TYPES or action_name == "final_response":
            event["output_ref"] = f"final_answer_{event_id}"
            return
        if action_type == "governance_action" and effect_type == "approve":
            event["output_ref"] = f"approval_{event_id}"
            return

    # 1b. status / error_type

    def _extract_status_error(self, event: dict[str, Any]) -> None:
        tool_output = event.get("tool_output")
        if not isinstance(tool_output, dict):
            return
        ok_flag = tool_output.get("ok")
        success_flag = tool_output.get("success")
        is_failed = ok_flag is False or success_flag is False
        if is_failed and event.get("status") != "failed":
            event["status"] = "failed"
        error_str = tool_output.get("error")
        if error_str and not event.get("error_type"):
            event["error_type"] = self._map_error_string(str(error_str))

    def _map_error_string(self, error_str: str) -> str:
        lower = error_str.lower()
        for keyword, mapped in _ERROR_KEYWORD_MAP:
            if keyword in lower:
                return mapped
        return "tool_failure"

    # 1c. approval slot

    def _extract_approval_slot(self, event: dict[str, Any]) -> None:
        if event.get("approval") is not None:
            self._enrich_existing_approval(event)
            return
        if not self._is_approval_event(event):
            return

        raw_event_type = (event.get("metadata") or {}).get("raw_event_type", "")
        is_request = (
            raw_event_type in APPROVAL_REQUEST_EVENT_TYPES
            or event.get("action_name") in {
                "ask_user_approval",
                "request_user_confirmation",
            }
        )
        is_response = (
            raw_event_type in APPROVAL_RESPONSE_EVENT_TYPES
            or event.get("action_name") in {
                "approve_send_email",
                "approval_response",
            }
        )

        tool_output = event.get("tool_output") or {}
        if not isinstance(tool_output, dict):
            tool_output = {}
        has_approved = (
            tool_output.get("approved") is True
            or tool_output.get("status") == "approved"
        )
        has_rejected = (
            tool_output.get("approved") is False
            or tool_output.get("status") == "rejected"
        )

        target = _infer_target_binding(event)

        if is_response or has_approved or has_rejected:
            if has_rejected:
                status = "rejected"
            elif has_approved:
                status = "approved"
            else:
                status = "unknown"
            approved_by = (
                tool_output.get("approved_by")
                or (event.get("typed_args") or {}).get("approved_by")
            )
            if approved_by is None and has_approved:
                approved_by = "user"
            event["approval"] = {
                "exists": True,
                "status": status,
                "target": target,
                "approved_by": approved_by,
                "approval_event": event.get("event_id"),
            }
        elif is_request:
            event["approval"] = {
                "exists": True,
                "status": "unknown",
                "target": target,
                "approved_by": None,
                "approval_event": event.get("event_id"),
            }
        else:
            # Generic governance action — check tool_output for approval signal.
            if has_approved or has_rejected:
                status = "rejected" if has_rejected else "approved"
                approved_by = tool_output.get("approved_by")
                if approved_by is None and has_approved:
                    approved_by = "user"
                event["approval"] = {
                    "exists": True,
                    "status": status,
                    "target": target,
                    "approved_by": approved_by,
                    "approval_event": event.get("event_id"),
                }

    def _enrich_existing_approval(self, event: dict[str, Any]) -> None:
        approval = event["approval"]
        if not isinstance(approval, dict):
            return
        if "exists" not in approval:
            approval["exists"] = True
        if "approval_event" not in approval:
            approval["approval_event"] = event.get("event_id")
        if "target" not in approval:
            approval["target"] = _infer_target_binding(event)
        if not approval.get("approved_by") and approval.get("status") == "approved":
            tool_output = event.get("tool_output") or {}
            if isinstance(tool_output, dict):
                ab = tool_output.get("approved_by")
                if ab:
                    approval["approved_by"] = ab
                else:
                    approval["approved_by"] = "user"

    def _is_approval_event(self, event: dict[str, Any]) -> bool:
        if event.get("action_type") in APPROVAL_ACTION_TYPES:
            return True
        if event.get("action_name") in APPROVAL_ACTION_NAMES:
            return True
        raw_event_type = (event.get("metadata") or {}).get("raw_event_type", "")
        if raw_event_type in (APPROVAL_REQUEST_EVENT_TYPES | APPROVAL_RESPONSE_EVENT_TYPES):
            return True
        return False

    # 1d. retrieval taint + provenance

    def _extract_retrieval_taint_and_provenance(self, event: dict[str, Any]) -> None:
        if not self._is_retrieval_event(event):
            return
        if event.get("taint") is not None:
            return

        source_hints = self._collect_source_hints(event)
        label = self._classify_trust(source_hints)

        if label is None:
            self._warn(event, "unknown_retrieval_trust_source")
            label = "unknown"

        source_str = self._best_source_string(event)
        event_id = event.get("event_id")
        event["taint"] = {
            "label": label,
            "source": source_str,
            "reason": self._taint_reason(label),
            "sanitizer_status": None,
            "validator_status": None,
            "declassification_event": None,
            "causal_path": [str(event_id)] if event_id else [],
        }

    def _is_retrieval_event(self, event: dict[str, Any]) -> bool:
        return (
            event.get("action_type") == "retrieval"
            or event.get("effect_type") == "retrieve"
        )

    def _collect_source_hints(self, event: dict[str, Any]) -> list[str]:
        hints: list[str] = []
        typed_args = event.get("typed_args") or {}
        tool_output = event.get("tool_output")
        if not isinstance(tool_output, dict):
            tool_output = {}
        meta = event.get("metadata") or {}

        for key in ("source", "source_type", "url", "host"):
            v = typed_args.get(key)
            if v:
                hints.append(str(v))
        for key in ("source", "doc_id"):
            v = tool_output.get(key)
            if v:
                hints.append(str(v))
        for key in ("source",):
            v = meta.get(key)
            if v:
                hints.append(str(v))
        provenance = event.get("provenance")
        if isinstance(provenance, str) and provenance:
            hints.append(provenance)
        elif isinstance(provenance, list):
            hints.extend(str(p) for p in provenance if p)
        return hints

    def _classify_trust(self, hints: list[str]) -> str | None:
        combined = " ".join(_lower_str(h) for h in hints)
        if not combined.strip():
            return None
        untrusted_score = sum(1 for kw in UNTRUSTED_HINTS if kw in combined)
        trusted_score = sum(1 for kw in TRUSTED_HINTS if kw in combined)
        if untrusted_score > 0:
            return "untrusted"
        if trusted_score > 0:
            return "trusted"
        return None

    def _best_source_string(self, event: dict[str, Any]) -> str | None:
        typed_args = event.get("typed_args") or {}
        for key in ("url", "host", "source", "source_type"):
            v = typed_args.get(key)
            if v:
                return str(v)
        tool_output = event.get("tool_output")
        if isinstance(tool_output, dict):
            for key in ("source", "doc_id"):
                v = tool_output.get(key)
                if v:
                    return str(v)
        return None

    def _taint_reason(self, label: str) -> str:
        if label == "trusted":
            return "internal/trusted retrieval source"
        if label == "untrusted":
            return "external/public retrieval source"
        return "retrieval source trust could not be determined"

    # 1e. provenance

    def _extract_provenance_from_event(self, event: dict[str, Any]) -> None:
        if event.get("provenance") is not None:
            return
        refs: list[str] = []
        if event.get("output_ref"):
            refs.append(event["output_ref"])
        args = event.get("typed_args") or {}
        for key in PROVENANCE_ARG_KEYS:
            v = args.get(key)
            if v:
                refs.append(str(v))
        output = event.get("tool_output")
        if isinstance(output, dict):
            for key in PROVENANCE_OUTPUT_KEYS:
                v = output.get(key)
                if v:
                    refs.append(str(v))
        if refs:
            event["provenance"] = _unique(refs)

    # 1f. policy slot

    def _extract_policy_slot(self, event: dict[str, Any]) -> None:
        if event.get("policy") is not None:
            return
        tool_output = event.get("tool_output")
        for container in (
            event.get("metadata"),
            event.get("typed_args"),
            tool_output if isinstance(tool_output, dict) else None,
        ):
            if not isinstance(container, dict):
                continue
            policy = container.get("policy")
            if policy is not None:
                if isinstance(policy, dict):
                    event["policy"] = policy
                else:
                    self._warn(event, "policy_shape_invalid")
                return

    # 1g. decision slot

    def _extract_decision_slot(self, event: dict[str, Any]) -> None:
        if event.get("decision") is not None:
            return
        if event.get("action_type") not in APPROVAL_ACTION_TYPES:
            return
        tool_output = event.get("tool_output")
        for container in (
            tool_output if isinstance(tool_output, dict) else None,
            event.get("typed_args"),
        ):
            if not isinstance(container, dict):
                continue
            candidate: dict[str, Any] = {}
            for key in ("verdict", "route", "reason", "missing_evidence"):
                v = container.get(key)
                if v is not None:
                    candidate[key] = v
            if candidate:
                event["decision"] = candidate
                return

    # 1h. state slots

    def _extract_state_slots(self, event: dict[str, Any]) -> None:
        typed_args = event.get("typed_args") or {}
        tool_output = event.get("tool_output")
        meta = event.get("metadata") or {}
        for slot in ("pre_state", "post_state"):
            if event.get(slot) is not None:
                continue
            for container in (
                typed_args,
                tool_output if isinstance(tool_output, dict) else {},
                meta,
            ):
                if not isinstance(container, dict):
                    continue
                v = container.get(slot)
                if v is not None:
                    event[slot] = v
                    break

    # 1i. reversibility

    def _extract_reversibility(self, event: dict[str, Any]) -> None:
        existing = event.get("reversibility")
        if existing and existing != "unknown":
            return

        effect_type = event.get("effect_type") or ""
        action_name = event.get("action_name") or ""
        action_type = event.get("action_type") or ""
        status = event.get("status") or ""

        if effect_type == "send" or action_name in ("send_email", "send_message"):
            event["reversibility"] = "hard"
            return
        if effect_type == "delete" or action_name == "delete_file":
            event["reversibility"] = "irreversible"
            return
        if effect_type == "execute" or action_name in ("execute_code", "execute_command"):
            event["reversibility"] = "hard"
            return
        if effect_type == "write" or action_type == "memory_op":
            event["reversibility"] = "compensatable"
            return
        if effect_type in ("retrieve", "read", "query") or action_type == "retrieval":
            event["reversibility"] = "retryable" if status == "failed" else "reversible"
            return
        if effect_type == "connect":
            event["reversibility"] = "retryable" if status == "failed" else "compensatable"
            return

    # ------------------------------------------------------------------
    # Approval index
    # ------------------------------------------------------------------

    def _build_approval_index(
        self, events: list[dict[str, Any]]
    ) -> dict[str, list[dict[str, Any]]]:
        index: dict[str, list[dict[str, Any]]] = {}
        for event in events:
            approval = event.get("approval")
            if not isinstance(approval, dict):
                continue
            if approval.get("status") != "approved":
                continue
            target_key = _approval_target_key(approval.get("target"))
            index.setdefault(target_key, []).append(event)
        return index

    # ------------------------------------------------------------------
    # Pass 2a — propagate taint / provenance via input_refs
    # ------------------------------------------------------------------

    def _propagate_input_evidence(
        self,
        event: dict[str, Any],
        output_index: dict[str, dict[str, Any]],
    ) -> None:
        input_refs = event.get("input_refs") or []
        if not input_refs:
            action_type = event.get("action_type") or ""
            action_name = event.get("action_name") or ""
            if action_type in FINAL_RESPONSE_TYPES or action_name == "final_response":
                parent = event.get("parent_event")
                if parent:
                    parent_event = output_index.get(str(parent))
                    if parent_event and parent_event.get("provenance"):
                        if not event.get("provenance"):
                            event["provenance"] = _as_list(parent_event["provenance"])
                else:
                    self._warn(event, "final_response_missing_causal_link")
            return

        producer_events: list[dict[str, Any]] = []
        for ref in input_refs:
            producer = output_index.get(str(ref))
            if producer:
                producer_events.append(producer)

        if not producer_events:
            return

        # Provenance propagation.
        if not event.get("provenance"):
            merged: list[str] = []
            for producer in producer_events:
                merged.extend(_as_list(producer.get("provenance")))
                if producer.get("output_ref"):
                    merged.append(producer["output_ref"])
            if merged:
                event["provenance"] = _unique(merged)

        # Taint propagation.
        producer_taints = [
            p.get("taint")
            for p in producer_events
            if isinstance(p.get("taint"), dict)
        ]

        if producer_taints and not event.get("taint"):
            event["taint"] = self._merge_taints(
                producer_taints, current_event_id=event.get("event_id")
            )
        elif producer_taints and isinstance(event.get("taint"), dict):
            self._extend_causal_path(event, producer_taints)

    def _merge_taints(
        self,
        taints: list[dict[str, Any]],
        current_event_id: str | None = None,
    ) -> dict[str, Any]:
        labels = [t.get("label") for t in taints if isinstance(t, dict)]
        label = "unknown"
        for candidate in TAINT_PRIORITY:
            if candidate in labels:
                label = candidate
                break

        sources: list[str] = []
        for t in taints:
            if t.get("source"):
                sources.append(str(t["source"]))

        causal_path: list[str] = []
        for t in taints:
            causal_path.extend(t.get("causal_path") or [])
        if current_event_id:
            causal_path.append(str(current_event_id))

        return {
            "label": label,
            "source": ",".join(_unique(sources)) if sources else None,
            "reason": "propagated via input_refs",
            "sanitizer_status": None,
            "validator_status": None,
            "declassification_event": None,
            "causal_path": _unique([p for p in causal_path if p]),
        }

    def _extend_causal_path(
        self,
        event: dict[str, Any],
        producer_taints: list[dict[str, Any]],
    ) -> None:
        taint = event.get("taint")
        if not isinstance(taint, dict):
            return
        path: list[str] = list(taint.get("causal_path") or [])
        for pt in producer_taints:
            path.extend(pt.get("causal_path") or [])
        event_id = event.get("event_id")
        if event_id:
            path.append(str(event_id))
        taint["causal_path"] = _unique([p for p in path if p])

    # ------------------------------------------------------------------
    # Pass 2b — attach matching approval
    # ------------------------------------------------------------------

    def _attach_matching_approval(
        self,
        event: dict[str, Any],
        approval_index: dict[str, list[dict[str, Any]]],
    ) -> None:
        if event.get("approval"):
            return
        if not self._is_sensitive_action(event):
            return
        target = _infer_target_binding(event)
        key = _approval_target_key(target)
        candidates = approval_index.get(key, [])
        previous = [
            app_event
            for app_event in candidates
            if (app_event.get("step_id") or 0) < (event.get("step_id") or 0)
        ]
        if not previous:
            return
        approval_event = previous[-1]
        approval = deepcopy(approval_event["approval"])
        approval["approval_event"] = approval_event.get("event_id")
        event["approval"] = approval

    def _is_sensitive_action(self, event: dict[str, Any]) -> bool:
        return event.get("effect_type") in SENSITIVE_EFFECT_TYPES

    # ------------------------------------------------------------------
    # Pass 2c — finalize defaults / warnings
    # ------------------------------------------------------------------

    def _finalize_event_defaults(self, event: dict[str, Any]) -> None:
        # Add evidence_extractor version stamp.
        metadata = event.setdefault("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
            event["metadata"] = metadata
        metadata.setdefault("evidence_extractor", "v0.1")

        # Warn on missing provenance for unresolved input_refs.
        input_refs = event.get("input_refs") or []
        if input_refs and not event.get("provenance"):
            for ref in input_refs:
                self._warn(event, f"missing_provenance_for_input_ref:{ref}")

        self._sanitize_approval_slot(event)
        self._sanitize_decision_slot(event)

    def _sanitize_approval_slot(self, event: dict[str, Any]) -> None:
        approval = event.get("approval")

        if approval is None:
            event["approval"] = None
            return

        metadata = event.setdefault("metadata", {})

        if not isinstance(approval, dict):
            metadata["raw_approval"] = approval
            metadata.setdefault("evidence_warnings", []).append("invalid_approval_shape")
            event["approval"] = None
            return

        extra = {k: v for k, v in approval.items() if k not in APPROVAL_KEYS}
        if extra:
            metadata["raw_approval_extra"] = extra

        event["approval"] = {
            "exists": approval.get("exists"),
            "status": approval.get("status"),
            "target": approval.get("target"),
            "approved_by": approval.get("approved_by"),
            "approval_event": approval.get("approval_event"),
        }

    def _sanitize_decision_slot(self, event: dict[str, Any]) -> None:
        decision = event.get("decision")

        if decision is None:
            event["decision"] = None
            return

        metadata = event.setdefault("metadata", {})

        if not isinstance(decision, dict):
            metadata["raw_decision"] = decision
            metadata.setdefault("evidence_warnings", []).append("invalid_decision_shape")
            event["decision"] = None
            return

        # Không có verdict/route thì chưa phải decision hợp lệ theo schema.
        if "verdict" not in decision and "route" not in decision:
            metadata["raw_decision"] = decision
            event["decision"] = None
            return

        event["decision"] = {
            "verdict": decision.get("verdict"),
            "route": decision.get("route"),
            "reason": decision.get("reason"),
            "missing_evidence": decision.get("missing_evidence") or [],
        }


# ===========================================================================
# Module-level convenience function
# ===========================================================================


def extract_evidence(trace: dict[str, Any]) -> dict[str, Any]:
    """Convenience wrapper around :class:`EvidenceExtractor`.

    Example::

        from src.c1.evidence_extractor import extract_evidence

        enriched_trace = extract_evidence(trace)

    Args:
        trace: Normalized trace dict produced by :mod:`c1.causal_linker`.

    Returns:
        Enriched trace dict with evidence slots filled in.
    """
    return EvidenceExtractor().extract_trace(trace)
