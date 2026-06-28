"""
c1.normalizer
~~~~~~~~~~~~~
C1 Normalizer: vocabulary loader + raw-event-to-normalized-event conversion.

Pipeline position::

    raw_trace (JSON)
        ──► TraceAdapter.parse()           list[intermediate raw-event dict]
        ──► Normalizer.normalize_raw_event()   normalized_event dict  (v0.1)

**Vocabulary** is loaded once from ``vocabulary.yaml`` and drives all
canonical lookups.  Every mapping is case-sensitive and aliased through
``action_name_aliases`` so framework-specific raw names (``gmail_send``,
``mcp.gmail.send``, …) resolve to a single canonical action name
(``send_email``).

**Normalization contract** (mirrors RAW-C1-01..05):

- Preserve raw values in ``metadata`` — never silently discard them.
- Unknown / unmappable values → ``"unknown"`` (enum) or ``None`` (nullable).
- Missing evidence is not mapped to SAFE; C2 must receive ``None`` / ``"unknown"``.
- Every required core field in ``normalized_event_schema v0.1`` is always
  present in the output dict (possibly as ``None`` or ``"unknown"``).
"""

from __future__ import annotations

import uuid
import warnings
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    raise ImportError(
        "PyYAML is required for c1.normalizer.  Install it with:  pip install pyyaml"
    )


# ---------------------------------------------------------------------------
# Vocabulary path — resolved lazily with multiple candidate locations
# ---------------------------------------------------------------------------

def _resolve_default_vocab_path() -> Path:
    """Search common project locations for vocabulary.yaml.

    Tries (in order):
    1. ``<repo_root>/vocabulary.yaml``
    2. ``<repo_root>/phase_2/outputs/vocabulary.yaml``
    3. ``<repo_root>/outputs/vocabulary.yaml``
    4. ``<repo_root>/config/vocabulary.yaml``

    Returns:
        First existing path.

    Raises:
        FileNotFoundError: If none of the candidates exist.
    """
    repo_root = Path(__file__).resolve().parents[2]
    candidates = [
        repo_root / "vocabulary.yaml",
        repo_root / "phase_2" / "outputs" / "vocabulary.yaml",
        repo_root / "outputs" / "vocabulary.yaml",
        repo_root / "config" / "vocabulary.yaml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "Cannot find vocabulary.yaml.  Tried:\n"
        + "\n".join(f"  {p}" for p in candidates)
    )

# ---------------------------------------------------------------------------
# event_type → (phase, action_type)  mapping  (spec §mapping rule)
# ---------------------------------------------------------------------------
_EVENT_TYPE_MAP: dict[str, tuple[str, str]] = {
    # ── original set ────────────────────────────────────────────────────
    "user_message":      ("plan",          "message"),
    "planner_step":      ("plan",          "message"),
    "retrieval":         ("after_action",  "retrieval"),
    "tool_call":         ("before_action", "tool_call"),
    "tool_result":       ("after_action",  "tool_result"),
    "approval_request":  ("before_action", "governance_action"),
    "approval_response": ("after_action",  "governance_action"),
    "memory_op":         ("before_action", "memory_op"),
    "final_response":    ("finish",        "agent_response"),
    "error":             ("after_action",  "unknown"),
    # ── extended set ────────────────────────────────────────────────────
    "memory_read":         ("before_action", "memory_op"),
    "memory_write":        ("before_action", "memory_op"),
    "external_api_call":   ("before_action", "external_api_call"),
    "resource_access":     ("before_action", "resource_access"),
    "policy_update":       ("state_change",  "policy_decision"),
    "state_change":        ("state_change",  "environment_update"),
    "environment_update":  ("state_change",  "environment_update"),
}

# ---------------------------------------------------------------------------
# status values understood by the raw adapter layer → normalized schema status
# ---------------------------------------------------------------------------
_STATUS_PASSTHROUGH: frozenset[str] = frozenset(
    {
        "pending", "success", "failed", "blocked",
        "aborted", "rejected", "allowed", "rewritten", "unknown",
    }
)

# Raw adapter status aliases not in the schema
_STATUS_ALIAS: dict[str, str] = {}  # extend if needed


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _normalize_step_id(raw_value: Any, meta: dict[str, Any]) -> int:
    """Coerce ``step_id`` to a non-negative integer.

    Args:
        raw_value: The raw ``step_id`` value (may be ``None``, string, or int).
        meta:      Running metadata dict; warnings are appended here.

    Returns:
        Integer step id; ``0`` when the value is missing or unconvertible.
    """
    try:
        if raw_value is None:
            meta.setdefault("normalization_warnings", []).append("missing_step_id")
            return 0
        return int(raw_value)
    except (TypeError, ValueError):
        meta.setdefault("normalization_warnings", []).append(
            f"invalid_step_id:{raw_value!r}"
        )
        return 0


# ===========================================================================
# Vocabulary
# ===========================================================================


class Vocabulary:
    """Loaded vocabulary from ``vocabulary.yaml``.

    All lookup methods return canonical string values or ``"unknown"`` /
    ``None`` — they never raise on unknown inputs.

    Args:
        path: Explicit path to the YAML file.  Defaults to
              ``phase_2/outputs/vocabulary.yaml`` relative to the repo root.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        vocab_path = Path(path) if path else _resolve_default_vocab_path()
        with vocab_path.open(encoding="utf-8") as fh:
            raw: dict = yaml.safe_load(fh)

        # ── enum allow-lists ────────────────────────────────────────────
        self.phases:            frozenset[str] = frozenset(raw.get("phase", []))
        self.action_types:      frozenset[str] = frozenset(raw.get("action_type", []))
        self.effect_types:      frozenset[str] = frozenset(raw.get("effect_type", []))
        self.target_resources:  frozenset[str] = frozenset(raw.get("target_resource", []))
        self.statuses:          frozenset[str] = frozenset(raw.get("status", []))
        self.error_types:       frozenset[str] = frozenset(raw.get("error_type", []))
        self.taint_labels:      frozenset[str] = frozenset(raw.get("taint_label", []))
        self.approval_statuses: frozenset[str] = frozenset(raw.get("approval_status", []))
        self.reversibilities:   frozenset[str] = frozenset(raw.get("reversibility", []))
        self.decision_verdicts: frozenset[str] = frozenset(raw.get("decision_verdict", []))
        self.decision_routes:   frozenset[str] = frozenset(raw.get("decision_route", []))

        # ── canonical aliases (action_type / reversibility normalization) ──
        self.canonical_aliases: dict[str, str] = raw.get("canonical_aliases", {})

        # ── mapping tables ──────────────────────────────────────────────
        self.effect_mapping:      dict[str, str] = raw.get("effect_mapping", {})
        self.target_mapping:      dict[str, str] = raw.get("target_mapping", {})
        self.action_type_mapping: dict[str, str] = raw.get("action_type_mapping", {})

        # ── reverse alias index: raw_alias → canonical_action_name ─────
        #   Built from action_name_aliases:
        #     send_email: [sendEmail, gmail_send, …]
        self._alias_index: dict[str, str] = {}
        for canonical, aliases in raw.get("action_name_aliases", {}).items():
            for alias in (aliases or []):
                self._alias_index[alias] = canonical
            # canonical name maps to itself
            self._alias_index[canonical] = canonical

    # ------------------------------------------------------------------
    # Core lookup methods
    # ------------------------------------------------------------------

    def normalize_action_name(self, raw_action_name: str | None) -> str:
        """Map a raw action/tool name to a canonical action name.

        Resolution order:
        1. Direct alias lookup (``action_name_aliases``).
        2. Return ``"unknown"`` and warn if not found.

        Args:
            raw_action_name: The raw ``tool_name`` or ``action`` field value.

        Returns:
            Canonical action name (e.g. ``"send_email"``) or ``"unknown"``.
        """
        if not raw_action_name:
            return "unknown"
        canonical = self._alias_index.get(raw_action_name)
        if canonical:
            return canonical
        warnings.warn(
            f"[Vocabulary] Unknown raw action name: {raw_action_name!r}",
            stacklevel=3,
        )
        return "unknown"

    def derive_action_type(self, canonical_action_name: str) -> str:
        """Derive the normalized ``action_type`` from a canonical action name.

        Args:
            canonical_action_name: Result of :meth:`normalize_action_name`.

        Returns:
            Canonical ``action_type`` string or ``"unknown"``.
        """
        raw = self.action_type_mapping.get(canonical_action_name, "unknown")
        # Apply canonical aliases (e.g. "approval" → "governance_action")
        return self.canonical_aliases.get(raw, raw)

    def derive_effect_type(self, canonical_action_name: str) -> str | None:
        """Derive the normalized ``effect_type`` from a canonical action name.

        Args:
            canonical_action_name: Result of :meth:`normalize_action_name`.

        Returns:
            Canonical ``effect_type`` string or ``None`` when unmappable.
        """
        return self.effect_mapping.get(canonical_action_name)

    def derive_target_resource(self, canonical_action_name: str) -> str | None:
        """Derive the normalized ``target_resource`` from a canonical action name.

        Args:
            canonical_action_name: Result of :meth:`normalize_action_name`.

        Returns:
            Canonical ``target_resource`` string or ``None`` when unmappable.
        """
        raw = self.target_mapping.get(canonical_action_name)
        if raw is None:
            return None
        # Apply canonical aliases (e.g. "policy" → "agent_context")
        return self.canonical_aliases.get(raw, raw)

    def normalize_status(self, raw_status: str | None) -> str:
        """Return the normalized status, falling back to ``"unknown"``.

        Args:
            raw_status: Raw status string from the intermediate event.

        Returns:
            Validated status string or ``"unknown"``.
        """
        if not raw_status:
            return "unknown"
        if raw_status in self.statuses:
            return raw_status
        # Try alias (adapter layer uses a slightly smaller set)
        mapped = _STATUS_ALIAS.get(raw_status)
        if mapped and mapped in self.statuses:
            return mapped
        return "unknown"

    def normalize_error_type(self, raw_error: Any) -> str | None:
        """Extract and normalize an ``error_type`` from a raw error payload.

        Handles three forms seen in the dataset:
        - ``None``               → ``None``
        - ``{"error_type": …}``  → validate the value
        - ``{"type": …}``        → validate the value
        - plain string           → validate as-is

        Args:
            raw_error: The ``error`` field value from the intermediate event.

        Returns:
            Validated ``error_type`` string or ``None``.
        """
        if raw_error is None:
            return None
        if isinstance(raw_error, dict):
            candidate = raw_error.get("error_type") or raw_error.get("type")
        elif isinstance(raw_error, str):
            candidate = raw_error
        else:
            return None
        if candidate and candidate in self.error_types:
            return candidate
        return "unknown" if candidate else None

    def normalize_reversibility(self, canonical_action_name: str) -> str | None:
        """Infer reversibility from the canonical action name / effect.

        Heuristic (can be overridden by the normalizer layer):
        - ``delete_file``, ``send_email``, ``send_message``  → ``"hard"``
        - ``read_*``, ``retrieve_*``, ``query_*``            → ``"reversible"``
        - ``write_*``, ``execute_*``, ``call_api``           → ``"compensatable"``
        - everything else                                    → ``None``

        Args:
            canonical_action_name: Result of :meth:`normalize_action_name`.

        Returns:
            Reversibility string or ``None``.
        """
        _HARD = {"delete_file", "send_email", "send_message"}
        _REVERSIBLE = {"read_memory", "read_file", "read_calendar",
                       "retrieve_document", "query_database"}
        _COMPENSATABLE = {"write_memory", "write_file", "write_calendar",
                          "execute_code", "call_api", "update_policy"}

        if canonical_action_name in _HARD:
            return "hard"
        if canonical_action_name in _REVERSIBLE:
            return "reversible"
        if canonical_action_name in _COMPENSATABLE:
            return "compensatable"
        return None


# ===========================================================================
# Module-level singleton (lazy-loaded)
# ===========================================================================

_default_vocab: Vocabulary | None = None


def get_default_vocabulary(path: Path | str | None = None) -> Vocabulary:
    """Return the module-level singleton :class:`Vocabulary`.

    The YAML file is parsed exactly once and cached.

    Args:
        path: Override the vocabulary file path (for testing).

    Returns:
        Singleton :class:`Vocabulary` instance.
    """
    global _default_vocab
    if _default_vocab is None or path is not None:
        _default_vocab = Vocabulary(path)
    return _default_vocab


# ===========================================================================
# Normalizer
# ===========================================================================


class Normalizer:
    """Converts intermediate raw-event dicts into normalized event dicts.

    A normalized event conforms (structurally) to the
    ``normalized_event_schema v0.1`` defined in
    ``phase_2/outputs/normalized_event_schema.json``.

    Args:
        vocabulary: Pre-loaded :class:`Vocabulary`.  If ``None``, the
                    module-level default is used.
    """

    def __init__(self, vocabulary: Vocabulary | None = None) -> None:
        self.vocab: Vocabulary = vocabulary or get_default_vocabulary()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def normalize_raw_event(self, raw_event: dict, trace_id: str) -> dict:
        """Convert one intermediate raw-event dict to a normalized event dict.

        The function never raises on missing or unknown fields — it returns
        ``None`` / ``"unknown"`` and records warnings in ``metadata``.

        Args:
            raw_event: Intermediate event dict produced by a
                       :class:`~c1.adapters.base.TraceAdapter`.
            trace_id:  Trace ID to embed in the normalized event.

        Returns:
            Normalized event dict with all required core fields present.
            ``metadata`` is always a ``dict`` (never ``None``).
        """
        meta: dict[str, Any] = {}

        # ── 1. Identity ────────────────────────────────────────────────
        raw_event_id: str = (
            raw_event.get("raw_event_id")
            or raw_event.get("event_id")
            or f"_gen_{uuid.uuid4().hex[:8]}"
        )
        normalized_event_id: str = raw_event.get("event_id") or raw_event_id
        # step_id must be an integer per schema — coerce safely
        step_id: int = _normalize_step_id(raw_event.get("step_id"), meta)
        timestamp = raw_event.get("timestamp")
        parent_event = raw_event.get("parent_event")

        # ── 2. Action name normalization ───────────────────────────────
        raw_tool_name: str | None = raw_event.get("tool_name")
        raw_action:    str | None = raw_event.get("action")
        # Prefer tool_name over action when both present and non-null
        raw_action_name: str | None = raw_tool_name or raw_action

        canonical_action_name = self.vocab.normalize_action_name(raw_action_name)
        if canonical_action_name == "unknown":
            if raw_action_name:
                meta["raw_action_name"] = raw_action_name
                meta.setdefault("normalization_warnings", []).append(
                    "unknown_action_name"
                )
            else:
                meta.setdefault("normalization_warnings", []).append(
                    "missing_action_name"
                )


        # ── 3. phase / action_type from event_type ─────────────────────
        raw_event_type: str = raw_event.get("event_type") or "unknown"
        meta["raw_event_type"] = raw_event_type

        phase, derived_action_type = _EVENT_TYPE_MAP.get(
            raw_event_type, ("unknown", "unknown")
        )

        # Warn when the event_type is completely unrecognised
        if raw_event_type not in _EVENT_TYPE_MAP:
            meta.setdefault("normalization_warnings", []).append(
                f"unknown_event_type:{raw_event_type}"
            )

        # Refine action_type: vocabulary mapping wins over event_type default
        # only when the action resolved properly
        if canonical_action_name != "unknown":
            vocab_action_type = self.vocab.derive_action_type(canonical_action_name)
            action_type = vocab_action_type if vocab_action_type != "unknown" else derived_action_type
        else:
            action_type = derived_action_type

        # Validate phase and action_type against vocabulary allow-lists
        if phase not in self.vocab.phases:
            meta.setdefault("normalization_warnings", []).append(
                f"invalid_phase:{phase}"
            )
            phase = "unknown"

        if action_type not in self.vocab.action_types:
            meta.setdefault("normalization_warnings", []).append(
                f"invalid_action_type:{action_type}"
            )
            action_type = "unknown"

        action_name = canonical_action_name  # always a string per schema

        # ── 4. effect_type / target_resource ──────────────────────────
        # Prefer vocabulary-derived values; fall back to pass-through from adapter
        if canonical_action_name != "unknown":
            effect_type    = self.vocab.derive_effect_type(canonical_action_name)
            target_resource = self.vocab.derive_target_resource(canonical_action_name)
        else:
            effect_type    = raw_event.get("effect_type")
            target_resource = raw_event.get("target_resource")

        # Validate against enum
        if effect_type and effect_type not in self.vocab.effect_types:
            meta.setdefault("normalization_warnings", []).append(
                f"invalid_effect_type:{effect_type}"
            )
            effect_type = "unknown"
        if target_resource and target_resource not in self.vocab.target_resources:
            meta.setdefault("normalization_warnings", []).append(
                f"invalid_target_resource:{target_resource}"
            )
            target_resource = "unknown"

        # ── 5. Payload ────────────────────────────────────────────────
        raw_input  = raw_event.get("input")
        raw_output = raw_event.get("output")

        # typed_args: use the input dict, or empty dict if not a dict
        typed_args: dict = raw_input if isinstance(raw_input, dict) else {}

        # tool_output: use the output value as-is
        tool_output = raw_output

        # input_refs: list of string references from "references"
        references = raw_event.get("references")
        input_refs: list[str] | None = (
            [r for r in references if isinstance(r, str)] if isinstance(references, list) else None
        )
        if input_refs == []:
            input_refs = None  # empty list → null per schema convention

        # output_ref: pass-through from adapter
        output_ref: str | None = raw_event.get("output_ref")

        # ── 6. State ──────────────────────────────────────────────────
        pre_state  = None   # not available from raw trace level
        post_state = None   # not available from raw trace level

        # ── 7. Outcome ────────────────────────────────────────────────
        raw_status_str: str | None = raw_event.get("status")
        status = self.vocab.normalize_status(raw_status_str)
        if status == "unknown" and raw_status_str and raw_status_str != "unknown":
            meta.setdefault("normalization_warnings", []).append(
                f"unknown_status:{raw_status_str}"
            )

        raw_error = raw_event.get("error")
        error_type = self.vocab.normalize_error_type(raw_error)

        reversibility = self.vocab.normalize_reversibility(canonical_action_name)

        # ── 8. Evidence slots (pass-through, never defaulted) ─────────
        provenance = raw_event.get("provenance")
        taint      = raw_event.get("taint")
        approval   = raw_event.get("approval")
        policy     = raw_event.get("policy")
        decision   = raw_event.get("decision")

        # ── 9. raw_event_ref ──────────────────────────────────────────
        raw_event_ref: str = raw_event_id

        # Preserve raw_action_name in metadata even when mapping succeeds
        if raw_action_name and raw_action_name != canonical_action_name:
            meta.setdefault("raw_action_name", raw_action_name)

        # ── 10. Assemble output dict ───────────────────────────────────
        normalized: dict[str, Any] = {
            # identity
            "event_id":     normalized_event_id,
            "trace_id":     trace_id,
            "step_id":      step_id,
            "timestamp":    timestamp,
            "parent_event": parent_event,
            # classification
            "phase":           phase,
            "action_type":     action_type,
            "action_name":     action_name,
            "effect_type":     effect_type,
            "target_resource": target_resource,
            # payload
            "typed_args":   typed_args,
            "tool_output":  tool_output,
            "input_refs":   input_refs,
            "output_ref":   output_ref,
            # state
            "pre_state":  pre_state,
            "post_state": post_state,
            # outcome
            "status":        status,
            "error_type":    error_type,
            "reversibility": reversibility,
            # bookkeeping
            "raw_event_ref": raw_event_ref,
            # evidence slots (may be None when not present in raw trace)
            "provenance": provenance,
            "taint":      taint,
            "approval":   approval,
            "policy":     policy,
            "decision":   decision,
            # metadata — always a dict, never None
            "metadata": meta,
        }

        return normalized


# ===========================================================================
# Module-level convenience functions
# ===========================================================================
# These functions operate on the default singleton vocabulary and are the
# public API described in the task spec.


def normalize_action_name(raw_action_name: str | None) -> str:
    """Map a raw action/tool alias to a canonical action name.

    Example::

        >>> normalize_action_name("gmail_send")
        'send_email'
        >>> normalize_action_name("mcp.gmail.send")
        'send_email'

    Args:
        raw_action_name: Framework-specific raw name.

    Returns:
        Canonical name or ``"unknown"``.
    """
    return get_default_vocabulary().normalize_action_name(raw_action_name)


def derive_action_type(canonical_action_name: str) -> str:
    """Derive ``action_type`` from a canonical action name.

    Example::

        >>> derive_action_type("send_email")
        'tool_call'

    Args:
        canonical_action_name: Output of :func:`normalize_action_name`.

    Returns:
        Canonical ``action_type`` or ``"unknown"``.
    """
    return get_default_vocabulary().derive_action_type(canonical_action_name)


def derive_effect_type(canonical_action_name: str) -> str | None:
    """Derive ``effect_type`` from a canonical action name.

    Example::

        >>> derive_effect_type("send_email")
        'send'

    Args:
        canonical_action_name: Output of :func:`normalize_action_name`.

    Returns:
        Canonical ``effect_type`` or ``None``.
    """
    return get_default_vocabulary().derive_effect_type(canonical_action_name)


def derive_target_resource(canonical_action_name: str) -> str | None:
    """Derive ``target_resource`` from a canonical action name.

    Example::

        >>> derive_target_resource("send_email")
        'email'

    Args:
        canonical_action_name: Output of :func:`normalize_action_name`.

    Returns:
        Canonical ``target_resource`` or ``None``.
    """
    return get_default_vocabulary().derive_target_resource(canonical_action_name)


def normalize_status(raw_status: str | None) -> str:
    """Normalize a raw status string to a schema-valid value.

    Args:
        raw_status: Raw status from the intermediate event.

    Returns:
        Valid status string or ``"unknown"``.
    """
    return get_default_vocabulary().normalize_status(raw_status)


def normalize_error_type(raw_error: Any) -> str | None:
    """Extract and normalize an error type from a raw error payload.

    Args:
        raw_error: ``error`` field value from the intermediate event.

    Returns:
        Valid ``error_type`` string or ``None``.
    """
    return get_default_vocabulary().normalize_error_type(raw_error)


def normalize_raw_event(raw_event: dict, trace_id: str) -> dict:
    """Normalize one intermediate raw-event dict to a normalized event dict.

    Convenience wrapper around :class:`Normalizer` using the default vocabulary.

    Args:
        raw_event: Intermediate dict from a :class:`~c1.adapters.base.TraceAdapter`.
        trace_id:  Trace ID to embed.

    Returns:
        Normalized event dict.
    """
    return Normalizer().normalize_raw_event(raw_event, trace_id)
