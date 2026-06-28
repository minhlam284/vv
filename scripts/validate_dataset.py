#!/usr/bin/env python3
"""
scripts/validate_dataset.py
────────────────────────────
Phase 3 dataset structural validator.

Purpose
-------
Check that the dataset satisfies structural invariants before it is fed into
C1 (canonicaliser) or C2 (preservation checker).  The validator does NOT
decide SAFE / VIOLATION / UNKNOWN — that is the job of C2.

Run
---
    python scripts/validate_dataset.py

Exit codes
----------
    0 — all checks pass (no ERRORs)
    1 — one or more ERRORs found
"""

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR       = REPO_ROOT / "data"
RAW_TRACE_DIR  = DATA_DIR / "raw_traces"

SYNTHETIC_DIR  = RAW_TRACE_DIR / "synthetic"
FRAMEWORK_DIR  = RAW_TRACE_DIR / "framework"
MUTATED_DIR    = RAW_TRACE_DIR / "mutated"

ORACLE_PATH    = DATA_DIR / "oracle_labels.csv"

# Accept both column names: spec says "raw_oracle", existing file uses "expected_verdict"
ORACLE_VERDICT_COLUMNS = {"raw_oracle", "expected_verdict"}

REQUIRED_ORACLE_COLUMNS = {"trace_id", "policy_id", "reason"}
# verdict column is checked separately to allow either alias

VALID_ORACLES      = {"SAFE", "VIOLATION", "UNKNOWN"}
REQUIRED_POLICIES  = {"P001", "P002", "P003"}

# Minimum counts
MIN_SYNTHETIC = 5
MIN_MUTATED   = 5

# ──────────────────────────────────────────────────────────────────────────────
# Issue collectors
# ──────────────────────────────────────────────────────────────────────────────

errors:   list[str] = []
warnings: list[str] = []


def err(msg: str) -> None:
    errors.append(msg)


def warn(msg: str) -> None:
    warnings.append(msg)


# ──────────────────────────────────────────────────────────────────────────────
# 1. Find trace files
# ──────────────────────────────────────────────────────────────────────────────

def find_trace_files() -> dict:
    """Return {folder_key: [Path, ...]} for all three source dirs."""
    result = {"synthetic": [], "framework": [], "mutated": []}

    for key, directory in [
        ("synthetic", SYNTHETIC_DIR),
        ("framework", FRAMEWORK_DIR),
        ("mutated",   MUTATED_DIR),
    ]:
        if not directory.exists():
            if key in ("synthetic", "mutated"):
                err(f"Directory missing: {directory.relative_to(REPO_ROOT)}")
            # framework/ is allowed to be absent
            continue
        result[key] = sorted(directory.glob("*.json"))

    return result


# ──────────────────────────────────────────────────────────────────────────────
# 2. Load and parse a single JSON file
# ──────────────────────────────────────────────────────────────────────────────

def load_json_file(path: Path):
    """Parse a JSON file. Returns None and records an ERROR on failure."""
    rel = path.relative_to(REPO_ROOT)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        err(f"{rel}: JSON parse error — {exc}")
        return None
    except OSError as exc:
        err(f"{rel}: cannot read file — {exc}")
        return None

    if not isinstance(data, dict):
        err(f"{rel}: root object must be a JSON object (dict), got {type(data).__name__}")
        return None

    return data


# ──────────────────────────────────────────────────────────────────────────────
# 3. Validate a single trace
# ──────────────────────────────────────────────────────────────────────────────

def validate_trace(path: Path, trace: dict):
    """
    Validate structural invariants for one trace dict.

    Returns the trace_id (str) if it can be determined, else None.
    Records ERRORs and WARNINGs into the module-level collectors.
    """
    rel   = str(path.relative_to(REPO_ROOT))

    # ── trace_id ──────────────────────────────────────────────────────────────
    trace_id = trace.get("trace_id")
    if not trace_id:
        err(f"{rel}: missing or empty 'trace_id'")
        trace_id = None

    label = f"{rel} (trace_id={trace_id!r})" if trace_id else rel

    # ── events ────────────────────────────────────────────────────────────────
    events = trace.get("events")
    if events is None:
        err(f"{label}: missing 'events' field")
        return trace_id
    if not isinstance(events, list):
        err(f"{label}: 'events' must be a list, got {type(events).__name__}")
        return trace_id
    if len(events) == 0:
        err(f"{label}: 'events' list is empty")
        return trace_id

    # ── per-event validation ──────────────────────────────────────────────────
    seen_event_ids: set = set()
    seen_step_ids:  set = set()

    # First pass: collect all event_ids so parent checks work
    known_event_ids: set = set()
    for ev in events:
        if isinstance(ev, dict):
            eid = ev.get("event_id")
            if eid:
                known_event_ids.add(str(eid))

    for idx, ev in enumerate(events):
        ev_label = f"{label}[event {idx}]"

        if not isinstance(ev, dict):
            err(f"{ev_label}: event must be a JSON object, got {type(ev).__name__}")
            continue

        # ── event_id ──────────────────────────────────────────────────────────
        event_id = ev.get("event_id")
        if event_id is None or event_id == "":
            err(f"{ev_label}: missing 'event_id'")
        else:
            eid_str = str(event_id)
            if eid_str in seen_event_ids:
                err(f"{label}: duplicate event_id {event_id!r}")
            else:
                seen_event_ids.add(eid_str)

        # ── step_id ───────────────────────────────────────────────────────────
        if "step_id" not in ev:
            err(f"{ev_label}: missing 'step_id'")
        else:
            step_id  = ev["step_id"]
            step_key = str(step_id)
            if step_key in seen_step_ids:
                err(f"{label}: duplicate step_id {step_id!r}")
            else:
                seen_step_ids.add(step_key)

        # ── action / tool_name ────────────────────────────────────────────────
        has_action    = ev.get("action")    not in (None, "")
        has_tool_name = ev.get("tool_name") not in (None, "")
        if not has_action and not has_tool_name:
            warn(f"{ev_label}: neither 'action' nor 'tool_name' is set")

        # ── input / output ────────────────────────────────────────────────────
        if "input"  not in ev:
            warn(f"{ev_label}: missing 'input' field")
        if "output" not in ev:
            warn(f"{ev_label}: missing 'output' field")

        # ── warning-only fields ───────────────────────────────────────────────
        for field in ("timestamp", "event_type", "source", "status", "error",
                       "parent_event", "references"):
            if field not in ev:
                warn(f"{ev_label}: missing '{field}' field")

        # ── parent_event integrity (ERROR if unresolved) ──────────────────────
        parent = ev.get("parent_event")
        if parent is not None:
            if str(parent) not in known_event_ids:
                err(
                    f"{ev_label}: parent_event {parent!r} does not refer to "
                    f"an existing event_id in this trace"
                )

        # ── references integrity (WARNING if event-like id unresolved) ────────
        refs = ev.get("references")
        if refs is not None:
            if not isinstance(refs, (list, dict)):
                warn(f"{ev_label}: 'references' should be a list or object")
            elif isinstance(refs, list):
                for ref in refs:
                    if not isinstance(ref, str):
                        warn(f"{ev_label}: reference item {ref!r} is not a string")
                    elif ref.startswith("e_") and ref not in known_event_ids:
                        warn(
                            f"{ev_label}: reference {ref!r} looks like an event_id "
                            f"but was not found in this trace"
                        )

    return trace_id


# ──────────────────────────────────────────────────────────────────────────────
# 4. Load oracle_labels.csv
# ──────────────────────────────────────────────────────────────────────────────

def load_oracle_labels():
    """Parse oracle_labels.csv. Returns list of row dicts, or None on fatal error."""
    if not ORACLE_PATH.exists():
        err(f"oracle_labels.csv not found: {ORACLE_PATH.relative_to(REPO_ROOT)}")
        return None

    try:
        with open(ORACLE_PATH, encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            rows = [row for row in reader if any(v.strip() for v in row.values())]
    except OSError as exc:
        err(f"oracle_labels.csv: cannot read — {exc}")
        return None
    except csv.Error as exc:
        err(f"oracle_labels.csv: CSV parse error — {exc}")
        return None

    if not rows:
        err("oracle_labels.csv: file is empty or has no data rows")
        return None

    return rows


# ──────────────────────────────────────────────────────────────────────────────
# 5. Validate oracle labels
# ──────────────────────────────────────────────────────────────────────────────

def _detect_verdict_column(rows: list) -> str | None:
    """Return the verdict column name actually present, or None."""
    if not rows:
        return None
    fieldnames = set(rows[0].keys())
    for candidate in ORACLE_VERDICT_COLUMNS:
        if candidate in fieldnames:
            return candidate
    return None


def validate_oracle_labels(rows: list, trace_ids: set):
    """
    Validate oracle rows.

    Returns (verdict_col_name, policy_coverage_dict, oracle_trace_ids_set).
    policy_coverage_dict: { policy_id: { verdict: count } }
    """
    oracle_label = ORACLE_PATH.relative_to(REPO_ROOT)

    if not rows:
        err(f"{oracle_label}: no data rows")
        return None, {}, set()

    fieldnames = set(rows[0].keys())

    # Check required non-verdict columns
    for col in REQUIRED_ORACLE_COLUMNS:
        if col not in fieldnames:
            err(f"{oracle_label}: missing required column '{col}'")

    verdict_col = _detect_verdict_column(rows)
    if verdict_col is None:
        err(
            f"{oracle_label}: missing verdict column "
            f"(expected one of: {sorted(ORACLE_VERDICT_COLUMNS)})"
        )
    elif verdict_col != "raw_oracle":
        warn(
            f"{oracle_label}: verdict column is '{verdict_col}' "
            f"(spec name is 'raw_oracle') — treating as equivalent"
        )

    oracle_trace_ids: set  = set()
    policy_coverage        = defaultdict(lambda: defaultdict(int))

    for i, row in enumerate(rows, start=2):  # row 1 = header
        row_label = f"{oracle_label} row {i}"

        tid = (row.get("trace_id") or "").strip()
        if not tid:
            err(f"{row_label}: empty 'trace_id'")
        else:
            oracle_trace_ids.add(tid)
            if tid not in trace_ids:
                err(f"{oracle_label}: trace_id '{tid}' does not exist in dataset")

        pid = (row.get("policy_id") or "").strip()
        if not pid:
            err(f"{row_label}: empty 'policy_id'")

        if verdict_col:
            verdict = (row.get(verdict_col) or "").strip()
            if not verdict:
                err(f"{row_label}: empty verdict column '{verdict_col}'")
            elif verdict not in VALID_ORACLES:
                err(
                    f"{row_label}: invalid verdict '{verdict}' "
                    f"(must be one of {sorted(VALID_ORACLES)})"
                )
            elif tid and pid:
                policy_coverage[pid][verdict] += 1

        reason = (row.get("reason") or "").strip()
        if not reason:
            err(f"{row_label}: empty 'reason'")

    return verdict_col, dict(policy_coverage), oracle_trace_ids


# ──────────────────────────────────────────────────────────────────────────────
# 6. Cross-check coverage
# ──────────────────────────────────────────────────────────────────────────────

def validate_coverage(
    trace_files:      dict,
    trace_ids:        set,
    oracle_trace_ids: set,
) -> None:
    """Check folder counts and that every trace has ≥1 oracle label."""

    syn_count = len(trace_files["synthetic"])
    mut_count = len(trace_files["mutated"])

    if syn_count < MIN_SYNTHETIC:
        err(f"expected at least {MIN_SYNTHETIC} synthetic traces, found {syn_count}")
    if mut_count < MIN_MUTATED:
        err(f"expected at least {MIN_MUTATED} mutated traces, found {mut_count}")

    for tid in sorted(trace_ids):
        if tid not in oracle_trace_ids:
            err(f"trace '{tid}': has no oracle label")


def validate_policy_coverage(policy_coverage: dict) -> None:
    """P001, P002, P003 must all appear; check expected verdict distribution."""

    for pid in sorted(REQUIRED_POLICIES):
        if pid not in policy_coverage:
            err(f"policy '{pid}' has no entries in oracle_labels.csv")
            continue

        verdicts = policy_coverage[pid]

        if pid == "P001":
            for v in ("SAFE", "VIOLATION", "UNKNOWN"):
                if v not in verdicts:
                    warn(f"policy P001 has no '{v}' oracle label (recommended)")

        if pid in ("P002", "P003"):
            for v in ("VIOLATION", "UNKNOWN"):
                if v not in verdicts:
                    warn(f"policy {pid} has no '{v}' oracle label (recommended)")


# ──────────────────────────────────────────────────────────────────────────────
# 7. main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    # 1. find trace files
    trace_files = find_trace_files()

    all_paths = []
    for folder, paths in trace_files.items():
        for p in paths:
            all_paths.append((folder, p))

    # 2. validate each trace
    trace_ids: set = set()
    for _, path in all_paths:
        data = load_json_file(path)
        if data is None:
            continue
        tid = validate_trace(path, data)
        if tid:
            trace_ids.add(tid)

    # 3. load oracle labels
    oracle_rows = load_oracle_labels()
    policy_coverage:   dict = {}
    oracle_trace_ids:  set  = set()

    if oracle_rows is not None:
        verdict_col, policy_coverage, oracle_trace_ids = validate_oracle_labels(
            oracle_rows, trace_ids
        )

    # 4. cross-check coverage
    validate_coverage(trace_files, trace_ids, oracle_trace_ids)
    if policy_coverage:
        validate_policy_coverage(policy_coverage)

    # 5. print summary
    syn_count   = len(trace_files["synthetic"])
    fw_count    = len(trace_files["framework"])
    mut_count   = len(trace_files["mutated"])
    total       = syn_count + fw_count + mut_count

    oracle_rows_count = len(oracle_rows) if oracle_rows else 0
    labeled_traces    = len(oracle_trace_ids)
    missing_labels    = len(trace_ids - oracle_trace_ids)
    unknown_ids       = len(oracle_trace_ids - trace_ids)

    has_errors = bool(errors)

    print()
    print("Dataset validation " + ("FAILED" if has_errors else "PASSED"))

    print()
    print("Raw trace files:")
    print(f"  synthetic : {syn_count}")
    print(f"  framework : {fw_count}")
    print(f"  mutated   : {mut_count}")
    print(f"  total     : {total}")

    print()
    print("Oracle labels:")
    print(f"  rows             : {oracle_rows_count}")
    print(f"  labeled traces   : {labeled_traces}")
    print(f"  missing labels   : {missing_labels}")
    print(f"  unknown trace_ids: {unknown_ids}")

    if policy_coverage:
        print()
        print("Policy coverage:")
        for pid in sorted(REQUIRED_POLICIES):
            vc    = policy_coverage.get(pid, {})
            parts = ", ".join(
                f"{v}={vc.get(v, 0)}" for v in ("SAFE", "VIOLATION", "UNKNOWN")
            )
            print(f"  {pid}: {parts}")

    if warnings:
        print()
        print(f"WARNINGS ({len(warnings)}):")
        for w in warnings:
            print(f"  - {w}")

    if errors:
        print()
        print(f"ERRORS ({len(errors)}):")
        for e in errors:
            print(f"  - {e}")

    print()
    sys.exit(1 if has_errors else 0)


if __name__ == "__main__":
    main()
