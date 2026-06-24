# Claim

## Main Claim

This work proposes a **rule-driven trace canonicalization layer** for runtime verification of LLM agents.

The key claim is:

> If a raw trace contains the evidence required by a verification rule, and the canonicalization layer preserves that evidence in the normalized event stream, then the verifier should not turn a raw violation into a `SAFE` verdict. If required evidence is missing, the system should return `UNKNOWN` instead of `SAFE`.

## Formal Claim

Let:

```text
τ        = raw agent trace
α        = canonicalization function
E        = α(τ) = normalized event trace
φ        = verification policy / rule
Req(φ)   = set of evidence fields required by φ
Fields(E)= evidence fields available in E
V        = verifier over normalized event trace
```

Evidence completeness:

```text
Complete(E, φ) ⇔ Req(φ) ⊆ Fields(E)
```

Verifier result:

```text
V(E, φ) ∈ {SAFE, VIOLATION, UNKNOWN, INCONSISTENT}
```

Preservation property:

```text
If τ violates φ
and α preserves all required evidence Req(φ),
then V(α(τ), φ) ≠ SAFE.
```

In plain language:

> A raw violation must not be abstracted into a safe verdict.

## What the Work Claims

### Claim 1 — Rule-first, not schema-first

The work does not begin by inventing a new event schema. Instead, it begins from verification rules, extracts the evidence required by those rules, and then builds a normalized event profile around the evidence that verification actually needs.

### Claim 2 — Canonicalization as a bridge layer

The work provides a bridge between heterogeneous agent runtimes and verifier backends.

Raw traces from different sources are converted into a normalized event stream that can be consumed by multiple verifier styles, such as:

- AgentSpec-style DSL
- LTL monitor
- Hoare-style contract checker
- SMT/FOL checker
- DTMC/PRISM-style model checker

### Claim 3 — Evidence preservation is the core safety mechanism

The central contribution is not only normalizing events, but also checking whether the normalized trace contains the evidence required by each rule.

If the evidence is complete, the verifier can evaluate the rule.

If the evidence is missing, the verdict must be:

```text
UNKNOWN
```

not:

```text
SAFE
```

### Claim 4 — The normalized profile is justified by rule requirements

Every important field in the normalized event profile should be justified by at least one verification rule.

Examples:

| Field | Why it exists |
|---|---|
| `effect_type` | Needed to identify dangerous effects such as send, delete, write, execute |
| `target_resource` | Needed to know whether the action targets email, file, memory, database, web, or API |
| `approval.status` | Needed for approval-before-action rules |
| `input_refs` | Needed for provenance and causal reasoning |
| `taint` | Needed for untrusted-data-flow policies |
| `status` | Needed to distinguish successful, failed, blocked, or rewritten actions |
| `parent_event` | Needed to reconstruct causal chains |
| `pre_state` / `post_state` | Needed for state pre/post-condition rules |

### Claim 5 — Evaluation should measure abstraction quality

The work should be evaluated not only by whether a verifier returns correct verdicts, but also by whether the abstraction preserves evidence.

Important metrics include:

- Policy coverage
- Evidence completeness
- Verdict preservation
- False safe rate
- Unknown rate
- Mapping coverage
- Mapping ambiguity
- Normalization consistency
- Verifier reuse
- Parser reduction
- Policy rewrite cost
- Field ablation impact

## What the Work Does Not Claim

This work does **not** claim that:

1. It creates a completely new verifier to replace AgentSpec, LTL, SMT, Hoare contracts, or PRISM.
2. It creates a completely new schema from scratch.
3. It guarantees that every LLM-agent behavior is safe.
4. It can verify policies when the runtime does not observe or log the required evidence.
5. It proves that human-written policies are always correct.
6. It detects side effects that are not visible in the raw trace.
7. It supports every possible policy over every possible agent framework.
8. It solves all runtime verification problems for LLM agents.

## Defensible Paper Claim

A concise paper-friendly version:

> We introduce a rule-driven trace canonicalization layer for LLM-agent runtime verification. Instead of proposing a schema from scratch, the system derives evidence requirements from verification rules and maps heterogeneous raw traces into a normalized event stream. A preservation checker ensures that rules are evaluated only when required evidence is present; otherwise, the system returns `UNKNOWN` rather than `SAFE`. This prevents abstraction from hiding raw-trace violations and enables multiple verifier backends to reuse the same event stream.

## Strong but Safe Boundary

The strongest defensible claim is:

> For a supported policy fragment, if the raw trace contains all evidence required by the policy and the canonicalizer preserves that evidence, then the normalized verifier will not report `SAFE` for a raw violating trace.

This is strong enough to be publishable, but narrow enough to defend.
