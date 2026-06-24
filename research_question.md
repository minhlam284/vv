# Research Questions

## Working Title

**Rule-driven Trace Canonicalization for Runtime Verification of LLM Agents**

## Core Research Problem

Current LLM-agent runtimes produce heterogeneous traces from multiple behavior sources such as planning steps, tool calls, memory operations, retrieval, MCP calls, external APIs, and final responses. Existing runtime-verification approaches often assume their own trace abstraction or parser, which makes policies difficult to reuse across frameworks and verifier backends.

The central problem of this work is:

> How can heterogeneous raw traces from LLM agents be canonicalized into a verifier-ready normalized event stream while preserving the evidence required by verification rules?

## Main Research Question

**RQ1.** Can a rule-driven trace canonicalization layer preserve the evidence required by runtime-verification policies across heterogeneous LLM-agent trace formats?

This question focuses on whether a normalized event stream can support verification without forcing every verifier backend to parse raw traces independently.

## Sub-questions

### RQ1.1 — Trace Canonicalization

**Can raw events from different agent runtimes be mapped into a common normalized event profile with high coverage and low ambiguity?**

This evaluates whether events from sources such as LangChain-style traces, MCP/tool-call traces, and custom ReAct traces can be converted into a shared vocabulary.

Relevant measurements:

- Mapping coverage
- Mapping ambiguity
- Normalization consistency
- Trace reduction
- Adapter effort

### RQ1.2 — Rule-driven Evidence Requirements

**Can verification rules be converted into a Rule IR that explicitly identifies the evidence required to evaluate each rule soundly?**

This evaluates whether policies can be represented independently from a specific verifier backend.

Relevant measurements:

- Policy coverage
- Evidence completeness
- Required-evidence extraction accuracy
- Policy rewrite cost

### RQ1.3 — Evidence Preservation

**When a raw trace violates a policy, does the normalized trace preserve enough evidence to avoid producing a false `SAFE` verdict?**

This is the core safety-oriented question of the work.

Relevant measurements:

- Verdict preservation
- False safe rate
- Unknown rate
- Evidence completeness

### RQ1.4 — Verifier Reuse

**Can multiple verifier backends operate over the same normalized event stream without writing custom raw-trace parsers for each backend?**

This evaluates the practical value of the canonicalization layer as a bridge between agent runtimes and verifier backends.

Relevant measurements:

- Verifier reuse
- Parser reduction
- Backend agreement
- Policy rewrite cost

### RQ1.5 — Field Ablation

**Which normalized event fields are necessary for preserving verdicts and reducing false-safe outcomes?**

This validates that the normalized profile is not arbitrary. Each field should be justified by at least one rule requirement.

Ablation variants:

- Full normalized profile
- Without provenance
- Without taint
- Without causal links
- Without pre/post state
- Without status/error type
- Tool-call-only abstraction

Relevant measurements:

- Policy coverage drop
- False safe rate increase
- Unknown rate increase
- Verdict preservation drop

## Hypotheses

### H1 — Rule-driven canonicalization improves policy portability

A normalized event stream derived from rule evidence requirements will allow more policies to be reused across verifier backends than raw-trace-specific parsers.

### H2 — Evidence preservation reduces false-safe verdicts

If the normalized event stream preserves all required evidence for a policy, then raw unsafe traces should not be classified as `SAFE` by the normalized verifier.

### H3 — Unknown is safer than unsafe abstraction

When required evidence is missing, returning `UNKNOWN` or `INSUFFICIENT_EVIDENCE` reduces the risk of incorrectly reporting unsafe behavior as safe.

### H4 — Causal, provenance, taint, and status fields are necessary

Removing evidence fields such as causal links, provenance, taint labels, or tool status should reduce policy coverage and verdict preservation, while increasing unknown or false-safe outcomes.

## Minimal Evaluation Questions

For the first prototype, the work should answer:

1. How many raw events can C1 map into normalized events?
2. How many policies can be expressed over the normalized event stream?
3. How often does the normalized verifier match the raw-trace oracle?
4. How often does it incorrectly report `SAFE` for raw unsafe traces?
5. How often does it return `UNKNOWN` due to missing evidence?
6. How much parser or policy rewriting effort is reduced compared with baselines?
7. Which fields are most important according to ablation?

## Expected Answer Shape

A successful result should show that:

- The canonicalizer maps most raw events into a stable normalized vocabulary.
- The Rule IR can express a meaningful subset of policies from prior work.
- Evidence completeness correlates with verdict preservation.
- Missing evidence results in `UNKNOWN`, not `SAFE`.
- False safe rate is lower than tool-call-only or generic span-trace baselines.
- Multiple verifier backends can consume the same normalized event stream.
