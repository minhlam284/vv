# Paper ID: P01

## 1. Basic information

- Title: AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents
- Year: 2026
- Venue / Source: ICSE 2026 / arXiv:2503.18666v3
- Main problem:
  LLM agents can autonomously plan and execute actions in sensitive environments. Existing safeguards are often pre-execution or post-hoc, lack explicit runtime enforcement, and are hard to customize across domains.
- Main contribution:
  AgentSpec proposes a lightweight DSL for runtime enforcement of LLM-agent safety rules. A rule has a trigger, predicates/checks, and enforcement actions. The paper implements AgentSpec for code agents, embodied agents, and autonomous-driving agents, and evaluates both manually written and LLM-generated rules.

## 2. Agent trace / event abstraction

Paper uses which type of trace?

- Tool-call event: Yes. The paper monitors action/tool events such as `PythonREPL`, `Transfer`, `pour`, `pick`, etc.
- Message-action trace: Partial. It uses user input plus the current execution trajectory, but does not focus on a full message-action replay log.
- State transition: Yes. The paper formalizes an agent trajectory as state-action-state transitions.
- Action trajectory: Yes. Runtime enforcement checks the current trajectory and the planned next action.
- Span / observability trace: No. It does not use observability/span traces as the main abstraction.
- Other: AgentSpec DSL event abstraction with `state_change`, `before_action` / action event, and `agent_finish`.

Important fields mentioned:

- action name: Required. Examples: `Transfer`, `PythonREPL`, `pour`, `state_change`.
- arguments: Required for many predicates, e.g. recipient, URL, command/code, object target, distance threshold.
- output: Partially used as observation after action execution.
- state: Required. Rules may inspect current state or state changes.
- timestamp / order: Not explicit timestamp, but ordering is represented by trajectory order.
- source / provenance: Partially used in code-agent rule, e.g. untrusted URL/source whitelist.
- approval: Used through `user_inspection`, where the user approves or rejects the action.
- error / status: Not a central field in the DSL; enforcement outcome can imply stopped/allowed.
- user instruction: Used as input `u` to predicate evaluation and trajectory checking.

## 3. Verification / policy / rule

Extracted rules:

### Rule 1

- Original description:
  For a financial transfer, if the recipient is not a verified family member, the agent should ask for explicit user confirmation before proceeding.
- Normalized rule:
  WHEN action_name = `Transfer`
  AND recipient_is_verified_family_member = false
  REQUIRE user_approval before execution
  ELSE block_or_abort.
- Rule class:
  Approval rule; permission rule; human-in-the-loop enforcement.
- Trigger:
  Before executing `Transfer`.
- Condition:
  `!is_to_family_member`.
- Required evidence:
  action name, recipient argument, user/family-member relation, approval event, approval result, temporal order before execution.
- Verdict / enforcement:
  `user_inspection`; if approved, continue; if rejected, terminate/abort the action.
- Possible backend:
  AgentSpec DSL; Python runtime monitor; Hoare-style precondition; LTL monitor for “transfer requires prior approval unless trusted recipient”.

### Rule 2

- Original description:
  For a code agent, if a Python program requests content from an untrusted source and writes/prints it to I/O, the agent should require user inspection.
- Normalized rule:
  WHEN action_name = `PythonREPL`
  AND request_source ∉ trusted_whitelist
  AND effect_type ∈ {write, print, output}
  REQUIRE user_approval before execution
  ELSE violation.
- Rule class:
  Permission rule; provenance/source rule; weak taint-flow rule.
- Trigger:
  Before executing `PythonREPL`.
- Condition:
  `request_untrusted_source AND write_to_io`.
- Required evidence:
  action name, code/tool input, URL/source, whitelist membership, sink/effect type, user approval, temporal order before execution.
- Verdict / enforcement:
  `user_inspection`; user decides whether the code is allowed.
- Possible backend:
  AgentSpec DSL; Python monitor over tool input; SMT-style predicate over source and sink; taint monitor if source/sink labels are explicit.

### Rule 3

- Original description:
  For an embodied agent, if it plans to pour liquid into an object that should not get wet, stop the action.
- Normalized rule:
  WHEN action_name = `pour`
  AND target_object.wettable = false
  ENFORCE stop.
- Rule class:
  State/action precondition rule; safety rule; physical-hazard prevention.
- Trigger:
  Before executing `pour`.
- Condition:
  `!is_into_wettable_object`.
- Required evidence:
  action name, target object, object property/class, current state, planned action order, hazard category.
- Verdict / enforcement:
  `stop`; terminate the unsafe planned action.
- Possible backend:
  AgentSpec DSL; Python monitor; Hoare-style precondition for `pour`; state-transition monitor.

### Rule 4

- Original description:
  For autonomous driving, if a front vehicle is too close, adjust driving parameters to avoid collision.
- Normalized rule:
  WHEN event_type = `state_change`
  AND front_vehicle_distance < 10
  ENFORCE safe following/yield/overtake/stop distances.
- Rule class:
  State invariant rule; temporal safety rule; corrective-control rule.
- Trigger:
  `state_change`.
- Condition:
  `front_vehicle_closer_than(10)`.
- Required evidence:
  current state, previous state, front-vehicle distance, road/object context, enforcement parameters, action/state update.
- Verdict / enforcement:
  Invoke predefined actions such as `follow_dist`, `yield_dist`, `overtake_dist`, `obstacle_stop_dist`, and `obstacle_decrease_ratio`.
- Possible backend:
  AgentSpec DSL; state-transition monitor; controller-level runtime monitor; PRISM/DTMC extension if modeling future collision probability.

## 4. What can be reused for our work?

- Abstraction reused:
  AgentSpec-style runtime events: `state_change`, action/before-action event, and `agent_finish`. Also reuse the idea of checking the current trajectory plus planned next action before execution.
- Rule reused:
  Trigger-check-enforce rule structure. This maps cleanly to our Rule IR:
  `WHEN trigger AND condition REQUIRE/ENFORCE action ELSE violation`.
- Evidence reused:
  action name, typed arguments, current state, trajectory order, user instruction, approval result, source/whitelist, object property, and enforcement outcome.
- Limitation:
  AgentSpec focuses on runtime enforcement at discrete checkpoints. It does not primarily solve trace canonicalization across heterogeneous frameworks, does not define a general evidence-completeness check, and has limited support for long-term trajectory risk, provenance/taint completeness, and “unknown due to missing evidence” verdicts.

## Extraction note for our project

P01 is highly reusable as the “Agent runtime verification / enforcement” anchor paper. It gives a concrete DSL-level rule structure and several executable examples. For our V&V work, we should not copy AgentSpec as the whole solution; instead, we use it as one backend/abstraction source. The key insight to extract is:

`AgentSpec rule = trigger + predicate/check + enforcement`

Our normalized Rule IR can generalize this into:

`WHEN event matches trigger`
`AND predicates hold`
`REQUIRE required evidence`
`ELSE violation / unknown / enforcement`

The missing part that our work can contribute is preservation checking: before sending a normalized trace to AgentSpec-like backends, verify whether the trace still contains all evidence required by the rule.
