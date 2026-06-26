# Rule Taxonomy

This taxonomy normalizes the extracted literature rules into a fixed set of verifier-neutral rule classes. Each class is intended to support Rule IR construction, required-evidence extraction, preservation checking, and backend selection.

---

## 1. Permission Rule

**Normalized class key:** `permission`

### Definition

A permission rule checks whether an agent action is allowed under the current policy, privilege, capability, authentication state, or user approval.

This class answers the question: **"Is this action authorized before execution?"**

### Typical trigger

- `tool_call`
- `external_api_call`
- `memory_op`
- `resource_access_attempt`
- `before_action`
- `code_execution_request`

### Required evidence

- `action_name`
- `action_type`
- `effect_type`
- `typed_args`
- `target_resource`
- `concrete_target`
- `actor_id` / `server_id` / `skill_id`
- `privilege`
- `declared_capability`
- `runtime_permission`
- `allowed_action_set`
- `allowlist` / `denylist`
- `approval.event`
- `approval.status`
- `auth_state`
- `policy_decision`

### Example rules

- External email requires approval.
- Deleting a file requires user confirmation.
- Accessing a private calendar requires authentication.
- MCP server filesystem access must be declared in the manifest and granted as runtime permission.
- Network access is allowed only to approved endpoints.
- Process execution requires an explicit command-execution capability.

### Backend candidate

- Python runtime monitor
- AgentSpec-style DSL
- Policy DSL / access-control checker
- Hoare precondition
- SMT set-membership check
- LTL monitor for approval-before-action patterns
- Container / sandbox / firewall enforcement

### Rule IR pattern

```text
WHEN event.action_type = tool_call/resource_access
AND event.target_resource = X
REQUIRE declared_permission_or_approval_exists(event.actor, X)
ELSE violation
```

---

## 2. Temporal Rule

**Normalized class key:** `temporal`

### Definition

A temporal rule checks whether events occur in the required order. It verifies that a prerequisite event happens before a dependent event, or that a recovery/governance action occurs before the next unsafe step.

This class answers the question: **"Did the required event happen before or after another event at the correct time?"**

### Typical trigger

- `before_action`
- `after_action`
- `state_change`
- `agent_response`
- `message_edge`
- `memory_read`
- `memory_write`
- `sink_invocation`
- `finish`

### Required evidence

- `event_id`
- `trace_id`
- `session_id`
- `timestamp`
- `step_id`
- `timestep`
- `parent_event`
- `previous_event`
- `next_event`
- `temporal_order`
- `before_after_relation`
- `causal_link`
- `approval.timestamp`
- `auth.timestamp`
- `status_transition`

### Example rules

- Approval must occur before external send.
- Authentication must occur before private data access.
- An anomalous agent response must be removed before the next collaboration round.
- A corrupted communication edge must be pruned before later agents consume its content.
- Code must compile successfully before execution.
- A failed tool result must not be reported as success in the final answer.

### Backend candidate

- LTL monitor
- Runtime trace monitor
- Python event-order checker
- AgentSpec `before_action` / `state_change` hook
- Temporal graph monitor
- Hoare pre/post contract with history variable
- SMT over ordered event ids

### Rule IR pattern

```text
WHEN event.effect_type = sensitive_action
REQUIRE exists previous_event(type = prerequisite, target = same_target)
AND previous_event.step_id < event.step_id
ELSE violation
```

---

## 3. State Pre/Post Rule

**Normalized class key:** `state_pre_post`

### Definition

A state pre/post rule checks whether the state before an action satisfies the required precondition and whether the state after the action satisfies the expected postcondition or invariant.

This class answers the question: **"Was the action valid under the current state, and did it leave the system in an acceptable state?"**

### Typical trigger

- `state_change`
- `before_action`
- `after_action`
- `tool_result`
- `environment_update`
- `memory_update`
- `physical_action`
- `controller_action`

### Required evidence

- `pre_state`
- `post_state`
- `current_state`
- `previous_state`
- `next_state`
- `state_diff`
- `action_name`
- `effect_type`
- `target_resource`
- `typed_args`
- `tool_output`
- `status`
- `invariant`
- `object_property`
- `hazard_category`
- `corrective_action`

### Example rules

- Do not pour liquid into an object that should not get wet.
- If the front vehicle is too close, enforce corrective driving behavior before continuing.
- A file write must only occur when the target path is inside the approved filesystem scope.
- A memory write must preserve provenance and trust label after promotion from ephemeral to persistent state.
- A tool failure must update the final task state as failed, not successful.

### Backend candidate

- Hoare contract
- State-transition monitor
- Python runtime monitor
- AgentSpec `state_change` hook
- Controller-level runtime monitor
- SMT predicate over pre/post state
- Model checker for bounded state transitions

### Rule IR pattern

```text
WHEN event.action_name = A
REQUIRE pre_state satisfies Pre(A)
AND post_state satisfies Post(A)
ELSE violation
```

---

## 4. Privilege Confinement Rule

**Normalized class key:** `privilege_confinement`

### Definition

A privilege confinement rule checks that an agent, tool, skill, MCP server, or generated program cannot silently expand its authority beyond the declared policy boundary.

This class answers the question: **"Did the actor stay within its declared privilege boundary?"**

### Typical trigger

- `resource_access_attempt`
- `skill_execution`
- `tool_invocation`
- `process_start`
- `policy_update`
- `capability_request`
- `sandbox_escape_attempt`
- `permission_sensitive_operation`

### Required evidence

- `actor_id`
- `server_id`
- `skill_id`
- `tool_id`
- `process_id`
- `sandbox_id`
- `declared_permissions`
- `declared_capability`
- `runtime_permission`
- `allowed_action_set`
- `policy_version`
- `policy_update_event`
- `capability_scope`
- `capability_lifetime`
- `requested_resource`
- `concrete_target`
- `access_mode`
- `approval.status`
- `sandbox_status`
- `escape_status`

### Example rules

- An MCP server can only access resources declared in its manifest and granted at runtime.
- A weather skill must not access private email.
- A spreadsheet skill must not receive unrestricted shell access.
- A capability cannot escape its lexical/request scope.
- A tool or skill must run under sandboxed filesystem, network, environment, and credential limits.
- A policy expansion requires approval and a recorded policy version change.

### Backend candidate

- Capability type system
- AgentBound-style sandbox enforcement
- Container / WASM sandbox
- eBPF / syscall monitor
- Python policy checker
- SMT set and scope check
- Hoare contract over capability scope
- Access-control DSL

### Rule IR pattern

```text
WHEN actor requests operation O on resource R
REQUIRE O in actor.allowed_action_set
AND R within actor.capability_scope
AND no unapproved policy expansion exists
ELSE violation
```

---

## 5. Provenance Rule

**Normalized class key:** `provenance`

### Definition

A provenance rule checks whether an action, output, memory item, retrieved document, communication edge, or final claim can be traced back to its source events and trust labels.

This class answers the question: **"Where did this data/action/claim come from, and is the causal chain preserved?"**

### Typical trigger

- `retrieval`
- `tool_output`
- `agent_response`
- `message_edge`
- `context_build`
- `memory_write`
- `memory_read`
- `final_response`
- `sink_invocation`
- `graph_abstraction`

### Required evidence

- `source_id`
- `source_type`
- `source_trust_label`
- `input_refs`
- `output_ref`
- `parent_event`
- `causal_link`
- `message_id`
- `document_id`
- `retrieval_id`
- `tool_result_id`
- `agent_id`
- `sender_id`
- `receiver_id`
- `communication_edge`
- `prompt_span`
- `argument_value`
- `memory_target`
- `provenance_chain`

### Example rules

- A final answer claim must link to the retrieved evidence or tool output that supports it.
- A memory write must include source provenance and trust label.
- A communication edge must preserve sender, receiver, timestep, and message content.
- A runtime argument derived from a user prompt must preserve prompt-to-argument mapping.
- A graph abstraction must preserve source edges and node attributes needed for anomaly detection.

### Backend candidate

- Provenance graph monitor
- Python evidence-completeness checker
- Taint/provenance tracker
- Temporal graph monitor
- LTL monitor over causal links
- SMT reachability over provenance edges
- Replay/localization checker

### Rule IR pattern

```text
WHEN event consumes input_ref or produces output_ref
REQUIRE source_id, trust_label, and causal_path are preserved
ELSE unknown
```

---

## 6. Taint Rule

**Normalized class key:** `taint`

### Definition

A taint rule checks whether untrusted, user-controlled, classified, or otherwise sensitive data flows into a dangerous sink without sanitization, approval, declassification, or external enforcement.

This class answers the question: **"Did unsafe data flow into a sensitive action or sink?"**

### Typical trigger

- `context_build`
- `tool_call`
- `external_api_call`
- `sink_invocation`
- `classified_output`
- `memory_write`
- `network_send`
- `message_send`
- `code_execution_request`
- `database_query`

### Required evidence

- `source_id`
- `source_type`
- `source_trust_label`
- `taint_label`
- `classification_label`
- `input_refs`
- `output_ref`
- `causal_path`
- `prompt_span`
- `runtime_argument`
- `sink_type`
- `sink_function`
- `sink_argument`
- `sanitizer_status`
- `validator_status`
- `declassification_event`
- `output_channel`
- `recipient`
- `secure_channel_status`
- `oracle_status`

### Example rules

- User-prompt-derived data must not reach `eval`, `exec`, SQL execution, SSRF-prone request, or template rendering without sanitizer.
- Untrusted retrieval content must not be written, printed, emailed, or executed without approval or validation.
- Classified data may only be transformed by pure functions.
- Classified values must be redacted on agent-visible channels.
- Classified content may only be sent to a trusted/local model and must remain classified on return.
- Prompt-injection content must not causally trigger privileged tool calls without external policy enforcement.
- Stored tainted content must not later flow into a sink without cross-turn taint provenance.

### Backend candidate

- Dynamic taint monitor
- Static taint analysis / CodeQL
- Runtime instrumentation
- Python monitor
- Scala capture checker / information-flow type system
- Non-interference checker
- SMT/constraint solver for path feasibility
- Sink oracle / fuzzing oracle

### Rule IR pattern

```text
WHEN tainted(source) reaches sensitive_sink(argument)
REQUIRE sanitizer_or_validator_exists_on_path
ELSE violation
```

---

## 7. Recovery / Governance Rule

**Normalized class key:** `recovery_governance`

### Definition

A recovery/governance rule checks whether the system performs the correct intervention after detecting an unsafe, anomalous, failed, incomplete, or uncertain event.

This class answers the question: **"When something goes wrong or evidence is insufficient, did the agent block, retry, replan, remove, escalate, or mark unknown correctly?"**

### Typical trigger

- `policy_decision`
- `verifier_verdict`
- `anomaly_detection`
- `tool_result`
- `error_event`
- `failed_action`
- `blocked_action`
- `evidence_missing`
- `agent_finish`
- `governance_action`

### Required evidence

- `verdict`
- `policy_decision`
- `status`
- `error_type`
- `failure_reason`
- `missing_evidence`
- `confidence_score`
- `anomaly_score`
- `threshold`
- `affected_node`
- `affected_edge`
- `propagation_path`
- `decision_action`
- `reversibility`
- `rollback_action`
- `retry_event`
- `replan_event`
- `block_event`
- `human_review_event`
- `post_intervention_state`

### Example rules

- If required evidence is missing, return `UNKNOWN`, not `SAFE`.
- If a node or communication edge is anomalous, remove it before the next collaboration round.
- If a tool action is blocked, the agent must not report the task as successfully completed.
- If sandbox escape is detected, terminate the process and log the violation.
- If an action is irreversible and policy confidence is low, request user review before continuing.
- If graph abstraction loses evidence needed for anomaly detection, mark preservation as insufficient.

### Backend candidate

- Python decision manager
- Runtime governance layer
- AgentSpec enforcement action
- Temporal graph mitigation module
- LTL monitor for `detect -> intervene_before_next_step`
- Evidence-completeness checker
- Policy router / human-in-the-loop review
- Audit logger

### Rule IR pattern

```text
WHEN verifier.verdict in {violation, unknown, inconsistent}
REQUIRE governance_action in allowed_response(verdict)
AND governance_action occurs before continuation
ELSE violation
```

---

## Summary Matrix

| Rule class | Main question | Typical evidence focus | Common backend |
|---|---|---|---|
| `permission` | Is the action authorized? | action, target, privilege, approval, capability | Policy DSL, Python monitor, Hoare, SMT |
| `temporal` | Did events occur in the required order? | event order, timestamp, previous event, causal link | LTL, event-order checker, temporal monitor |
| `state_pre_post` | Are pre/post states valid? | pre_state, post_state, invariant, status | Hoare, state-transition monitor, SMT |
| `privilege_confinement` | Did the actor stay within its authority boundary? | capability scope, sandbox, policy version, access mode | Sandbox, capability type system, eBPF, SMT |
| `provenance` | Is source/causal evidence preserved? | input_refs, output_ref, source id, trust label, causal path | Provenance graph, replay checker, SMT reachability |
| `taint` | Did unsafe data reach a sensitive sink? | taint label, source-to-sink path, sanitizer, sink argument | Taint monitor, CodeQL, type system, fuzzing oracle |
| `recovery_governance` | Was the correct intervention taken? | verdict, error, anomaly score, missing evidence, decision action | Decision manager, LTL, governance router |

---

## Notes for Rule IR Usage

- Each extracted rule should use exactly one primary `rule_class` from the fixed set.
- If a rule naturally spans multiple classes, keep the dominant class as `rule_class` and record secondary classes in `notes`.
- If required evidence is missing, the verifier should return `UNKNOWN`, not `SAFE`.
- `SAFE` should only be returned when both the rule condition and required evidence are fully checkable.
- `VIOLATION` should be returned when evidence is complete and the rule condition is broken.
