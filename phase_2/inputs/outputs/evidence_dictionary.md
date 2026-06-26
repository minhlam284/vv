# Evidence Dictionary

This dictionary defines the evidence fields used by the normalized event stream and by the Rule IR preservation check. Phase 2 can use this file as the starting point for designing the normalized event schema.

Each field answers four questions:

1. What does this field mean?
2. What values or type can it have?
3. Which rule classes need it?
4. What does it look like in an agent trace?

## Rule class keys

The dictionary uses the fixed rule classes from `rule_taxonomy.md`:

- `permission`
- `temporal`
- `state_pre_post`
- `privilege_confinement`
- `provenance`
- `taint`
- `recovery_governance`

---

## event_id

- Meaning: A unique identifier for one normalized event in a trace.
- Possible values: String identifier, for example `e_001`, `event_17`, `traceA_step_04_call_01`.
- Needed by:
  - `temporal`
  - `provenance`
  - `taint`
  - `recovery_governance`
  - `state_pre_post`
- Example:
  - `e_003` identifies the tool call that sends an email.
  - `e_009` identifies the memory write caused by a retrieval result.

---

## trace_id

- Meaning: Identifier for the whole execution trace, session run, replay, or verification instance.
- Possible values: String identifier, for example `trace_001`, `run_2026_06_25_01`, `session_A_trace_2`.
- Needed by:
  - `temporal`
  - `provenance`
  - `taint`
  - `recovery_governance`
- Example:
  - All events from one agent execution share `trace_id = trace_001`.
  - A cross-turn taint rule uses `trace_id` to connect a stored prompt payload to a later sink invocation.

---

## step_id

- Meaning: The logical order index of an event within a trace or agent trajectory.
- Possible values: Integer or structured step label, for example `1`, `2`, `plan_1`, `tool_3`, `round_2_agent_1`.
- Needed by:
  - `temporal`
  - `state_pre_post`
  - `provenance`
  - `recovery_governance`
- Example:
  - `step_id = 4` occurs after `step_id = 3`.
  - A temporal rule checks whether approval at `step_id = 2` happened before external send at `step_id = 5`.

---

## timestamp

- Meaning: Wall-clock time or logical time at which the event occurred.
- Possible values: ISO timestamp, Unix timestamp, or logical timestamp, for example `2026-06-25T16:30:00+07:00`, `1782389400`, `t=4`.
- Needed by:
  - `temporal`
  - `recovery_governance`
  - `provenance`
  - `taint`
- Example:
  - `timestamp = 2026-06-25T16:30:00+07:00` for a file delete request.
  - `timestamp = t=3` for a temporal graph response in a multi-agent collaboration.

---

## parent_event

- Meaning: The direct event that caused or produced the current event.
- Possible values: Event id, list of event ids, or `null`, for example `e_002`, `[e_002, e_004]`, `null`.
- Needed by:
  - `provenance`
  - `taint`
  - `temporal`
  - `recovery_governance`
- Example:
  - An email-send event has `parent_event = e_006`, where `e_006` is the plan step that requested sending the email.
  - A final answer has `parent_event = e_011`, where `e_011` is the tool result used to support the answer.

---

## phase

- Meaning: The phase of agent execution represented by the event.
- Possible values:
  - `plan`
  - `before_action`
  - `after_action`
  - `state_change`
  - `finish`
- Needed by:
  - `permission`
  - `temporal`
  - `state_pre_post`
  - `recovery_governance`
- Example:
  - `phase = before_action` before executing `Transfer`.
  - `phase = state_change` when front-vehicle distance changes in an embodied or driving agent.
  - `phase = finish` when the agent emits the final response.

---

## action_type

- Meaning: The high-level category of the event or action.
- Possible values:
  - `tool_call`
  - `external_api_call`
  - `memory_op`
  - `retrieval`
  - `message`
  - `agent_response`
  - `resource_access`
  - `code_execution`
  - `policy_decision`
  - `governance_action`
- Needed by:
  - `permission`
  - `temporal`
  - `provenance`
  - `taint`
  - `recovery_governance`
- Example:
  - `action_type = tool_call` for `PythonREPL`.
  - `action_type = memory_op` for writing a retrieved instruction into persistent memory.
  - `action_type = resource_access` for MCP filesystem access.

---

## action_name

- Meaning: The concrete action, tool, API, method, skill, or operation name.
- Possible values: Tool or operation name, for example `send_email`, `Transfer`, `PythonREPL`, `httpGet`, `exec`, `memory.write`, `sqlite3.execute`.
- Needed by:
  - `permission`
  - `state_pre_post`
  - `privilege_confinement`
  - `provenance`
  - `taint`
  - `recovery_governance`
- Example:
  - `action_name = Transfer` for a financial transfer.
  - `action_name = subprocess.run` for command execution.
  - `action_name = readClassified` for reading classified content.

---

## effect_type

- Meaning: The semantic effect of an action.
- Possible values:
  - `read`
  - `write`
  - `delete`
  - `send`
  - `execute`
  - `retrieve`
  - `connect`
  - `approve`
  - `block`
  - `rewrite`
  - `replan`
- Needed by:
  - `permission`
  - `taint`
  - `recovery_governance`
  - `privilege_confinement`
  - `state_pre_post`
- Example:
  - `send` email.
  - `delete` file.
  - `retrieve` document.
  - `execute` shell command.

---

## target_resource

- Meaning: The resource affected by the action.
- Possible values:
  - `email`
  - `file`
  - `calendar`
  - `memory`
  - `database`
  - `web`
  - `api`
  - `environment_variable`
  - `system_command`
  - `network_endpoint`
  - `agent_context`
  - `log`
  - `classified_data`
  - `communication_edge`
- Needed by:
  - `permission`
  - `privilege_confinement`
  - `taint`
  - `provenance`
  - `state_pre_post`
  - `recovery_governance`
- Example:
  - `target_resource = email` for external message sending.
  - `target_resource = file` for reading `/project/config.yaml`.
  - `target_resource = database` for executing an SQL query.

---

## typed_args

- Meaning: Structured arguments passed to the action, with names, values, and optionally types.
- Possible values: JSON object or key-value map, for example `{ "recipient": "a@example.com", "subject": "Report" }`, `{ "path": "/tmp/a.txt", "mode": "delete" }`.
- Needed by:
  - `permission`
  - `state_pre_post`
  - `privilege_confinement`
  - `provenance`
  - `taint`
- Example:
  - Email send arguments: `recipient`, `cc`, `subject`, `body`.
  - Filesystem arguments: `path`, `mode`, `root_scope`.
  - Network arguments: `url`, `host`, `method`, `payload`.

---

## tool_output

- Meaning: Output, observation, return value, or result emitted by a tool, API, code execution, retrieval, or model call.
- Possible values: Text, JSON object, file reference, HTTP response, error object, redacted value, classified wrapper, or `null`.
- Needed by:
  - `state_pre_post`
  - `provenance`
  - `taint`
  - `recovery_governance`
- Example:
  - Retrieved document text from a web search.
  - `Classified(****)` returned to an agent-visible output channel.
  - HTTP response body from `httpGet`.
  - Compiler error from `execute_scala`.

---

## status

- Meaning: Execution status or policy status of an event.
- Possible values:
  - `pending`
  - `success`
  - `failed`
  - `blocked`
  - `aborted`
  - `rejected`
  - `allowed`
  - `rewritten`
  - `unknown`
- Needed by:
  - `recovery_governance`
  - `state_pre_post`
  - `permission`
  - `temporal`
- Example:
  - `status = blocked` when a network request to an undeclared host is denied.
  - `status = failed` when a tool call raises an exception.
  - `status = success` when a retrieval operation completes.

---

## error_type

- Meaning: Normalized type or category of an error, failure, violation, or anomaly.
- Possible values:
  - `permission_denied`
  - `missing_approval`
  - `policy_violation`
  - `runtime_exception`
  - `tool_failure`
  - `sandbox_violation`
  - `taint_violation`
  - `sink_reached`
  - `anomaly_detected`
  - `evidence_missing`
  - `inconsistent_evidence`
  - `timeout`
  - `unknown`
- Needed by:
  - `recovery_governance`
  - `permission`
  - `taint`
  - `provenance`
  - `state_pre_post`
- Example:
  - `error_type = missing_approval` when an external send has no prior approval.
  - `error_type = taint_violation` when prompt-derived data reaches `eval` unsanitized.
  - `error_type = sandbox_violation` when a tool reads outside its approved directory.

---

## pre_state

- Meaning: Relevant state before an action or transition.
- Possible values: JSON object, symbolic state, environment snapshot, graph state, capability state, or selected state variables.
- Needed by:
  - `state_pre_post`
  - `permission`
  - `privilege_confinement`
  - `temporal`
- Example:
  - `pre_state.front_vehicle_distance = 8` before corrective driving action.
  - `pre_state.authenticated = false` before private calendar access.
  - `pre_state.memory.contains_tainted_payload = true` before memory read.

---

## post_state

- Meaning: Relevant state after an action or transition.
- Possible values: JSON object, symbolic state, environment snapshot, graph state, capability state, or selected state variables.
- Needed by:
  - `state_pre_post`
  - `recovery_governance`
  - `temporal`
  - `provenance`
- Example:
  - `post_state.front_vehicle_distance >= 10` after corrective driving action.
  - `post_state.node_removed = true` after removing an anomalous agent node.
  - `post_state.file_exists = false` after file deletion.

---

## input_refs

- Meaning: References to prior outputs, messages, retrieved documents, memory entries, or state objects consumed by the current event.
- Possible values: List of ids, for example `[out_002, doc_005]`, `[msg_001, mem_008]`.
- Needed by:
  - `provenance`
  - `taint`
  - `temporal`
  - `recovery_governance`
- Example:
  - An email body uses `input_refs = [retrieval_05.output_ref]`.
  - A final answer uses `input_refs = [tool_result_08.output_ref]`.
  - A tool argument uses `input_refs = [user_prompt_01]`.

---

## output_ref

- Meaning: Identifier of the output produced by the current event.
- Possible values: String identifier or `null`, for example `out_003`, `doc_007`, `mem_entry_02`, `null`.
- Needed by:
  - `provenance`
  - `taint`
  - `temporal`
  - `recovery_governance`
- Example:
  - A retrieval event produces `output_ref = doc_005`.
  - A memory write produces `output_ref = mem_009`.
  - A final response produces `output_ref = answer_001`.

---

## provenance

- Meaning: Metadata describing where an input, output, argument, or state value came from and how it was produced.
- Possible values: JSON object or provenance record containing source type, source id, parent event, trust label, transformation history, and causal links.
- Needed by:
  - `provenance`
  - `taint`
  - `permission`
  - `recovery_governance`
  - `privilege_confinement`
- Example:
  - `provenance.source = retrieval_05` for an email body generated from web content.
  - `provenance.source = user_prompt_01` for an SQL query argument derived from the user prompt.
  - `provenance.source = trusted_tool_registry` for a tool invocation.

---

## source_id

- Meaning: Identifier of the original source that introduced a value into the trace.
- Possible values: String identifier, for example `user_prompt_001`, `retrieval_doc_005`, `memory_entry_007`, `agent_A_round_2`, `tool_output_004`.
- Needed by:
  - `provenance`
  - `taint`
  - `temporal`
  - `recovery_governance`
- Example:
  - `source_id = user_prompt_001` for user-controlled payload.
  - `source_id = retrieval_doc_005` for untrusted web content.
  - `source_id = agent_B_round_3_response` for a downstream multi-agent response.

---

## taint

- Meaning: Trust, contamination, sensitivity, or data-flow label attached to data or events.
- Possible values:
  - `trusted`
  - `untrusted`
  - `user_controlled`
  - `prompt_derived`
  - `retrieval_derived`
  - `classified`
  - `sensitive`
  - `sanitized`
  - `unknown`
- Needed by:
  - `taint`
  - `provenance`
  - `permission`
  - `privilege_confinement`
- Example:
  - `taint = user_controlled` for a prompt substring later passed to `subprocess.run`.
  - `taint = untrusted` for external web content inserted into context.
  - `taint = classified` for sensitive file content wrapped as `Classified[T]`.

---

## causal_path

- Meaning: Ordered causal chain linking source events, intermediate transformations, and the current event or sink.
- Possible values: List of event ids or edge records, for example `[e_001, e_004, e_007, e_010]`.
- Needed by:
  - `taint`
  - `provenance`
  - `temporal`
  - `recovery_governance`
- Example:
  - `user_prompt -> LLM_response -> tool_argument -> sqlite3.execute`.
  - `retrieval -> context_append -> plan_step -> send_email`.
  - `agent_A_response -> communication_edge -> agent_B_response`.

---

## approval.exists

- Meaning: Whether an approval event exists for the action, resource, target, or policy decision.
- Possible values:
  - `true`
  - `false`
  - `unknown`
- Needed by:
  - `permission`
  - `temporal`
  - `privilege_confinement`
  - `recovery_governance`
- Example:
  - `approval.exists = true` when the user approved sending an email.
  - `approval.exists = false` when a file delete is attempted with no confirmation event.
  - `approval.exists = unknown` when the trace does not preserve approval history.

---

## approval.status

- Meaning: Whether the action has user, policy, or governance approval.
- Possible values:
  - `approved`
  - `rejected`
  - `missing`
  - `unknown`
  - `expired`
  - `not_required`
- Needed by:
  - `permission`
  - `temporal`
  - `privilege_confinement`
  - `recovery_governance`
- Example:
  - `approval.status = approved` before executing an external transfer.
  - `approval.status = rejected` for a user-inspection decision.
  - `approval.status = unknown` when approval information was not logged.

---

## approval.target

- Meaning: The concrete action, resource, recipient, endpoint, file, memory target, or capability scope covered by an approval event.
- Possible values: Resource identifier, argument binding, event id, or structured object, for example `same_email`, `recipient:a@example.com`, `/project/data`, `host:api.example.com`, `capability:network:example.com`.
- Needed by:
  - `permission`
  - `temporal`
  - `privilege_confinement`
  - `provenance`
- Example:
  - Approval for `recipient = boss@example.com` cannot automatically approve `recipient = external@example.net`.
  - Approval for reading `/project` does not approve writing `/etc/passwd`.
  - Approval for `network:api.example.com` does not approve `network:evil.example`.

---

## allowed_action_set

- Meaning: The set of actions, capabilities, resources, endpoints, commands, or effects currently allowed by policy.
- Possible values: List, set, policy object, capability manifest, allowlist, or permission map, for example `[read_file, send_email]`, `{network: [api.example.com]}`, `{filesystem: {root: /project, mode: read}}`.
- Needed by:
  - `permission`
  - `privilege_confinement`
  - `state_pre_post`
  - `recovery_governance`
- Example:
  - A network action is allowed only if `host ∈ allowed_action_set.network_hosts`.
  - A command execution is allowed only if `command ∈ allowed_action_set.commands`.
  - A file write is denied if the current action set allows only file reads.

---

## policy_version

- Meaning: Identifier of the policy, manifest, rule set, sandbox profile, or privilege configuration used to evaluate the event.
- Possible values: String, semantic version, commit hash, manifest id, or config id, for example `policy_v1.2`, `manifest_sha256:abc123`, `sandbox_profile_04`.
- Needed by:
  - `privilege_confinement`
  - `permission`
  - `temporal`
  - `recovery_governance`
  - `provenance`
- Example:
  - `policy_version = manifest_v3` indicates which AgentManifest capability list was active.
  - A privilege-confinement rule checks whether `policy_version` changed before a broader action set was used.
  - An audit rule records which policy produced the allow/block decision.

---

## reversibility

- Meaning: Whether an action can be undone, compensated, retried, rolled back, or safely replanned after failure or violation.
- Possible values:
  - `reversible`
  - `irreversible`
  - `compensatable`
  - `retryable`
  - `hard`
  - `unknown`
- Needed by:
  - `recovery_governance`
  - `permission`
  - `state_pre_post`
  - `privilege_confinement`
- Example:
  - Sending an external email may be `irreversible` or `hard`.
  - A failed retrieval can be `retryable`.
  - A memory write may be `reversible` if the system supports delete/rollback.
  - A money transfer should be treated as `hard` or `irreversible`.

---

## decision

- Meaning: The verifier, policy evaluator, runtime monitor, or governance layer decision for the event.
- Possible values:
  - `allow`
  - `block`
  - `abort`
  - `retry`
  - `replan`
  - `rewrite`
  - `ask_user`
  - `escalate`
  - `log_only`
  - `safe`
  - `violation`
  - `unknown`
  - `inconsistent`
- Needed by:
  - `recovery_governance`
  - `permission`
  - `temporal`
  - `state_pre_post`
  - `privilege_confinement`
- Example:
  - `decision = block` when an untrusted prompt reaches a command-execution sink.
  - `decision = ask_user` when an external transfer requires inspection.
  - `decision = replan` when a tool fails but the task is recoverable.
  - `decision = unknown` when required evidence is missing.

---

# Summary matrix

| Evidence field | Main role | Primary rule classes |
|---|---|---|
| `event_id` | Identify one event | `temporal`, `provenance`, `taint`, `recovery_governance` |
| `trace_id` | Group events into one run | `temporal`, `provenance`, `taint`, `recovery_governance` |
| `step_id` | Logical order | `temporal`, `state_pre_post`, `provenance` |
| `timestamp` | Time/order evidence | `temporal`, `recovery_governance` |
| `parent_event` | Direct causal parent | `provenance`, `taint`, `temporal` |
| `phase` | Execution phase | `permission`, `temporal`, `state_pre_post` |
| `action_type` | High-level event category | `permission`, `provenance`, `taint`, `recovery_governance` |
| `action_name` | Concrete tool/action name | `permission`, `state_pre_post`, `taint` |
| `effect_type` | Semantic side effect | `permission`, `taint`, `recovery_governance` |
| `target_resource` | Affected resource | `permission`, `privilege_confinement`, `taint` |
| `typed_args` | Structured action arguments | `permission`, `taint`, `state_pre_post` |
| `tool_output` | Tool/API/model output | `state_pre_post`, `provenance`, `taint` |
| `status` | Execution status | `recovery_governance`, `permission`, `state_pre_post` |
| `error_type` | Failure/violation category | `recovery_governance`, `taint`, `permission` |
| `pre_state` | State before action | `state_pre_post`, `permission`, `privilege_confinement` |
| `post_state` | State after action | `state_pre_post`, `recovery_governance` |
| `input_refs` | Consumed inputs | `provenance`, `taint`, `temporal` |
| `output_ref` | Produced output | `provenance`, `taint`, `temporal` |
| `provenance` | Source and transformation history | `provenance`, `taint`, `permission` |
| `source_id` | Original source identifier | `provenance`, `taint` |
| `taint` | Trust/sensitivity label | `taint`, `provenance`, `permission` |
| `causal_path` | Ordered source-to-action chain | `taint`, `provenance`, `temporal` |
| `approval.exists` | Approval presence | `permission`, `temporal`, `privilege_confinement` |
| `approval.status` | Approval result | `permission`, `temporal`, `privilege_confinement` |
| `approval.target` | What approval covers | `permission`, `temporal`, `privilege_confinement` |
| `allowed_action_set` | Current allowed operations | `permission`, `privilege_confinement` |
| `policy_version` | Active policy/config version | `privilege_confinement`, `permission`, `recovery_governance` |
| `reversibility` | Recovery risk of action | `recovery_governance`, `permission` |
| `decision` | Runtime/verifier decision | `recovery_governance`, `permission`, `state_pre_post` |

---

# Phase 2 schema implication

A minimal normalized event schema should include all core identity/order/action fields:

```text
event_id, trace_id, step_id, timestamp, parent_event,
phase, action_type, action_name, effect_type, target_resource,
typed_args, status, input_refs, output_ref
```

Rule-driven optional evidence slots should be added when needed:

```text
tool_output, error_type, pre_state, post_state,
provenance, source_id, taint, causal_path,
approval.exists, approval.status, approval.target,
allowed_action_set, policy_version, reversibility, decision
```

The preservation check should return `unknown` instead of `safe` when a rule requires one of these evidence fields and the normalized event stream does not preserve it.
