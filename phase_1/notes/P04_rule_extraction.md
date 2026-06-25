# Paper ID: P04

## 1. Basic information

- Title: Toward Securing AI Agents Like Operating Systems
- Year: 2026
- Venue / Source: arXiv:2605.14932v1
- Main problem:
  OpenClaw-style LLM agents are increasingly integrated with local files, shell commands, email/calendar, web services, third-party skills, persistent memory, credentials, and user accounts. This creates a broad attack surface. Existing protections often rely too much on LLM-level guardrails or fragmented runtime checks, while many agent components share the same trust domain.
- Main contribution:
  The paper analyzes AI agents through an operating-system security lens. It maps agent components to OS concepts, derives a unified OpenClaw-style agent architecture, maps OS defenses to agent defenses, and evaluates four agents—OpenClaw, IronClaw, Nanobot, and NemoClaw—against realistic attacks. The key insight is that agents need OS-like protection mechanisms: isolation, privilege separation, sandboxing, network filtering, logging, and least privilege.

## 2. Agent trace / event abstraction

Paper uses which type of trace?

- Tool-call event: Yes. The paper models agents as systems where the LLM repeatedly emits tool calls, the runtime parses tool-call arguments, executes tools, and appends tool results back to the message list.
- Message-action trace: Yes. The agent execution model is based on a message list containing system prompt, user prompt, LLM outputs, tool calls, and tool results.
- State transition: Partial. The paper distinguishes runtime core, agent core, persistent state, ephemeral state, session store, memory, logs, and task queues. It does not define a formal transition system but clearly models changes across agent execution steps.
- Action trajectory: Yes. The paper uses an iterative agentic execution loop: input preparation → iterative generation/tool execution → response emission.
- Span / observability trace: Partial. The case study uses eBPF monitoring to observe system events such as file writes, network access, process creation, and Docker/container activity.
- Other: OS-inspired architecture; security-boundary abstraction; attack-vector trace; runtime monitor trace.

Important fields mentioned:

- action name: tool call, skill execution, file read/write, web fetch, shell command, memory update, message send, configuration change, log deletion.
- arguments: file path, URL/domain, shell command, skill identifier, channel/account id, memory file, configuration file, log file.
- output: tool result, final agent response, emitted message, fetched content, written file, monitor event.
- state: message list `M`, session context `C_e`, memory `M_e`, persistent state, ephemeral state, agent identity, credentials, logs, task queue, installed tools/skills.
- timestamp / order: event loop order, tool-call sequence, before/after tool execution, session history, log order, monitor event order.
- source / provenance: peer/channel identity, skill provenance, tool provenance, untrusted web/file content, context fragment provenance, user/session origin.
- approval: Not central in the implementation. The paper recommends permission-style approval and least privilege for skills/tools, but evaluates mostly allow/block behavior rather than explicit user approval flow.
- error / status: attack success/failure, allowed/blocked, sandbox violation, logging/audit evasion, unauthorized access, exfiltration.
- user instruction: incoming event `e`, user prompt `p_u`, peer message, malicious prompt/instruction, scheduled event.

## 3. Verification / policy / rule

Extracted rules:

### Rule 1

- Original description:
  Agents should not mix trusted and untrusted data in a shared LLM context without isolation. Current agents often feed trusted and untrusted data into the same context, violating process isolation.
- Normalized rule:
  WHEN untrusted input/tool output is added to the agent context
  AND the context contains privileged instructions, credentials, private session data, or security-relevant state
  REQUIRE isolation, provenance labeling, or sanitization before the data can influence later tool calls
  ELSE violation or unknown.
- Rule class:
  Process isolation rule; taint rule; context-integrity rule.
- Trigger:
  Before appending external data, tool output, skill output, or web/file content to the message list.
- Condition:
  `input.source = untrusted` AND `context.scope contains trusted/control data` AND no isolation/sanitization/provenance label exists.
- Required evidence:
  source of context fragment, trust label, message-list position, parent event, target context scope, downstream tool-call link, sanitization status.
- Verdict / enforcement:
  Block, sanitize, isolate into scoped context, or mark as tainted and restrict downstream tool calls.
- Possible backend:
  Taint monitor; Python context monitor; information-flow control; LTL monitor over `tainted_input -> no_privileged_action`.

### Rule 2

- Original description:
  Tools should be invoked through controlled interfaces. A malicious skill should not be able to redirect, replace, or tamper with trusted tools through PATH manipulation, helper-script overwrite, or arbitrary command injection.
- Normalized rule:
  WHEN the agent invokes a tool
  REQUIRE tool identity is immutable, provenance is trusted, and arguments are validated
  ELSE block tool invocation.
- Rule class:
  Tool provenance rule; interface mediation rule; hardware-interface/syscall-like rule.
- Trigger:
  Before tool invocation.
- Condition:
  tool implementation is not registered/trusted OR tool path changed OR arguments contain injected commands OR tool provenance is missing.
- Required evidence:
  tool name, tool id/path, tool provenance, registration record, arguments, caller skill, environment variables, previous modification events.
- Verdict / enforcement:
  Allow trusted invocation; block or require review if tool provenance or argument integrity is missing.
- Possible backend:
  Python monitor; signed-tool registry; Hoare precondition; SMT check over registered tool set.

### Rule 3

- Original description:
  Executable skills/tools should run in a sandbox with limited filesystem, network, environment, and credential access. Sandboxing is only effective when all relevant effects are mediated.
- Normalized rule:
  WHEN skill/tool executes
  REQUIRE sandbox scope includes only explicitly allowed filesystem paths, network endpoints, environment variables, and credentials
  ELSE block execution or deny resource access.
- Rule class:
  Sandboxing rule; resource confinement rule; least-privilege rule.
- Trigger:
  Skill/tool process start; resource access inside skill/tool.
- Condition:
  requested resource is outside sandbox policy OR execution escapes mediated environment.
- Required evidence:
  skill id, tool id, process id, sandbox id, allowed filesystem paths, allowed domains, allowed env vars, credential scope, resource access request.
- Verdict / enforcement:
  Allow inside sandbox; block outside sandbox; terminate escaped process.
- Possible backend:
  Container/WASM sandbox; eBPF monitor; Python policy checker; OS-level access-control monitor.

### Rule 4

- Original description:
  Agents need application-level privileges for skills/tools/tasks. A weather skill should not access private email; a spreadsheet skill should not get unrestricted shell access.
- Normalized rule:
  WHEN a skill/tool requests an operation
  REQUIRE operation is covered by its declared permission and the current task context
  ELSE deny.
- Rule class:
  Permission rule; privilege-separation rule; least-privilege rule.
- Trigger:
  Tool call, skill installation, or permission-sensitive operation.
- Condition:
  requested capability not declared OR requested capability exceeds task scope.
- Required evidence:
  skill id, tool name, declared permissions, requested action, target resource, task context, user/session scope.
- Verdict / enforcement:
  Allow if permission is declared and scoped; deny otherwise.
- Possible backend:
  Permission DSL; Python monitor; Hoare precondition; SMT set-membership rule.

### Rule 5

- Original description:
  Agents should restrict network and messaging egress. An attacker should not be able to make an agent fetch arbitrary URLs or send messages to arbitrary peers.
- Normalized rule:
  WHEN agent/tool/skill attempts network access or message sending
  REQUIRE destination endpoint/account is allowlisted for the current skill and task
  ELSE block.
- Rule class:
  Network filtering rule; exfiltration-prevention rule; communication-integrity rule.
- Trigger:
  Web fetch, HTTP request, API call, email/message send, webhook call.
- Condition:
  target URL/domain/account/channel is not in allowlist OR channel is not authorized for this session.
- Required evidence:
  destination URL/domain/account, tool/skill id, session id, allowlist, message payload class, source context/provenance.
- Verdict / enforcement:
  Allow approved endpoint; block arbitrary endpoint; log attempted egress.
- Possible backend:
  Firewall/egress filter; Python monitor; policy DSL; LTL monitor over `send -> authorized_destination`.

### Rule 6

- Original description:
  Agent logs are security-relevant and should not be writable or deletable by arbitrary tools/skills. Current agents often store JSON logs that can be overwritten by malicious tools.
- Normalized rule:
  WHEN a tool/skill attempts to modify logs or audit records
  REQUIRE caller is trusted runtime logger and operation is append-only
  ELSE block and raise tampering alert.
- Rule class:
  Audit integrity rule; system logging rule; tamper-resistance rule.
- Trigger:
  File write/delete/truncate operation targeting logs or audit files.
- Condition:
  caller is not runtime logger OR operation is not append-only OR target file is protected log.
- Required evidence:
  caller id, file path, operation type, log file classification, previous log hash/sequence id, append-only status.
- Verdict / enforcement:
  Allow runtime append; block delete/truncate/overwrite; emit tampering verdict.
- Possible backend:
  eBPF monitor; append-only storage; Python file-policy monitor; integrity checker.

### Rule 7

- Original description:
  Agent memory requires provenance tracking and sanitization. Malicious injected data or tool errors may be persisted and affect future behavior.
- Normalized rule:
  WHEN memory is written, compacted, or promoted from ephemeral state to persistent state
  REQUIRE source provenance, trust label, and sanitization check
  ELSE return unknown or block memory write.
- Rule class:
  Provenance rule; memory-safety rule; taint rule.
- Trigger:
  Memory write, memory compaction, session-to-memory promotion.
- Condition:
  memory content comes from untrusted source OR provenance is missing OR content contains instruction-like text that may steer future behavior.
- Required evidence:
  memory target, content source, parent event, trust label, sanitization result, user/session owner, write timestamp/order.
- Verdict / enforcement:
  Allow safe memory write; sanitize; isolate as untrusted memory; block if provenance missing.
- Possible backend:
  Provenance monitor; taint tracker; Python evidence-completeness checker.

### Rule 8

- Original description:
  Natural-language data and instructions are mixed in LLM contexts. Prompt injection defenses are not reliable enforcement boundaries, so untrusted data should be labeled and mediated externally.
- Normalized rule:
  WHEN untrusted data contains instruction-like content
  AND a downstream privileged action may be triggered
  REQUIRE external policy check independent of the LLM
  ELSE violation or unknown.
- Rule class:
  Data-execution-prevention-like rule; taint rule; external enforcement rule.
- Trigger:
  Before executing a privileged action that depends on untrusted content.
- Condition:
  action causally depends on untrusted content AND no external policy approval exists.
- Required evidence:
  untrusted input source, causal link to action, action type, target resource, policy decision, trust label.
- Verdict / enforcement:
  Block, ask for review, or mark unknown if causal/provenance evidence is incomplete.
- Possible backend:
  Information-flow monitor; taint monitor; Python policy checker; LTL/SMT rule over causal links.

## 4. What can be reused for our work?

- Abstraction reused:
  OS-inspired normalized event profile:
  `event = (event_id, session_id, actor, source, trust_label, action_type, target_resource, arguments, state_scope, provenance, policy_decision, status)`.

  The agentic execution loop can be reused as a trace skeleton:
  `incoming event → context construction → LLM output → tool call → tool result → memory/log update → final response`.

- Rule reused:
  1. Isolate untrusted context before it influences privileged action.
  2. Validate tool provenance and immutable tool registration.
  3. Run tools/skills under sandboxed least privilege.
  4. Enforce skill/tool permissions by declared capability.
  5. Restrict network/messaging egress.
  6. Protect logs with append-only/tamper-evident policy.
  7. Require provenance before memory write.
  8. Treat prompt-injection/data-instruction mixing as an information-flow problem.

- Evidence reused:
  actor/session id, peer/channel id, tool/skill id, tool provenance, source trust label, message order, context scope, file path, URL/domain, command, process id, sandbox id, permission set, allowlist, memory target, log target, policy verdict, eBPF/monitor event.

- Limitation:
  This paper is mainly a systems/security analysis and case study, not a formal verification framework. It does not define a DSL, LTL specification, SMT encoding, or verifier-neutral schema. Many rules are recommendations derived from OS principles and attack observations. For our work, the value is in extracting security rule classes and required evidence, then mapping them into our Rule IR and preservation-aware event abstraction.

## Extraction note for our project

P04 should be used as an anchor paper for **agent runtime governance**, **tool/skill boundary safety**, and **provenance/taint evidence requirements**.

Main insight:

```text
AI agent runtime ≈ operating-system kernel
LLM ≈ untrusted user
Tools ≈ system calls
Skills ≈ programs
Context/memory/logs/files/network ≈ protected resources
```

Map to our normalized event stream:

```text
incoming_message(peer, channel, trust_label)
context_build(input_refs, memory_refs, skill_refs)
llm_step(message_list_id, output)
tool_call(tool_id, args, caller_skill, provenance)
resource_access(effect_type, target_resource, concrete_target)
policy_decision(allow/block/unknown, reason)
memory_write(content_ref, provenance, trust_label)
log_event(event_ref, append_only_status)
final_response(output_refs)
```

What our work can add beyond this paper:

1. Convert the OS-security recommendations into explicit verifier-neutral rules.
2. Define required evidence for each rule class.
3. Add preservation checking: if context provenance, tool provenance, permission set, or causal link is missing, the verifier should return `unknown`, not `safe`.
4. Map OS-inspired mechanisms to verifier backends such as Python monitor, LTL, Hoare contract, SMT, or policy DSL.
