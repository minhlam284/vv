# Paper ID: P06

## 1. Basic information

- Title: Make Agent Defeat Agent: Automatic Detection of Taint-Style Vulnerabilities in LLM-based Agents
- Year: 2025
- Venue / Source: 34th USENIX Security Symposium (USENIX Security 2025)
- Main problem:
  LLM-based agents often pass user-controlled or LLM-generated content into security-sensitive operations without adequate validation. This creates taint-style vulnerabilities such as code injection, command injection, SQL injection, SSRF, and server-side template injection. Existing static approaches can produce many false positives/negatives because agent inputs are natural-language prompts and agent execution often involves indirect calls, LLM planning, tool selection, and dynamically constructed arguments.
- Main contribution:
  The paper proposes AgentFuzz, a directed greybox fuzzing framework for automatically detecting taint-style vulnerabilities in LLM-based agents. AgentFuzz generates functionality-specific natural-language seed prompts, schedules seeds using semantic and distance feedback from execution traces, mutates prompts to satisfy sink constraints, and uses vulnerability oracles to confirm whether tainted payloads reach security-sensitive sinks.

## 2. Agent trace / event abstraction

Paper uses which type of trace?

- Tool-call event: Yes. The paper models the agent as parsing the LLM response, extracting a planned action/tool, and invoking the corresponding component or tool with arguments.
- Message-action trace: Yes. The core trace is user prompt -> assembled prompt -> LLM response -> parsed action -> component/tool invocation -> result.
- State transition: Partial. The fuzzing process tracks seed pool state, feedback state, selected seed, mutation history, execution path, and vulnerability oracle status.
- Action trajectory: Yes. The paper traces prompt execution through components, call chains, indirect calls, conditional branches, and sinks.
- Span / observability trace: Partial. AgentFuzz instruments runtime execution to record stack frames, method calls, distances to sinks, sink parameters, and whether payloads reach sinks.
- Other: Taint-style source-to-sink trace; directed fuzzing trace; semantic execution trace; prompt-to-argument mapping trace.

Important fields mentioned:

- action name: LLM-planned tool/component name, method name, class name, sink function such as `eval`, `exec`, `subprocess.run`, `requests.get`, `jinja2.Environment.from_string`, `sqlite3.Cursor.execute`.
- arguments: user prompt, LLM response content, tool/component argument, sink argument, mutated payload, solved constraint value.
- output: agent result, tool result, execution trace, feedback score, vulnerability PoC, sink/oracle result.
- state: seed pool, call chain, control-flow path, runtime stack frame, selected mutator, feedback score, vulnerability oracle state.
- timestamp / order: prompt submission order, LLM planning order, component invocation order, execution trace order, sink reachability order, fuzzing iteration order.
- source / provenance: user prompt as source, prompt substring that maps to runtime argument, LLM response, tool/component argument, sink parameter, payload provenance.
- approval: No human approval mechanism is central. The paper focuses on automated vulnerability detection rather than approval enforcement.
- error / status: sink reached/not reached, constraint satisfied/unsatisfied, oracle success/failure, exploitability confirmed, false positive/false negative, CVE assignment.
- user instruction: Natural-language user prompt, malicious crafted prompt, prompt injection prefix, functionality-specific seed prompt.

## 3. Verification / policy / rule

Extracted rules:

### Rule 1

- Original description:
  Taint-style vulnerabilities occur when malicious prompt content flows through the LLM response and tool/component arguments into security-sensitive operations without adequate sanitization.
- Normalized rule:
  WHEN source = user_prompt OR LLM_response_derived_from_user_prompt
  AND data flows into security_sensitive_sink
  REQUIRE sanitizer/validator before sink
  ELSE violation.
- Rule class:
  Taint-flow rule; source-to-sink rule; input-sanitization rule.
- Trigger:
  Before invoking a security-sensitive sink such as code execution, command execution, SQL execution, SSRF-prone request, or template rendering.
- Condition:
  `tainted(source=user_prompt)` reaches `sink_argument` AND no adequate sanitizer exists on the path.
- Required evidence:
  source prompt, LLM response, selected tool/component, runtime argument, sink function, sink argument, data-flow/provenance link, sanitizer status, execution order.
- Verdict / enforcement:
  Violation if tainted payload reaches sink unsanitized. In AgentFuzz, verdict is oracle success and PoC generated. In our verifier, verdict should be `unsafe` or `violation`.
- Possible backend:
  Taint monitor; Python runtime monitor; CodeQL/static taint analysis; dynamic instrumentation; SMT/constraint solver for path constraints.

### Rule 2

- Original description:
  Security-sensitive operations should be modeled as sinks, including code injection, command injection, SSRF, SSTI, and SQL injection sinks.
- Normalized rule:
  WHEN function_call.method ∈ predefined_sink_set
  REQUIRE sink-specific validation and taint evidence
  ELSE mark sink call as high-risk.
- Rule class:
  Sink classification rule; vulnerability oracle rule; security-sensitive operation rule.
- Trigger:
  Function call to a predefined sink.
- Condition:
  Called function matches sink signature, e.g. `builtins.eval`, `builtins.exec`, `subprocess.run`, `os.system`, `requests.get/post/request`, `jinja2.Environment.from_string`, `render_template_string`, `sqlite3.Cursor.execute`, `sqlalchemy.Session.execute`.
- Required evidence:
  package, class, method, parameters, sink type, callsite id, runtime stack frame, sink argument values.
- Verdict / enforcement:
  Mark as high-risk sink; require further taint/sanitization check; fuzzing oracle monitors whether payload reaches sink.
- Possible backend:
  CodeQL sink detector; static sink registry; Python audit hook; sys.settrace; runtime monitor.

### Rule 3

- Original description:
  The LLM can select a vulnerable component based on natural-language semantics in class/method names, and the selected component may forward user-controlled arguments to a sink.
- Normalized rule:
  WHEN LLM selects a component/tool
  AND component call chain reaches a sink
  REQUIRE semantic alignment and argument provenance to be recorded
  ELSE evidence is incomplete.
- Rule class:
  Tool-selection provenance rule; semantic trace rule; evidence-completeness rule.
- Trigger:
  After LLM response is parsed into a tool/component action.
- Condition:
  Selected component or method appears on a call chain to a sink OR execution trace is semantically close to a vulnerable call chain.
- Required evidence:
  user prompt, LLM response, parsed action/tool name, class/method names in execution trace, target call chain, semantic score, distance score.
- Verdict / enforcement:
  For fuzzing: prioritize the seed if semantic/distance score is high. For verification: return `unknown` if tool-selection provenance or trace evidence is missing.
- Possible backend:
  Python trace monitor; semantic classifier; CodeQL call-chain extraction; evidence-completeness checker.

### Rule 4

- Original description:
  To trigger taint-style vulnerabilities, the prompt must satisfy both semantic requirements for invoking the vulnerable component and code constraints along the path to the sink.
- Normalized rule:
  WHEN prompt-derived argument reaches a branch guarding a sink
  AND branch condition is unsatisfied
  USE constraint evidence to determine required argument value
  AND map solved value back to the prompt segment.
- Rule class:
  Constraint-satisfaction rule; prompt-to-argument mapping rule; path feasibility rule.
- Trigger:
  During execution when trace diverges from the expected path to the sink at a conditional branch.
- Condition:
  There exists an unsatisfied condition on a prompt-derived runtime argument before the sink.
- Required evidence:
  expected path to sink, actual execution trace, unsatisfied condition, symbolic variable, concrete runtime value, solved constraint, prompt substring mapping.
- Verdict / enforcement:
  For AgentFuzz: mutate prompt to satisfy constraint. For our verifier: record required evidence for path feasibility; if missing, verdict should be `unknown`.
- Possible backend:
  Concolic execution; Z3 solver; Python symbolic executor; prompt-to-argument mapper.

### Rule 5

- Original description:
  Prompt-to-Argument Mapping uses overlap between the user prompt and runtime argument to identify which prompt segment controls the component argument.
- Normalized rule:
  WHEN runtime argument contains data derived from user prompt
  REQUIRE a causal/provenance link from prompt substring to argument value
  ELSE taint evidence is incomplete.
- Rule class:
  Provenance rule; argument taint rule; causal-link rule.
- Trigger:
  When a component argument or sink argument is observed at runtime.
- Condition:
  Runtime argument has substring/value overlap with the user prompt, or is generated by LLM from prompt content.
- Required evidence:
  prompt text, argument value, longest common substring match, replacement segment, sink argument, payload insertion point.
- Verdict / enforcement:
  Evidence complete if prompt substring can be mapped to argument/sink. Otherwise return `unknown` or require conservative taint.
- Possible backend:
  Taint tracker; LCSM-based provenance mapper; dynamic monitor; causal-link checker.

### Rule 6

- Original description:
  If a payload reaches the sink and the sink oracle confirms execution or dangerous behavior, AgentFuzz reports a vulnerability PoC.
- Normalized rule:
  WHEN payload inserted into tainted prompt segment reaches sink argument
  AND sink-specific oracle observes execution/effect
  THEN report exploitable vulnerability.
- Rule class:
  Vulnerability oracle rule; exploitability rule; dynamic-verdict rule.
- Trigger:
  Sink invocation during fuzzing or runtime verification.
- Condition:
  Payload value reaches sink and oracle condition succeeds, e.g. code execution observed, command executed, SSRF request attempted, SQL query executed with payload, template payload rendered.
- Required evidence:
  payload, sink type, sink argument, runtime hook event, oracle result, execution effect, PoC prompt.
- Verdict / enforcement:
  `unsafe` / vulnerability found / PoC generated.
- Possible backend:
  Runtime hook oracle; sys.settrace; sys.addaudithook; eBPF/audit logs; Python monitor.

### Rule 7

- Original description:
  Prompt-based guardrails and LLM refusal are not sufficient because prompt injection can bypass them, and taint-style vulnerabilities may still be exploitable.
- Normalized rule:
  WHEN security-sensitive operation depends on prompt/LLM output
  DO NOT rely only on natural-language prompt policy
  REQUIRE code-level sanitizer, sandbox, or external verifier
  ELSE unsafe or unknown.
- Rule class:
  Guardrail-insufficiency rule; enforcement rule; semantic-gap rule.
- Trigger:
  Before executing a sensitive operation whose argument is generated from prompt/LLM output.
- Condition:
  Only defense is system prompt instruction or LLM refusal, with no code-level validation/sandbox/monitor.
- Required evidence:
  system prompt constraints, sanitizer existence, sandbox configuration, sink argument, prompt injection evidence, policy decision.
- Verdict / enforcement:
  Mark as insufficient protection; require sanitizer/isolation or return `unknown` rather than `safe`.
- Possible backend:
  Evidence-completeness checker; policy monitor; sandbox verifier; taint-flow checker.

### Rule 8

- Original description:
  Second-order vulnerabilities can occur when a prompt payload is stored and later flows into a sink in a subsequent interaction.
- Normalized rule:
  WHEN tainted prompt content is stored in agent state
  AND later retrieved into a security-sensitive sink
  REQUIRE cross-turn taint provenance
  ELSE potential second-order violation.
- Rule class:
  Cross-turn taint rule; stateful provenance rule; second-order vulnerability rule.
- Trigger:
  State write from prompt/LLM output; later state read into sink.
- Condition:
  Stored value originated from user prompt and reaches sink in a later interaction/session.
- Required evidence:
  session id, prompt id, stored value, storage location, retrieval event, sink argument, cross-turn causal link, timestamp/order.
- Verdict / enforcement:
  Violation if stored tainted payload reaches sink unsanitized; `unknown` if cross-turn provenance is not preserved.
- Possible backend:
  Stateful taint tracker; replay monitor; temporal database/log verifier; LTL monitor over event traces.

## 4. What can be reused for our work?

- Abstraction reused:
  Taint-style agent trace:

  ```text
  user_prompt
  -> assembled_prompt
  -> LLM_response
  -> parsed_action(tool/component)
  -> component_argument
  -> branch_condition/path_constraint
  -> security_sensitive_sink(argument)
  -> oracle/verdict
  ```

  Runtime event schema:

  ```text
  event = (
    event_id,
    prompt_id,
    session_id,
    action_name,
    component_class,
    method_name,
    argument_value,
    source_prompt_span,
    call_chain,
    sink_type,
    sink_argument,
    sanitizer_status,
    oracle_status,
    verdict
  )
  ```

- Rule reused:
  1. Unsanitized prompt-derived data must not reach security-sensitive sinks.
  2. Sensitive sinks must be explicitly classified and monitored.
  3. Tool/component selection needs provenance from LLM response to runtime call.
  4. Runtime arguments need prompt-to-argument provenance mapping.
  5. Path constraints before sinks are required evidence for exploitability.
  6. Payload reaching sink plus oracle success gives `unsafe` verdict.
  7. Prompt-only guardrails are insufficient evidence for safety.
  8. Cross-turn stored taint must be preserved to detect second-order vulnerabilities.

- Evidence reused:
  user prompt, prompt substring/span, LLM response, parsed tool/action, class and method names, call chain, execution trace, CFG distance, semantic score, runtime stack frame, branch condition, runtime variable values, constraint solution, sanitizer status, sink signature, sink argument, payload, oracle result, PoC prompt, session/order for second-order flows.

- Limitation:
  AgentFuzz is a vulnerability detection and fuzzing framework, not a runtime enforcement framework. It focuses mainly on single-prompt taint-style vulnerabilities and may miss complex second-order/cross-turn cases. It also depends on predefined sink lists, instrumentation, LLM-assisted semantic scoring, and effective prompt mutation. For our V&V work, we should reuse its trace/evidence model and taint rules, but pair them with explicit verifier verdicts such as `safe`, `unsafe`, and `unknown`.

## Extraction note for our project

P06 should be used as an anchor paper for **provenance / taint / data-flow safety** and **trace-based assurance**.

Main insight:

```text
taint-style vulnerability in agents =
user prompt payload
-> LLM planned action
-> tool/component argument
-> security-sensitive sink
without sanitizer
```

Why it is valuable for our V&V work:

1. It gives concrete source-to-sink evidence requirements for verifier rules.
2. It shows why trace abstraction must preserve `prompt -> LLM response -> action -> argument -> sink` causal links.
3. It gives sink categories that can become our rule templates: CODEi, CMDi, SQLi, SSRF, SSTI.
4. It supports an `unknown` verdict: if prompt-to-argument mapping, sanitizer status, or sink argument evidence is missing, the verifier should not claim safety.
5. It complements P05: P05 prevents taint leaks by type checking, while P06 detects taint-style vulnerabilities dynamically through fuzzing and runtime oracles.
