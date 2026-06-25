# Paper ID: P05

## 1. Basic information

- Title: Tracking Capabilities for Safer Agents
- Year: 2026
- Venue / Source: ACM Conference on AI and Agentic Systems (CAIS '26), under the title *Securing Agents With Tracked Capabilities* / arXiv:2603.00991v2
- Main problem:
  LLM agents that interact with real-world tools can leak private information, cause unintended side effects, or be manipulated by prompt injection. Existing defenses such as allowlists, blocklists, and interactive confirmations are often coarse-grained and cannot guarantee information-flow safety across multiple agent steps.
- Main contribution:
  The paper proposes a programming-language-based safety harness for agents. Instead of calling tools directly, the agent generates Scala 3 code with capture checking. Capabilities are tracked in the type system, so the compiler can statically prevent unsafe behaviors such as unauthorized effects, capability leakage, and information leakage from classified data.

## 2. Agent trace / event abstraction

Paper uses which type of trace?

- Tool-call event: Yes. The agent submits Scala snippets via MCP tool calls such as `execute_scala`, `execute_in_session`, and `show_interface`.
- Message-action trace: Yes. The agent receives a user request, generates code, gets compiler/runtime output, fixes errors, and continues across turns.
- State transition: Yes. Stateful REPL sessions persist values and definitions across turns, while scoped capabilities expire after the block returns.
- Action trajectory: Yes. The workflow is: user request → agent-generated Scala code → compile/type-check → execute → return output or compiler error → retry if needed.
- Span / observability trace: Partial. The framework separates normal output observed by the agent from secure output delivered only to the user.
- Other: Capability-flow trace; type-checking trace; classified-data flow trace.

Important fields mentioned:

- action name: `execute_scala`, `create_repl_session`, `execute_in_session`, `requestFileSystem`, `access`, `readClassified`, `writeClassified`, `requestNetwork`, `httpGet`, `httpPost`, `requestExecPermission`, `exec`, `chat`, `println`, `displaySecurely`.
- arguments: Scala code snippet, session id, file root, file path, URL/host, command name, command arguments, classified value, prompt/message.
- output: compiler success/error, runtime result, redacted output, secure user-only output, classified wrapper, process result.
- state: REPL session state, capability scope, `Classified[T]` values, output channels, persistent variables, safe-mode compiler settings.
- timestamp / order: turn order, code-submission order, compile-before-execute order, capability lifetime inside request block, multi-turn REPL persistence.
- source / provenance: classified file path, untrusted cloud model, trusted local LLM, external tool/file/web source, normal output channel, secure output channel.
- approval: Not the main mechanism. The paper argues against relying mainly on interactive confirmations; safety is enforced by types and capabilities.
- error / status: compile accepted/rejected, capability outlives scope, unsafe closure captures capability, path outside root, unauthorized host/command, redacted output.
- user instruction: user task prompt; malicious direct prompt; social-engineering prompt; indirect prompt injection embedded in files or tool outputs.

## 3. Verification / policy / rule

Extracted rules:

### Rule 1

- Original description:
  Agent code cannot access filesystem resources directly. It must request a scoped `FileSystem` capability through `requestFileSystem(root)`, and file handles cannot escape the block.
- Normalized rule:
  WHEN agent code performs filesystem access
  REQUIRE active `FileSystem` capability scoped to an approved root
  AND requested path is inside that root
  AND file handle does not escape the capability scope
  ELSE reject at compile time or block at runtime.
- Rule class:
  Capability rule; filesystem confinement rule; lifetime/scope rule.
- Trigger:
  Before file read/write/delete/list operation, and at compile time when a `FileEntry` or `FileSystem` capability is returned or stored outside its scope.
- Condition:
  Missing `FileSystem` capability OR path outside root OR captured `FileSystem`/`FileEntry` escapes from `requestFileSystem` block.
- Required evidence:
  code snippet, requested path, root path, `FileSystem` capability id/scope, `FileEntry` capture set, compile diagnostic, runtime path-check result.
- Verdict / enforcement:
  Compile-time reject if capability escapes or is used without declared capture; runtime `SecurityException` if path is outside root.
- Possible backend:
  Scala 3 capture checker; capability-safe language; Hoare precondition over path scope; Python monitor equivalent; SMT set/path-prefix check.

### Rule 2

- Original description:
  Classified data is wrapped in `Classified[T]`. Its `map` method accepts only pure functions, so code inside `map` cannot print, write files, call network APIs, or perform other side effects.
- Normalized rule:
  WHEN transforming classified data
  REQUIRE transformation function has empty capability capture set
  ELSE reject.
- Rule class:
  Information-flow rule; local-purity rule; taint/data-leak prevention rule.
- Trigger:
  Calling `Classified.map` or `Classified.flatMap`.
- Condition:
  Closure captures any capability such as `IOCapability`, `FileEntry`, `FileSystem`, `Network`, or `ProcessPermission`.
- Required evidence:
  classified value id/type, closure body, inferred capture set, required pure function type `T -> U`, compiler diagnostic.
- Verdict / enforcement:
  Compile-time reject. Classified data cannot flow into side-effecting code.
- Possible backend:
  Scala 3 capture checker; static information-flow type system; taint monitor; non-interference checker.

### Rule 3

- Original description:
  Printing or converting classified values must not reveal plaintext to the untrusted cloud agent. `toString` on `Classified[T]` returns a redacted value, and secure output is delivered only to the user.
- Normalized rule:
  WHEN output value has type `Classified[T]`
  AND output channel is observable by the agent/cloud LLM
  THEN emit only redacted representation
  ELSE plaintext may be delivered only through secure user-only channel.
- Rule class:
  Output-channel rule; redaction rule; confidentiality rule.
- Trigger:
  `println`, `print`, `toString`, REPL output, or any return value sent back to the agent context.
- Condition:
  Value is classified and destination channel is normal/agent-visible.
- Required evidence:
  value type/classification, output channel id, recipient, redaction result, secure-channel status.
- Verdict / enforcement:
  Agent-visible output = `Classified(****)`; user secure output may contain plaintext.
- Possible backend:
  Runtime output-channel monitor; information-flow monitor; policy DSL; Python monitor.

### Rule 4

- Original description:
  Classified content can be processed by a trusted local LLM through a typed `chat(Classified[String]): Classified[String]` interface. The untrusted cloud agent never sees plaintext.
- Normalized rule:
  WHEN classified content is passed to an LLM
  REQUIRE LLM endpoint is trusted/local
  AND return value remains classified
  AND plaintext is not inserted into agent conversation context
  ELSE reject or mark violation.
- Rule class:
  Trusted-submodel rule; declassification-control rule; information-flow rule.
- Trigger:
  `chat` call with classified input.
- Condition:
  Classified input sent to untrusted/cloud model OR output returned as plain `String` OR plaintext enters normal output channel.
- Required evidence:
  model trust label, input classification, `chat` overload used, return type, output channel, context insertion event.
- Verdict / enforcement:
  Allow only `Classified[String] -> Classified[String]` path for sensitive content; reject or redact otherwise.
- Possible backend:
  Type checker; information-flow monitor; provenance/taint tracker; Python runtime policy.

### Rule 5

- Original description:
  Network access is granted only through `requestNetwork(hosts)`. HTTP operations require a `Network` capability and the destination host must be in the allowlist.
- Normalized rule:
  WHEN agent code performs network access
  REQUIRE active `Network` capability
  AND destination host ∈ allowedHosts
  ELSE block.
- Rule class:
  Network permission rule; egress-control rule; exfiltration-prevention rule.
- Trigger:
  `httpGet` or `httpPost`.
- Condition:
  No `Network` capability OR URL host not in allowedHosts.
- Required evidence:
  URL, parsed host, allowed host set, `Network` capability id/scope, code location, runtime decision.
- Verdict / enforcement:
  Allow approved host; block unauthorized host.
- Possible backend:
  Scala capability library; firewall/egress filter; policy DSL; SMT set-membership check.

### Rule 6

- Original description:
  Process execution is granted only through `requestExecPermission(commands)`. The agent can execute only explicitly allowed commands.
- Normalized rule:
  WHEN agent code executes a process
  REQUIRE active `ProcessPermission`
  AND command ∈ allowedCommands
  ELSE block.
- Rule class:
  Command-execution permission rule; sandbox/least-privilege rule.
- Trigger:
  `exec` or `execOutput`.
- Condition:
  No process permission OR command not allowed OR strict mode blocks file-operation commands.
- Required evidence:
  command name, arguments, working directory, timeout, allowed command set, strict-mode flag, process permission id.
- Verdict / enforcement:
  Allow approved command; block unauthorized process execution.
- Possible backend:
  Scala capability library; sandbox monitor; Hoare precondition; Python monitor; syscall policy.

### Rule 7

- Original description:
  Agent-generated Scala code is compiled in safe mode. Unsafe features such as unchecked casts, unsafe modules, unchecked annotations, and runtime reflection are forbidden.
- Normalized rule:
  WHEN agent submits code for execution
  REQUIRE safe mode, capture checking, explicit nulls, and mutation-effect tracking
  AND forbid unsafe language features
  ELSE reject before execution.
- Rule class:
  Static verification rule; language-safety rule; compile-before-execute rule.
- Trigger:
  Code submission through MCP tool call.
- Condition:
  Use of unchecked type casts, unsafe modules, `@unchecked`, runtime reflection, unsafe global APIs, or untracked effects.
- Required evidence:
  code snippet, compiler flags, imported language mode, safe-mode diagnostics, compile result.
- Verdict / enforcement:
  Compile-time reject; code is not executed.
- Possible backend:
  Scala 3 compiler with capture checking; static verifier; typed DSL compiler.

### Rule 8

- Original description:
  Capabilities cannot be forged, capability requirements cannot be forgotten, and all safety-relevant effects must be mediated by capabilities unless contained at runtime.
- Normalized rule:
  WHEN an agent program performs a safety-relevant effect
  REQUIRE the effect is represented by an explicit capability in the type system
  ELSE verifier must return `unknown` or reject the program as outside the harness.
- Rule class:
  Capability completeness rule; evidence-completeness rule; verifier-soundness rule.
- Trigger:
  During harness design, code validation, or when an unmediated API/library call is used.
- Condition:
  Effectful operation has no corresponding tracked capability OR unsafe library bypasses capability discipline.
- Required evidence:
  effect type, capability mapping, API surface, library safety annotation, safe/unsafe boundary proof, compile diagnostics.
- Verdict / enforcement:
  Reject in safe mode, wrap in a capability-safe API, or return `unknown` if the trace/backend lacks evidence.
- Possible backend:
  Capability-safe type checker; evidence-completeness checker; static API scanner; proof obligation checker.

## 4. What can be reused for our work?

- Abstraction reused:
  Code-as-action trace:

  ```text
  event = (
    event_id,
    session_id,
    code_snippet,
    compile_status,
    inferred_capabilities,
    requested_capability,
    resource_target,
    output_channel,
    classification_label,
    verdict
  )
  ```

  Classified-data flow trace:

  ```text
  classified_source
  -> Classified[T]
  -> pure transformation / trusted LLM
  -> Classified[U]
  -> secure output or classified sink
  ```

- Rule reused:
  1. Filesystem access must be scoped by `requestFileSystem`.
  2. Classified data can only be transformed by pure functions.
  3. Classified values must be redacted on agent-visible channels.
  4. Classified content may be processed only by trusted/local LLM and must remain classified.
  5. Network access requires explicit host capability.
  6. Process execution requires explicit command capability.
  7. Agent code must compile in safe mode before execution.
  8. Every safety-relevant effect must have a corresponding tracked capability, otherwise verdict should be `unknown` or `reject`.

- Evidence reused:
  code snippet, compiler diagnostics, capture set, capability id, capability scope, root path, file path, URL/host, command name, session id, output channel, classification label, trusted/untrusted model label, runtime exception, redaction result.

- Limitation:
  The framework gives strong static guarantees for code that stays inside the capability-safe Scala harness. It does not prove task correctness, does not cover timing/termination side channels, and external commands degrade to the safety of the allowlist or sandbox. It also requires building typed facades/wrappers for tools and ensuring capability completeness.

## Extraction note for our project

P05 should be used as an anchor paper for **provenance / taint / data-flow safety** and **verifier backend mapping**.

Main insight:

```text
Agent action = typed code snippet
Policy evidence = compiler-inferred capability capture set
Verifier = Scala 3 capture checker + safe-mode compiler
Verdict = compile accept / compile reject / runtime block
```

Why it is valuable for our V&V work:

1. It gives concrete rule templates for `required evidence`: capability, capture set, classification label, output channel, trusted model label.
2. It gives a backend mapping stronger than runtime monitoring: type-system enforcement.
3. It directly supports our `unknown` verdict: if an effect is not represented by a tracked capability, safety cannot be concluded.
4. It gives reusable rules for preventing secret leakage across multi-step agent traces.
