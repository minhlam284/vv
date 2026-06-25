# Paper ID: P03

## 1. Basic information

- Title: AgentBound: Securing Execution Boundaries of AI Agents
- Year: 2026
- Venue / Source: ACM FSE 2026 / Proc. ACM Software Engineering, Vol. 3, No. FSE, Article FSE096 / arXiv:2510.21236v3
- Main problem:
  MCP servers used by AI agents often execute as local processes with broad host privileges. If an MCP server is malicious, compromised, or manipulated through prompt injection / tool poisoning / rug pull / application-level attacks, it can read files, access environment variables, contact arbitrary network endpoints, or execute system commands. Current MCP ecosystems largely follow a trust-by-default model and lack enforceable least-privilege boundaries.
- Main contribution:
  AgentBound proposes the first access control framework for MCP servers. It has two core components: AgentManifest, a declarative access-control policy that lists allowed capabilities, and AgentBox, a policy enforcement engine that runs MCP servers inside an isolated sandbox/container. The framework enforces default-deny, least-privilege execution without requiring MCP server modifications.

## 2. Agent trace / event abstraction

Paper uses which type of trace?

- Tool-call event: Yes. The paper focuses on MCP tool/resource access and the server-side operations triggered by agent tool calls.
- Message-action trace: Partial. MCP uses JSON-RPC communication between host/client/server, but the paper is not mainly about full message replay.
- State transition: Partial. Runtime permission state changes when generic capabilities are instantiated into concrete runtime permissions.
- Action trajectory: Partial. Agent execution involves a loop of LLM response → tool call → MCP server action → result, but the paper mainly abstracts the boundary as capability-controlled execution.
- Span / observability trace: No. It is not an observability/span tracing paper.
- Other: Capability manifest + sandbox enforcement trace; MCP server resource-access event.

Important fields mentioned:

- action name: MCP tool call, filesystem read/write/delete, network client/server access, environment read/write, system exec, process interaction, clipboard read/write, peripheral access.
- arguments: file path, directory path, URL/hostname/IP, environment variable name, command/subprocess, runtime permission scope.
- output: tool result, file content, network response, blocked/allowed access, final agent result.
- state: declared capabilities in AgentManifest, instantiated runtime permissions, sandbox/container state, allowed mounts, network allow-list, environment whitelist.
- timestamp / order: runtime order is implicit: manifest declaration → user consent/runtime permission instantiation → server launch in sandbox → MCP operation → allow/block decision.
- source / provenance: manifest source, developer-declared capability, auto-generated capability rationale, user-granted runtime permission, MCP server/tool identity.
- approval: Yes. User consent is required to instantiate runtime permissions from generic capabilities.
- error / status: allowed, blocked, aborted, prevented, non-preventable, sandbox violation, missing capability.
- user instruction: The user instruction causes the agent to call MCP tools; however, AgentBound enforces at the MCP server boundary regardless of LLM reasoning.

## 3. Verification / policy / rule

Extracted rules:

### Rule 1

- Original description:
  By default, MCP servers should not inherit full host privileges. An MCP server can only access resources explicitly declared in its manifest and granted as runtime permissions.
- Normalized rule:
  WHEN an MCP server attempts a resource access
  AND requested capability is not declared in AgentManifest
  OR no corresponding runtime permission has been granted
  THEN block or abort execution.
- Rule class:
  Permission rule; least-privilege rule; access-control rule.
- Trigger:
  MCP server attempts filesystem, network, environment, process, or system-resource access.
- Condition:
  `requested_capability ∉ manifest.capabilities` OR `requested_resource ∉ granted_runtime_permissions`.
- Required evidence:
  server id, tool/action name, requested capability, concrete resource target, manifest capability list, runtime permission list, user consent status, access mode.
- Verdict / enforcement:
  Verdict = allow if declared and granted; otherwise block/abort.
- Possible backend:
  Python monitor; policy DSL; access-control checker; SMT set-membership check; Hoare precondition; sandbox enforcement.

### Rule 2

- Original description:
  If an MCP server tries to access environment variables such as API keys without declaring `mcp.ac.system.env.read`, access must be denied.
- Normalized rule:
  WHEN effect_type = `read`
  AND target_resource = `environment_variable`
  REQUIRE capability `mcp.ac.system.env.read`
  AND runtime permission for the specific variable name
  ELSE block.
- Rule class:
  Permission rule; secret-protection rule; data-confidentiality rule.
- Trigger:
  Environment variable read operation inside MCP server.
- Condition:
  The environment variable is not listed in the granted environment whitelist, or the manifest does not declare environment-read capability.
- Required evidence:
  action name, effect type, environment variable name, declared capability, granted variable whitelist, server id, user consent.
- Verdict / enforcement:
  Allow only whitelisted environment variables; otherwise block access or abort execution.
- Possible backend:
  Python monitor; Hoare precondition; SMT authorization predicate; container environment whitelist.

### Rule 3

- Original description:
  If an MCP server with network capability tries to contact a malicious or undeclared host, AgentBox blocks outbound traffic because network access is restricted to manifest/user-approved endpoints.
- Normalized rule:
  WHEN effect_type = `network_connect`
  AND target_host not in allowed_network_endpoints
  THEN block network request.
- Rule class:
  Permission rule; network confinement rule; exfiltration-prevention rule.
- Trigger:
  Outbound network request from MCP server.
- Condition:
  Destination hostname/IP/URL is not in the allowed network list derived from manifest and runtime permission.
- Required evidence:
  action name, requested URL/host/IP, declared network capability, allowed endpoint list, runtime permission, server id, DNS/IP resolution, block/allow status.
- Verdict / enforcement:
  Block unauthorized outbound network traffic; allow only whitelisted endpoints.
- Possible backend:
  Python monitor; policy DSL; firewall/iptables enforcement; SMT predicate over allowed endpoint set.

### Rule 4

- Original description:
  If a filesystem MCP server only has read access to a codebase directory, it must not overwrite files or read files outside the approved directory.
- Normalized rule:
  WHEN effect_type ∈ {read, write, delete}
  AND target_resource = `filesystem`
  REQUIRE matching filesystem capability
  AND path within approved scope
  AND access mode permits the requested operation
  ELSE block.
- Rule class:
  Permission rule; filesystem confinement rule; integrity/confidentiality rule.
- Trigger:
  File read/write/delete operation by MCP server.
- Condition:
  Requested path is outside allowed mount/scope, or requested access mode exceeds granted permission.
- Required evidence:
  action name, effect type, file path, directory scope, read/write/delete mode, declared capability, runtime permission, mount configuration, user consent.
- Verdict / enforcement:
  Allow scoped read/write/delete only if permitted; otherwise block.
- Possible backend:
  Python monitor; Hoare contract; path-policy checker; container mount enforcement; SMT path prefix check.

### Rule 5

- Original description:
  If an MCP server tries to execute OS commands without `mcp.ac.system.exec`, execution should be denied.
- Normalized rule:
  WHEN effect_type = `execute`
  AND target_resource = `system_command`
  REQUIRE capability `mcp.ac.system.exec`
  AND approved command/runtime scope
  ELSE block.
- Rule class:
  Permission rule; system-command confinement rule; privilege-escalation prevention.
- Trigger:
  Subprocess/shell/CLI execution by MCP server.
- Condition:
  Missing system-exec capability or requested command outside approved runtime permission.
- Required evidence:
  command string, process invocation, declared capability, runtime permission, server id, sandbox status, access decision.
- Verdict / enforcement:
  Block execution if not explicitly permitted.
- Possible backend:
  Python runtime monitor; syscall/container monitor; policy DSL; Hoare precondition; SMT authorization predicate.

### Rule 6

- Original description:
  AgentBound cannot prevent attacks that remain within declared policy boundaries, such as a puppet attack that changes parameters of a permitted call or an SQL injection inside an allowed database operation.
- Normalized rule:
  WHEN an operation is within declared and granted capabilities
  BUT semantic misuse or application-level vulnerability is suspected
  THEN access-control verifier may return `safe-by-capability` but should mark semantic risk as out-of-scope / unknown.
- Rule class:
  Limitation rule; evidence-completeness rule; semantic-gap rule.
- Trigger:
  Operation passes capability check but may still be unsafe at semantic/application layer.
- Condition:
  Required semantic evidence is missing or not represented by the capability policy, e.g., SQL query intent, crypto recipient manipulation, malicious but permitted endpoint parameter.
- Required evidence:
  capability decision, concrete arguments, semantic intent, data-flow/provenance, application invariant, policy boundary, vulnerability signature.
- Verdict / enforcement:
  AgentBound verdict = allowed if inside boundary. Our framework should return `unknown` or route to complementary analyzer if semantic evidence is insufficient.
- Possible backend:
  Evidence-completeness checker; taint monitor; application-level contract; SQL/static analyzer; LLM/tool-call monitor.

## 4. What can be reused for our work?

- Abstraction reused:
  AgentBound provides a strong abstraction for tool-use safety:
  `resource_access_event = (server_id, action/tool, capability, effect_type, target_resource, concrete_target, runtime_permission, user_consent, allow/block)`.

  This can be mapped directly into our normalized event stream for MCP/external API/tool-call events.

- Rule reused:
  1. Default deny unless manifest declares the capability.
  2. Generic capability must be instantiated into concrete runtime permission.
  3. Filesystem access must be scoped by path and access mode.
  4. Network access must be restricted to approved endpoints.
  5. Environment variables and secrets require explicit permission.
  6. If an action stays inside declared capabilities but semantic misuse is possible, access control alone is insufficient.

- Evidence reused:
  server id, manifest capability list, capability category, runtime permission, user consent, tool/action name, resource type, concrete resource target, access mode, allow/block decision, sandbox status, attack type.

- Limitation:
  AgentBound is an access-control and sandboxing framework, not a general semantic verifier. It blocks system-resource-targeting attacks that violate policy boundaries, but it cannot stop attacks that stay within allowed capabilities or exploit application-level semantics, such as SQL injection or permitted parameter manipulation. It also does not provide a general trace canonicalization layer or verifier-neutral Rule IR.

## Extraction note for our project

P03 should be used as the anchor paper for **tool-use safety / permission checking** and **runtime access-control enforcement**.

Main insight:

```text
MCP/tool safety rule = declared capability + concrete runtime permission + user consent + sandbox enforcement
```

Map to our normalized event stream:

```text
raw MCP/tool call
→ event(resource_access_attempt,
        server_id,
        tool_name,
        effect_type,
        target_resource,
        concrete_target,
        declared_capability,
        runtime_permission,
        approval_status)
→ event(policy_decision, allow/block/abort, reason)
```

Map to Rule IR:

```text
WHEN event.effect_type = access_resource
AND event.target_resource = filesystem/network/env/system
REQUIRE declared_capability exists
AND runtime_permission exists
AND user_consent = true
ELSE violation
```

What our work can add beyond AgentBound:

1. Canonicalize AgentBound-style access events together with AgentSpec, GUARDIAN, ToolEmu, and provenance/taint traces.
2. Add preservation checking: if manifest, runtime permission, concrete target, or consent evidence is missing, the verifier should return `unknown`, not `safe`.
3. Connect access-control verdicts with higher-level trace rules, e.g., no untrusted retrieval → email send, no sensitive file → external network, no failed tool → final success claim.
4. Represent AgentBound’s semantic-gap cases as explicit `unknown/needs-complementary-verifier` rather than treating capability-allowed actions as fully safe.
