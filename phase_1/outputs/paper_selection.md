# Paper Selection Criteria

A paper is selected if it satisfies at least 2 of the following criteria:

1. It studies runtime verification, runtime monitoring, enforcement, or governance for LLM agents.
2. It uses traces, events, trajectories, tool calls, state transitions, or message-action logs.
3. It defines policies, rules, contracts, temporal constraints, or safety properties.
4. It can provide evidence requirements such as action name, arguments, state, approval, provenance, taint, or causal links.
5. It supports or can be mapped to verifier backends such as DSL, LTL, Hoare contract, SMT, PRISM, or Python monitor.

## Selection rationale

This corpus is selected for **rule-driven trace canonicalization** rather than for a broad survey. The goal is to choose papers that can directly contribute one or more of the following artifacts:

- verify rules,
- trace/event abstractions,
- evidence fields,
- policy or contract structures,
- verifier-backend mappings,
- runtime verdict or intervention logic.

A paper is therefore not selected only because it is about “LLM agent safety”. It must help justify how raw agent behavior can be converted into verifier-ready events and how rules can be checked without losing required evidence.

## Paper groups

| Group | Target count | Selected IDs | Role in this project |
|---|---:|---|---|
| Agent runtime verification / enforcement | 2 | P01, P02 | Extract runtime events, temporal monitoring ideas, and verify/enforcement rules |
| Tool-use safety / permission checking | 2 | P03, P04 | Extract permission, approval, least-privilege, effect, and sandbox rules |
| Trace-based assurance / replay / contract | 2 | P05, P06 | Extract message-action traces, trajectories, risk labels, and verdict schemas |
| Provenance / taint / data-flow safety | 2 | P07, P08 | Extract taint, provenance, capability, and information-flow evidence |

## Selected papers

| ID | Paper | Year | Venue | Why selected | Criteria matched | Trace abstraction | Rule type found |
|---|---|---:|---|---|---|---|---|
| P01 | **AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents** | 2026 | ICSE 2026 | Directly studies runtime enforcement for LLM agents. It gives a lightweight DSL with trigger, predicate/check, and enforcement actions. This is the strongest source for executable verify rules. | C1, C2, C3, C4, C5 | Agent execution event stream: `state_change`, `action`, `agent_finish`, current trajectory, planned action, agent state | Trigger-check-enforce DSL; runtime constraints; approval/inspection; stop/corrective/self-reflection actions |
| P02 | **GUARDIAN: Safeguarding LLM Multi-Agent Collaborations with Temporal Graph Modeling** | 2025 | NeurIPS 2025 | Selected because it models multi-agent collaboration as a temporal attributed graph and detects error/hallucination propagation. It gives a useful temporal abstraction for monitoring agent-to-agent communication. | C1, C2, C4, C5 | Temporal attributed interaction graph: node = agent at timestep, edge = inter-agent communication, attribute = response/text | Temporal anomaly rule; propagation constraint; graph-based safety monitor |
| P03 | **AgentBound: Securing Execution Boundaries of AI Agents** | 2026 | ACM FSE 2026 / Proc. ACM Softw. Eng. | Strong paper for permission and approval rules around MCP servers. It introduces declarative access-control policies, runtime enforcement, manifests, least privilege, and capability-constrained execution. | C1, C2, C3, C4, C5 | MCP server/tool request log; requested capability; resource target; manifest permission; runtime permission decision | Manifest permission rule; runtime allow/deny; least-privilege rule; resource-bound access-control policy |
| P04 | **Towards Practically-Secure Tools for AI Agents** | 2026 | EuroMLSys 2026 | Selected because it combines static effect analysis, tool-effect synopsis, client-side policy engine, per-call sandbox policy, and trace replay. This is useful for effect policies and tool contracts. | C1, C2, C3, C4, C5 | User-LLM-tool message trace; tool-call trace; effect synopsis; per-call sandbox policy; replayed trace | Effect policy rule; sandbox contract; allowed/denied path/domain rule; tool synopsis contract |
| P05 | **Identifying the Risks of LM Agents with an LM-Emulated Sandbox** | 2024 | ICLR 2024 | Strong trace-to-verdict paper. ToolEmu uses action-observation trajectories in an emulated sandbox and an automatic safety evaluator to identify risky actions and consequences. | C2, C3, C4, C5 | Action-observation trajectory: user instruction, tool action, typed action input, observation, final answer, emulated state | Risk evaluator rubric; unsafe action pattern; severity/risk verdict; clarification-before-risky-action rule |
| P06 | **R-Judge: Benchmarking Safety Risk Awareness for LLM Agents** | 2024 | Findings of EMNLP 2024 | Selected because it provides multi-turn agent interaction records with annotated safety labels and risk descriptions. It is useful for defining verdict schema and violation categories. | C2, C3, C4, C5 | Multi-turn user-agent-environment interaction record; safety label; risk scenario; risk description | Safety label rule; violated risk category; post-hoc judge/verdict rule |
| P07 | **Make Agent Defeat Agent: Automatic Detection of Taint-Style Vulnerabilities in LLM-based Agents** | 2025 | USENIX Security 2025 | Best source for taint-style agent vulnerabilities. AgentFuzz detects prompt-to-tool vulnerabilities where malicious prompts exploit security-sensitive operations. Useful for source-sink evidence. | C1, C2, C3, C4, C5 | Prompt/input to tool-use vulnerability trace; seed prompt; mutated argument; security-sensitive operation; exploit trigger | Taint-style source-sink rule; risky operation trigger; prompt-to-tool exploit pattern |
| P08 | **Securing Agents With Tracked Capabilities** | 2026 | CAIS 2026 | Selected because it gives capability/type-contract thinking for agent tool use. It uses tracked capabilities and capture checking to prevent information leakage and malicious side effects. | C1, C3, C4, C5 | Capability-annotated code/tool action; typed effect/capability flow; classified data wrapper; compiler verdict | Capability contract; type/effect constraint; information-flow rule; local-purity rule |

## Source links

| ID | Source |
|---|---|
| P01 | https://arxiv.org/abs/2503.18666 |
| P02 | https://proceedings.neurips.cc/paper_files/paper/2025/hash/0bc795afae289ed465a65a3b4b1f4eb7-Abstract-Conference.html |
| P03 | https://doi.org/10.1145/3808103 |
| P04 | https://doi.org/10.1145/3805621.3807645 |
| P05 | https://proceedings.iclr.cc/paper_files/paper/2024/file/7274ed909a312d4d869cc328ad1c5f04-Paper-Conference.pdf |
| P06 | https://aclanthology.org/2024.findings-emnlp.79/ |
| P07 | https://www.usenix.org/conference/usenixsecurity25/presentation/liu-fengyu |
| P08 | https://doi.org/10.1145/3786335.3813127 |

## Done check

- [x] Selection criteria are explicit.
- [x] A paper is selected only if it satisfies at least 2 criteria.
- [x] The corpus has 8 papers.
- [x] The corpus covers the 4 required groups.
- [x] Each paper has a reason for selection.
- [x] Each paper contributes trace abstraction and rule type.
