# Schema Design Notes — Task 2.2–2.3

## Mục tiêu

Chốt **field candidate** cho normalized event schema từ Phase 1, sau đó phân loại field nào là **core** và field nào là **evidence extension**.

Nguyên tắc chốt field: **rule-first, không schema-first**. Field được giữ lại khi nó xuất hiện trong `rule_evidence_matrix.csv`, được định nghĩa trong `evidence_dictionary.md`, hoặc cần cho adapter/debug để không mất liên kết với raw trace.

Nguồn Phase 1 đã dùng:

- `paper_selection.md`: 8 paper chính, chia thành các nhóm runtime verification/enforcement, permission/tool safety, trace-based assurance, provenance/taint.
- `literature_rules.csv`: 25 extracted rules `R001`–`R025`.
- `rule_taxonomy.md`: 7 rule class chuẩn hóa.
- `evidence_dictionary.md`: định nghĩa field và rule class cần field.
- `rule_evidence_matrix.csv`: rule → required/optional evidence.

---

## 1. Nhóm field candidate

| Nhóm field | Ý nghĩa | Ví dụ |
| --- | --- | --- |
| Identity | Định danh event/trace/step để mọi rule có thể trỏ đúng event. | `event_id`, `trace_id`, `step_id` |
| Time/order | Thứ tự event, quan hệ trước/sau, prerequisite-before-action. | `timestamp`, `step_id`, `parent_event` |
| Action | Hành động agent đã định làm hoặc đã làm. | `phase`, `action_type`, `action_name` |
| Effect/target | Tác động của action và resource bị tác động. | `effect_type`, `target_resource` |
| Causal/provenance | Liên kết nguồn gốc, input-output, path source → sink. | `input_refs`, `output_ref`, `provenance` |
| Security/evidence | Evidence cho permission/taint/privilege/approval rule. | `taint`, `approval.*`, `allowed_action_set` |
| State | Pre/post condition và state snapshot/diff. | `pre_state`, `post_state` |
| Recovery | Lỗi, status, quyết định xử lý, rollback/retry/replan. | `status`, `error_type`, `reversibility` |
| Raw link | Link ngược về trace gốc để debug/replay/audit. | `raw_event_ref` |

---

## 2. Quyết định core vs evidence extension

### Core candidate fields

Core candidate là các field nên nằm trong normalized event model vì chúng nằm ở giao điểm của nhiều abstraction: identity/order/action/effect/basic causal/status/state/recovery/raw link. Tuy nhiên **core candidate không đồng nghĩa với required non-null**. Task 2.3 sẽ chia tiếp thành `required core` và `nullable core`.

```text
event_id, trace_id, step_id, timestamp, parent_event,
phase, action_type, action_name, typed_args,
effect_type, target_resource,
input_refs, output_ref,
status, raw_event_ref,
pre_state, post_state,
error_type, reversibility
```

### Evidence extension fields

Evidence extension là field/slot chỉ xuất hiện khi rule cần evidence tương ứng hoặc adapter extract được. Ví dụ permission rule cần approval/policy, taint rule cần taint/provenance, recovery rule cần decision.

```text
provenance, source_id, causal_path,
taint,
approval.exists, approval.status, approval.target,
allowed_action_set, policy_version,
tool_output,
decision,
metadata
```

Trong schema v0.1, các field extension chi tiết có thể được gom vào các object slot: `provenance`, `taint`, `approval`, `policy`, `decision`, `metadata`.

### Nhận xét nhanh

- Các field được yêu cầu nhiều nhất trong Phase 1 là: `trace_id` (25 rules), `step_id` (25 rules), `phase` (25 rules), `event_id` (25 rules), `action_type` (25 rules), `action_name` (23 rules), `typed_args` (21 rules), `decision` (18 rules), `target_resource` (17 rules), `status` (17 rules).
- `raw_event_ref` không xuất hiện trực tiếp trong `rule_evidence_matrix.csv`, nhưng trong schema v0.1 nên là required core field để quay lại raw trace khi cần replay, debug, hoặc kiểm tra adapter có làm mất evidence không.
- Evidence quá đặc thù theo domain như `recipient`, `path`, `url`, `command`, `front_vehicle_distance`, `object_property` không nên thành top-level field. Chúng đi vào `typed_args`, `pre_state`, `post_state`, hoặc `provenance`.

---

## 3. Candidate field list và rule source

| Nhóm | Field | Loại | Ý nghĩa | Rule class liên quan | Required bởi rule | Optional bởi rule |
| --- | --- | --- | --- | --- | --- | --- |
| Identity | `event_id` | core | Định danh duy nhất cho một normalized event. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R001`, `R002`, `R003`, `R004`, `R005`, `R006`, `R007`, `R008`, `R009`, `R010`, `R011`, `R012`, `R013`, `R014`, `R015`, `R016`, `R017`, `R018`, `R019`, `R020`, `R021`, `R022`, `R023`, `R024`, `R025` | — |
| Identity | `trace_id` | core | Gom các event thuộc cùng một run/session/trace. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R001`, `R002`, `R003`, `R004`, `R005`, `R006`, `R007`, `R008`, `R009`, `R010`, `R011`, `R012`, `R013`, `R014`, `R015`, `R016`, `R017`, `R018`, `R019`, `R020`, `R021`, `R022`, `R023`, `R024`, `R025` | — |
| Time/order | `step_id` | core | Thứ tự logic của event trong trace; cũng giúp định danh vị trí step. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R001`, `R002`, `R003`, `R004`, `R005`, `R006`, `R007`, `R008`, `R009`, `R010`, `R011`, `R012`, `R013`, `R014`, `R015`, `R016`, `R017`, `R018`, `R019`, `R020`, `R021`, `R022`, `R023`, `R024`, `R025` | — |
| Time/order | `timestamp` | core | Thời điểm wall-clock hoặc logical time của event. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R001`, `R002`, `R004`, `R005`, `R006`, `R007`, `R014`, `R017`, `R022`, `R024`, `R025` | — |
| Time/order | `parent_event` | core | Event cha trực tiếp gây ra event hiện tại; dùng cho causal ordering. | `permission`, `privilege_confinement`, `provenance`, `state_pre_post`, `taint`, `temporal` | `R014`, `R022`, `R024`, `R025` | `R001`, `R003`, `R015` |
| Action | `phase` | core | Pha thực thi của agent: plan, before_action, after_action, state_change, finish. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R001`, `R002`, `R003`, `R004`, `R005`, `R006`, `R007`, `R008`, `R009`, `R010`, `R011`, `R012`, `R013`, `R014`, `R015`, `R016`, `R017`, `R018`, `R019`, `R020`, `R021`, `R022`, `R023`, `R024`, `R025` | — |
| Action | `action_type` | core | Loại hành động/event ở mức cao: tool_call, retrieval, memory_op, external_api_call... | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R001`, `R002`, `R003`, `R004`, `R005`, `R006`, `R007`, `R008`, `R009`, `R010`, `R011`, `R012`, `R013`, `R014`, `R015`, `R016`, `R017`, `R018`, `R019`, `R020`, `R021`, `R022`, `R023`, `R024`, `R025` | — |
| Action | `action_name` | core | Tên tool/API/method cụ thể sau normalize. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R001`, `R002`, `R003`, `R004`, `R005`, `R006`, `R007`, `R009`, `R010`, `R011`, `R012`, `R013`, `R015`, `R016`, `R017`, `R018`, `R019`, `R020`, `R021`, `R022`, `R023`, `R024`, `R025` | — |
| Action | `typed_args` | core | Đối số có cấu trúc của action; chứa các evidence đặc thù như recipient, path, url, command. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R001`, `R002`, `R003`, `R005`, `R006`, `R009`, `R010`, `R011`, `R012`, `R013`, `R015`, `R016`, `R017`, `R018`, `R019`, `R020`, `R021`, `R022`, `R023`, `R024`, `R025` | `R007`, `R008`, `R014` |
| Effect/target | `effect_type` | core | Side effect/ngữ nghĩa tác động: read, write, delete, send, execute, retrieve... | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R001`, `R002`, `R009`, `R010`, `R011`, `R012`, `R013`, `R016`, `R017`, `R018`, `R020`, `R021`, `R022`, `R023`, `R025` | — |
| Effect/target | `target_resource` | core | Resource bị tác động: email, file, database, memory, api, web... | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R001`, `R002`, `R003`, `R009`, `R010`, `R011`, `R012`, `R013`, `R014`, `R016`, `R017`, `R018`, `R020`, `R021`, `R022`, `R023`, `R025` | — |
| Causal/provenance | `input_refs` | core | Danh sách output/message/document/memory được event hiện tại tiêu thụ. | `privilege_confinement`, `provenance`, `recovery_governance`, `taint`, `temporal` | `R007`, `R008`, `R014`, `R022`, `R024`, `R025` | — |
| Causal/provenance | `output_ref` | core | ID của output/tool result/memory entry/final answer được event tạo ra. | `privilege_confinement`, `provenance`, `recovery_governance`, `taint`, `temporal` | `R007`, `R008`, `R014`, `R020`, `R022`, `R024`, `R025` | — |
| Causal/provenance | `provenance` | evidence_extension | Metadata nguồn gốc, trust label, transformation history, và causal links. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `taint`, `temporal` | `R005`, `R007`, `R008`, `R014`, `R015`, `R020`, `R022`, `R024`, `R025` | `R001`, `R006`, `R009`, `R011`, `R016`, `R017`, `R019`, `R021`, `R023` |
| Causal/provenance | `source_id` | evidence_extension | Nguồn gốc ban đầu của dữ liệu/value trong trace. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `taint`, `temporal` | `R002`, `R007`, `R014`, `R015`, `R022`, `R024`, `R025` | `R009`, `R010`, `R011`, `R019`, `R020`, `R021`, `R023` |
| Causal/provenance | `causal_path` | evidence_extension | Chuỗi event từ source tới sink/current event. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R002`, `R005`, `R006`, `R007`, `R008`, `R014`, `R022`, `R024`, `R025` | `R003`, `R004`, `R020` |
| Security/evidence | `taint` | evidence_extension | Nhãn trust/sensitivity/data-flow như untrusted, user_controlled, classified, sanitized. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `taint`, `temporal` | `R002`, `R007`, `R014`, `R019`, `R020`, `R022`, `R023`, `R025` | — |
| Security/evidence | `approval.exists` | evidence_extension | Có tồn tại approval event phù hợp cho action/target hay không. | `permission`, `privilege_confinement`, `provenance`, `taint`, `temporal` | `R001`, `R002`, `R009` | `R010` |
| Security/evidence | `approval.status` | evidence_extension | Trạng thái approval: approved, rejected, missing, expired, not_required... | `permission`, `privilege_confinement`, `provenance`, `taint`, `temporal` | `R001`, `R002`, `R009`, `R010` | `R011`, `R012`, `R013`, `R021` |
| Security/evidence | `approval.target` | evidence_extension | Action/resource/recipient/endpoint/scope mà approval bao phủ. | `permission`, `provenance`, `taint`, `temporal` | `R001`, `R002` | — |
| Security/evidence | `allowed_action_set` | evidence_extension | Allowlist/capability/policy set đang cho phép những action/resource nào. | `permission`, `privilege_confinement`, `provenance`, `state_pre_post`, `taint`, `temporal` | `R009`, `R010`, `R011`, `R012`, `R013`, `R015`, `R016`, `R018`, `R019`, `R021` | `R001`, `R002` |
| Security/evidence | `policy_version` | evidence_extension | Phiên bản policy/manifest/sandbox profile đang dùng để evaluate event. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R011`, `R012`, `R015`, `R016` | `R001`, `R002`, `R005`, `R006`, `R007`, `R008`, `R009`, `R010`, `R013`, `R014`, `R017`, `R018`, `R020`, `R021`, `R023`, `R024`, `R025` |
| State | `pre_state` | evidence_extension | State liên quan trước khi action xảy ra. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R003`, `R004`, `R018` | `R012`, `R015`, `R016`, `R017`, `R025` |
| State | `post_state` | evidence_extension | State liên quan sau khi action xảy ra. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R003`, `R004`, `R018` | `R012`, `R015`, `R016`, `R017`, `R025` |
| State | `tool_output` | evidence_extension | Output/observation/result/error từ tool/API/code/retrieval; thường dùng cho post-state và provenance. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R005`, `R006` | `R002`, `R004`, `R008`, `R019`, `R020`, `R022`, `R024` |
| Recovery | `status` | core | Trạng thái thực thi/policy của event: pending, success, failed, blocked, allowed... | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R003`, `R004`, `R005`, `R006`, `R007`, `R008`, `R015`, `R016`, `R017`, `R018`, `R019`, `R020`, `R021`, `R022`, `R023`, `R024`, `R025` | `R009`, `R010`, `R011`, `R012`, `R013`, `R014` |
| Recovery | `error_type` | evidence_extension | Loại lỗi/violation/anomaly được normalize. | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | — | `R004`, `R005`, `R006`, `R007`, `R013`, `R015`, `R016`, `R017`, `R018`, `R019`, `R022`, `R023`, `R025` |
| Recovery | `reversibility` | evidence_extension | Mức độ có thể undo/retry/rollback/compensate của action. | `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `temporal` | `R017` | `R003`, `R004`, `R005`, `R006`, `R018` |
| Recovery | `decision` | evidence_extension | Quyết định của verifier/policy/governance: allow, block, replan, ask_user, violation... | `permission`, `privilege_confinement`, `provenance`, `recovery_governance`, `state_pre_post`, `taint`, `temporal` | `R004`, `R005`, `R006`, `R007`, `R009`, `R010`, `R011`, `R012`, `R013`, `R014`, `R015`, `R016`, `R017`, `R018`, `R019`, `R020`, `R021`, `R023` | `R002`, `R003`, `R008`, `R022`, `R024`, `R025` |
| Raw link | `raw_event_ref` | evidence_extension / audit | Liên kết ngược về raw trace/span/log gốc để debug, replay, hoặc audit. | adapter/audit | — | — |

---

## 4. Rule → evidence mapping từ Phase 1

Bảng này là traceability ngược: mỗi field trong phần trên đến từ rule nào.

| Rule | Rule class | Rule description | Required evidence | Optional evidence | Nếu thiếu evidence |
| --- | --- | --- | --- | --- | --- |
| `R001` | `permission` + `temporal` | Financial transfer to non-verified family member requires explicit user confirmation. | `event_id`, `trace_id`, `step_id`, `timestamp`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `approval.exists`, `approval.status`, `approval.target` | `parent_event`, `policy_version`, `allowed_action_set`, `provenance` | UNKNOWN |
| `R002` | `permission` + `taint` + `provenance` + `temporal` | Python code that requests content from an untrusted source and writes or prints it requires user inspection. | `event_id`, `trace_id`, `step_id`, `timestamp`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `source_id`, `taint`, `causal_path`, `approval.exists`, `approval.status`, `approval.target` | `tool_output`, `allowed_action_set`, `policy_version`, `decision` | UNKNOWN; VIOLATION if untrusted source-to-sink flow is observed without approval |
| `R003` | `state_pre_post` | Embodied agent must not pour liquid into an object that should not get wet. | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `action_name`, `typed_args`, `target_resource`, `pre_state`, `post_state`, `status` | `parent_event`, `causal_path`, `decision`, `reversibility` | UNKNOWN; VIOLATION if pre_state shows non-wettable target and action is allowed |
| `R004` | `state_pre_post` + `temporal` + `recovery_governance` | Autonomous driving agent must correct behavior when front vehicle is too close. | `event_id`, `trace_id`, `step_id`, `timestamp`, `phase`, `action_type`, `action_name`, `pre_state`, `post_state`, `status`, `decision` | `causal_path`, `reversibility`, `tool_output`, `error_type` | UNKNOWN; VIOLATION if unsafe pre_state remains unresolved in post_state |
| `R005` | `recovery_governance` + `temporal` + `provenance` | Hallucinated or anomalous agent response must be removed before it propagates downstream. | `event_id`, `trace_id`, `step_id`, `timestamp`, `phase`, `action_type`, `action_name`, `typed_args`, `tool_output`, `status`, `provenance`, `causal_path`, `decision` | `error_type`, `reversibility`, `policy_version` | UNKNOWN; VIOLATION if anomalous node is consumed before removal |
| `R006` | `recovery_governance` + `temporal` | Compromised agent node with high attribute anomaly must be excluded before others consume its output. | `event_id`, `trace_id`, `step_id`, `timestamp`, `phase`, `action_type`, `action_name`, `typed_args`, `tool_output`, `status`, `causal_path`, `decision` | `provenance`, `error_type`, `reversibility`, `policy_version` | UNKNOWN; VIOLATION if compromised agent output is consumed after detection |
| `R007` | `provenance` + `taint` + `recovery_governance` | Corrupted inter-agent communication edge must be pruned or the affected node excluded. | `event_id`, `trace_id`, `step_id`, `timestamp`, `phase`, `action_type`, `action_name`, `input_refs`, `output_ref`, `provenance`, `source_id`, `taint`, `causal_path`, `status`, `decision` | `typed_args`, `error_type`, `policy_version` | UNKNOWN; VIOLATION if corrupted edge is used downstream |
| `R008` | `provenance` | Temporal graph compression must preserve anomaly-relevant temporal, structural, and attribute evidence. | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `input_refs`, `output_ref`, `provenance`, `causal_path`, `status` | `typed_args`, `tool_output`, `policy_version`, `decision` | UNKNOWN |
| `R009` | `permission` + `privilege_confinement` | MCP server resource access is default-deny unless declared in manifest and granted at runtime. | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `allowed_action_set`, `approval.exists`, `approval.status`, `decision` | `policy_version`, `source_id`, `provenance`, `status` | UNKNOWN; VIOLATION if requested action is outside allowed set and decision is allow |
| `R010` | `permission` + `privilege_confinement` | Environment variable reads require declared env-read capability and variable-specific runtime permission. | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `allowed_action_set`, `approval.status`, `decision` | `approval.exists`, `policy_version`, `source_id`, `status` | UNKNOWN; VIOLATION if environment/secret access is allowed without permission |
| `R011` | `privilege_confinement` + `permission` | Outbound network traffic must be restricted to manifest/user-approved endpoints. | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `allowed_action_set`, `policy_version`, `decision` | `source_id`, `provenance`, `status`, `approval.status` | UNKNOWN; VIOLATION if non-allowlisted endpoint is allowed |
| `R012` | `privilege_confinement` + `permission` | Filesystem access must be scoped by approved path and access mode. | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `allowed_action_set`, `policy_version`, `decision` | `status`, `approval.status`, `pre_state`, `post_state` | UNKNOWN; VIOLATION if path or access mode exceeds scope and is allowed |
| `R013` | `privilege_confinement` + `permission` | OS command execution requires explicit system-exec capability and approved command scope. | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `allowed_action_set`, `decision` | `status`, `error_type`, `approval.status`, `policy_version` | UNKNOWN; VIOLATION if command outside approved scope is executed |
| `R014` | `taint` + `provenance` + `privilege_confinement` | Untrusted data must not be mixed with privileged context without isolation, labeling, or sanitization. | `event_id`, `trace_id`, `step_id`, `timestamp`, `parent_event`, `phase`, `action_type`, `input_refs`, `output_ref`, `provenance`, `source_id`, `taint`, `causal_path`, `target_resource`, `decision` | `typed_args`, `policy_version`, `status` | UNKNOWN; VIOLATION if tainted context influences privileged action without isolation |
| `R015` | `provenance` + `privilege_confinement` | Tool invocation must use immutable trusted tool identity and validated arguments. | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `action_name`, `typed_args`, `provenance`, `source_id`, `allowed_action_set`, `policy_version`, `status`, `decision` | `parent_event`, `pre_state`, `post_state`, `error_type` | UNKNOWN; VIOLATION if untrusted or tampered tool is invoked |
| `R016` | `privilege_confinement` + `permission` | Executable skills and tools must run inside a sandbox that mediates filesystem, network, environment, and credentials. | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `allowed_action_set`, `policy_version`, `status`, `decision` | `pre_state`, `post_state`, `error_type`, `provenance` | UNKNOWN; VIOLATION if out-of-sandbox resource access is allowed |
| `R017` | `recovery_governance` + `privilege_confinement` | Security logs and audit records must not be overwritten, deleted, or truncated by arbitrary tools or skills. | `event_id`, `trace_id`, `step_id`, `timestamp`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `status`, `reversibility`, `decision` | `error_type`, `pre_state`, `post_state`, `policy_version`, `provenance` | UNKNOWN; VIOLATION if protected log is deleted, truncated, or overwritten by non-logger |
| `R018` | `privilege_confinement` + `state_pre_post` | Filesystem access requires a scoped FileSystem capability, approved root, and non-escaping handles. | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `allowed_action_set`, `pre_state`, `post_state`, `status`, `decision` | `error_type`, `policy_version`, `reversibility` | UNKNOWN; VIOLATION if capability escapes scope or path outside root is allowed |
| `R019` | `taint` + `privilege_confinement` | Classified data transformations must be pure and cannot capture side-effect capabilities. | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `action_name`, `typed_args`, `taint`, `allowed_action_set`, `status`, `decision` | `source_id`, `provenance`, `error_type`, `tool_output` | UNKNOWN; VIOLATION if classified data reaches side-effecting capability |
| `R020` | `taint` + `provenance` | Classified values must be redacted on agent-visible output channels. | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `taint`, `output_ref`, `provenance`, `status`, `decision` | `source_id`, `tool_output`, `causal_path`, `policy_version` | UNKNOWN; VIOLATION if classified plaintext is emitted to agent-visible output |
| `R021` | `permission` + `privilege_confinement` | Network access requires an active Network capability and destination host allowlist. | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `allowed_action_set`, `status`, `decision` | `policy_version`, `approval.status`, `source_id`, `provenance` | UNKNOWN; VIOLATION if destination host outside allowed set is allowed |
| `R022` | `taint` + `provenance` | Prompt-derived or LLM-derived data must not reach security-sensitive sinks without sanitization. | `event_id`, `trace_id`, `step_id`, `timestamp`, `parent_event`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `input_refs`, `output_ref`, `provenance`, `source_id`, `taint`, `causal_path`, `status` | `error_type`, `tool_output`, `decision` | UNKNOWN; VIOLATION if unsanitized taint reaches security-sensitive sink |
| `R023` | `taint` | Security-sensitive sinks must be explicitly classified and monitored. | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `taint`, `status`, `decision` | `provenance`, `source_id`, `error_type`, `policy_version` | UNKNOWN; VIOLATION if unclassified or unmonitored sensitive sink executes |
| `R024` | `provenance` | LLM-selected tool/component needs provenance from prompt and response to runtime call chain. | `event_id`, `trace_id`, `step_id`, `timestamp`, `parent_event`, `phase`, `action_type`, `action_name`, `typed_args`, `input_refs`, `output_ref`, `provenance`, `source_id`, `causal_path`, `status` | `tool_output`, `policy_version`, `decision` | UNKNOWN |
| `R025` | `temporal` + `taint` + `provenance` | Stored prompt payloads can create second-order vulnerabilities when later retrieved into sinks. | `event_id`, `trace_id`, `step_id`, `timestamp`, `parent_event`, `phase`, `action_type`, `action_name`, `effect_type`, `target_resource`, `typed_args`, `input_refs`, `output_ref`, `provenance`, `source_id`, `taint`, `causal_path`, `status` | `pre_state`, `post_state`, `error_type`, `policy_version`, `decision` | UNKNOWN; VIOLATION if stored taint later reaches sink unsanitized |

---

## 5. Paper → rule coverage

| Paper | Title | Rule IDs | Primary rule classes |
| --- | --- | --- | --- |
| `P01` | AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents | `R001`, `R002`, `R003`, `R004` | `permission`, `state_pre_post`, `taint` |
| `P02` | GUARDIAN: Safeguarding LLM Multi-Agent Collaborations with Temporal Graph Modeling | `R005`, `R006`, `R007`, `R008` | `provenance`, `recovery_governance` |
| `P03` | AgentBound: Securing Execution Boundaries of AI Agents | `R009`, `R010`, `R011`, `R012`, `R013` | `permission`, `privilege_confinement` |
| `P04` | Toward Securing AI Agents Like Operating Systems | `R014`, `R015`, `R016`, `R017` | `privilege_confinement`, `provenance`, `recovery_governance`, `taint` |
| `P05` | Tracking Capabilities for Safer Agents | `R018`, `R019`, `R020`, `R021` | `permission`, `privilege_confinement`, `taint` |
| `P06` | Make Agent Defeat Agent: Automatic Detection of Taint-Style Vulnerabilities in LLM-based Agents | `R022`, `R023`, `R024`, `R025` | `provenance`, `taint`, `temporal` |

---

## 6. Alias / normalization decision

| Field thô / tên trong paper | Canonical field | Ghi chú normalize |
| --- | --- | --- |
| `recipient`, `path`, `url`, `host`, `command`, `sink_argument`, `runtime_argument` | `typed_args` | Giữ evidence đặc thù của tool/action trong object argument thay vì tạo top-level field mới. |
| `approval.event`, `approval_state`, `user_confirmation`, `consent` | `approval.exists`, `approval.status`, `approval.target` | Tách approval thành presence/status/target để check cả permission lẫn temporal binding. |
| `temporal_order`, `previous_event`, `next_event`, `before_after_relation` | `step_id`, `timestamp`, `parent_event`, `causal_path` | Không cần field riêng nếu order có thể suy từ step/time/causal links. |
| `source_trust_label`, `classification_label`, `taint_label`, `input_taint` | `taint` + `provenance` | Taint là label chính; provenance giữ nguồn và transformation history. |
| `policy_decision`, `verdict`, `decision_action`, `governance_action` | `decision` + `status` + `error_type` | Chuẩn hóa output của monitor/governance để tránh mỗi backend một tên. |
| `current_state`, `previous_state`, `next_state`, `state_diff`, `post_intervention_state` | `pre_state`, `post_state` | State detail nằm trong JSON object/diff, không cần bung thành nhiều top-level field. |

---

## 7. Task 2.3 — Schema v0.1: required / nullable / optional

### 7.1. Mục tiêu thiết kế

Schema v0.1 không nên bắt mọi event phải có mọi evidence field. Mục tiêu là tách rõ:

1. **Required core fields**: event nào cũng phải có để C1/C2 có thể định danh, sắp thứ tự, phân loại và truy ngược raw trace.
2. **Nullable core fields**: field vẫn nằm ở top-level vì nhiều rule cần query nhanh, nhưng được phép `null` khi event không có thông tin đó hoặc field không áp dụng.
3. **Optional evidence slots**: chỉ xuất hiện khi rule cần hoặc adapter extract được. Thiếu slot này không làm schema reject event; C2 sẽ trả `UNKNOWN` nếu rule cần evidence đó.

Lý do: không ép `retrieval` event phải có `approval`, không ép `message` event phải có `pre_state`, không ép `finish` event phải có `effect_type`. Schema chỉ kiểm tra event có đủ khung tối thiểu; preservation check của C2 mới quyết định rule có đủ evidence hay không.

---

### 7.2. Bảng phân loại field v0.1

| Nhóm schema | Bắt buộc có key? | Được phép `null`? | Field | Vai trò | Khi thiếu thì sao? |
| --- | --- | --- | --- | --- | --- |
| Required core | Có | Không | `event_id` | Định danh duy nhất một normalized event. | Schema reject vì không thể trace/cite event. |
| Required core | Có | Không | `trace_id` | Gom event vào cùng một trace/session/run. | Schema reject vì không thể chạy temporal/provenance theo trace. |
| Required core | Có | Không | `step_id` | Thứ tự logic tối thiểu trong trace. | Schema reject vì không thể check order cơ bản. |
| Required core | Có | Không | `phase` | Pha thực thi: `plan`, `before_action`, `after_action`, `state_change`, `finish`. | Schema reject vì không biết event thuộc hook nào. |
| Required core | Có | Không | `action_type` | Loại event/action: `tool_call`, `retrieval`, `memory_op`, `message`, ... | Schema reject vì không thể route rule. |
| Required core | Có | Không | `action_name` | Tên action/tool/API sau normalize; dùng `unknown` nếu raw trace không có tên rõ. | Schema reject nếu key thiếu; nếu không biết tên thì đặt `unknown`. |
| Required core | Có | Không | `status` | Trạng thái event: `pending`, `success`, `failed`, `blocked`, ... | Schema reject vì recovery/governance cần status cơ bản. |
| Required core | Có | Không | `raw_event_ref` | Link ngược về span/log/raw event gốc để audit/debug/replay. | Schema reject vì không thể kiểm tra adapter có làm mất evidence không. |
| Nullable core | Có | Có | `timestamp` | Wall-clock/logical time. | Nếu rule cần time chính xác mà thiếu thì C2 trả `UNKNOWN`. |
| Nullable core | Có | Có | `parent_event` | Event cha/cause trực tiếp. | Provenance/temporal rule có thể `UNKNOWN`. |
| Nullable core | Có | Có | `effect_type` | Side effect: `read`, `write`, `delete`, `send`, `execute`, ... | Permission/taint rule cần effect có thể `UNKNOWN`. |
| Nullable core | Có | Có | `target_resource` | Resource bị tác động: `email`, `file`, `database`, `memory`, ... | Permission/privilege rule cần target có thể `UNKNOWN`. |
| Nullable core | Có | Có | `typed_args` | Argument có cấu trúc của action: recipient/path/url/command/... | Rule cần argument binding có thể `UNKNOWN`. |
| Nullable core | Có | Có | `input_refs` | Các output/message/doc/memory được event tiêu thụ. | Provenance/taint rule có thể `UNKNOWN`. |
| Nullable core | Có | Có | `output_ref` | Output/tool result/memory entry/final answer do event tạo ra. | Provenance/taint rule có thể `UNKNOWN`. |
| Nullable core | Có | Có | `pre_state` | State/snapshot trước action. | State precondition rule có thể `UNKNOWN`. |
| Nullable core | Có | Có | `post_state` | State/snapshot sau action. | State postcondition/recovery rule có thể `UNKNOWN`. |
| Nullable core | Có | Có | `error_type` | Loại lỗi/violation/anomaly chuẩn hóa. | Recovery rule có thể `UNKNOWN` nếu cần lỗi cụ thể. |
| Nullable core | Có | Có | `reversibility` | Mức có thể undo/retry/rollback: `reversible`, `irreversible`, `retryable`, ... | Governance rule cần risk/recovery có thể `UNKNOWN`. |
| Optional evidence slot | Không | Có, nếu slot xuất hiện | `provenance` | Source, causal chain, transformation history, trust metadata. | Không reject; C2 trả `UNKNOWN` nếu rule provenance/taint cần. |
| Optional evidence slot | Không | Có, nếu slot xuất hiện | `taint` | Trust/sensitivity/classification/sanitization label. | Không reject; C2 trả `UNKNOWN` nếu taint rule cần. |
| Optional evidence slot | Không | Có, nếu slot xuất hiện | `approval` | Approval presence/status/target/event. | Không reject; C2 trả `UNKNOWN` hoặc `VIOLATION` tùy rule và evidence. |
| Optional evidence slot | Không | Có, nếu slot xuất hiện | `policy` | Policy version, allowed action set, capability/sandbox scope. | Không reject; permission/privilege rule có thể `UNKNOWN`. |
| Optional evidence slot | Không | Có, nếu slot xuất hiện | `decision` | Verifier/governance decision, verdict, missing evidence, route action. | Không reject; governance rule có thể `UNKNOWN`. |
| Optional evidence slot | Không | Có, nếu slot xuất hiện | `metadata` | Adapter-specific/debug fields: parser warning, tool output, confidence, raw payload hash, framework id. | Không reject; chỉ dùng khi rule hoặc debug cần. |

Ghi chú: `typed_args` được giữ ở **nullable core** dù không nên required, vì nhiều permission/taint/privilege rule cần argument binding như `recipient`, `path`, `url`, `host`, `command`. Nếu một event không có argument tự nhiên, đặt `typed_args = null`.

---

### 7.3. Required core fields

Required core là phần tối thiểu để mọi event có thể được định danh, sắp thứ tự, phân loại và truy ngược raw trace.

```text
event_id, trace_id, step_id,
phase, action_type, action_name,
status, raw_event_ref
```

Quy ước validation:

- Key phải tồn tại ở mọi event.
- Value không được `null`.
- Nếu raw trace thiếu tên action cụ thể, adapter có thể đặt `action_name = "unknown"`, nhưng không được bỏ field.
- `raw_event_ref` required vì Phase 2 cần audit được C1 canonicalizer có preserve evidence hay không.

---

### 7.4. Nullable core fields

Nullable core là các field query thường xuyên nên để top-level, nhưng không phải event nào cũng có giá trị hợp lệ.

```text
timestamp, parent_event,
effect_type, target_resource, typed_args,
input_refs, output_ref,
pre_state, post_state,
error_type, reversibility
```

Quy ước validation:

- Key nên tồn tại ở mọi normalized event để verifier/backend query ổn định.
- Value được phép `null`.
- `null` có nghĩa là **not observed / not applicable / not preserved**, không đồng nghĩa với safe.
- Khi Rule IR yêu cầu một nullable field nhưng value là `null`, C2 đánh dấu `missing_evidence` và trả `UNKNOWN`, trừ khi rule định nghĩa rõ thiếu field là violation.

---

### 7.5. Optional evidence slots

Optional evidence slots là object con, chỉ attach khi adapter extract được hoặc khi policy/rule cần.

```text
provenance, taint, approval, policy, decision, metadata
```

| Slot | Field con gợi ý | Rule class dùng nhiều | Ghi chú |
| --- | --- | --- | --- |
| `provenance` | `source_id`, `source_type`, `source_trust_label`, `causal_path`, `parent_event`, `transforms` | `provenance`, `taint`, `temporal` | Gom các field như `source_id`, `causal_path` vào một slot thay vì làm top-level required. |
| `taint` | `label`, `classification`, `sanitizer_status`, `validator_status`, `declassification_event`, `sink_type` | `taint`, `provenance`, `permission` | Chỉ cần khi kiểm tra source-sink, prompt injection, classified/sensitive flow. |
| `approval` | `exists`, `status`, `target`, `event_ref`, `timestamp`, `approver` | `permission`, `temporal`, `privilege_confinement` | Không ép mọi event có approval; chỉ action sensitive mới cần. |
| `policy` | `policy_version`, `allowed_action_set`, `capability_scope`, `runtime_permission`, `sandbox_status`, `allowlist`, `denylist` | `permission`, `privilege_confinement`, `recovery_governance` | Gom `allowed_action_set` và `policy_version` vào một slot policy. |
| `decision` | `verdict`, `action`, `reason`, `missing_evidence`, `confidence`, `route` | `recovery_governance`, `permission`, `state_pre_post` | Dùng cho output của C2/governance layer. |
| `metadata` | `tool_output`, `adapter_name`, `framework`, `parser_warning`, `raw_payload_hash`, `confidence_score` | Debug/replay hoặc rule đặc thù | Không nên để mọi field đặc thù thành top-level. |

---

### 7.6. Schema v0.1 example

```json
{
  "event_id": "e_017",
  "trace_id": "trace_001",
  "step_id": 7,
  "phase": "before_action",
  "action_type": "tool_call",
  "action_name": "send_email",
  "status": "pending",
  "raw_event_ref": "raw_trace.span.17",

  "timestamp": "2026-06-25T16:30:00+07:00",
  "parent_event": "e_014",
  "effect_type": "send",
  "target_resource": "email",
  "typed_args": {
    "recipient": "external@example.com",
    "subject": "Report"
  },
  "input_refs": ["doc_005"],
  "output_ref": null,
  "pre_state": null,
  "post_state": null,
  "error_type": null,
  "reversibility": "irreversible",

  "provenance": {
    "source_id": "retrieval_doc_005",
    "causal_path": ["e_001", "e_004", "e_014", "e_017"]
  },
  "taint": {
    "label": "untrusted",
    "sanitizer_status": "not_sanitized"
  },
  "approval": {
    "exists": false,
    "status": "missing",
    "target": "recipient:external@example.com"
  },
  "policy": {
    "policy_version": "policy_v1",
    "allowed_action_set": ["read_file", "retrieve"]
  },
  "decision": null,
  "metadata": {
    "adapter_name": "adapter_custom",
    "tool_output": null
  }
}
```

---

### 7.7. C2 behavior khi field thiếu

| Tình huống | Schema v0.1 xử lý | C2 preservation check xử lý |
| --- | --- | --- |
| Thiếu required core field | Reject event. | Không chạy rule vì event không hợp lệ. |
| Nullable core field có value `null` | Accept event. | Nếu rule cần field đó, trả `UNKNOWN` và ghi `missing_evidence`. |
| Optional evidence slot không tồn tại | Accept event. | Nếu rule cần slot đó, trả `UNKNOWN`; không được trả `SAFE`. |
| Optional evidence slot tồn tại nhưng thiếu field con | Accept event ở schema level. | C2 check field con theo `Req(rule)`; nếu thiếu thì `UNKNOWN`. |
| Evidence đầy đủ nhưng rule bị vi phạm | Accept event. | Trả `VIOLATION`. |
| Evidence đầy đủ và rule thỏa | Accept event. | Trả `SAFE`. |

---

### 7.8. Chốt schema v0.1

Schema v0.1 nên dùng cấu trúc phẳng cho required/nullable core và slot object cho optional evidence:

```text
NormalizedEventV0_1 = {
  required_core: event_id, trace_id, step_id, phase, action_type, action_name, status, raw_event_ref,
  nullable_core: timestamp, parent_event, effect_type, target_resource, typed_args, input_refs, output_ref, pre_state, post_state, error_type, reversibility,
  optional_evidence_slots: provenance, taint, approval, policy, decision, metadata
}
```

Đây là mức tối thiểu đủ để Phase 2.4 có thể viết JSON Schema/Pydantic model mà không làm schema quá cứng. Rule-specific completeness vẫn thuộc C2 preservation checker, không đẩy hết vào schema validation.

---

## 8. Done checklist

- [x] Đã gom tất cả field xuất hiện trong `rule_evidence_matrix.csv`.
- [x] Đã thêm `raw_event_ref` theo yêu cầu Raw link.
- [x] Đã phân loại `core` vs `evidence_extension` cho Task 2.2.
- [x] Đã có bảng nhóm field: Identity, Time/order, Action, Effect/target, Causal/provenance, Security/evidence, State, Recovery, Raw link.
- [x] Đã có mapping field → rule source.
- [x] Đã có mapping rule → required/optional evidence.
- [x] Đã chia schema v0.1 thành `required core`, `nullable core`, và `optional evidence slots` cho Task 2.3.
- [x] Đã giải thích vì sao thiếu evidence không làm schema reject ngay mà để C2 trả `UNKNOWN`.
- [x] Đã có JSON example cho `NormalizedEventV0_1`.

---

## 8. Task 2.4 — `normalized_event_schema.json` v0.1

### 8.1. Output chính

Task 2.4 tạo JSON Schema v0.1 tại:

```text
normalized_event_schema.json
```

Schema này validate một trace-level object có dạng:

```json
{
  "trace_id": "t_001",
  "schema_version": "0.1",
  "events": []
}
```

Mỗi item trong `events` là một normalized event. Schema v0.1 tách field theo quyết định Task 2.3:

- Required/non-null core: bắt buộc để định danh, sắp thứ tự, route rule, và link về raw trace.
- Nullable core: bắt buộc có key trong event object, nhưng value được phép `null` khi không áp dụng hoặc adapter không extract được.
- Optional evidence slots: chỉ cần xuất hiện khi adapter có evidence hoặc C2/rule cần; nếu rule cần mà thiếu thì preservation checker trả `UNKNOWN` thay vì schema reject ngay.

### 8.2. Required / nullable / optional trong JSON Schema

| Nhóm | Field trong schema | Quyết định validation |
| --- | --- | --- |
| Required core | `event_id`, `trace_id`, `step_id`, `phase`, `action_type`, `action_name`, `status`, `raw_event_ref` | Bắt buộc có và không được `null`. |
| Nullable core | `timestamp`, `parent_event`, `effect_type`, `target_resource`, `typed_args`, `tool_output`, `input_refs`, `output_ref`, `pre_state`, `post_state`, `error_type`, `reversibility` | Bắt buộc có key; value có thể là `null` nếu không áp dụng. `typed_args` dùng `{}` khi không có args. |
| Optional evidence slots | `provenance`, `taint`, `approval`, `policy`, `decision`, `metadata` | Không bắt buộc trong mọi event. Khi có thì phải đúng shape của slot tương ứng. |

### 8.3. Validation result

Đã tạo sample tại:

```text
normalized_event_sample.json
```

Kết quả validate:

```text
VALID: normalized_event_sample.json validates against normalized_event_schema.json
```

### 8.4. Ghi chú thiết kế

- `schema_version` hiện cố định bằng `0.1`.
- `phase`, `action_type`, `effect_type`, `target_resource`, `status`, `error_type`, `reversibility`, `approval.status`, `taint.label`, và `decision.verdict` dùng enum để giữ vocabulary ổn định.
- `typed_args`, `tool_output`, `pre_state`, `post_state`, và `metadata` cho phép JSON object/value linh hoạt để adapter không phải bung các evidence đặc thù thành top-level field.
- Schema không kiểm tra semantic rule như approval-before-send hoặc taint-to-sink. Các rule đó thuộc C2 preservation checker/verifier.


---

## 9. Task 2.5 — `vocabulary.yaml` v0.1

### 9.1. Mục tiêu

Task 2.5 khóa vocabulary để C1 adapter normalize raw trace về cùng một bộ label trước khi emit normalized event. File output:

```text
vocabulary.yaml
```

Vocabulary này dùng cho các enum chính của schema v0.1:

| Enum group | Vai trò |
| --- | --- |
| `phase` | Chuẩn hóa phase của agent event: plan, before_action, after_action, state_change, finish. |
| `action_type` | Chuẩn hóa loại event/action: tool_call, memory_op, retrieval, external_api_call, message, approval, policy_update, final_response, v.v. |
| `effect_type` | Chuẩn hóa tác động semantic: read, write, delete, send, execute, retrieve, connect, approve, block, rewrite, replan. |
| `target_resource` | Chuẩn hóa resource bị tác động: file, email, calendar, memory, database, web, api, user, policy, system_command, v.v. |
| `status` | Chuẩn hóa trạng thái event: pending, success, failed, blocked, rewritten, aborted, rejected, allowed, unknown. |
| `taint_label` | Chuẩn hóa trust/sensitivity label: trusted, untrusted, sensitive, unknown, user_controlled, prompt_derived, retrieval_derived, classified, sanitized. |
| `approval_status` | Chuẩn hóa approval evidence: approved, rejected, missing, unknown, expired, not_required. |
| `reversibility` | Chuẩn hóa mức độ có thể phục hồi: easy, hard, irreversible, unknown, reversible, compensatable, retryable. |
| `decision_verdict` | Chuẩn hóa verdict của verifier/governance: safe, violation, unknown, inconsistent. |
| `decision_route` | Chuẩn hóa route sau verdict: allow, block, abort, retry, replan, rewrite, ask_user, escalate, log_only. |

### 9.2. Nguyên tắc thiết kế

`vocabulary.yaml` là source dùng cho C1 normalizer, còn `normalized_event_schema.json` là source dùng cho validation. Hai file đã được align theo rule:

```text
Every non-null enum value in normalized_event_schema.json must exist in vocabulary.yaml.
```

Một số vocabulary value có thể rộng hơn schema để phục vụ normalizer và Phase 4. Khi raw action không map được chắc chắn, C1 nên dùng `unknown` cho enum field và giữ raw value trong `metadata` hoặc `raw_event_ref`.

---

## 10. Task 2.6 — Mapping rule cho action/effect/target

### 10.1. Vì sao cần mapping

Cùng một hành động có thể xuất hiện dưới nhiều tên khác nhau giữa framework/runtime khác nhau, ví dụ:

```text
sendEmail
gmail_send
email.send
mcp.gmail.send
```

C1 phải normalize các alias này về cùng canonical action:

```text
send_email
```

Sau đó mới derive được:

```text
action_type = tool_call
effect_type = send
target_resource = email
```

Nếu không có mapping này, cùng một policy như `approval before external send` sẽ phải viết nhiều lần cho từng tool/framework, làm mất portability của Rule IR.

### 10.2. Mapping đã thêm trong `vocabulary.yaml`

`vocabulary.yaml` hiện có 15 canonical actions, vượt yêu cầu tối thiểu 10 action phổ biến:

| Canonical action | Effect | Target | Action type |
| --- | --- | --- | --- |
| `send_email` | `send` | `email` | `tool_call` |
| `retrieve_document` | `retrieve` | `web` | `retrieval` |
| `delete_file` | `delete` | `file` | `tool_call` |
| `write_memory` | `write` | `memory` | `memory_op` |
| `read_memory` | `read` | `memory` | `memory_op` |
| `read_calendar` | `read` | `calendar` | `tool_call` |
| `write_calendar` | `write` | `calendar` | `tool_call` |
| `read_file` | `read` | `file` | `tool_call` |
| `write_file` | `write` | `file` | `tool_call` |
| `execute_code` | `execute` | `system_command` | `code_execution` |
| `call_api` | `connect` | `api` | `external_api_call` |
| `query_database` | `read` | `database` | `tool_call` |
| `send_message` | `send` | `communication_edge` | `message` |
| `ask_user_approval` | `approve` | `user` | `approval` |
| `update_policy` | `rewrite` | `policy` | `policy_update` |

### 10.3. Validation result

Đã tạo coverage report tại:

```text
vocabulary_schema_coverage_report.txt
```

Kết quả:

```text
PASS - every non-null schema enum value is present in vocabulary.yaml.
```

`normalized_event_sample.json` vẫn validate được với `normalized_event_schema.json` sau khi align vocabulary.

---

## 11. Updated checklist

- [x] Task 2.5: Có `vocabulary.yaml` với các enum chính.
- [x] Task 2.5: Mọi non-null enum trong `normalized_event_schema.json` đều có trong `vocabulary.yaml`.
- [x] Task 2.6: Có `action_name_aliases` cho nhiều raw tool names.
- [x] Task 2.6: Có `effect_mapping` cho canonical actions.
- [x] Task 2.6: Có `target_mapping` cho canonical actions.
- [x] Task 2.6: Có ít nhất 10 action phổ biến; hiện có 15 canonical actions.
- [x] Sample trace vẫn validate được sau khi align schema/vocabulary.


---

## 12. Task 2.9 — Schema invariants v0.1

### 12.1. Mục tiêu

Các invariant dưới đây là **basic trace validation rules** cho normalized event stream. Đây chưa phải verifier/policy checker. Validator chỉ kiểm tra trace có structurally consistent hay không trước khi C2 preservation checker và verifier backend chạy.

### 12.2. Invariant list

| ID | Invariant | Check level | Failure result | Ghi chú |
| --- | --- | --- | --- | --- |
| `INV-01` | `event_id` must be unique within a trace. | trace-level | `INVALID_TRACE` | Nếu trùng id thì causal link, parent reference, approval reference có thể bị nhập nhằng. |
| `INV-02` | `trace_id` of every event must match root `trace_id`. | trace-level | `INVALID_TRACE` | Không cho trộn event từ nhiều run/session trong cùng một trace object. |
| `INV-03` | `step_id` must be non-negative and ordered. | trace-level | `INVALID_TRACE` | Với schema v0.1, `step_id` nên là integer `>= 0`; event list nên được sắp theo thứ tự không giảm của `step_id`. If a framework provides a non-numeric step id, C1 should assign a monotonic integer `step_id` and preserve the original value in `metadata.raw_step_id`. |
| `INV-04` | `parent_event` and `approval.approval_event` must refer to existing `event_id` if not null. `input_refs` may refer to `event_id`, `output_ref`, `source_id`, `document_id`, `tool_result_id`, `approval_id`, or other adapter-produced artifact ids. | trace-level | `INVALID_TRACE` for broken event references; `UNKNOWN` for unresolved rule-required input references | C2 should resolve `input_refs` against previous `event_id`, `output_ref`, provenance/source ids, and metadata. If unresolved and the rule needs causal/provenance evidence, return `UNKNOWN`, not `SAFE`. |
| `INV-05` | `phase` must be one of `vocabulary.phase`. | event-level | `INVALID_TRACE` | C1 adapter phải normalize raw phase về controlled vocabulary. |
| `INV-06` | `action_type` must be one of `vocabulary.action_type`. | event-level | `INVALID_TRACE` | Dùng để route event sang permission/state/provenance/recovery logic. |
| `INV-07` | `effect_type` must be one of `vocabulary.effect_type` or `null`. | event-level | `INVALID_TRACE` | `null` nghĩa là effect không áp dụng hoặc chưa extract được. |
| `INV-08` | `target_resource` must be one of `vocabulary.target_resource` or `null`. | event-level | `INVALID_TRACE` | `null` nghĩa là event không có resource target rõ ràng. |
| `INV-09` | `status` must be one of `vocabulary.status`. | event-level | `INVALID_TRACE` | Status là evidence quan trọng cho recovery/governance rule. |
| `INV-10` | Missing optional evidence must not be converted to `SAFE` by default. | C2 boundary | `UNKNOWN` | Nếu rule cần `approval`, `taint`, `provenance`, `policy`, hoặc `decision` mà field thiếu, C2 phải trả `UNKNOWN`/`INSUFFICIENT_EVIDENCE`, không được mặc định `SAFE`. |

### 12.3. Phân biệt schema invariant và verifier rule

- Schema invariant kiểm tra trace có hợp lệ để xử lý tiếp không.
- C2 preservation checker kiểm tra rule-specific evidence có đủ không.
- Verifier/policy checker mới quyết định `SAFE`, `VIOLATION`, hoặc `UNKNOWN` theo từng rule.

Ví dụ: một `send_email` event không có `approval` vẫn có thể là schema-valid nếu optional evidence slot bị thiếu. Nhưng với rule `Approval before external send`, C2 phải trả `UNKNOWN`, không được coi là `SAFE`.

### 12.4. Validator implication cho Phase 4/5

Phase 4/5 có thể implement validator theo pipeline:

```text
load vocabulary.yaml
load normalized_event_schema.json
validate JSON Schema
check INV-01..INV-09 for structural consistency
pass structurally valid trace to C2 preservation checker
if required evidence missing for a rule -> UNKNOWN, not SAFE
```

### 12.5. Updated checklist

- [x] Có invariant cho unique `event_id`.
- [x] Có invariant cho root/event `trace_id` consistency.
- [x] Có invariant cho non-negative and ordered `step_id`.
- [x] Có invariant cho reference integrity: `parent_event`, `input_refs`, `approval.approval_event`.
- [x] Có invariant cho enum fields backed by `vocabulary.yaml`.
- [x] Có invariant chống default-safe khi thiếu optional evidence.

---

## 13. Task 2.11 — Scope schema v0.1

### 13.1. Mục tiêu

Phần này chốt phạm vi của `normalized_event_schema.json` v0.1 để tránh schema phình quá to. Schema v0.1 chỉ cần đủ cho prototype C1 canonicalizer và C2 preservation checker chạy trên các policy đầu tiên. Những phần cần suy luận sâu, mô hình trạng thái đầy đủ, hoặc graph phân tích hoàn chỉnh sẽ để sang version sau.

### 13.2. Supported in v0.1

| Nhóm được support | Ý nghĩa trong schema v0.1 | Field/vocabulary liên quan | Ghi chú |
| --- | --- | --- | --- |
| Tool call | Biểu diễn tool/API/function call của agent. | `action_type=tool_call`, `action_name`, `typed_args`, `tool_output`, `status` | Dùng cho permission, taint, state, recovery rules. |
| Retrieval | Biểu diễn event lấy tài liệu/context từ web/vector store/RAG. | `action_type=retrieval`, `effect_type=retrieve`, `output_ref`, `provenance`, `taint` | Dùng để kiểm tra untrusted retrieval và source tracking. |
| Memory operation | Biểu diễn read/write vào memory ngắn hạn/dài hạn. | `action_type=memory_op`, `target_resource=memory`, `effect_type=read/write` | Dùng cho memory provenance, taint, consent policy. |
| External API call | Biểu diễn request ra hệ thống ngoài như email, calendar, database, web API. | `action_type=external_api_call`, `target_resource`, `effect_type`, `typed_args` | Dùng cho approval, permission, privilege confinement. |
| Approval event | Biểu diễn bằng chứng user/policy approval. | `action_type=governance_action`, `action_name=approve_*`, `approval.exists`, `approval.status`, `approval.target`, `approval.approval_event` | Raw/vocabulary alias `approval` is normalized to schema canonical `governance_action`. |
| Final response | Biểu diễn câu trả lời cuối của agent. | `action_type=agent_response`, `action_name=final_response`, `phase=finish`, `input_refs`, `parent_event`, `status` | Raw/vocabulary alias `final_response` is normalized to schema canonical `agent_response`. |
| Policy update | Biểu diễn thay đổi hoặc rewrite policy. | `action_type=policy_decision` or `governance_action`, `policy.policy_version`, `decision` | Raw/vocabulary alias `policy_update` is normalized to schema canonical `policy_decision`. |
| Basic causal links | Liên kết event với nguồn/cha/input/output. | `parent_event`, `input_refs`, `output_ref`, `provenance` | Đủ cho causal chain mức event/reference, chưa phải full graph. |
| Basic taint/provenance | Gắn nhãn trust/sensitivity/source đơn giản. | `taint.label`, `taint.source`, `taint.reason`, `provenance` | Đủ cho policy source-to-sink cơ bản. |
| Basic status/error | Lưu trạng thái chạy, lỗi, reversibility. | `status`, `error_type`, `reversibility`, `decision` | Dùng cho recovery/governance và UNKNOWN handling. |

### 13.3. Not supported in v0.1

| Không support trong v0.1 | Lý do không đưa vào schema v0.1 | Cách xử lý tạm thời |
| --- | --- | --- |
| Full symbolic state | Quá rộng, phụ thuộc domain và verifier backend. | Dùng `pre_state`, `post_state`, hoặc `metadata` cho selected state variables nếu adapter có extract được. |
| Full data-flow graph | Cần dynamic taint/provenance engine riêng, không nên ép vào schema tối thiểu. | Dùng `input_refs`, `output_ref`, `provenance`, `taint.causal_path` cho causal/data-flow cơ bản. |
| Full natural language claim extraction | Cần claim parser/judge riêng, dễ làm scope phình. | Map final response với tool/retrieval source bằng `input_refs`, `parent_event`, hoặc `metadata.final_claim_link`. |
| Full PRISM/DTMC model | Cần state space, transition probability, reward/cost model riêng. | v0.1 chỉ giữ event stream; PRISM/DTMC exporter để version sau. |
| Side effects not present in raw trace | Nếu runtime không log/observe side effect thì canonicalizer không thể preserve evidence. | C2 trả `UNKNOWN`/`INSUFFICIENT_EVIDENCE`, không mặc định `SAFE`. |

### 13.4. Scope decision

Schema v0.1 là **minimal verifier-ready event schema**, không phải full observability schema hoặc full formal model. Mọi field chính thức ở v0.1 phải phục vụ một trong ba mục tiêu:

1. Giúp C1 normalize raw trace thành event stream ổn định.
2. Giúp C2 kiểm tra đủ/thiếu required evidence cho rule.
3. Giúp verifier backend đọc được action, target, status, causal link, approval, taint/provenance cơ bản.

Nếu một rule cần evidence ngoài scope v0.1, xử lý theo thứ tự:

```text
A. Nếu evidence phổ biến và nhiều rule cần -> cân nhắc thêm field chính thức ở version sau.
B. Nếu evidence ít gặp hoặc domain-specific -> đưa vào metadata/evidence slot.
C. Nếu không thể extract từ raw trace -> mark rule unsupported hoặc return UNKNOWN.
```

### 13.5. Updated checklist

- [x] Có phần Supported in v0.1.
- [x] Có phần Not supported in v0.1.
- [x] Scope giữ đúng hướng minimal schema, tránh phình thành full verifier/model.
- [x] Missing evidence tiếp tục được xử lý bằng `UNKNOWN`, không default `SAFE`.

