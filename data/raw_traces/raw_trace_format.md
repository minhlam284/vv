# Raw Trace Format v0.1

## 1. Mục tiêu

Raw trace là log thô ghi lại toàn bộ hành vi quan sát được của một agent runtime trước khi đi qua C1 canonicalizer.

Mục tiêu của raw trace là làm input thống nhất cho C1 để C1 có thể:

- parse các event từ nhiều nguồn runtime khác nhau;
- normalize tên action/tool về vocabulary chung;
- dựng lại thứ tự và causal chain giữa các event;
- preserve các evidence cần cho C2 preservation checker;
- emit normalized event stream theo `normalized_event_schema.json` v0.1.

Raw trace không phải là schema normalized cuối cùng. Nó là format tối thiểu để viết synthetic trace nhất quán và để adapter có đủ thông tin chuyển sang normalized event.

---

## 2. Trace object format

Một raw trace là một JSON object cấp trace.

Các field bắt buộc ở cấp trace:

| Field | Type | Bắt buộc | Ý nghĩa |
|---|---:|---:|---|
| `trace_id` | string | yes | ID duy nhất của một agent run/session/replay. |
| `source` | string/object | yes | Nguồn sinh trace, ví dụ `custom_agent`, `langchain`, `mcp`, `openai_agent`, `synthetic`. |
| `events` | array | yes | Danh sách raw event theo thứ tự runtime quan sát được. |

Ví dụ trace-level object:

```json
{
  "trace_id": "raw_trace_001",
  "source": "synthetic",
  "events": []
}
```

Quy ước:

- `trace_id` phải không rỗng.
- `events` phải là array, có thể rỗng khi tạo skeleton, nhưng synthetic trace dùng để test nên có ít nhất một event.
- `source` nên đủ rõ để C1 chọn adapter phù hợp.

---

## 3. Event object format

Mỗi item trong `events` là một raw event object.

Các field tối thiểu ở cấp event:

| Field | Type | Bắt buộc | Ý nghĩa |
|---|---:|---:|---|
| `event_id` | string | yes | ID duy nhất của event trong trace. |
| `step_id` | integer/string | yes | Thứ tự logic hoặc step runtime. C1 nên map về integer monotonic khi normalize. |
| `timestamp` | string/number/null | yes | Wall-clock time hoặc logical time. Có thể `null` nếu synthetic trace không cần thời gian thật. |
| `event_type` | string | yes | Loại raw event, lấy từ danh sách allowed event type. |
| `source` | string/object | yes | Component sinh event, ví dụ `user`, `planner`, `retriever`, `tool`, `memory`, `mcp_server`. |
| `action` / `tool_name` | string/null | yes | Tên action/tool/API raw. Với event không phải tool, dùng `action`; với tool call có thể dùng `tool_name`. Ít nhất một trong hai nên có giá trị nếu event biểu diễn hành động. |
| `input` | object/string/array/null | yes | Input/argument/context đi vào event. |
| `output` | object/string/array/null | yes | Output/result/observation sinh ra từ event. |
| `status` | string | yes | Trạng thái event, lấy từ allowed status. |
| `error` | object/string/null | yes | Thông tin lỗi nếu có; `null` nếu không có lỗi. |
| `parent_event` | string/null | yes | `event_id` của event cha trực tiếp nếu biết. |
| `references` | array/object/null | yes | Các reference tới message/document/tool result/memory entry/approval/source khác. |

Ví dụ raw event tối thiểu:

```json
{
  "event_id": "raw_e_001",
  "step_id": 1,
  "timestamp": "2026-06-28T10:00:00+07:00",
  "event_type": "tool_call",
  "source": "tool_runtime",
  "tool_name": "mcp.gmail.send",
  "action": null,
  "input": {
    "recipient": "team@example.com",
    "subject": "Report",
    "body_ref": "draft_001"
  },
  "output": null,
  "status": "pending",
  "error": null,
  "parent_event": "raw_e_000",
  "references": ["draft_001"]
}
```

Quy ước:

- Raw trace được phép giữ tên framework-specific như `sendEmail`, `gmail_send`, `mcp.gmail.send`.
- C1 chịu trách nhiệm normalize các tên đó thành canonical action như `send_email`.
- Nếu một field không có thông tin, vẫn giữ key và đặt `null` để tránh adapter phải đoán xem field bị thiếu hay không áp dụng.

---

## 4. Allowed event_type

Danh sách `event_type` v0.1:

| event_type | Ý nghĩa |
|---|---|
| `user_message` | Message/instruction từ user. |
| `planner_step` | Bước lập kế hoạch hoặc reasoning step có thể log được. |
| `retrieval` | Event lấy tài liệu/context từ web, vector DB, RAG, KB. |
| `tool_call` | Lệnh gọi tool/function/API trước hoặc trong khi thực thi. |
| `tool_result` | Kết quả trả về từ tool/function/API. |
| `approval_request` | Agent/system hỏi user hoặc policy layer để xin approval. |
| `approval_response` | User/policy trả lời approval/reject/unknown. |
| `memory_op` | Đọc/ghi/update/delete memory. |
| `final_response` | Câu trả lời cuối của agent cho user/downstream. |
| `error` | Lỗi runtime, lỗi tool, lỗi policy, exception hoặc malformed event. |

Quy ước mapping sang normalized event:

| Raw `event_type` | Gợi ý normalized mapping |
|---|---|
| `user_message` | `action_type=message`, `phase=plan` hoặc `before_action` |
| `planner_step` | `phase=plan`, `action_type=message` hoặc `unknown` |
| `retrieval` | `action_type=retrieval`, `effect_type=retrieve` |
| `tool_call` | `phase=before_action`, `action_type=tool_call` |
| `tool_result` | `phase=after_action`, `action_type=tool_result` |
| `approval_request` | `action_type=governance_action`, `effect_type=approve` |
| `approval_response` | `approval.status`, `decision.route` nếu có |
| `memory_op` | `action_type=memory_op`, `target_resource=memory` |
| `final_response` | `phase=finish`, `action_type=agent_response` |
| `error` | `status=failed` hoặc `status=unknown`, `error_type` nếu normalize được |

---

## 5. Allowed status

Danh sách `status` tối thiểu:

| status | Ý nghĩa |
|---|---|
| `pending` | Event/action đã được tạo hoặc chuẩn bị chạy nhưng chưa có kết quả cuối. |
| `success` | Event/action hoàn thành thành công. |
| `failed` | Event/action thất bại hoặc có exception. |
| `blocked` | Event/action bị policy/governance chặn. |
| `unknown` | Runtime không log đủ trạng thái hoặc adapter chưa xác định được. |

Ghi chú:

- Raw trace v0.1 chỉ cần 5 status trên để viết synthetic trace ổn định.
- Khi normalize sang schema v0.1, C1 có thể map thêm các status chi tiết hơn như `aborted`, `rejected`, `allowed`, `rewritten` nếu raw runtime cung cấp.

---

## 6. Example raw trace

Ví dụ ngắn cho policy: external email cần approval trước khi send.

```json
{
  "trace_id": "raw_trace_email_001",
  "source": "synthetic",
  "events": [
    {
      "event_id": "raw_e_001",
      "step_id": 1,
      "timestamp": "2026-06-28T10:00:00+07:00",
      "event_type": "user_message",
      "source": "user",
      "action": "ask_agent",
      "tool_name": null,
      "input": {
        "text": "Send the report to team@example.com"
      },
      "output": {
        "message_id": "msg_001"
      },
      "status": "success",
      "error": null,
      "parent_event": null,
      "references": []
    },
    {
      "event_id": "raw_e_002",
      "step_id": 2,
      "timestamp": "2026-06-28T10:00:02+07:00",
      "event_type": "approval_request",
      "source": "governance_layer",
      "action": "request_user_confirmation",
      "tool_name": null,
      "input": {
        "target_action": "sendEmail",
        "recipient": "team@example.com",
        "reason": "external email send"
      },
      "output": {
        "approval_request_id": "approval_req_001"
      },
      "status": "success",
      "error": null,
      "parent_event": "raw_e_001",
      "references": ["msg_001"]
    },
    {
      "event_id": "raw_e_003",
      "step_id": 3,
      "timestamp": "2026-06-28T10:00:05+07:00",
      "event_type": "approval_response",
      "source": "user",
      "action": "approve",
      "tool_name": null,
      "input": {
        "approval_request_id": "approval_req_001"
      },
      "output": {
        "approval_id": "approval_001",
        "status": "approved",
        "target": {
          "recipient": "team@example.com"
        }
      },
      "status": "success",
      "error": null,
      "parent_event": "raw_e_002",
      "references": ["approval_req_001"]
    },
    {
      "event_id": "raw_e_004",
      "step_id": 4,
      "timestamp": "2026-06-28T10:00:08+07:00",
      "event_type": "tool_call",
      "source": "tool_runtime",
      "action": null,
      "tool_name": "mcp.gmail.send",
      "input": {
        "recipient": "team@example.com",
        "subject": "Report",
        "body_ref": "draft_001"
      },
      "output": null,
      "status": "pending",
      "error": null,
      "parent_event": "raw_e_003",
      "references": ["approval_001", "draft_001"]
    }
  ]
}
```

C1 expected normalization hints:

- `tool_name = "mcp.gmail.send"` → `action_name = "send_email"`
- `event_type = "tool_call"` → `phase = "before_action"`, `action_type = "tool_call"`
- `send_email` → `effect_type = "send"`, `target_resource = "email"`
- approval evidence lấy từ `approval_response.output`
- causal order lấy từ `step_id`, `parent_event`, và `references`

---

## 7. Validation rules

Raw trace hợp lệ khi thỏa các rule sau.

### 7.1. Trace-level validation

| ID | Rule | Nếu fail |
|---|---|---|
| `RAW-TRACE-01` | `trace_id` phải tồn tại và không rỗng. | Reject trace. |
| `RAW-TRACE-02` | `source` phải tồn tại. | Reject trace hoặc yêu cầu adapter default. |
| `RAW-TRACE-03` | `events` phải là array. | Reject trace. |
| `RAW-TRACE-04` | Mọi `event_id` trong `events` phải unique. | Reject trace. |
| `RAW-TRACE-05` | `events` nên được sort theo `step_id` không giảm. | Warning hoặc reject với synthetic test strict. |

### 7.2. Event-level validation

| ID | Rule | Nếu fail |
|---|---|---|
| `RAW-EVENT-01` | Event phải có đủ key tối thiểu: `event_id`, `step_id`, `timestamp`, `event_type`, `source`, `action`, `tool_name`, `input`, `output`, `status`, `error`, `parent_event`, `references`. | Reject event. |
| `RAW-EVENT-02` | `event_type` phải nằm trong allowed event type. | Reject event hoặc map thành `error`/`unknown` nếu adapter cho phép. |
| `RAW-EVENT-03` | `status` phải nằm trong allowed status. | Reject event hoặc map thành `unknown`. |
| `RAW-EVENT-04` | Nếu `event_type = tool_call` thì ít nhất một trong `action` hoặc `tool_name` phải khác `null`. | Reject event. |
| `RAW-EVENT-05` | Nếu `status = failed` thì `error` nên khác `null`. | Warning; C2 có thể trả `UNKNOWN` nếu thiếu error evidence. |
| `RAW-EVENT-06` | Nếu `parent_event` khác `null`, nó phải trỏ tới một `event_id` đã tồn tại trong cùng trace. | Reject trace vì causal chain bị gãy. |
| `RAW-EVENT-07` | `references` nếu là array thì các item nên là string id. | Warning hoặc reject với synthetic test strict. |

### 7.3. C1/C2 boundary validation

| ID | Rule | Ý nghĩa |
|---|---|---|
| `RAW-C1-01` | Raw alias phải được preserve. | Nếu `tool_name` không map được, C1 dùng `unknown` ở normalized field nhưng phải giữ raw name trong `raw_event_ref` hoặc `metadata`. |
| `RAW-C1-02` | Missing raw evidence không được biến thành `SAFE`. | Nếu raw trace thiếu approval/taint/provenance mà rule cần, C2 phải trả `UNKNOWN`. |
| `RAW-C1-03` | Causal evidence không được drop im lặng. | `parent_event` và `references` phải được dùng để tạo `parent_event`, `input_refs`, `output_ref`, `provenance`, hoặc `taint.causal_path` khi normalize. |
| `RAW-C1-04` | Tool result/final response phải giữ link nếu có. | Nếu final response dựa trên tool output, raw trace nên có `references` để C2 check rule “tool failure must not be reported as success”. |
| `RAW-C1-05` | Unknown là trạng thái hợp lệ, nhưng không phải safe. | `unknown` chỉ có nghĩa là chưa đủ evidence hoặc không map được chắc chắn. |

### 7.4. Done criteria

Task 3.2 được coi là done khi:

- Có file `data/raw_traces/raw_trace_format.md`.
- File định nghĩa rõ trace-level fields và event-level fields tối thiểu.
- Có allowed `event_type` và `status`.
- Có một JSON example raw trace ngắn.
- Có validation rules đủ để viết synthetic trace nhất quán.
- Spec phân biệt rõ raw trace validation với C2 preservation behavior: thiếu evidence thì `UNKNOWN`, không mặc định `SAFE`.
