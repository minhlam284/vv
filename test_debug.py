import sys
from src.c2.rule_ir import RuleIR
from src.c2.verdict_engine import evaluate_rule

def make_p001_rule():
    return RuleIR.from_dict({
        "policy_id": "P001",
        "name": "approval_before_send",
        "rule_class": ["permission", "temporal"],
        "when": [
            {"field": "effect_type", "op": "eq", "value": "send"},
            {"field": "target_resource", "op": "eq", "value": "email"}
        ],
        "require": [],
        "required_evidence": [
            "effect_type",
            "target_resource",
            "approval.exists",
            "approval.status",
            "approval.target",
            "step_id",
            "input_refs"
        ],
        "else": "violation"
    })

trace_a = {
    "trace_id": "t1",
    "events": [
        {
            "event_id": "e_002",
            "step_id": 2,
            "effect_type": "send",
            "target_resource": "email",
            "typed_args": {"recipient": "team@example.com"},
            "approval": {"status": "approved", "exists": True},
            "input_refs": []
        }
    ]
}
res_a = evaluate_rule(trace_a, make_p001_rule())
print("Test A missing:", getattr(res_a, 'missing_evidence', []))
