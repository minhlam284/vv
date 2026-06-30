from src.c2.reports import generate_reports

results = [
{
"trace_id": "case_001",
"verdicts": [
{
"policy_id": "P001",
"trace_id": "case_001",
"verdict": "SAFE",
"reason": "approval exists before send",
"missing_evidence": [],
"evidence_map": {
"approval.status": ["e_001"],
"effect_type": ["e_002"]
},
"triggered_event_ids": ["e_002"]
}
],
"preservation": [
{
"policy_id": "P001",
"trace_id": "case_001",
"status": "COMPLETE",
"missing_evidence": [],
"evidence_map": {
"approval.status": ["e_001"],
"effect_type": ["e_002"]
},
"triggered_event_ids": ["e_002"]
}
]
},
{
"trace_id": "case_003",
"verdicts": [
{
"policy_id": "P001",
"trace_id": "case_003",
"verdict": "UNKNOWN",
"reason": "approval evidence missing",
"missing_evidence": ["approval.status"],
"evidence_map": {
"effect_type": ["e_002"]
},
"triggered_event_ids": ["e_002"]
}
],
"preservation": [
{
"policy_id": "P001",
"trace_id": "case_003",
"status": "INCOMPLETE",
"missing_evidence": ["approval.status"],
"evidence_map": {
"effect_type": ["e_002"]
},
"triggered_event_ids": ["e_002"]
}
]
}
]

paths = generate_reports(results, "results")
print(paths)
