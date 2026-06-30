import sys
sys.path.append('.')
from tests.c2.conftest import make_p001_rule, make_p003_rule, p003_safe_trace
from src.c2.verdict_engine import evaluate_rule
import json

p3_rule = make_p003_rule()
trace = p003_safe_trace()
res = evaluate_rule(trace, p3_rule)
print("P3 verdict:", res.verdict)
print("P3 missing:", res.missing_evidence)
print("P3 reason:", res.reason)

p1_rule = make_p001_rule()
from tests.c2.conftest import p001_violation_trace
t1 = p001_violation_trace()
res1 = evaluate_rule(t1, p1_rule)
print("P1 verdict:", res1.verdict)
print("P1 missing:", res1.missing_evidence)

