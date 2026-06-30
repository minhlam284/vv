from pathlib import Path
import pytest
from src.c2.rule_ir import RuleIR, load_rule_ir, load_rule_irs


def test_parse_p001_rule_from_dict(p001_rule):
    rule = p001_rule
    assert rule.policy_id == "P001"
    assert rule.name == "approval_before_send"
    assert "permission" in rule.rule_class
    assert "temporal" in rule.rule_class
    assert rule.else_verdict == "VIOLATION"
    assert rule.when[0].field == "effect_type"


def test_rule_json_round_trip(p001_rule):
    rule = p001_rule
    text = rule.to_json()
    loaded = RuleIR.from_json(text)
    assert loaded.policy_id == rule.policy_id
    
    rule_dict = loaded.to_dict()
    assert "else" in rule_dict
    assert "else_verdict" not in rule_dict


def test_load_single_rule_file(p001_rule, tmp_path):
    p001_path = tmp_path / "p001.json"
    p001_path.write_text(p001_rule.to_json())
    
    loaded = load_rule_ir(p001_path)
    assert loaded.policy_id == "P001"


def test_load_rule_directory_sorted(p001_rule, p002_rule, tmp_path):
    p002_path = tmp_path / "p002.json"
    p001_path = tmp_path / "p001.json"
    
    p002_path.write_text(p002_rule.to_json())
    p001_path.write_text(p001_rule.to_json())
    
    loaded_rules = load_rule_irs(tmp_path)
    policy_ids = [r.policy_id for r in loaded_rules]
    assert policy_ids == sorted(policy_ids)


def test_invalid_operator_fails():
    with pytest.raises(ValueError):
        RuleIR.from_dict({
            "policy_id": "P001",
            "name": "approval_before_send",
            "rule_class": ["permission"],
            "when": [
                {"field": "effect_type", "op": "bad_op", "value": "send"}
            ],
            "require": [],
            "required_evidence": [],
            "else": "violation"
        })


def test_invalid_rule_class_fails():
    with pytest.raises(ValueError):
        RuleIR.from_dict({
            "policy_id": "P001",
            "name": "approval_before_send",
            "rule_class": ["not_a_class"],
            "when": [],
            "require": [],
            "required_evidence": [],
            "else": "violation"
        })


def test_duplicate_required_evidence_deduped():
    rule = RuleIR.from_dict({
        "policy_id": "P001",
        "name": "approval_before_send",
        "rule_class": ["permission"],
        "when": [],
        "require": [],
        "required_evidence": ["effect_type", "effect_type", "target_resource"],
        "else": "violation"
    })
    
    assert rule.required_evidence == ["effect_type", "target_resource"]
