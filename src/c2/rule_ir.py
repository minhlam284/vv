import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

ALLOWED_RULE_CLASSES = {
    "permission",
    "temporal",
    "state_pre_post",
    "privilege_confinement",
    "provenance",
    "taint",
    "recovery_governance",
}

SUPPORTED_CONDITION_OPS = {
    "eq",
    "neq",
    "in",
    "not_in",
    "exists",
    "not_exists",
    "contains",
}

class Verdict:
    SAFE = "SAFE"
    VIOLATION = "VIOLATION"
    UNKNOWN = "UNKNOWN"
    INCONSISTENT = "INCONSISTENT"

    @classmethod
    def normalize(cls, value: str) -> str:
        v = value.upper()
        if v not in {cls.SAFE, cls.VIOLATION, cls.UNKNOWN, cls.INCONSISTENT}:
            raise ValueError(f"Invalid verdict: {value}")
        return v

class PreservationStatus:
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    INCONSISTENT = "INCONSISTENT"
    NOT_APPLICABLE = "NOT_APPLICABLE"

    @classmethod
    def validate(cls, value: str) -> None:
        v = value.upper()
        if v not in {cls.COMPLETE, cls.INCOMPLETE, cls.INCONSISTENT, cls.NOT_APPLICABLE}:
            raise ValueError(f"Invalid preservation status: {value}")


@dataclass
class Condition:
    field: str
    op: str
    value: Any = None

    def __post_init__(self):
        if not self.field:
            raise ValueError("Condition field must be non-empty.")
        if self.op not in SUPPORTED_CONDITION_OPS:
            raise ValueError(f"Condition op must be one of {SUPPORTED_CONDITION_OPS}.")

    @classmethod
    def from_dict(cls, data: dict) -> 'Condition':
        return cls(
            field=data["field"],
            op=data["op"],
            value=data.get("value")
        )

    def to_dict(self) -> dict:
        d = {"field": self.field, "op": self.op}
        if self.value is not None or self.op not in ("exists", "not_exists"):
            d["value"] = self.value
        return d


@dataclass
class Requirement:
    type: str
    conditions: List[Condition] = field(default_factory=list)
    same_target: bool = False
    target_field: Optional[str] = None
    reference_field: Optional[str] = None
    temporal_scope: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.type:
            raise ValueError("Requirement type must be non-empty.")

    @classmethod
    def from_dict(cls, data: dict) -> 'Requirement':
        d = data.copy()
        req_type = d.pop("type")
        conditions = [Condition.from_dict(c) for c in d.pop("conditions", [])]
        same_target = d.pop("same_target", False)
        target_field = d.pop("target_field", None)
        reference_field = d.pop("reference_field", None)
        temporal_scope = d.pop("temporal_scope", None)
        # Anything else goes to metadata
        metadata = d.pop("metadata", {})
        metadata.update(d)
        
        return cls(
            type=req_type,
            conditions=conditions,
            same_target=same_target,
            target_field=target_field,
            reference_field=reference_field,
            temporal_scope=temporal_scope,
            metadata=metadata
        )

    def to_dict(self) -> dict:
        d = {
            "type": self.type,
        }
        if self.conditions:
            d["conditions"] = [c.to_dict() for c in self.conditions]
        if self.same_target:
            d["same_target"] = self.same_target
        if self.target_field is not None:
            d["target_field"] = self.target_field
        if self.reference_field is not None:
            d["reference_field"] = self.reference_field
        if self.temporal_scope is not None:
            d["temporal_scope"] = self.temporal_scope
        for k, v in self.metadata.items():
            if k not in d:
                d[k] = v
        return d


@dataclass
class RuleIR:
    policy_id: str
    name: str
    rule_class: List[str]
    required_evidence: List[str]
    else_verdict: str = Verdict.VIOLATION
    when: List[Condition] = field(default_factory=list)
    require: List[Requirement] = field(default_factory=list)
    description: Optional[str] = None
    version: Optional[str] = None
    backend_hints: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.policy_id:
            raise ValueError("policy_id must be non-empty.")
        if not self.name:
            raise ValueError("name must be non-empty.")
        if not self.rule_class:
            raise ValueError("rule_class must be a non-empty list.")
        for rc in self.rule_class:
            if rc not in ALLOWED_RULE_CLASSES:
                raise ValueError(f"Invalid rule_class: {rc}")
        if not self.required_evidence or not all(self.required_evidence):
            raise ValueError("required_evidence must be a list of non-empty strings.")
        
        deduped = []
        seen = set()
        for ev in self.required_evidence:
            if not isinstance(ev, str) or not ev:
                raise ValueError("required_evidence must be a list of non-empty strings.")
            if ev not in seen:
                seen.add(ev)
                deduped.append(ev)
        self.required_evidence = deduped

        self.else_verdict = Verdict.normalize(self.else_verdict)

    @classmethod
    def from_dict(cls, data: dict) -> 'RuleIR':
        return cls(
            policy_id=data["policy_id"],
            name=data["name"],
            rule_class=data["rule_class"],
            required_evidence=data["required_evidence"],
            else_verdict=data.get("else", Verdict.VIOLATION),
            when=[Condition.from_dict(c) for c in data.get("when", [])],
            require=[Requirement.from_dict(r) for r in data.get("require", [])],
            description=data.get("description"),
            version=data.get("version"),
            backend_hints=data.get("backend_hints", []),
            metadata=data.get("metadata", {})
        )

    def to_dict(self) -> dict:
        d = {
            "policy_id": self.policy_id,
            "name": self.name,
            "rule_class": self.rule_class,
            "when": [c.to_dict() for c in self.when],
            "require": [r.to_dict() for r in self.require],
            "required_evidence": self.required_evidence,
            "else": self.else_verdict,
        }
        if self.description is not None:
            d["description"] = self.description
        if self.version is not None:
            d["version"] = self.version
        if self.backend_hints:
            d["backend_hints"] = self.backend_hints
        if self.metadata:
            d["metadata"] = self.metadata
        return d

    @classmethod
    def from_json(cls, text: str) -> 'RuleIR':
        return cls.from_dict(json.loads(text))

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> 'RuleIR':
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_file(self, path: Union[str, Path]) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)


def load_rule_ir(path: Union[str, Path]) -> RuleIR:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Rule IR file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Expected a file for load_rule_ir, got directory: {path}")
    return RuleIR.from_file(path)


def load_rule_irs(path: Union[str, Path]) -> List[RuleIR]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Rule IR path not found: {path}")
    if path.is_file():
        return [RuleIR.from_file(path)]
    rules = []
    for p in sorted(path.glob("*.json")):
        if p.is_file():
            rules.append(RuleIR.from_file(p))
    return rules


@dataclass
class PreservationResult:
    policy_id: str
    trace_id: str
    status: str
    missing_evidence: List[str]
    evidence_map: Dict[str, List[str]]
    triggered_event_ids: List[str]
    reason: Optional[str] = None

    def __post_init__(self):
        self.status = self.status.upper()
        PreservationStatus.validate(self.status)

    def to_dict(self) -> dict:
        d = {
            "policy_id": self.policy_id,
            "trace_id": self.trace_id,
            "status": self.status,
            "missing_evidence": self.missing_evidence,
            "evidence_map": self.evidence_map,
            "triggered_event_ids": self.triggered_event_ids,
        }
        if self.reason is not None:
            d["reason"] = self.reason
        return d

    @classmethod
    def complete(cls, policy_id: str, trace_id: str, evidence_map: Optional[Dict[str, List[str]]] = None, triggered_event_ids: Optional[List[str]] = None) -> 'PreservationResult':
        return cls(
            policy_id=policy_id,
            trace_id=trace_id,
            status=PreservationStatus.COMPLETE,
            missing_evidence=[],
            evidence_map=evidence_map or {},
            triggered_event_ids=triggered_event_ids or []
        )

    @classmethod
    def incomplete(cls, policy_id: str, trace_id: str, missing_evidence: List[str], evidence_map: Optional[Dict[str, List[str]]] = None, triggered_event_ids: Optional[List[str]] = None, reason: Optional[str] = None) -> 'PreservationResult':
        return cls(
            policy_id=policy_id,
            trace_id=trace_id,
            status=PreservationStatus.INCOMPLETE,
            missing_evidence=missing_evidence,
            evidence_map=evidence_map or {},
            triggered_event_ids=triggered_event_ids or [],
            reason=reason
        )

    @classmethod
    def not_applicable(cls, policy_id: str, trace_id: str, reason: Optional[str] = None) -> 'PreservationResult':
        return cls(
            policy_id=policy_id,
            trace_id=trace_id,
            status=PreservationStatus.NOT_APPLICABLE,
            missing_evidence=[],
            evidence_map={},
            triggered_event_ids=[],
            reason=reason
        )


@dataclass
class VerdictResult:
    policy_id: str
    trace_id: str
    verdict: str
    reason: str
    violated_rule: Optional[str] = None
    missing_evidence: List[str] = field(default_factory=list)
    evidence_map: Dict[str, List[str]] = field(default_factory=dict)
    triggered_event_ids: List[str] = field(default_factory=list)
    confidence: Optional[float] = None
    route: Optional[str] = None

    def __post_init__(self):
        self.verdict = Verdict.normalize(self.verdict)

    def to_dict(self) -> dict:
        d = {
            "policy_id": self.policy_id,
            "trace_id": self.trace_id,
            "verdict": self.verdict,
            "reason": self.reason,
            "missing_evidence": self.missing_evidence,
            "evidence_map": self.evidence_map,
            "triggered_event_ids": self.triggered_event_ids,
        }
        if self.violated_rule is not None:
            d["violated_rule"] = self.violated_rule
        if self.confidence is not None:
            d["confidence"] = self.confidence
        if self.route is not None:
            d["route"] = self.route
        return d

    @classmethod
    def safe(cls, policy_id: str, trace_id: str, reason: str, **kwargs) -> 'VerdictResult':
        return cls(policy_id=policy_id, trace_id=trace_id, verdict=Verdict.SAFE, reason=reason, **kwargs)

    @classmethod
    def violation(cls, policy_id: str, trace_id: str, reason: str, **kwargs) -> 'VerdictResult':
        return cls(policy_id=policy_id, trace_id=trace_id, verdict=Verdict.VIOLATION, reason=reason, **kwargs)

    @classmethod
    def unknown(cls, policy_id: str, trace_id: str, reason: str, **kwargs) -> 'VerdictResult':
        return cls(policy_id=policy_id, trace_id=trace_id, verdict=Verdict.UNKNOWN, reason=reason, **kwargs)

    @classmethod
    def inconsistent(cls, policy_id: str, trace_id: str, reason: str, **kwargs) -> 'VerdictResult':
        return cls(policy_id=policy_id, trace_id=trace_id, verdict=Verdict.INCONSISTENT, reason=reason, **kwargs)
