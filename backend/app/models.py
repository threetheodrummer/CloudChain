"""
Pydantic schemas shared across scanners, the graph engine, risk scoring,
storage, and the API layer.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def finding_fingerprint(resource_id: str, issue_code: str, dedupe_key: str = "") -> str:
    """Stable identity for a finding, used for drift diffing across scans.

    dedupe_key exists because a single resource can have multiple distinct
    violations of the *same* issue_code (e.g. two different open ports on
    one security group, or two access keys on one IAM user) -- without it
    those would collide into a single fingerprint and silently disappear
    from drift tracking.
    """
    raw = f"{resource_id}:{issue_code}:{dedupe_key}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


class ScoreFactor(BaseModel):
    """One auditable line item in a score calculation.

    Every number CloudChain shows has to be traceable to the findings that
    produced it. A ScoreFactor is one row of that audit trail: what was
    counted, why, and how much it moved the number.
    """

    label: str
    detail: str
    contribution: float


class Finding(BaseModel):
    resource_id: str
    resource_type: str  # s3_bucket | iam_user | iam_role | security_group
    issue_code: str
    title: str
    description: str
    base_severity: Severity
    internet_facing: bool = False
    sensitive: bool = False
    remediation: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    dedupe_key: str = ""  # set by scanners when a resource can have multiple findings of the same issue_code

    @property
    def id(self) -> str:
        return finding_fingerprint(self.resource_id, self.issue_code, self.dedupe_key)


class ScoredFinding(Finding):
    risk_score: float
    in_attack_path: bool = False
    rank: int = 0
    # Step-by-step arithmetic behind risk_score, so the UI can show why a
    # finding outranks another instead of asking the user to trust a number.
    score_breakdown: List[ScoreFactor] = Field(default_factory=list)


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    attributes: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str


class AttackPath(BaseModel):
    path_id: str
    node_ids: List[str]
    steps: List[str]  # human-readable narrative steps, one per hop
    severity: Severity
    narrative: str


class ScanGraph(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)


class VerdictStatus(str, Enum):
    """Outcome of re-checking one claim against the live account.

    There is deliberately no "EXPLOITED" state. CloudChain verifies the
    preconditions of each hop with read-only calls; it never performs the
    escalation itself. See app/validation/path_validator.py.
    """

    CONFIRMED = "CONFIRMED"  # a read-only API response proves the precondition
    REFUTED = "REFUTED"  # a read-only API response contradicts it
    UNVERIFIABLE = "UNVERIFIABLE"  # the API did not return enough to decide


class EvidenceCall(BaseModel):
    """One read-only API call made while verifying a hop, and what came back.

    `cli` is the equivalent aws-cli invocation so a reviewer can reproduce the
    check by hand rather than taking CloudChain's word for it.
    """

    api: str
    request: str
    observed: str
    cli: str = ""


class HopVerification(BaseModel):
    index: int
    source: str
    target: str
    relation: str
    claim: str  # what this hop asserts, in plain English
    status: VerdictStatus
    reason: str
    calls: List[EvidenceCall] = Field(default_factory=list)


class PathValidation(BaseModel):
    path_id: str
    status: VerdictStatus
    summary: str
    validated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    read_only: bool = True
    hops: List[HopVerification] = Field(default_factory=list)


class ScanResult(BaseModel):
    scan_id: str
    mode: str  # demo | real
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    findings: List[ScoredFinding] = Field(default_factory=list)
    attack_paths: List[AttackPath] = Field(default_factory=list)
    graph: ScanGraph = Field(default_factory=ScanGraph)

    @property
    def summary(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.base_severity.value] += 1
        return counts


class DriftStatus(str, Enum):
    NEW = "NEW"
    RESOLVED = "RESOLVED"
    UNCHANGED = "UNCHANGED"


class DriftEntry(BaseModel):
    finding_id: str
    resource_id: str
    issue_code: str
    title: str
    status: DriftStatus


class DriftReport(BaseModel):
    previous_scan_id: Optional[str]
    current_scan_id: str
    new_findings: List[DriftEntry] = Field(default_factory=list)
    resolved_findings: List[DriftEntry] = Field(default_factory=list)
    unchanged_count: int = 0
