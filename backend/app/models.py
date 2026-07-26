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
