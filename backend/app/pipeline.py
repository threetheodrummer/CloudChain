"""
The full CloudChain scan pipeline, shared by the FastAPI app, the background
job runner, and the CLI so there's exactly one code path for "run a scan":

    data source (real|demo) -> scanners -> attack-path graph
        -> risk scoring -> persistence -> drift vs previous scan

Each stage reports through an optional progress callback so the UI can show
what the scanner is actually doing rather than a meaningless spinner.
"""
from __future__ import annotations

import time
import uuid
from typing import Callable, List, Optional, Tuple

from app.config import settings
from app.graph import build_attack_graph, find_attack_paths, finding_ids_on_paths, to_scan_graph
from app.models import DriftReport, Finding, ScanResult
from app.risk import score_findings
from app.scanners import IAMScanner, S3Scanner, SecurityGroupScanner
from app.sources import get_data_source
from app.storage import compare_scans, get_previous_scan, save_scan

# (stage_id, human-readable label) in execution order. The frontend renders
# this same list as a checklist, so keep the ids stable.
STAGES: List[Tuple[str, str]] = [
    ("connect", "Establishing connection to account"),
    ("s3", "Enumerating S3 buckets and object exposure"),
    ("iam", "Analysing IAM users, roles and policy grants"),
    ("ec2", "Inspecting EC2 security group ingress rules"),
    ("graph", "Correlating findings into an attack-path graph"),
    ("score", "Computing contextual risk scores"),
    ("drift", "Comparing against previous scan"),
]

ProgressFn = Callable[[str, str], None]


def _noop(stage_id: str, detail: str) -> None:
    pass


def run_scan(
    mode: str = "demo",
    region: Optional[str] = None,
    persist: bool = True,
    on_progress: Optional[ProgressFn] = None,
    access_key_id: Optional[str] = None,
    secret_access_key: Optional[str] = None,
    session_token: Optional[str] = None,
    stage_delay: float = 0.0,
) -> Tuple[ScanResult, DriftReport]:
    """Run one full scan.

    stage_delay pauses briefly between stages. It exists purely so demo-mode
    scans -- which complete in milliseconds against seeded data -- don't blow
    past the progress UI before it can be read. Real scans pass 0.0 and are
    paced by actual AWS API latency.
    """
    progress = on_progress or _noop
    region = region or settings.aws_region
    scan_id = f"{mode}-{uuid.uuid4().hex[:10]}"

    def stage(stage_id: str, detail: str = "") -> None:
        progress(stage_id, detail)
        if stage_delay:
            time.sleep(stage_delay)

    stage("connect", f"mode={mode}")
    source = get_data_source(
        mode,
        region=region,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=session_token,
    )

    findings: List[Finding] = []

    stage("s3", "checking public access, encryption, versioning, exposed objects")
    findings.extend(S3Scanner(source).scan())

    stage("iam", "checking MFA, stale keys, wildcard grants, PassRole escalation")
    findings.extend(IAMScanner(source).scan())

    stage("ec2", "checking ingress rules open to 0.0.0.0/0")
    findings.extend(SecurityGroupScanner(source).scan())

    stage("graph", f"{len(findings)} findings collected")
    graph, findings_by_resource = build_attack_graph(findings)
    attack_paths = find_attack_paths(graph, findings_by_resource)
    ids_in_path = finding_ids_on_paths(attack_paths, findings_by_resource)

    stage("score", f"{len(attack_paths)} attack path(s) found")
    scored = score_findings(findings, ids_in_path)

    result = ScanResult(
        scan_id=scan_id,
        mode=mode,
        findings=scored,
        attack_paths=attack_paths,
        graph=to_scan_graph(graph),
    )

    stage("drift", "diffing against previous snapshot")
    previous = get_previous_scan(scan_id, mode) if persist else None
    drift = compare_scans(result, previous)

    if persist:
        save_scan(result)

    return result, drift
