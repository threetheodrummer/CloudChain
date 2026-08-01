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
from app.graph import (
    build_attack_graph,
    find_attack_paths,
    find_escalation_paths,
    finding_ids_on_paths,
    to_scan_graph,
)
from app.models import DriftReport, Finding, ScanResult
from app.risk import score_findings
from app.scanners import IAMScanner, S3Scanner, SecurityGroupScanner
from app.sources import AWSDataSource, get_data_sources
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


def analyse_sources(
    sources: List["AWSDataSource"],
    scan_id: str,
    mode: str,
    stage: Optional[Callable[[str, str], None]] = None,
) -> ScanResult:
    """Scanners -> graph -> scoring, for any set of data sources.

    Extracted so that scanning a live account and scanning a Terraform plan run
    through byte-identical analysis. The whole value of shift-left checking is
    that the answer you get in CI is the answer you'd get after apply; two
    parallel implementations would quietly diverge and destroy that guarantee.
    """
    step = stage or (lambda sid, detail="": None)
    account_label = ", ".join(s.account_name or s.account_id or "unknown" for s in sources)

    findings: List[Finding] = []

    def collect(scanner_cls, source) -> List[Finding]:
        """Run one scanner and stamp its findings with the account they came from.

        Stamping centrally rather than in each scanner keeps the account
        dimension out of a dozen Finding(...) call sites, and guarantees no
        scanner can forget to attribute a finding.
        """
        out = scanner_cls(source).scan()
        for f in out:
            f.account_id = source.account_id
            f.account_name = source.account_name
        return out

    step("s3", f"checking public access, encryption, versioning, exposed objects across {account_label}")
    for source in sources:
        findings.extend(collect(S3Scanner, source))

    step("iam", "checking MFA, stale keys, wildcard grants, PassRole escalation, cross-account trust")
    for source in sources:
        findings.extend(collect(IAMScanner, source))

    step("ec2", "checking ingress rules open to 0.0.0.0/0")
    for source in sources:
        findings.extend(collect(SecurityGroupScanner, source))

    step("graph", f"{len(findings)} findings across {len(sources)} account(s)")
    graph, findings_by_resource = build_attack_graph(findings)
    attack_paths = find_attack_paths(graph, findings_by_resource)

    # Identity-to-admin routes are computed for every scan, not just for
    # Terraform plan checking. Most real accounts have no internet entry point
    # at all, so reporting only internet-reachable chains means reporting
    # nothing -- which is exactly what happened the first time CloudChain was
    # pointed at a deliberately vulnerable account.
    escalation_paths = find_escalation_paths(graph, findings_by_resource)

    # Only internet-reachable chains boost a finding's risk score. An
    # escalation primitive is real but conditional, and the 2.5x multiplier is
    # calibrated for "an unauthenticated attacker can reach this".
    ids_in_path = finding_ids_on_paths(attack_paths, findings_by_resource)

    step(
        "score",
        f"{len(attack_paths)} internet-reachable path(s), "
        f"{len(escalation_paths)} escalation path(s)",
    )
    scored = score_findings(findings, ids_in_path)

    return ScanResult(
        scan_id=scan_id,
        mode=mode,
        findings=scored,
        attack_paths=attack_paths,
        escalation_paths=escalation_paths,
        graph=to_scan_graph(graph),
    )


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
    sources = get_data_sources(
        mode,
        region=region,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=session_token,
    )
    result = analyse_sources(sources, scan_id=scan_id, mode=mode, stage=stage)

    stage("drift", "diffing against previous snapshot")
    previous = get_previous_scan(scan_id, mode) if persist else None
    drift = compare_scans(result, previous)

    if persist:
        save_scan(result)

    return result, drift
