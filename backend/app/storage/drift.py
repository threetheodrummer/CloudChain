"""
Drift detection: diffs two ScanResults by finding fingerprint
(resource_id + issue_code) to surface what's new, what's resolved, and
what's unchanged since the last scan.
"""
from __future__ import annotations

from typing import Optional

from app.models import DriftEntry, DriftReport, DriftStatus, ScanResult


def compare_scans(current: ScanResult, previous: Optional[ScanResult]) -> DriftReport:
    if previous is None:
        return DriftReport(
            previous_scan_id=None,
            current_scan_id=current.scan_id,
            new_findings=[
                DriftEntry(
                    finding_id=f.id,
                    resource_id=f.resource_id,
                    issue_code=f.issue_code,
                    title=f.title,
                    status=DriftStatus.NEW,
                )
                for f in current.findings
            ],
            resolved_findings=[],
            unchanged_count=0,
        )

    current_ids = {f.id: f for f in current.findings}
    previous_ids = {f.id: f for f in previous.findings}

    new_ids = current_ids.keys() - previous_ids.keys()
    resolved_ids = previous_ids.keys() - current_ids.keys()
    unchanged_ids = current_ids.keys() & previous_ids.keys()

    return DriftReport(
        previous_scan_id=previous.scan_id,
        current_scan_id=current.scan_id,
        new_findings=[
            DriftEntry(
                finding_id=fid,
                resource_id=current_ids[fid].resource_id,
                issue_code=current_ids[fid].issue_code,
                title=current_ids[fid].title,
                status=DriftStatus.NEW,
            )
            for fid in new_ids
        ],
        resolved_findings=[
            DriftEntry(
                finding_id=fid,
                resource_id=previous_ids[fid].resource_id,
                issue_code=previous_ids[fid].issue_code,
                title=previous_ids[fid].title,
                status=DriftStatus.RESOLVED,
            )
            for fid in resolved_ids
        ],
        unchanged_count=len(unchanged_ids),
    )
