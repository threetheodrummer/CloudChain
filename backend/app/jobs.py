"""
Background scan jobs.

A scan against a real AWS account takes long enough that a blocking HTTP
request is a poor fit, so scans run on a worker thread and the frontend polls
for stage-by-stage progress:

    POST /api/scan/start   -> {"job_id": ...}
    GET  /api/scan/status/{job_id} -> {"status": ..., "stages": [...], ...}

CREDENTIAL HANDLING
-------------------
When the user supplies AWS access keys through the UI, those keys live in this
module's memory for exactly as long as the scan runs, and are then cleared
(see _run). They are deliberately:
  * never written to the SQLite snapshot database,
  * never included in the job status payload returned to the client,
  * never logged.
Only the resulting findings are persisted. This is the single most
security-sensitive part of the codebase -- keep it that way.
"""
from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.pipeline import STAGES, run_scan
from app.report.generator import build_report

logger = logging.getLogger("cloudchain.jobs")

# Demo scans finish in milliseconds; without a small pause per stage the
# progress UI would flash past unread. Real scans use no artificial delay.
DEMO_STAGE_DELAY_SECONDS = 0.55


@dataclass
class ScanJob:
    job_id: str
    mode: str
    status: str = "pending"  # pending | running | complete | failed
    current_stage: Optional[str] = None
    completed_stages: List[str] = field(default_factory=list)
    stage_detail: str = ""
    error: str = ""
    report: Optional[Dict[str, Any]] = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def public_state(self) -> Dict[str, Any]:
        """The payload sent to the browser. Contains no credentials."""
        return {
            "job_id": self.job_id,
            "mode": self.mode,
            "status": self.status,
            "current_stage": self.current_stage,
            "completed_stages": list(self.completed_stages),
            "stage_detail": self.stage_detail,
            "error": self.error,
            "stages": [{"id": sid, "label": label} for sid, label in STAGES],
            "report": self.report,
        }


_jobs: Dict[str, ScanJob] = {}
_lock = threading.Lock()


def _run(
    job: ScanJob,
    region: str,
    access_key_id: Optional[str],
    secret_access_key: Optional[str],
    session_token: Optional[str],
) -> None:
    try:
        job.status = "running"

        def on_progress(stage_id: str, detail: str) -> None:
            if job.current_stage and job.current_stage not in job.completed_stages:
                job.completed_stages.append(job.current_stage)
            job.current_stage = stage_id
            job.stage_detail = detail

        result, drift = run_scan(
            mode=job.mode,
            region=region,
            on_progress=on_progress,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            stage_delay=DEMO_STAGE_DELAY_SECONDS if job.mode == "demo" else 0.0,
        )

        if job.current_stage and job.current_stage not in job.completed_stages:
            job.completed_stages.append(job.current_stage)
        job.current_stage = None
        job.report = build_report(result, drift)
        job.status = "complete"

    except Exception as exc:
        # Log the exception type/message but never the credentials themselves.
        logger.exception("scan job %s failed", job.job_id)
        job.error = f"{type(exc).__name__}: {exc}"
        job.status = "failed"
    finally:
        # Drop the credential references as soon as the scan ends.
        access_key_id = secret_access_key = session_token = None
        del access_key_id, secret_access_key, session_token


def start_scan(
    mode: str,
    region: str = "us-east-1",
    access_key_id: Optional[str] = None,
    secret_access_key: Optional[str] = None,
    session_token: Optional[str] = None,
) -> ScanJob:
    job = ScanJob(job_id=uuid.uuid4().hex[:12], mode=mode)
    with _lock:
        _jobs[job.job_id] = job

    thread = threading.Thread(
        target=_run,
        args=(job, region, access_key_id, secret_access_key, session_token),
        daemon=True,
        name=f"cloudchain-scan-{job.job_id}",
    )
    thread.start()
    return job


def get_job(job_id: str) -> Optional[ScanJob]:
    with _lock:
        return _jobs.get(job_id)
