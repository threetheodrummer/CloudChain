"""
CloudChain FastAPI backend.

Endpoints are simple JSON contracts so the React frontend can render findings,
the attack-path graph, scan progress, and drift without backend changes.

Run locally:
    uvicorn app.main:app --reload --port 8000
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.attribution import LOOKBACK_DAYS, attribute_findings
from app.config import settings
from app.jobs import get_job, start_scan
from app.models import ScanResult
from app.pipeline import run_scan
from app.report.generator import build_report
from app.sources import get_data_sources, validate_credentials
from app.storage import compare_scans, get_previous_scan, get_scan, list_scans
from app.terraform import analyse_plan
from app.validation import validate_paths

app = FastAPI(title="CloudChain", version="0.2.0", description="Attack-path-aware CSPM")

# Dev-friendly CORS. Restrict allow_origins to the deployed frontend origin
# before shipping this anywhere real.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class AWSCredentials(BaseModel):
    """Credentials submitted from the UI for a real-account scan.

    These are used for the duration of a single scan and then discarded --
    never persisted to the database, never logged. See app/jobs.py.
    """

    access_key_id: str = Field(default="", description="AKIA... access key id")
    secret_access_key: str = Field(default="", description="Secret access key")
    session_token: str = Field(default="", description="Optional STS session token")
    region: str = Field(default="us-east-1")


class StartScanRequest(BaseModel):
    mode: str = Field(default="demo", description="'demo' or 'real'")
    credentials: Optional[AWSCredentials] = None


@app.get("/api/health")
def health():
    return {"status": "ok", "default_mode": settings.default_mode}


@app.post("/api/aws/validate")
def validate_aws(creds: AWSCredentials):
    """Check a credential pair via STS GetCallerIdentity before scanning, so
    the UI can show a clear error instead of an empty report."""
    result = validate_credentials(
        region=creds.region,
        access_key_id=creds.access_key_id or None,
        secret_access_key=creds.secret_access_key or None,
        session_token=creds.session_token or None,
    )
    if not result["valid"]:
        raise HTTPException(status_code=401, detail=result["error"] or "Invalid AWS credentials")
    return {"account": result["account"], "arn": result["arn"]}


@app.post("/api/scan/start")
def scan_start(req: StartScanRequest):
    """Kick off a scan on a worker thread and return a job id to poll."""
    if req.mode not in ("demo", "real"):
        raise HTTPException(400, detail="mode must be 'demo' or 'real'")

    creds = req.credentials
    if req.mode == "real":
        if not creds or not creds.access_key_id or not creds.secret_access_key:
            raise HTTPException(400, detail="Real-account scans require an access key id and secret")

        check = validate_credentials(
            region=creds.region,
            access_key_id=creds.access_key_id,
            secret_access_key=creds.secret_access_key,
            session_token=creds.session_token or None,
        )
        if not check["valid"]:
            raise HTTPException(401, detail=check["error"] or "Invalid AWS credentials")

    job = start_scan(
        mode=req.mode,
        region=creds.region if creds else settings.aws_region,
        access_key_id=creds.access_key_id if creds else None,
        secret_access_key=creds.secret_access_key if creds else None,
        session_token=(creds.session_token or None) if creds else None,
    )
    return {"job_id": job.job_id, "status": job.status}


@app.get("/api/scan/status/{job_id}")
def scan_status(job_id: str):
    job = get_job(job_id)
    if job is None:
        raise HTTPException(404, detail="job not found")
    return job.public_state()


@app.post("/api/scan")
def trigger_scan(mode: str = Query(default=None, description="'demo' or 'real'")):
    """Synchronous scan. Kept for the CLI/scripting path and for tests; the UI
    uses the job-based endpoints above."""
    scan_mode = mode or settings.default_mode
    if scan_mode not in ("demo", "real"):
        raise HTTPException(400, detail="mode must be 'demo' or 'real'")

    result, drift = run_scan(mode=scan_mode)
    return build_report(result, drift)


@app.get("/api/scans")
def scans(mode: Optional[str] = None, limit: int = 20):
    results = list_scans(mode=mode, limit=limit)
    return [
        {"scan_id": s.scan_id, "mode": s.mode, "timestamp": s.timestamp.isoformat(), "summary": s.summary}
        for s in results
    ]


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: str):
    result = get_scan(scan_id)
    if result is None:
        raise HTTPException(404, detail="scan not found")
    return result.model_dump()


@app.get("/api/scans/{scan_id}/report")
def scan_report(scan_id: str):
    result = get_scan(scan_id)
    if result is None:
        raise HTTPException(404, detail="scan not found")
    return build_report(result)


@app.post("/api/scans/{scan_id}/validate")
def validate_scan_paths(scan_id: str, creds: Optional[AWSCredentials] = None):
    """Re-check every attack path in a stored scan against the account.

    Validation issues read-only calls only -- it verifies each hop's
    preconditions and never performs the escalation. See
    app/validation/path_validator.py for what that guarantee rests on.

    Demo scans validate with no input. Real scans need credentials again,
    because scan-time credentials are deliberately never persisted.
    """
    result = get_scan(scan_id)
    if result is None:
        raise HTTPException(404, detail="scan not found")

    if not result.attack_paths:
        return {"scan_id": scan_id, "mode": result.mode, "validations": []}

    if result.mode == "real":
        if not creds or not creds.access_key_id or not creds.secret_access_key:
            raise HTTPException(
                400,
                detail=(
                    "Validating a real-account scan requires credentials again -- "
                    "scan-time credentials are never stored."
                ),
            )
        check = validate_credentials(
            region=creds.region,
            access_key_id=creds.access_key_id,
            secret_access_key=creds.secret_access_key,
            session_token=creds.session_token or None,
        )
        if not check["valid"]:
            raise HTTPException(401, detail=check["error"] or "Invalid AWS credentials")

    # One source per account, so a chain that crosses an org boundary can have
    # each hop checked against the account that actually owns the resource.
    sources = get_data_sources(
        result.mode,
        region=creds.region if creds else settings.aws_region,
        access_key_id=creds.access_key_id if creds else None,
        secret_access_key=creds.secret_access_key if creds else None,
        session_token=(creds.session_token or None) if creds else None,
    )

    validations = validate_paths(result.attack_paths, sources, result.graph)
    return {
        "scan_id": scan_id,
        "mode": result.mode,
        "validations": [v.model_dump(mode="json") for v in validations],
    }


@app.post("/api/scans/{scan_id}/attribute")
def attribute_scan_findings(
    scan_id: str,
    creds: Optional[AWSCredentials] = None,
    limit: int = Query(default=25, ge=1, le=200),
    only_new: bool = Query(
        default=False, description="Attribute only findings that are new since the previous scan"
    ),
):
    """Name the API call, actor and timestamp behind each finding.

    Reads CloudTrail's 90-day event history. Findings older than that come back
    UNATTRIBUTED, which is the honest answer rather than a guess.
    """
    result = get_scan(scan_id)
    if result is None:
        raise HTTPException(404, detail="scan not found")

    if result.mode == "real":
        if not creds or not creds.access_key_id or not creds.secret_access_key:
            raise HTTPException(
                400,
                detail=(
                    "Attributing a real-account scan requires credentials again -- "
                    "scan-time credentials are never stored."
                ),
            )
        check = validate_credentials(
            region=creds.region,
            access_key_id=creds.access_key_id,
            secret_access_key=creds.secret_access_key,
            session_token=creds.session_token or None,
        )
        if not check["valid"]:
            raise HTTPException(401, detail=check["error"] or "Invalid AWS credentials")

    findings = result.findings
    if only_new:
        previous = get_previous_scan(result.scan_id, result.mode)
        drift = compare_scans(result, previous)
        new_ids = {e.finding_id for e in drift.new_findings}
        findings = [f for f in findings if f.id in new_ids]

    sources = get_data_sources(
        result.mode,
        region=creds.region if creds else settings.aws_region,
        access_key_id=creds.access_key_id if creds else None,
        secret_access_key=creds.secret_access_key if creds else None,
        session_token=(creds.session_token or None) if creds else None,
    )

    attributions = attribute_findings(findings[:limit], sources)
    return {
        "scan_id": scan_id,
        "mode": result.mode,
        "lookback_days": LOOKBACK_DAYS,
        "attributions": [a.model_dump(mode="json") for a in attributions],
    }


class PlanRequest(BaseModel):
    """A `terraform show -json` document, plus where it will be applied."""

    plan: Dict[str, Any] = Field(description="Parsed output of `terraform show -json tfplan`")
    account_id: str = Field(default="", description="Account the plan targets")
    account_name: str = Field(default="")
    baseline_scan_id: str = Field(
        default="", description="Scan to diff against; defaults to the latest demo scan"
    )


@app.post("/api/plan/analyze")
def analyze_plan(req: PlanRequest):
    """Scan a Terraform plan and report what it changes about the attack surface.

    Runs the identical scanners, graph engine and posture model used for a live
    account, so the verdict here is the verdict you'd get after apply.
    """
    baseline: Optional[ScanResult] = None
    if req.baseline_scan_id:
        baseline = get_scan(req.baseline_scan_id)
        if baseline is None:
            raise HTTPException(404, detail="baseline scan not found")
    else:
        recent = list_scans(limit=1)
        baseline = recent[0] if recent else None

    try:
        return analyse_plan(
            req.plan,
            baseline=baseline,
            account_id=req.account_id,
            account_name=req.account_name,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(400, detail=f"could not parse the Terraform plan: {exc}") from exc


@app.get("/api/report/latest")
def latest_report(mode: str = "demo"):
    results = list_scans(mode=mode, limit=1)
    if not results:
        raise HTTPException(404, detail=f"no scans recorded yet for mode={mode!r}. POST /api/scan first.")
    return build_report(results[0])
