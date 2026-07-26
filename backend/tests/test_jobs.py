import time

from app.jobs import get_job, start_scan
from app.pipeline import STAGES, run_scan


def _wait(job, timeout=30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if job.status in ("complete", "failed"):
            return job
        time.sleep(0.05)
    raise AssertionError(f"job did not finish within {timeout}s (status={job.status})")


def test_pipeline_reports_every_stage_in_order():
    seen = []
    run_scan(mode="demo", persist=False, on_progress=lambda sid, detail: seen.append(sid))
    assert seen == [sid for sid, _ in STAGES]


def test_demo_job_completes_and_returns_a_report():
    job = start_scan(mode="demo")
    _wait(job)
    assert job.status == "complete", job.error
    assert job.report is not None
    # Asserted against the report's own contents rather than a hardcoded count,
    # so adding a demo account or a scanner check doesn't fail this for the
    # wrong reason.
    summary = job.report["summary"]
    assert summary["total_findings"] == len(job.report["findings"])
    assert summary["total_findings"] > 0
    assert summary["attack_paths_found"] == len(job.report["attack_paths"])
    assert summary["attack_paths_found"] >= 1


def test_job_marks_all_stages_completed():
    job = start_scan(mode="demo")
    _wait(job)
    assert job.completed_stages == [sid for sid, _ in STAGES]
    assert job.current_stage is None


def test_job_is_retrievable_by_id():
    job = start_scan(mode="demo")
    assert get_job(job.job_id) is job
    _wait(job)


def test_public_state_never_leaks_credentials():
    # A real-mode job is started with bogus keys; it will fail (no AWS), but
    # the state returned to the browser must never contain the secret.
    secret = "TOTALLY-SECRET-VALUE-123"
    job = start_scan(
        mode="real",
        region="us-east-1",
        access_key_id="AKIAFAKE",
        secret_access_key=secret,
        session_token=None,
    )
    _wait(job)
    payload = repr(job.public_state())
    assert secret not in payload
    assert "AKIAFAKE" not in payload


def test_public_state_shape():
    job = start_scan(mode="demo")
    state = job.public_state()
    assert set(state) == {
        "job_id", "mode", "status", "current_stage", "completed_stages",
        "stage_detail", "error", "stages", "report",
    }
    assert len(state["stages"]) == len(STAGES)
    _wait(job)
