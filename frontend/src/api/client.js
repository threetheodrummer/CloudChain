const BASE = '/api';

async function handle(res) {
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body && body.detail) detail = body.detail;
    } catch {
      // response wasn't JSON; keep the status line
    }
    throw new Error(detail);
  }
  return res.json();
}

/** Verify AWS keys via STS before starting a scan. */
export async function validateAwsCredentials(credentials) {
  const res = await fetch(`${BASE}/aws/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials)
  });
  return handle(res);
}

/** Kick off a background scan. Returns { job_id, status }. */
export async function startScan(mode, credentials) {
  const res = await fetch(`${BASE}/scan/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode, credentials: credentials ?? null })
  });
  return handle(res);
}

export async function getScanStatus(jobId) {
  const res = await fetch(`${BASE}/scan/status/${jobId}`);
  return handle(res);
}

/** List past scans (most recent first). */
export async function listScans(mode, limit = 25) {
  const qs = new URLSearchParams();
  if (mode) qs.set('mode', mode);
  qs.set('limit', String(limit));
  const res = await fetch(`${BASE}/scans?${qs.toString()}`);
  return handle(res);
}

/** Report view of one previously stored scan. */
export async function getScanReport(scanId) {
  const res = await fetch(`${BASE}/scans/${scanId}/report`);
  return handle(res);
}

/** Most recent report for a mode. */
export async function getLatestReport(mode = 'demo') {
  const res = await fetch(`${BASE}/report/latest?mode=${mode}`);
  return handle(res);
}

/**
 * Re-check every attack path in a stored scan against the account.
 * Read-only: the backend verifies each hop's preconditions and never performs
 * the escalation. Real-mode scans need credentials again, since scan-time
 * credentials are deliberately never persisted.
 */
export async function validateScanPaths(scanId, credentials) {
  const res = await fetch(`${BASE}/scans/${scanId}/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentials ?? null)
  });
  return handle(res);
}

/**
 * Name the API call, actor and timestamp behind each finding.
 * Reads CloudTrail's 90-day event history, so older changes come back
 * UNATTRIBUTED rather than guessed at.
 */
export async function attributeScanFindings(scanId, { limit = 25, onlyNew = false } = {}) {
  const qs = new URLSearchParams({ limit: String(limit), only_new: String(onlyNew) });
  const res = await fetch(`${BASE}/scans/${scanId}/attribute?${qs.toString()}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(null)
  });
  return handle(res);
}

/**
 * Download the report as a PDF.
 *
 * The document is rendered server-side from the same report the dashboard is
 * showing, so the file and the screen can never disagree. Fetched as a blob
 * rather than opened in a tab so the browser saves it with our filename
 * instead of displaying it in the built-in viewer.
 */
export async function downloadReportPdf(scanId) {
  const res = await fetch(`${BASE}/scans/${scanId}/report.pdf`);
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body && body.detail) detail = body.detail;
    } catch {
      // not JSON; keep the status line
    }
    throw new Error(detail);
  }

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `cloudchain-${scanId}.pdf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke on the next tick so Firefox doesn't cancel the in-flight download.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export async function getHealth() {
  const res = await fetch(`${BASE}/health`);
  return handle(res);
}

/**
 * Poll a scan job until it finishes.
 * onUpdate receives every intermediate state so the UI can show live stages.
 */
export function pollScan(jobId, onUpdate, intervalMs = 400) {
  let stopped = false;
  let timer = null;

  const promise = new Promise((resolve, reject) => {
    const tick = async () => {
      if (stopped) return;
      try {
        const state = await getScanStatus(jobId);
        if (stopped) return;
        onUpdate?.(state);
        if (state.status === 'complete') return resolve(state);
        if (state.status === 'failed') return reject(new Error(state.error || 'Scan failed'));
        timer = setTimeout(tick, intervalMs);
      } catch (err) {
        if (!stopped) reject(err);
      }
    };
    tick();
  });

  return {
    promise,
    cancel: () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    }
  };
}
