/**
 * Report export.
 *
 * Generated from the same report object the dashboard is rendering, so a
 * downloaded file can never disagree with what's on screen. The HTML export is
 * fully self-contained (inline CSS, no external assets) so it opens correctly
 * from disk and prints/saves to PDF cleanly.
 *
 * Raw JSON is deliberately not offered as a download: the API already serves
 * it at /api/scans/{scan_id}/report for anyone scripting against CloudChain,
 * and a second button on the dashboard only added noise for readers who want
 * the readable artefact.
 */

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke on the next tick so Firefox doesn't cancel the in-flight download.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function stamp(report) {
  const d = new Date(report.timestamp);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}`;
}

const esc = (s) =>
  String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

const GRADE_TONE = { A: '#0f766e', B: '#0369a1', C: '#a16207', D: '#c2410c', E: '#be123c', F: '#9f1239' };

export function downloadHtml(report) {
  const { posture, summary, attack_paths: paths, findings, drift } = report;
  const tone = GRADE_TONE[posture.grade] || '#9f1239';

  const sevRow = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    .map((s) => `<td><strong>${summary.by_severity[s] || 0}</strong><span>${s}</span></td>`)
    .join('');

  const pathBlocks = paths.length
    ? paths
        .map(
          (p) => `
      <div class="path">
        <div class="path-sev">${esc(p.severity)}</div>
        <ol>${p.steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>
        <p class="outcome">Result: full account takeover.</p>
      </div>`
        )
        .join('')
    : '<p class="none">No attack path to AdministratorAccess was found.</p>';

  const findingRows = findings
    .map(
      (f) => `
      <tr class="${f.in_attack_path ? 'chained' : ''}">
        <td>${f.rank}</td>
        <td class="mono">${f.risk_score}</td>
        <td><span class="pill pill-${f.severity.toLowerCase()}">${esc(f.severity)}</span></td>
        <td class="mono">${esc(f.issue_code)}</td>
        <td>${esc(f.resource_id)}</td>
        <td>${f.in_attack_path ? 'yes' : ''}</td>
      </tr>
      <tr class="detail"><td></td><td colspan="5"><em>${esc(f.title)}</em><br/>${esc(f.remediation)}</td></tr>`
    )
    .join('');

  const driftBlock = drift?.previous_scan_id
    ? `<section>
        <h2>Drift since previous scan</h2>
        <p>${drift.new_findings.length} new &middot; ${drift.resolved_findings.length} resolved &middot; ${drift.unchanged_count} unchanged</p>
        <ul class="drift">
          ${drift.new_findings.map((e) => `<li><b class="new">NEW</b> ${esc(e.issue_code)} on ${esc(e.resource_id)}</li>`).join('')}
          ${drift.resolved_findings.map((e) => `<li><b class="res">RESOLVED</b> ${esc(e.issue_code)} on ${esc(e.resource_id)}</li>`).join('')}
        </ul>
      </section>`
    : '';

  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<title>CloudChain report ${esc(report.scan_id)}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin:0; padding:40px 32px 64px; font-family:'Segoe UI',system-ui,-apple-system,sans-serif; color:#1a2233; background:#fff; max-width:900px; margin:0 auto; }
  h1 { font-size:26px; margin:0 0 4px; }
  h2 { font-size:14px; text-transform:uppercase; letter-spacing:.08em; color:#5b6b82; margin:34px 0 12px; border-bottom:1px solid #e3e8ef; padding-bottom:6px; }
  .sub { color:#66748c; font-size:13px; margin:0 0 26px; }
  .mono { font-family:'Cascadia Code',Consolas,monospace; }
  .score { display:flex; align-items:center; gap:20px; border:1px solid #e3e8ef; border-radius:12px; padding:18px 22px; }
  .score .num { font-size:44px; font-weight:700; line-height:1; }
  .score .grade { font-size:13px; font-weight:700; letter-spacing:.1em; color:#fff; background:${tone}; border-radius:999px; padding:3px 12px; }
  .score ul { margin:0; padding-left:18px; font-size:13px; color:#44536b; }
  table.sev { border-collapse:collapse; margin:16px 0 0; }
  table.sev td { text-align:center; padding:10px 20px; border:1px solid #e3e8ef; }
  table.sev strong { display:block; font-size:22px; }
  table.sev span { font-size:10px; letter-spacing:.08em; color:#66748c; }
  .path { border:1px solid #f0c9d2; background:#fff7f9; border-radius:10px; padding:14px 18px; margin-bottom:14px; }
  .path-sev { font-size:11px; font-weight:700; letter-spacing:.08em; color:#9f1239; margin-bottom:6px; }
  .path ol { margin:0; padding-left:20px; font-size:13.5px; line-height:1.7; }
  .outcome { margin:10px 0 0; font-size:13px; font-weight:600; color:#9f1239; }
  .none { color:#0f766e; font-size:13px; }
  table.find { width:100%; border-collapse:collapse; font-size:12.5px; }
  table.find th { text-align:left; padding:8px; border-bottom:1px solid #d9e0ea; font-size:10.5px; text-transform:uppercase; letter-spacing:.06em; color:#66748c; }
  table.find td { padding:7px 8px; border-bottom:1px solid #eef1f6; vertical-align:top; }
  tr.chained { background:#fff7f9; }
  tr.detail td { font-size:11.5px; color:#5b6b82; padding-top:0; padding-bottom:10px; }
  .pill { font-size:10.5px; font-weight:700; padding:2px 7px; border-radius:999px; }
  .pill-critical { background:#ffe4ea; color:#9f1239; }
  .pill-high { background:#ffedd5; color:#c2410c; }
  .pill-medium { background:#fef3c7; color:#a16207; }
  .pill-low { background:#e0f2fe; color:#0369a1; }
  ul.drift { list-style:none; padding:0; font-size:12.5px; font-family:'Cascadia Code',Consolas,monospace; }
  ul.drift b { margin-right:8px; }
  ul.drift .new { color:#c2410c; } ul.drift .res { color:#0f766e; }
  footer { margin-top:40px; padding-top:14px; border-top:1px solid #e3e8ef; font-size:11.5px; color:#8593a8; }
  @media print { body { padding:0; } h2 { page-break-after:avoid; } .path, tr { page-break-inside:avoid; } }
</style></head>
<body>
  <h1>CloudChain posture report</h1>
  <p class="sub">
    Scan <span class="mono">${esc(report.scan_id)}</span> &middot; ${esc(report.mode)} mode &middot;
    ${new Date(report.timestamp).toLocaleString()}
  </p>

  <div class="score">
    <div><div class="num">${posture.score}<span style="font-size:15px;color:#8593a8">/100</span></div></div>
    <div><span class="grade">GRADE ${esc(posture.grade)}</span></div>
    <div style="flex:1">
      <ul>
        ${(posture.components || [])
          .map(
            (c) =>
              `<li>${c.points_lost.toFixed(1)} of ${c.weight} &mdash; <strong>${esc(c.name)}</strong>: ${esc(c.headline)}</li>`
          )
          .join('') || '<li>No deductions.</li>'}
      </ul>
    </div>
  </div>

  ${
    posture.explanation
      ? `<p class="sub" style="margin-top:-4px">${esc(posture.explanation)}</p>`
      : ''
  }

  <h2>How the score was calculated</h2>
  <table>
    <tr><th>Dimension</th><th>Deducted</th><th>Method</th></tr>
    ${(posture.components || [])
      .map(
        (c) => `<tr>
          <td>${esc(c.name)}</td>
          <td class="mono">${c.points_lost.toFixed(2)} / ${c.weight}</td>
          <td>${esc(c.method)}</td>
        </tr>`
      )
      .join('')}
  </table>

  <h2>Findings by severity</h2>
  <table class="sev"><tr>${sevRow}</tr></table>

  <h2>Attack paths (${summary.attack_paths_found})</h2>
  ${pathBlocks}

  <h2>All findings (${findings.length})</h2>
  <table class="find">
    <thead><tr><th>#</th><th>Score</th><th>Severity</th><th>Issue</th><th>Resource</th><th>Chained</th></tr></thead>
    <tbody>${findingRows}</tbody>
  </table>

  ${driftBlock}

  <footer>
    Generated by CloudChain. Risk scores weight base severity by internet exposure,
    data sensitivity, and whether the finding sits on a confirmed attack path.
  </footer>
</body></html>`;

  triggerDownload(new Blob([html], { type: 'text/html' }), `cloudchain-${report.scan_id}-${stamp(report)}.html`);
}
