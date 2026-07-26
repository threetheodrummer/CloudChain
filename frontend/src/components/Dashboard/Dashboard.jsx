import Wordmark from '../Wordmark/Wordmark';
import GlowPanel from '../GlowPanel/GlowPanel';
import RiskGauge from '../RiskGauge/RiskGauge';
import AttackGraph from '../AttackGraph/AttackGraph';
import { downloadHtml, downloadJson } from '../../lib/downloadReport';
import './Dashboard.css';

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

/** Horizontal severity distribution bar built from the scan summary. */
const SeverityChart = ({ bySeverity, total }) => {
  if (!total) return null;
  return (
    <div className="sev-chart">
      <div className="sev-chart__bar">
        {SEVERITY_ORDER.map((sev) => {
          const count = bySeverity[sev] || 0;
          if (!count) return null;
          return (
            <div
              key={sev}
              className={`sev-chart__seg sev-chart__seg--${sev.toLowerCase()}`}
              style={{ width: `${(count / total) * 100}%` }}
              title={`${sev}: ${count}`}
            />
          );
        })}
      </div>
      <div className="sev-chart__legend">
        {SEVERITY_ORDER.map((sev) => (
          <span key={sev} className={`sev-chart__key sev-chart__key--${sev.toLowerCase()}`}>
            <i /> {sev} <strong>{bySeverity[sev] || 0}</strong>
          </span>
        ))}
      </div>
    </div>
  );
};

const Dashboard = ({ report, onNewScan }) => {
  const { summary, attack_paths: attackPaths, top_findings: topFindings, drift, posture, graph } = report;

  return (
    <div className="app-shell">
      <header className="app-shell__header">
        <div>
          <h1><Wordmark size="md" radius={90} /></h1>
          <span className="app-shell__scan-id">{report.scan_id}</span>
        </div>
        <div className="app-shell__header-right">
          <span className="app-shell__mode-badge">{report.mode} mode</span>
          <div className="app-shell__downloads">
            <button type="button" className="app-shell__download" onClick={() => downloadHtml(report)}>
              Download report
            </button>
            <button type="button" className="app-shell__download app-shell__download--ghost" onClick={() => downloadJson(report)}>
              JSON
            </button>
          </div>
          <button type="button" className="app-shell__new-scan" onClick={onNewScan}>
            New scan
          </button>
        </div>
      </header>

      <section className="app-shell__posture">
        <GlowPanel tone={posture.grade === 'A' || posture.grade === 'B' ? 'cyan' : 'danger'} radius={14} animated>
          <RiskGauge posture={posture} />
        </GlowPanel>
      </section>

      <section className="app-shell__summary">
        <GlowPanel radius={12} glowRadius={26}>
          <div className="summary-card summary-card--wide">
            <span className="summary-card__value">{summary.total_findings}</span>
            <span className="summary-card__label">Total findings</span>
          </div>
        </GlowPanel>
        <GlowPanel tone="danger" radius={12} glowRadius={26}>
          <div className="summary-card summary-card--wide summary-card--paths">
            <span className="summary-card__value">{summary.attack_paths_found}</span>
            <span className="summary-card__label">Attack paths to admin</span>
          </div>
        </GlowPanel>
        {drift && (
          <>
            <GlowPanel radius={12} glowRadius={26}>
              <div className="summary-card">
                <span className="summary-card__value">{drift.new_findings.length}</span>
                <span className="summary-card__label">New</span>
              </div>
            </GlowPanel>
            <GlowPanel radius={12} glowRadius={26}>
              <div className="summary-card">
                <span className="summary-card__value">{drift.resolved_findings.length}</span>
                <span className="summary-card__label">Resolved</span>
              </div>
            </GlowPanel>
          </>
        )}
      </section>

      <section className="app-shell__chart">
        <h2>Severity distribution</h2>
        <GlowPanel radius={12}>
          <div className="panel-body">
            <SeverityChart bySeverity={summary.by_severity} total={summary.total_findings} />
          </div>
        </GlowPanel>
      </section>

      {attackPaths.length > 0 && (
        <section className="app-shell__paths">
          <h2>Attack paths</h2>
          {attackPaths.map((p) => (
            <GlowPanel tone="danger" radius={12} key={p.path_id} className="path-card-glow">
            <div className="path-card">
              <span className="path-card__severity">{p.severity}</span>
              <ol className="path-card__steps">
                {p.steps.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>
              <p className="path-card__outcome">Result: full account takeover.</p>
            </div>
            </GlowPanel>
          ))}

          <h2>Attack path graph</h2>
          {attackPaths.map((p) => (
            <GlowPanel tone="danger" radius={12} key={`g-${p.path_id}`} className="path-card-glow">
              <AttackGraph graph={graph} path={p} />
            </GlowPanel>
          ))}
        </section>
      )}

      <section className="app-shell__findings">
        <h2>Top findings by contextual risk</h2>
        <GlowPanel radius={12}>
        <div className="panel-body">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Score</th>
              <th>Severity</th>
              <th>Issue</th>
              <th>Resource</th>
              <th>Chained</th>
            </tr>
          </thead>
          <tbody>
            {topFindings.map((f) => (
              <tr key={`${f.resource_id}-${f.issue_code}-${f.rank}`} className={f.in_attack_path ? 'row--chained' : ''}>
                <td>{f.rank}</td>
                <td className="cell--score">{f.risk_score}</td>
                <td>
                  <span className={`severity-pill severity-pill--${f.severity.toLowerCase()}`}>
                    {f.severity}
                  </span>
                </td>
                <td className="cell--issue">{f.issue_code}</td>
                <td className="cell--resource">{f.resource_id}</td>
                <td>{f.in_attack_path ? <span className="chained-flag">on path</span> : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
        </GlowPanel>
      </section>

      {drift && drift.previous_scan_id && (
        <section className="app-shell__drift">
          <h2>Drift since previous scan</h2>
          <p className="drift-summary">
            {drift.new_findings.length} new &middot; {drift.resolved_findings.length} resolved
            &middot; {drift.unchanged_count} unchanged
          </p>
          {drift.new_findings.map((e) => (
            <div className="drift-row drift-row--new" key={e.finding_id}>
              <span>NEW</span> {e.issue_code} on {e.resource_id}
            </div>
          ))}
          {drift.resolved_findings.map((e) => (
            <div className="drift-row drift-row--resolved" key={e.finding_id}>
              <span>RESOLVED</span> {e.issue_code} on {e.resource_id}
            </div>
          ))}
        </section>
      )}
    </div>
  );
};

export default Dashboard;
