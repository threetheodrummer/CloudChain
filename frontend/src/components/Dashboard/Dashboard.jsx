import { useState } from 'react';
import Wordmark from '../Wordmark/Wordmark';
import GlowPanel from '../GlowPanel/GlowPanel';
import RiskGauge from '../RiskGauge/RiskGauge';
import AttackGraph from '../AttackGraph/AttackGraph';
import PathValidation from '../PathValidation/PathValidation';
import { validateScanPaths } from '../../api/client';
import { downloadHtml } from '../../lib/downloadReport';
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

/**
 * A finding row that expands to show the multiplier chain behind its score.
 *
 * Ranking findings by a computed number is only useful if the reader can see
 * why one outranks another -- otherwise it's just a different opaque ordering
 * than the severity label it replaced.
 */
const FindingRow = ({ finding, open, onToggle }) => {
  const breakdown = finding.score_breakdown || [];
  const expandable = breakdown.length > 0;

  return (
    <>
      <tr
        className={[
          finding.in_attack_path ? 'row--chained' : '',
          expandable ? 'row--expandable' : '',
          open ? 'row--open' : ''
        ].join(' ').trim()}
        onClick={expandable ? onToggle : undefined}
      >
        <td>{finding.rank}</td>
        <td className="cell--score">
          {expandable && <span className="score-caret">{open ? '▾' : '▸'}</span>}
          {finding.risk_score}
        </td>
        <td>
          <span className={`severity-pill severity-pill--${finding.severity.toLowerCase()}`}>
            {finding.severity}
          </span>
        </td>
        <td className="cell--issue">{finding.issue_code}</td>
        <td className="cell--resource">{finding.resource_id}</td>
        <td className="cell--account">
          {finding.account_name && (
            <span className="account-pill" title={finding.account_id}>{finding.account_name}</span>
          )}
        </td>
        <td>{finding.in_attack_path ? <span className="chained-flag">on path</span> : ''}</td>
      </tr>

      {open && (
        <tr className="row--breakdown">
          <td colSpan={7}>
            <div className="breakdown">
              <span className="breakdown__tag">Score derivation</span>
              <ol className="breakdown__steps">
                {breakdown.map((step, i) => (
                  <li key={i}>
                    <span className="breakdown__label">{step.label}</span>
                    <span className="breakdown__detail">{step.detail}</span>
                  </li>
                ))}
              </ol>
              <p className="breakdown__remediation">
                <strong>Fix:</strong> {finding.remediation}
              </p>
            </div>
          </td>
        </tr>
      )}
    </>
  );
};

const Dashboard = ({ report, onNewScan }) => {
  const { summary, attack_paths: attackPaths, top_findings: topFindings, drift, posture, graph } = report;
  const [openFinding, setOpenFinding] = useState(null);

  // Validation is on demand rather than part of the scan: it costs a second
  // round of API calls, and the interesting question ("is this still true?")
  // is usually asked about one path, not all of them.
  const [validations, setValidations] = useState({});
  const [validating, setValidating] = useState(false);
  const [validationError, setValidationError] = useState('');

  const runValidation = async () => {
    setValidating(true);
    setValidationError('');
    try {
      const res = await validateScanPaths(report.scan_id);
      const byPath = {};
      for (const v of res.validations) byPath[v.path_id] = v;
      setValidations(byPath);
    } catch (err) {
      setValidationError(err.message || 'Validation failed');
    } finally {
      setValidating(false);
    }
  };

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
            <span className="summary-card__label">
              Attack paths to admin
              {summary.cross_account_paths > 0 && (
                <em className="summary-card__note">
                  {summary.cross_account_paths} cross accounts
                </em>
              )}
            </span>
          </div>
          {summary.accounts_scanned > 1 && (
            <div className="summary-card summary-card--wide">
              <span className="summary-card__value">{summary.accounts_scanned}</span>
              <span className="summary-card__label">
                Accounts scanned
                <em className="summary-card__note">
                  {(report.accounts || []).map((a) => a.name).join(' · ')}
                </em>
              </span>
            </div>
          )}
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
              <div className="path-card__tags">
                <span className="path-card__severity">{p.severity}</span>
                {p.crosses_accounts && (
                  <span className="path-card__cross" title={(p.accounts || []).join(' → ')}>
                    crosses {(p.accounts || []).length} accounts
                  </span>
                )}
              </div>
              <ol className="path-card__steps">
                {p.steps.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>
              <p className="path-card__outcome">Result: full account takeover.</p>

              <PathValidation
                validation={validations[p.path_id]}
                onValidate={runValidation}
                loading={validating}
                error={validationError}
              />
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
        <p className="app-shell__hint">Click any row to see how its score was calculated.</p>
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
              <th>Account</th>
              <th>Chained</th>
            </tr>
          </thead>
          <tbody>
            {topFindings.map((f) => {
              const rowKey = `${f.resource_id}-${f.issue_code}-${f.rank}`;
              return (
                <FindingRow
                  key={rowKey}
                  finding={f}
                  open={openFinding === rowKey}
                  onToggle={() => setOpenFinding(openFinding === rowKey ? null : rowKey)}
                />
              );
            })}
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
