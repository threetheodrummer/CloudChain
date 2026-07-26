import { useEffect, useState } from 'react';
import GlowPanel from '../GlowPanel/GlowPanel';
import { listScans } from '../../api/client';
import './ScanHistory.css';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const ScanHistory = ({ onOpenScan, onNewScan }) => {
  const [scans, setScans] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    listScans(undefined, 25)
      .then((data) => !cancelled && setScans(data))
      .catch((err) => !cancelled && setError(err.message || String(err)));
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="history">
      <header className="history__header">
        <h1>Scan history</h1>
        <p>
          Every scan is snapshotted to SQLite, which is what makes drift detection
          possible: each run is diffed against the one before it.
        </p>
      </header>

      {error && <div className="history__error">{error}</div>}

      {!scans && !error && <div className="history__empty">Loading past scans&hellip;</div>}

      {scans && scans.length === 0 && (
        <div className="history__empty">
          No scans recorded yet.
          <button type="button" onClick={onNewScan}>Run your first scan</button>
        </div>
      )}

      {scans && scans.length > 0 && (
        <GlowPanel radius={12}>
        <div className="history__surface">
        <table className="history__table">
          <thead>
            <tr>
              <th>Scan</th>
              <th>Mode</th>
              <th>When</th>
              <th>Findings</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => {
              const total = SEVERITIES.reduce((n, sev) => n + (s.summary[sev] || 0), 0);
              return (
                <tr key={s.scan_id}>
                  <td className="history__id">{s.scan_id}</td>
                  <td>
                    <span className={`history__mode history__mode--${s.mode}`}>{s.mode}</span>
                  </td>
                  <td className="history__time">{new Date(s.timestamp).toLocaleString()}</td>
                  <td>
                    <div className="history__sev">
                      {SEVERITIES.map((sev) =>
                        s.summary[sev] ? (
                          <span key={sev} className={`history__pill history__pill--${sev.toLowerCase()}`}>
                            {s.summary[sev]} {sev.charAt(0)}
                          </span>
                        ) : null
                      )}
                      <span className="history__total">{total} total</span>
                    </div>
                  </td>
                  <td>
                    <button type="button" className="history__open" onClick={() => onOpenScan(s.scan_id)}>
                      Open
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        </div>
        </GlowPanel>
      )}
    </div>
  );
};

export default ScanHistory;
