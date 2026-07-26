import GlowPanel from '../GlowPanel/GlowPanel';
import './ScanProgress.css';

/**
 * Live scan progress. Stages and their completion state come from the
 * backend job (GET /api/scan/status/{job_id}) -- this is the scanner's real
 * position in the pipeline, not a timed animation.
 */
const ScanProgress = ({ state, mode, onCancel }) => {
  const stages = state?.stages ?? [];
  const completed = new Set(state?.completed_stages ?? []);
  const current = state?.current_stage;
  const done = completed.size;
  const pct = stages.length ? Math.round((done / stages.length) * 100) : 0;

  const statusFor = (id) => {
    if (completed.has(id)) return 'done';
    if (id === current) return 'active';
    return 'pending';
  };

  return (
    <div className="scan-progress">
      <GlowPanel tone="cyan" radius={14} animated>
      <div className="scan-progress__panel">
        <header className="scan-progress__header">
          <span className="scan-progress__mode">
            {mode === 'demo' ? 'Demo account' : 'AWS account'}
          </span>
          <h1>Scanning cloud posture</h1>
          <p>
            Enumerating resources, then correlating findings into attack paths that
            reach administrative access.
          </p>
        </header>

        <div className="scan-progress__bar">
          <div className="scan-progress__bar-fill" style={{ width: `${pct}%` }} />
        </div>
        <div className="scan-progress__pct">
          {pct}% &middot; {done} of {stages.length} stages
        </div>

        <ol className="scan-progress__stages">
          {stages.map((s) => {
            const st = statusFor(s.id);
            return (
              <li key={s.id} className={`stage stage--${st}`}>
                <span className="stage__marker">
                  {st === 'done' ? '✓' : st === 'active' ? '' : ''}
                </span>
                <span className="stage__body">
                  <span className="stage__label">{s.label}</span>
                  {st === 'active' && state?.stage_detail && (
                    <span className="stage__detail">{state.stage_detail}</span>
                  )}
                </span>
              </li>
            );
          })}
        </ol>

        {onCancel && (
          <button type="button" className="scan-progress__cancel" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>
      </GlowPanel>
    </div>
  );
};

export default ScanProgress;
