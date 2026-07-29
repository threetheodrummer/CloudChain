import { useState } from 'react';
import './Attribution.css';

/**
 * Who changed this, and when.
 *
 * Drift says a finding is new. This answers the question everyone asks next,
 * and that no CSPM answers: which identity made the change, from where, and
 * at what time. That's what turns posture management into something with a
 * feedback loop rather than a list that regrows every week.
 */

const CONFIDENCE_META = {
  EXACT: {
    tone: 'exact',
    label: 'Exact',
    hint: 'One CloudTrail event touches this resource — unambiguous.'
  },
  LIKELY: {
    tone: 'likely',
    label: 'Likely',
    hint: 'Several events could explain this; the most recent is shown.'
  },
  UNATTRIBUTED: {
    tone: 'unknown',
    label: 'Unattributed',
    hint: 'No matching event inside CloudTrail’s lookup window.'
  }
};

const Row = ({ attribution }) => {
  const [open, setOpen] = useState(false);
  const meta = CONFIDENCE_META[attribution.confidence] || CONFIDENCE_META.UNATTRIBUTED;
  const event = attribution.event;
  const others = attribution.other_candidates || [];
  const expandable = Boolean(event);

  return (
    <li className={`attr attr--${meta.tone}`}>
      <div className="attr__head">
        <span className={`attr__badge attr__badge--${meta.tone}`} title={meta.hint}>
          {meta.label}
        </span>
        <code className="attr__issue">{attribution.issue_code}</code>
        <span className="attr__resource">{attribution.resource_id}</span>
      </div>

      <p className="attr__summary">{attribution.summary}</p>

      {expandable && (
        <>
          <button type="button" className="attr__toggle" onClick={() => setOpen(!open)}>
            {open ? 'Hide' : 'Show'} the event record
            {others.length > 0 && ` and ${others.length} other candidate${others.length === 1 ? '' : 's'}`}
          </button>

          {open && (
            <div className="attr__detail">
              <dl className="attr__fields">
                <dt>Event</dt>
                <dd><code>{event.event_name}</code></dd>
                <dt>Actor</dt>
                <dd><code>{event.actor_arn}</code> <em>({event.actor_type})</em></dd>
                <dt>When</dt>
                <dd>{new Date(event.event_time).toLocaleString()}</dd>
                {event.source_ip && (<><dt>Source IP</dt><dd><code>{event.source_ip}</code></dd></>)}
                {event.user_agent && (<><dt>Via</dt><dd>{event.user_agent}</dd></>)}
                <dt>Event ID</dt>
                <dd><code>{event.event_id}</code></dd>
              </dl>

              {Object.keys(event.request_parameters || {}).length > 0 && (
                <pre className="attr__params">
                  {JSON.stringify(event.request_parameters, null, 2)}
                </pre>
              )}

              {others.length > 0 && (
                <div className="attr__others">
                  <span className="attr__others-label">Other candidate events</span>
                  <ul>
                    {others.map((o) => (
                      <li key={o.event_id}>
                        <code>{o.event_name}</code> by {o.actor_arn} —{' '}
                        {new Date(o.event_time).toLocaleString()}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </li>
  );
};

const Attribution = ({ scanId, data, loading, error, onAttribute }) => {
  if (error) {
    return (
      <div className="attribution attribution--error">
        <p className="attribution__note">{error}</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="attribution">
        <button type="button" className="attribution__cta" onClick={onAttribute} disabled={loading}>
          {loading ? 'Reading CloudTrail…' : 'Who changed this?'}
        </button>
        <p className="attribution__note">
          Looks up the API call, identity and timestamp behind each finding.
        </p>
      </div>
    );
  }

  const attributions = data.attributions || [];
  const attributed = attributions.filter((a) => a.confidence !== 'UNATTRIBUTED');

  return (
    <div className="attribution">
      <div className="attribution__head">
        <h3>Change attribution</h3>
        <span className="attribution__meta">
          {attributed.length} of {attributions.length} traced &middot; last{' '}
          {data.lookback_days} days
        </span>
      </div>

      <ul className="attribution__list">
        {attributions.map((a) => (
          <Row key={a.finding_id} attribution={a} />
        ))}
      </ul>

      <p className="attribution__note">
        CloudTrail records that a change happened, not that it produced this exact
        finding state — hence the confidence label on each row. Changes older than{' '}
        {data.lookback_days} days fall outside the lookup window and stay unattributed.
      </p>

      <button type="button" className="attribution__cta attribution__cta--small" onClick={onAttribute} disabled={loading}>
        {loading ? 'Reading CloudTrail…' : 'Refresh'}
      </button>
    </div>
  );
};

export default Attribution;
