import { useState } from 'react';
import './PathValidation.css';

/**
 * Evidence trail for one attack path.
 *
 * Every CSPM reports attack paths as fact when they're really model output.
 * This panel shows the result of going back to the account and re-checking
 * each hop with read-only calls, along with the calls themselves -- so the
 * reader can audit the claim instead of trusting it.
 */

const STATUS_META = {
  CONFIRMED: { tone: 'ok', label: 'Confirmed', mark: '✓' },
  REFUTED: { tone: 'stale', label: 'Refuted', mark: '✕' },
  UNVERIFIABLE: { tone: 'unknown', label: 'Unverifiable', mark: '?' }
};

const Hop = ({ hop }) => {
  const [open, setOpen] = useState(false);
  const meta = STATUS_META[hop.status] || STATUS_META.UNVERIFIABLE;

  return (
    <li className={`hop hop--${meta.tone}`}>
      <button type="button" className="hop__head" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className={`hop__mark hop__mark--${meta.tone}`} aria-hidden="true">{meta.mark}</span>
        <span className="hop__claim">{hop.claim}</span>
        <span className={`hop__status hop__status--${meta.tone}`}>{meta.label}</span>
      </button>

      <p className="hop__reason">{hop.reason}</p>

      {hop.calls.length > 0 && (
        <>
          <button type="button" className="hop__toggle" onClick={() => setOpen(!open)}>
            {open ? 'Hide' : 'Show'} the {hop.calls.length} API call
            {hop.calls.length === 1 ? '' : 's'} behind this
          </button>

          {open && (
            <table className="hop__calls">
              <thead>
                <tr>
                  <th>API call</th>
                  <th>Request</th>
                  <th>Observed</th>
                </tr>
              </thead>
              <tbody>
                {hop.calls.map((c, i) => (
                  <tr key={i}>
                    <td className="hop__api">{c.api}</td>
                    <td className="hop__req">{c.request}</td>
                    <td className="hop__obs">
                      {c.observed}
                      {c.cli && <code className="hop__cli">{c.cli}</code>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </li>
  );
};

const PathValidation = ({ validation, onValidate, loading, error }) => {
  if (error) {
    return (
      <div className="validation validation--error">
        <span className="validation__badge validation__badge--stale">Validation failed</span>
        <p className="validation__summary">{error}</p>
      </div>
    );
  }

  if (!validation) {
    return (
      <div className="validation validation--idle">
        <button type="button" className="validation__cta" onClick={onValidate} disabled={loading}>
          {loading ? 'Re-checking against the account…' : 'Validate this path'}
        </button>
        <p className="validation__hint">
          Re-runs every hop against the account with read-only calls. Nothing is
          created, changed, or downloaded.
        </p>
      </div>
    );
  }

  const meta = STATUS_META[validation.status] || STATUS_META.UNVERIFIABLE;

  return (
    <div className={`validation validation--${meta.tone}`}>
      <div className="validation__head">
        <span className={`validation__badge validation__badge--${meta.tone}`}>
          {meta.mark} {meta.label}
        </span>
        <span className="validation__meta">
          {new Date(validation.validated_at).toLocaleString()}
          {validation.read_only && <> &middot; read-only</>}
        </span>
      </div>

      <p className="validation__summary">{validation.summary}</p>

      <ul className="validation__hops">
        {validation.hops.map((h) => (
          <Hop key={h.index} hop={h} />
        ))}
      </ul>

      <button type="button" className="validation__revalidate" onClick={onValidate} disabled={loading}>
        {loading ? 'Re-checking…' : 'Re-validate'}
      </button>
    </div>
  );
};

export default PathValidation;
