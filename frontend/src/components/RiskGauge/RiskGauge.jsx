import { useState } from 'react';
import './RiskGauge.css';

const GRADE_TONE = {
  A: '#7ee0c3',
  B: '#8ecae6',
  C: '#ffd166',
  D: '#ff9d5c',
  E: '#ff7d6b',
  F: '#ff5d7a'
};

const SIZE = 168;
const STROKE = 12;
const R = (SIZE - STROKE) / 2;
// 270-degree arc, leaving a gap at the bottom.
const ARC = 0.75;
const CIRC = 2 * Math.PI * R;

/** Deduction bar tone: how much of this dimension's budget was spent. */
const barTone = (pct) => (pct >= 66 ? '#ff5d7a' : pct >= 33 ? '#ffd166' : '#7ee0c3');

/**
 * One posture dimension. Collapsed it shows a headline and its deduction;
 * expanded it shows the formula and every finding that fed into it.
 *
 * The expansion is the point of the component. Any CSPM can show a number --
 * being able to click it and see which findings produced it is what makes the
 * number arguable rather than something the user has to take on faith.
 */
const Dimension = ({ component, open, onToggle }) => {
  const { key, name, weight, raw, points_lost: lost, headline, method, factors } = component;
  const pct = weight ? (lost / weight) * 100 : 0;
  const tone = barTone(pct);

  return (
    <div className={`dim ${open ? 'dim--open' : ''}`}>
      <button type="button" className="dim__head" onClick={onToggle} aria-expanded={open}>
        <span className="dim__chevron" aria-hidden="true">{open ? '−' : '+'}</span>
        <span className="dim__name">{name}</span>
        <span className="dim__bar">
          <span className="dim__fill" style={{ width: `${pct}%`, background: tone }} />
        </span>
        <span className="dim__points" style={{ color: tone }}>
          &minus;{lost.toFixed(1)}<em> / {weight}</em>
        </span>
      </button>

      <p className="dim__headline">{headline}</p>

      {open && (
        <div className="dim__detail">
          <span className="dim__tag">How this was calculated</span>
          <p className="dim__method">{method}</p>
          <p className="dim__math">
            raw {raw.toFixed(2)} &times; weight {weight} = <strong>&minus;{lost.toFixed(2)} points</strong>
          </p>

          {factors.length > 0 ? (
            <table className="dim__factors">
              <thead>
                <tr>
                  <th>Contributing evidence</th>
                  <th>Why it counts</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                {factors.map((f, i) => (
                  <tr key={`${key}-${i}`}>
                    <td className="dim__factor-label">{f.label}</td>
                    <td className="dim__factor-detail">{f.detail}</td>
                    <td className="dim__factor-value">
                      {f.contribution > 0 ? `+${f.contribution}` : f.contribution}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="dim__empty">Nothing in this scan contributed to this dimension.</p>
          )}
        </div>
      )}
    </div>
  );
};

/**
 * Posture score gauge. The score, grade and every component are computed
 * server-side in app/risk/posture.py; this only draws them, so the number on
 * screen and the number in the downloaded report can never disagree.
 */
const RiskGauge = ({ posture }) => {
  const {
    score,
    grade,
    components = [],
    auto_failed: autoFailed,
    total_deducted: totalDeducted
  } = posture;

  const [openKey, setOpenKey] = useState(null);
  const tone = GRADE_TONE[grade] || '#ff5d7a';
  const filled = CIRC * ARC * (score / 100);
  const track = CIRC * ARC;

  return (
    <div className="gauge">
      <div className="gauge__left">
        <div className="gauge__dial">
          <svg viewBox={`0 0 ${SIZE} ${SIZE}`} width={SIZE} height={SIZE} role="img"
               aria-label={`Posture score ${score} of 100, grade ${grade}`}>
            <g transform={`rotate(135 ${SIZE / 2} ${SIZE / 2})`}>
              <circle
                cx={SIZE / 2} cy={SIZE / 2} r={R}
                fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth={STROKE}
                strokeDasharray={`${track} ${CIRC}`} strokeLinecap="round"
              />
              <circle
                cx={SIZE / 2} cy={SIZE / 2} r={R}
                fill="none" stroke={tone} strokeWidth={STROKE}
                strokeDasharray={`${filled} ${CIRC}`} strokeLinecap="round"
                className="gauge__fill"
              />
            </g>
          </svg>
          <div className="gauge__center">
            <span className="gauge__score">{score}</span>
            <span className="gauge__outof">/ 100</span>
            <span className="gauge__grade" style={{ color: tone, borderColor: tone }}>{grade}</span>
          </div>
        </div>
        <p className="gauge__deducted">&minus;{totalDeducted} points from 100</p>
      </div>

      <div className="gauge__detail">
        <h3>Posture score</h3>
        <p className="gauge__explain">
          Deducted across four independent dimensions. Click any one to see the
          findings behind it.
          {autoFailed && (
            <> A confirmed path to <code>AdministratorAccess</code> caps the grade at F.</>
          )}
        </p>

        <div className="gauge__dims">
          {components.map((c) => (
            <Dimension
              key={c.key}
              component={c}
              open={openKey === c.key}
              onToggle={() => setOpenKey(openKey === c.key ? null : c.key)}
            />
          ))}
          {components.length === 0 && (
            <p className="gauge__clean">No deductions &mdash; nothing found.</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default RiskGauge;
