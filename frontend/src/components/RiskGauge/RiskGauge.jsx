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

/**
 * Posture score gauge. The score and grade are computed server-side in
 * app/risk/posture.py; this only draws them, so the number on screen and the
 * number in the downloaded report can never disagree.
 */
const RiskGauge = ({ posture }) => {
  const { score, grade, deductions, auto_failed: autoFailed } = posture;
  const tone = GRADE_TONE[grade] || '#ff5d7a';
  const filled = CIRC * ARC * (score / 100);
  const track = CIRC * ARC;

  return (
    <div className="gauge">
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

      <div className="gauge__detail">
        <h3>Posture score</h3>
        <p className="gauge__explain">
          Starts at 100 and deducts per finding, weighted by severity.
          {autoFailed && (
            <> A confirmed path to <code>AdministratorAccess</code> is an automatic F.</>
          )}
        </p>
        <ul className="gauge__deductions">
          {deductions.map((d) => (
            <li key={d.reason}>
              <span className="gauge__points">&minus;{d.points}</span>
              {d.reason}
            </li>
          ))}
          {deductions.length === 0 && <li className="gauge__clean">No deductions &mdash; nothing found.</li>}
        </ul>
      </div>
    </div>
  );
};

export default RiskGauge;
