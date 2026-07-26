import GlowPanel from '../GlowPanel/GlowPanel';
import Wordmark from '../Wordmark/Wordmark';
import './Landing.css';

const STATS = [
  ['7-stage', 'scan pipeline, reporting real progress'],
  ['Graph', 'correlation from exposure to admin access'],
  ['Drift', 'diffed against every previous snapshot']
];

/**
 * First screen after the splash. The scan options stay hidden behind
 * "Get Started" so the app opens on an intro rather than dropping the user
 * straight into a choice.
 */
const Landing = ({ onGetStarted }) => {
  return (
    <div className="landing">
      <div className="landing__hero">
        <h1 className="landing__title">
          <Wordmark size="lg" radius={140} />
        </h1>
        <p className="landing__tagline">Attack-path-aware cloud security posture management</p>
        <p className="landing__blurb">
          Most scanners hand you a flat list of misconfigurations. CloudChain correlates
          them into a graph and tells you which chain actually reaches
          <span className="landing__mono"> AdministratorAccess</span>.
        </p>

        <button type="button" className="landing__cta" onClick={onGetStarted}>
          Get started
        </button>
        <p className="landing__hint">No AWS account required &mdash; a demo environment is built in.</p>
      </div>

      <div className="landing__stats">
        {STATS.map(([head, tail], i) => (
          <GlowPanel key={head} radius={12} glowRadius={28} animated={i === 0}>
            <div className="landing__stat">
              <strong>{head}</strong>
              <span>{tail}</span>
            </div>
          </GlowPanel>
        ))}
      </div>
    </div>
  );
};

export default Landing;
