import Wordmark from '../Wordmark/Wordmark';
import GlowPanel from '../GlowPanel/GlowPanel';
import './ModeSelect.css';

/**
 * First screen after the splash: choose what to scan.
 */
const ModeSelect = ({ onSelectDemo, onSelectAws }) => {
  return (
    <div className="mode-select">
      <div className="mode-select__intro">
        <h1><Wordmark size="lg" radius={130} /></h1>
        <p>Attack-path-aware cloud security posture management</p>
      </div>

      <div className="mode-select__options">
        <GlowPanel tone="cyan" radius={14} animated>
        <button type="button" className="mode-card" onClick={onSelectDemo}>
          <span className="mode-card__tag mode-card__tag--demo">No account needed</span>
          <h2>Demo account</h2>
          <p>
            Scan a seeded AWS environment containing a deliberate privilege-escalation
            chain: a public bucket leaking credentials that reach AdministratorAccess.
          </p>
          <ul>
            <li>3 S3 buckets, 3 IAM users, 2 roles, 2 security groups</li>
            <li>Reproduces a real escalation path end to end</li>
            <li>Runs instantly, nothing to configure</li>
          </ul>
          <span className="mode-card__cta">Run demo scan &rarr;</span>
        </button>
        </GlowPanel>

        <GlowPanel tone="amber" radius={14}>
        <button type="button" className="mode-card" onClick={onSelectAws}>
          <span className="mode-card__tag mode-card__tag--aws">Read-only access</span>
          <h2>AWS account</h2>
          <p>
            Connect a real AWS account with read-only credentials and scan its live
            posture across S3, IAM and EC2 security groups.
          </p>
          <ul>
            <li>Uses IAM access keys, validated before scanning</li>
            <li>Credentials stay in memory for one scan, never stored</li>
            <li>SecurityAudit policy is sufficient</li>
          </ul>
          <span className="mode-card__cta">Connect account &rarr;</span>
        </button>
        </GlowPanel>
      </div>
    </div>
  );
};

export default ModeSelect;
