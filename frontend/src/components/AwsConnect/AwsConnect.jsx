import { useState } from 'react';
import GlowPanel from '../GlowPanel/GlowPanel';
import './AwsConnect.css';

const REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-central-1',
  'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
];

/**
 * Credential form for scanning a real AWS account.
 *
 * Note this asks for IAM *access keys*, not an AWS console email/password.
 * A tool like this has no legitimate reason to handle console login
 * credentials, and any site that asks for them should be treated as
 * phishing. Access keys can be scoped read-only (SecurityAudit) and revoked
 * independently, which is the correct model here.
 */
const AwsConnect = ({ onConnect, onBack, error, busy }) => {
  const [form, setForm] = useState({
    access_key_id: '',
    secret_access_key: '',
    session_token: '',
    region: 'us-east-1'
  });
  const [showSecret, setShowSecret] = useState(false);

  const update = (key) => (e) => setForm((f) => ({ ...f, [key]: e.target.value }));

  const canSubmit =
    form.access_key_id.trim().length > 0 &&
    form.secret_access_key.trim().length > 0 &&
    !busy;

  const submit = (e) => {
    e.preventDefault();
    if (!canSubmit) return;
    onConnect(form);
  };

  return (
    <div className="aws-connect">
      <button type="button" className="aws-connect__back" onClick={onBack} disabled={busy}>
        &larr; Back
      </button>

      <GlowPanel tone="amber" radius={14}>
      <div className="aws-connect__panel">
        <header className="aws-connect__header">
          <h1>Connect an AWS account</h1>
          <p>
            CloudChain reads your account&rsquo;s configuration to map misconfigurations
            into attack paths. It never creates, modifies or deletes anything.
          </p>
        </header>

        <div className="aws-connect__notice">
          <strong>Use read-only IAM access keys.</strong>
          <span>
            Attach the AWS-managed <code>SecurityAudit</code> policy to a dedicated IAM
            user and generate keys for it. Your keys are validated with STS, held in
            memory for the duration of one scan, and never written to disk, logged, or
            included in scan results. CloudChain will never ask for your AWS console
            email or password.
          </span>
        </div>

        <form className="aws-connect__form" onSubmit={submit}>
          <label>
            <span>Access key ID</span>
            <input
              type="text"
              autoComplete="off"
              spellCheck="false"
              placeholder="AKIAIOSFODNN7EXAMPLE"
              value={form.access_key_id}
              onChange={update('access_key_id')}
              disabled={busy}
            />
          </label>

          <label>
            <span>Secret access key</span>
            <div className="aws-connect__secret">
              <input
                type={showSecret ? 'text' : 'password'}
                autoComplete="off"
                spellCheck="false"
                placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                value={form.secret_access_key}
                onChange={update('secret_access_key')}
                disabled={busy}
              />
              <button
                type="button"
                onClick={() => setShowSecret((s) => !s)}
                disabled={busy}
                aria-label={showSecret ? 'Hide secret key' : 'Show secret key'}
              >
                {showSecret ? 'Hide' : 'Show'}
              </button>
            </div>
          </label>

          <label>
            <span>
              Session token <em>optional</em>
            </span>
            <input
              type="password"
              autoComplete="off"
              spellCheck="false"
              placeholder="Only needed for temporary STS credentials"
              value={form.session_token}
              onChange={update('session_token')}
              disabled={busy}
            />
          </label>

          <label>
            <span>Region</span>
            <select value={form.region} onChange={update('region')} disabled={busy}>
              {REGIONS.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </label>

          {error && <div className="aws-connect__error">{error}</div>}

          <button type="submit" className="aws-connect__submit" disabled={!canSubmit}>
            {busy ? 'Validating credentials…' : 'Validate and scan'}
          </button>
        </form>
      </div>
      </GlowPanel>
    </div>
  );
};

export default AwsConnect;
