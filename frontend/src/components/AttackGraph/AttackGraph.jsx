import './AttackGraph.css';

const NODE_STYLE = {
  s3_bucket: { fill: '#123043', stroke: '#22d3ee', label: 'S3 bucket' },
  iam_user: { fill: '#2a2340', stroke: '#a78bfa', label: 'IAM user' },
  iam_role: { fill: '#3a2438', stroke: '#f472b6', label: 'IAM role' },
  iam_account: { fill: '#1d2836', stroke: '#8ecae6', label: 'Account' },
  security_group: { fill: '#123043', stroke: '#7ee0c3', label: 'Security group' },
  admin_access: { fill: '#3d1a26', stroke: '#ff5d7a', label: 'Admin access' }
};

const SHORT_RELATION = {
  leaks_credentials_for: 'leaks credentials for',
  can_pass_role_to: 'can pass role to',
  'can_pass_role_to (wildcard)': 'can pass any role to',
  can_assume_cross_account: 'can assume via sts:AssumeRole',
  grants_admin_access: 'grants',
  has_admin_policy: 'holds admin policy'
};

const NODE_W = 190;
const NODE_H = 76;
const GAP_Y = 96;
// Extra room where the chain crosses into another account, so the boundary
// marker has space to breathe.
const BOUNDARY_EXTRA = 42;
const PAD = 26;
const WIDTH = 700;

/**
 * Renders a confirmed attack path as a vertical chain: entry point at the top,
 * AdministratorAccess at the bottom, one labelled edge per hop.
 *
 * A chain layout is used rather than a force-directed blob because the thing
 * worth reading here is the *order* of the hops. Node data comes from the
 * report's graph payload, so this draws what the backend actually found.
 *
 * Where the chain leaves one account for another, a labelled boundary is drawn
 * across the diagram. That crossing is the single most important thing on the
 * page: it's the part no per-account scanner can see, because neither account
 * looks compromised on its own.
 */
const AttackGraph = ({ graph, path }) => {
  const nodeById = new Map((graph?.nodes ?? []).map((n) => [n.id, n]));
  const edgeKey = (a, b) => `${a}->${b}`;
  const edgeByPair = new Map((graph?.edges ?? []).map((e) => [edgeKey(e.source, e.target), e]));

  const chain = (path?.node_ids ?? []).filter((id) => nodeById.has(id));
  if (chain.length < 2) return null;

  const accountOf = (id) => {
    const attrs = nodeById.get(id)?.attributes ?? {};
    return { id: attrs.account_id || '', name: attrs.account_name || attrs.account_id || '' };
  };

  // Pre-compute y positions, widening the gap wherever an account boundary sits.
  const crossesAt = chain.map((id, i) =>
    i === 0 ? false : accountOf(chain[i - 1]).id !== accountOf(id).id
  );

  const tops = [];
  let y = PAD;
  for (let i = 0; i < chain.length; i += 1) {
    if (i > 0) y += GAP_Y + (crossesAt[i] ? BOUNDARY_EXTRA : 0);
    tops.push(y);
  }
  const height = tops[tops.length - 1] + NODE_H + PAD;
  const cx = WIDTH / 2;

  return (
    <div className="attack-graph">
      <svg
        viewBox={`0 0 ${WIDTH} ${height}`}
        className="attack-graph__svg"
        role="img"
        aria-label={`Attack path with ${chain.length} nodes ending at administrator access`}
      >
        <defs>
          <marker id="ag-arrow" viewBox="0 0 10 10" refX="9" refY="5"
                  markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#ff5d7a" />
          </marker>
        </defs>

        {chain.slice(0, -1).map((id, i) => {
          const from = tops[i] + NODE_H;
          const to = tops[i + 1];
          const edge = edgeByPair.get(edgeKey(id, chain[i + 1]));
          const relation = SHORT_RELATION[edge?.relation] || edge?.relation || '';
          const midY = (from + to) / 2;
          const boundary = crossesAt[i + 1];
          return (
            <g key={`e-${id}`}>
              {boundary && (
                <g className="attack-graph__boundary">
                  <line
                    x1={16} y1={midY} x2={WIDTH - 16} y2={midY}
                    stroke="#ffd166" strokeWidth="1" strokeDasharray="2 5"
                    opacity="0.55"
                  />
                  <text x={16} y={midY - 8} className="attack-graph__boundary-label">
                    account boundary · {accountOf(id).name} → {accountOf(chain[i + 1]).name}
                  </text>
                </g>
              )}
              <line
                x1={cx} y1={from} x2={cx} y2={to - 6}
                stroke={boundary ? '#ffd166' : '#ff5d7a'} strokeWidth="1.6" strokeDasharray="4 3"
                markerEnd="url(#ag-arrow)"
                className="attack-graph__edge"
              />
              <text
                x={cx + 12}
                y={boundary ? midY + 20 : midY + 3}
                className="attack-graph__relation"
              >
                {relation}
              </text>
            </g>
          );
        })}

        {chain.map((id, i) => {
          const node = nodeById.get(id);
          const style = NODE_STYLE[node.type] || NODE_STYLE.iam_account;
          const top = tops[i];
          const isSink = node.type === 'admin_access';
          const issues = node.attributes?.issue_codes ?? [];
          const account = accountOf(id);
          const meta = [account.name, issues.length ? `${issues.length} finding${issues.length !== 1 ? 's' : ''}` : '']
            .filter(Boolean)
            .join(' · ');
          return (
            <g key={id} className="attack-graph__node">
              <rect
                x={cx - NODE_W / 2} y={top} width={NODE_W} height={NODE_H} rx="10"
                fill={style.fill} stroke={style.stroke}
                strokeWidth={isSink ? 1.8 : 1.2}
              />
              <text x={cx} y={top + 22} className="attack-graph__type" fill={style.stroke}>
                {style.label}
              </text>
              <text x={cx} y={top + 44} className="attack-graph__label">
                {node.label.length > 24 ? `${node.label.slice(0, 23)}…` : node.label}
              </text>
              {meta && (
                <text x={cx} y={top + 62} className="attack-graph__issues">
                  {meta}
                </text>
              )}
              <text x={cx - NODE_W / 2 - 14} y={top + NODE_H / 2 + 4} className="attack-graph__step">
                {i + 1}
              </text>
            </g>
          );
        })}
      </svg>

      <div className="attack-graph__legend">
        {[...new Set(chain.map((id) => nodeById.get(id).type))].map((t) => {
          const s = NODE_STYLE[t] || NODE_STYLE.iam_account;
          return (
            <span key={t} className="attack-graph__key">
              <i style={{ background: s.fill, borderColor: s.stroke }} />
              {s.label}
            </span>
          );
        })}
        {path?.crosses_accounts && (
          <span className="attack-graph__key attack-graph__key--boundary">
            <i style={{ background: 'transparent', borderColor: '#ffd166' }} />
            account boundary
          </span>
        )}
      </div>
    </div>
  );
};

export default AttackGraph;
