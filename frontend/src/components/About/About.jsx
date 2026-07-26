import GlowPanel from '../GlowPanel/GlowPanel';
import './About.css';

const SECTIONS = {
  about: {
    title: 'How it works',
    body: [
      'CloudChain scans an AWS account for misconfigurations across S3, IAM and EC2 security groups, then does the thing most free scanners skip: it correlates those findings into a graph and looks for a route from something an attacker can reach on the internet all the way to AdministratorAccess.',
      'The scan runs in seven stages on a backend worker thread. The progress screen you see is the scanner reporting its real position in that pipeline, not a timed animation.'
    ],
    points: [
      ['S3', 'Public access, default encryption, versioning, and credential-like object keys in public buckets.'],
      ['IAM', 'MFA, stale access keys, wildcard grants, and PassRole-based privilege escalation.'],
      ['EC2', 'Ingress rules open to 0.0.0.0/0 on sensitive and database ports.']
    ]
  },
  'about-scoring': {
    title: 'Risk scoring',
    body: [
      'Most scanners attach a fixed severity label to each check, so a public empty bucket and a public bucket leaking admin credentials both report as HIGH. CloudChain scores each finding using the context available from the scan itself.'
    ],
    points: [
      ['Base severity', 'LOW 1, MEDIUM 3, HIGH 6, CRITICAL 10.'],
      ['Internet facing', 'x1.5 when the resource is reachable from outside.'],
      ['Sensitive', 'x1.5 when the finding involves credential or secret exposure.'],
      ['On an attack path', 'x2.5 — deliberately the largest factor. A finding proven to sit on a chain reaching admin is a different risk from the same issue in isolation.']
    ]
  },
  'about-paths': {
    title: 'Attack paths',
    body: [
      'Findings become nodes in a directed graph, and correlation rules add the edges. CloudChain then searches for any simple path from an internet-reachable, credential-exposing entry point to a synthetic AdministratorAccess sink.'
    ],
    points: [
      ['Leaked credentials', 'A credential-like object in a public bucket links that bucket to the identity those credentials belong to.'],
      ['PassRole escalation', 'An identity holding iam:PassRole plus a compute-creation action links to every role it can pass.'],
      ['Admin sink', 'Any role or identity carrying a wildcard (*:*) policy links to AdministratorAccess.'],
      ['Result', 'The demo account contains one complete chain: public bucket to leaked key to PassRole to admin.']
    ]
  }
};

const About = ({ section = 'about', onBack }) => {
  const content = SECTIONS[section] || SECTIONS.about;

  return (
    <div className="about">
      <button type="button" className="about__back" onClick={onBack}>
        &larr; Back
      </button>

      <GlowPanel tone="cyan" radius={14}>
      <div className="about__panel">
        <h1>{content.title}</h1>
        {content.body.map((p, i) => (
          <p key={i}>{p}</p>
        ))}

        <dl className="about__points">
          {content.points.map(([term, desc]) => (
            <div key={term}>
              <dt>{term}</dt>
              <dd>{desc}</dd>
            </div>
          ))}
        </dl>
      </div>
      </GlowPanel>
    </div>
  );
};

export default About;
