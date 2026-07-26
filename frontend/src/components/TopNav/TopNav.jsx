import { useEffect, useRef } from 'react';
import CardNav from '../CardNav/CardNav';
import logo from '../../assets/logo.svg';
import './TopNav.css';

/**
 * Application top bar.
 *
 * CardNav renders plain <a href> links and a CTA button with no click
 * handlers of its own, so rather than editing the component this wrapper
 * uses event delegation: it intercepts clicks inside the nav, reads the
 * `#route` off the anchor, and calls back into the app's router.
 * CardNav.jsx is left exactly as shipped by React Bits.
 */
const NAV_ITEMS = [
  {
    label: 'Scan',
    bgColor: '#0d1a2b',
    textColor: '#e6edf3',
    links: [
      { label: 'New scan', href: '#new-scan', ariaLabel: 'Start a new scan' },
      { label: 'Scan history', href: '#history', ariaLabel: 'View past scans' },
      { label: 'Latest report', href: '#latest', ariaLabel: 'Open the most recent report' }
    ]
  },
  {
    label: 'Account',
    bgColor: '#132132',
    textColor: '#e6edf3',
    links: [
      { label: 'Demo account', href: '#demo', ariaLabel: 'Scan the seeded demo account' },
      { label: 'Connect AWS', href: '#aws', ariaLabel: 'Connect a real AWS account' }
    ]
  },
  {
    label: 'About',
    bgColor: '#132132',
    textColor: '#e6edf3',
    links: [
      { label: 'How it works', href: '#about', ariaLabel: 'How CloudChain works' },
      { label: 'Risk scoring', href: '#about-scoring', ariaLabel: 'How risk scoring works' },
      { label: 'Attack paths', href: '#about-paths', ariaLabel: 'How attack paths are built' }
    ]
  }
];

const TopNav = ({ onNavigate }) => {
  const hostRef = useRef(null);
  const navigateRef = useRef(onNavigate);
  navigateRef.current = onNavigate;

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    const onClick = (e) => {
      const link = e.target.closest('a.nav-card-link');
      if (link) {
        const href = link.getAttribute('href') || '';
        if (href.startsWith('#')) {
          e.preventDefault();
          navigateRef.current?.(href.slice(1));
        }
      }
    };

    host.addEventListener('click', onClick);
    return () => host.removeEventListener('click', onClick);
  }, []);

  return (
    <div ref={hostRef} className="top-nav-host">
      <CardNav
        logo={logo}
        logoAlt="CloudChain"
        items={NAV_ITEMS}
        baseColor="#0b111c"
        menuColor="#9aabc0"
        buttonBgColor="#22d3ee"
        buttonTextColor="#04121a"
        ease="power3.out"
      />
    </div>
  );
};

export default TopNav;
