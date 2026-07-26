import BorderGlow from '../BorderGlow/BorderGlow';
import './GlowPanel.css';

/**
 * Project-themed wrapper around React Bits' BorderGlow.
 *
 * BorderGlow owns the card's background, border, radius and glow, so every
 * element wrapped in a GlowPanel drops its own background/border (see
 * GlowPanel.css, which neutralises the inner panel styling) and lets the
 * glow card provide them. This keeps one consistent treatment across the
 * whole app instead of repeating a dozen prop sets at each call site.
 *
 * BorderGlow.jsx itself is unmodified from React Bits.
 */
const TONES = {
  // default: the cyan/teal/violet family used by the aurora background
  cyan: {
    glowColor: '187 90 65',
    colors: ['#22d3ee', '#7ee0c3', '#7c3aed']
  },
  // for attack paths and other critical findings
  danger: {
    glowColor: '348 95 70',
    colors: ['#ff5d7a', '#ff9d5c', '#7c3aed']
  },
  // for the AWS credential screen
  amber: {
    glowColor: '32 95 68',
    colors: ['#ffb45c', '#22d3ee', '#7c3aed']
  }
};

const GlowPanel = ({
  children,
  tone = 'cyan',
  radius = 14,
  glowRadius = 34,
  edgeSensitivity = 26,
  glowIntensity = 0.85,
  fillOpacity = 0.35,
  animated = false,
  className = ''
}) => {
  const { glowColor, colors } = TONES[tone] ?? TONES.cyan;

  return (
    <BorderGlow
      className={`glow-panel ${className}`}
      edgeSensitivity={edgeSensitivity}
      glowColor={glowColor}
      backgroundColor="#0c1320"
      borderRadius={radius}
      glowRadius={glowRadius}
      glowIntensity={glowIntensity}
      coneSpread={28}
      animated={animated}
      colors={colors}
      fillOpacity={fillOpacity}
    >
      {children}
    </BorderGlow>
  );
};

export default GlowPanel;
