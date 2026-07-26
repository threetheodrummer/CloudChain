import { useRef } from 'react';
import VariableProximity from '../VariableProximity/VariableProximity';
import './Wordmark.css';

/**
 * The "CloudChain" wordmark, rendered with React Bits' VariableProximity so
 * the letterforms thicken as the cursor passes over them.
 *
 * VariableProximity measures the cursor against a container, so each wordmark
 * owns its own positioned container ref rather than sharing one.
 */
const Wordmark = ({ size = 'lg', radius = 110 }) => {
  const containerRef = useRef(null);

  return (
    <span ref={containerRef} className={`wordmark wordmark--${size}`}>
      <VariableProximity
        label="CloudChain"
        className="wordmark__text"
        fromFontVariationSettings="'wght' 400, 'opsz' 12"
        toFontVariationSettings="'wght' 1000, 'opsz' 40"
        containerRef={containerRef}
        radius={radius}
        falloff="gaussian"
      />
    </span>
  );
};

export default Wordmark;
