import CircularText from '../CircularText/CircularText';
import './LoadingScreen.css';

/**
 * Splash/loading screen shown while CloudChain boots (i.e. while the first
 * scan/report fetch to the backend is in flight). Wraps the React Bits
 * CircularText component unmodified.
 */
const LoadingScreen = () => {
  return (
    <div className="loading-screen">
      <div className="loading-screen__ring">
        <CircularText
          text="CLOUD CHAIN . THE CSPM YOU NEED . "
          onHover="speedUp"
          spinDuration={20}
          className="loading-screen__circular-text"
        />
        <div className="loading-screen__center-dot" />
      </div>
      <p className="loading-screen__hint">Scanning cloud posture&hellip;</p>
    </div>
  );
};

export default LoadingScreen;
