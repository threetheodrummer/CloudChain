import { useCallback, useEffect, useRef, useState } from 'react';
import LoadingScreen from './components/LoadingScreen/LoadingScreen';
import Aurora from './components/Aurora/Aurora';
import TopNav from './components/TopNav/TopNav';
import Landing from './components/Landing/Landing';
import ModeSelect from './components/ModeSelect/ModeSelect';
import AwsConnect from './components/AwsConnect/AwsConnect';
import ScanProgress from './components/ScanProgress/ScanProgress';
import Dashboard from './components/Dashboard/Dashboard';
import ScanHistory from './components/ScanHistory/ScanHistory';
import About from './components/About/About';
import { getHealth, getLatestReport, getScanReport, pollScan, startScan } from './api/client';
import './App.css';

// Minimum time the splash stays up, so the loading animation is actually
// visible even when the backend responds instantly.
const MIN_SPLASH_MS = 1800;

const VIEW = {
  BOOT: 'boot',
  LANDING: 'landing',
  CHOOSE: 'choose',
  AWS: 'aws',
  SCANNING: 'scanning',
  RESULTS: 'results',
  HISTORY: 'history',
  ABOUT: 'about',
  ERROR: 'error'
};

function App() {
  const [view, setView] = useState(VIEW.BOOT);
  const [mode, setMode] = useState('demo');
  const [scanState, setScanState] = useState(null);
  const [report, setReport] = useState(null);
  const [aboutSection, setAboutSection] = useState('about');
  const [error, setError] = useState(null);
  const [awsError, setAwsError] = useState(null);
  const [awsBusy, setAwsBusy] = useState(false);
  const pollerRef = useRef(null);

  // Boot: confirm the backend is reachable before offering any choices, so a
  // dead API surfaces here rather than halfway through a scan.
  useEffect(() => {
    let cancelled = false;
    const startedAt = Date.now();

    getHealth()
      .then(() => {
        if (cancelled) return;
        const wait = Math.max(0, MIN_SPLASH_MS - (Date.now() - startedAt));
        setTimeout(() => {
          if (!cancelled) setView(VIEW.LANDING);
        }, wait);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err.message || String(err));
        setView(VIEW.ERROR);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => () => pollerRef.current?.cancel(), []);

  const runScan = useCallback(async (scanMode, credentials) => {
    setMode(scanMode);
    setScanState(null);
    setReport(null);
    setError(null);

    const { job_id: jobId } = await startScan(scanMode, credentials);
    setView(VIEW.SCANNING);

    const poller = pollScan(jobId, setScanState);
    pollerRef.current = poller;

    try {
      const final = await poller.promise;
      setReport(final.report);
      setView(VIEW.RESULTS);
    } catch (err) {
      setError(err.message || String(err));
      setView(VIEW.ERROR);
    } finally {
      pollerRef.current = null;
    }
  }, []);

  const handleDemo = useCallback(() => {
    runScan('demo', null).catch((err) => {
      setError(err.message || String(err));
      setView(VIEW.ERROR);
    });
  }, [runScan]);

  const handleAwsConnect = useCallback(
    async (credentials) => {
      setAwsBusy(true);
      setAwsError(null);
      try {
        await runScan('real', credentials);
      } catch (err) {
        setAwsError(err.message || String(err));
        setView(VIEW.AWS);
      } finally {
        setAwsBusy(false);
      }
    },
    [runScan]
  );

  const reset = useCallback(() => {
    pollerRef.current?.cancel();
    pollerRef.current = null;
    setScanState(null);
    setReport(null);
    setError(null);
    setAwsError(null);
    setView(VIEW.CHOOSE);
  }, []);

  const goHome = useCallback(() => {
    pollerRef.current?.cancel();
    pollerRef.current = null;
    setScanState(null);
    setReport(null);
    setError(null);
    setView(VIEW.LANDING);
  }, []);

  const openScan = useCallback(async (scanId) => {
    try {
      const r = await getScanReport(scanId);
      setReport(r);
      setMode(r.mode);
      setView(VIEW.RESULTS);
    } catch (err) {
      setError(err.message || String(err));
      setView(VIEW.ERROR);
    }
  }, []);

  /** Routes fired by the top nav (see TopNav's delegated click handler). */
  const navigate = useCallback(
    async (route) => {
      if (route.startsWith('about')) {
        setAboutSection(route);
        setView(VIEW.ABOUT);
        return;
      }
      switch (route) {
        case 'new-scan':
          reset();
          break;
        case 'history':
          setView(VIEW.HISTORY);
          break;
        case 'demo':
          handleDemo();
          break;
        case 'aws':
          setAwsError(null);
          setView(VIEW.AWS);
          break;
        case 'latest':
          try {
            const r = await getLatestReport(mode);
            setReport(r);
            setView(VIEW.RESULTS);
          } catch (err) {
            setError(err.message || String(err));
            setView(VIEW.ERROR);
          }
          break;
        default:
          break;
      }
    },
    [handleDemo, mode, reset]
  );

  const background = (
    <div className="app-aurora-bg">
      <Aurora colorStops={['#0b1a2f', '#22d3ee', '#7c3aed']} amplitude={1.2} blend={0.6} speed={0.4} />
    </div>
  );

  if (view === VIEW.BOOT) {
    return (
      <>
        {background}
        <LoadingScreen />
      </>
    );
  }

  return (
    <>
      {background}
      <TopNav onNavigate={navigate} />

      {view === VIEW.LANDING && <Landing onGetStarted={() => setView(VIEW.CHOOSE)} />}

      {view === VIEW.CHOOSE && (
        <ModeSelect onSelectDemo={handleDemo} onSelectAws={() => setView(VIEW.AWS)} />
      )}

      {view === VIEW.AWS && (
        <AwsConnect onConnect={handleAwsConnect} onBack={reset} error={awsError} busy={awsBusy} />
      )}

      {view === VIEW.SCANNING && <ScanProgress state={scanState} mode={mode} onCancel={reset} />}

      {view === VIEW.RESULTS && report && <Dashboard report={report} onNewScan={reset} />}

      {view === VIEW.HISTORY && <ScanHistory onOpenScan={openScan} onNewScan={reset} />}

      {view === VIEW.ABOUT && <About section={aboutSection} onBack={goHome} />}

      {view === VIEW.ERROR && (
        <div className="app-shell--error">
          <h1>CloudChain</h1>
          <p>{error}</p>
          <p className="app-shell__hint">
            If the backend isn&rsquo;t running, start it with:{' '}
            <code>python -m uvicorn app.main:app --reload --port 8000</code>
          </p>
          <button type="button" className="app-shell__retry" onClick={reset}>
            Back to start
          </button>
        </div>
      )}
    </>
  );
}

export default App;
