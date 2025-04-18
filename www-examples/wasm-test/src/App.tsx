import React, { useState, useEffect } from 'react';
import './App.css';

// IMPORTANT: We can't directly access functions before initialization
let wasmInstance: any = null;

interface ConversionResult {
  content: string;
  content_type: string;
  headers: Record<string, string>;
  status_code: number;
}

const App: React.FC = () => {
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [settingsContent, setSettingsContent] = useState<string>('');
  const [conversionQuery, setConversionQuery] = useState<string>('');
  const [conversionResult, setConversionResult] = useState<ConversionResult | null>(null);
  const [status, setStatus] = useState<string>('Loading WASM module...');
  const [logLevel, setLogLevel] = useState<string>("info");
  const [loggingEnabled, setLoggingEnabled] = useState<boolean>(false);

  useEffect(() => {
    async function initWasm() {
      try {
        // This is the critical fix - we need to import the module, initialize it,
        // and only then try to use its functions
        const wasm = await import('../../../pkg/subconverter');
        await wasm.default();

        // Initialize logging if the function exists
        try {
          if (typeof wasm.init_wasm_logging === 'function') {
            await wasm.init_wasm_logging(logLevel);
            console.log("WASM logging initialized with level:", logLevel);
            setLoggingEnabled(true);
          } else {
            console.warn("WASM logging function not found - you need to rebuild with the updated code");
            setLoggingEnabled(false);
          }
        } catch (e) {
          console.warn("WASM logging initialization failed:", e);
          setLoggingEnabled(false);
        }

        // Store the initialized module globally or in state
        wasmInstance = wasm;

        setIsLoading(false);
        setStatus('WASM module loaded. Ready to use.');
        console.log("WASM module successfully initialized!");
      } catch (err) {
        console.error('Failed to initialize WASM module:', err);
        setError(`Failed to initialize WASM module: ${err instanceof Error ? err.message : String(err)}`);
        setIsLoading(false);
      }
    }

    initWasm();
  }, [logLevel]);

  const handleSettingsChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setSettingsContent(e.target.value);
  };

  const handleQueryChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setConversionQuery(e.target.value);
  };

  const handleLogLevelChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setLogLevel(e.target.value);
  };

  const initializeSettings = async () => {
    if (!settingsContent || !wasmInstance) return;

    setStatus('Initializing settings...');
    try {
      // Now we use the stored instance instead of re-importing
      await wasmInstance.initialize_settings_from_content(settingsContent);
      setStatus('Settings initialized successfully!');
    } catch (err) {
      console.error('Failed to initialize settings:', err);
      setStatus(`Error initializing settings: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const runConversion = async () => {
    if (!conversionQuery || !wasmInstance) return;

    setStatus('Processing subscription...');
    try {
      // Now we use the stored instance instead of re-importing
      const response = await wasmInstance.sub_process_wasm(conversionQuery);
      const result = JSON.parse(response) as ConversionResult;
      setConversionResult(result);
      setStatus(`Conversion completed with status: ${result.status_code}`);
    } catch (err) {
      console.error('Conversion failed:', err);
      setStatus(`Conversion error: ${err instanceof Error ? err.message : String(err)}`);
      setConversionResult(null);
    }
  };

  const loadExampleSettings = () => {
    setSettingsContent(`common:
  api_mode: false
  max_pending_connections: 1024
  max_concurrent_threads: 4
  exclude_remarks:
    - "(?i)\\bVIP\\b"
  include_remarks:
    - "(?i)\\bHK\\b"
    - "(?i)\\bSG\\b"
  add_emoji: true
  remove_emoji: false`);
  };

  const loadExampleQuery = () => {
    const query = {
      target: "clash",
      url: "https://example.com/subscription",
      udp: true,
      emoji: true,
      append_type: true
    };
    setConversionQuery(JSON.stringify(query, null, 2));
  };

  return (
    <div className="app">
      <header>
        <h1>Subconverter WASM Test</h1>
        <p className="status">{status}</p>
        {error && <p className="error">{error}</p>}
      </header>

      <div className="container">
        <section className="section debug-section">
          <h2>Logging Configuration</h2>
          <div className="controls">
            <label htmlFor="logLevel">Log Level:</label>
            <select
              id="logLevel"
              value={logLevel}
              onChange={handleLogLevelChange}
              disabled={!isLoading}
            >
              <option value="error">Error</option>
              <option value="warn">Warn</option>
              <option value="info">Info</option>
              <option value="debug">Debug</option>
              <option value="trace">Trace</option>
            </select>
            <p className="info-text">
              Log level can only be set before WASM initialization. Changing it will reload the WASM module.
            </p>
            <p className="info-text">
              {loggingEnabled
                ? "Logging is enabled! Check browser console (F12) to see log messages from Rust."
                : "Logging is not available. Please rebuild WASM with './build-wasm.sh' and refresh."}
            </p>
          </div>
        </section>

        <section className="section">
          <h2>1. Initialize Settings</h2>
          <div className="controls">
            <button onClick={loadExampleSettings} disabled={isLoading}>Load Example Settings</button>
            <button onClick={initializeSettings} disabled={isLoading || !settingsContent}>
              Initialize Settings
            </button>
          </div>
          <textarea
            value={settingsContent}
            onChange={handleSettingsChange}
            placeholder="Enter settings content (YAML, TOML, or INI format)"
            disabled={isLoading}
            rows={10}
          />
        </section>

        <section className="section">
          <h2>2. Convert Subscription</h2>
          <div className="controls">
            <button onClick={loadExampleQuery} disabled={isLoading}>Load Example Query</button>
            <button onClick={runConversion} disabled={isLoading || !conversionQuery}>
              Convert Subscription
            </button>
          </div>
          <textarea
            value={conversionQuery}
            onChange={handleQueryChange}
            placeholder="Enter subscription query JSON"
            disabled={isLoading}
            rows={8}
          />
        </section>

        {conversionResult && (
          <section className="section">
            <h2>Conversion Result</h2>
            <div className="result-meta">
              <p><strong>Status Code:</strong> {conversionResult.status_code}</p>
              <p><strong>Content Type:</strong> {conversionResult.content_type}</p>
            </div>
            <div className="result-content">
              <h3>Content:</h3>
              <pre>{conversionResult.content.length > 1000
                ? conversionResult.content.substring(0, 1000) + '...(truncated)'
                : conversionResult.content}</pre>
            </div>
          </section>
        )}

        <section className="section debug-section">
          <h2>Debug Information</h2>
          <div>
            <p><strong>WASM Module Loaded:</strong> {wasmInstance ? "Yes" : "No"}</p>
            <p><strong>Browser:</strong> {navigator.userAgent}</p>
            <p><strong>Current Log Level:</strong> {logLevel}</p>
            <p><strong>Logging Enabled:</strong> {loggingEnabled ? "Yes" : "No"}</p>
            <div className="debug-actions">
              <button onClick={() => {
                console.log("WASM instance:", wasmInstance);
                console.log("Settings content:", settingsContent);
                console.log("Query:", conversionQuery);
                alert("Debug info logged to console");
              }}>
                Log Debug Info to Console
              </button>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};

export default App;
