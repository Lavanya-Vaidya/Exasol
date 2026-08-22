import { useState } from "react";
import "./App.css";

function App() {
  const [mlResult, setMlResult] = useState(null);
  const [shadowData, setShadowData] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyzeActivity = async () => {
    setLoading(true);

    const data = {
      demo: "malware",
      tx_id: "T1",
    };

    try {
      const response = await fetch(
        "http://127.0.0.1:5001/analyze",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(data),
        }
      );

      const result = await response.json();

      console.log("Live AEGIS response:", result);

      setMlResult(result.ml);
      setShadowData(result.shadownet);

    } catch (error) {
      console.error("Error:", error);

      setMlResult({
        error: "Could not connect to AEGIS ML API",
      });
    }

    setLoading(false);
  };

  // Default display before analysis
  const displayShadow = shadowData || {
    tx_id: "T1",
    network_risk: "--",
    hidden_network: {
      shared_device: "--",
      linked_accounts: "--",
    },
    predicted_next_action: "Waiting for analysis",
    recommended_response: {
      action: "Awaiting SHADOWNET analysis",
      estimated_fraud_prevented: 0,
      collateral_impact: "--",
    },
  };

  return (
    <div className="app">
      <header>
        <div>
          <h1>AEGIS</h1>
          <p>Intelligent Threat Containment System</p>
        </div>

        <div className="status">
          ● SYSTEM ACTIVE
        </div>
      </header>

      <main>
        <section className="hero">
          <div>
            <p className="label">LIVE TRANSACTION</p>
            <h2>Transaction {displayShadow.tx_id}</h2>
          </div>

          <button
            className="analyze-button"
            onClick={analyzeActivity}
            disabled={loading}
          >
            {loading ? "ANALYZING..." : "ANALYZE ACTIVITY"}
          </button>
        </section>

        <div className="grid">

          {/* SHADOWNET */}
          <div className="card shadow-card">
            <div className="card-title">
              <span>🌐</span>

              <div>
                <p>INTELLIGENCE LAYER</p>
                <h3>SHADOWNET</h3>
              </div>
            </div>

            <div className="risk-number">
              {displayShadow.network_risk}%
              <span>NETWORK RISK</span>
            </div>

            <div className="info-row">
              <span>Shared Device</span>
              <strong>
                {displayShadow.hidden_network.shared_device}
              </strong>
            </div>

            <div className="info-row">
              <span>Linked Accounts</span>
              <strong>
                {displayShadow.hidden_network.linked_accounts}
              </strong>
            </div>

            <div className="prediction">
              <p>PREDICTED NEXT ACTION</p>
              <strong>
                {displayShadow.predicted_next_action}
              </strong>
            </div>
          </div>

          {/* AEGIS ML */}
          <div className="card aegis-card">
            <div className="card-title">
              <span>🛡️</span>

              <div>
                <p>BEHAVIORAL ANALYSIS</p>
                <h3>AEGIS ML ENGINE</h3>
              </div>
            </div>

            {!mlResult && !loading && (
              <div className="waiting">
                <div className="pulse"></div>

                <p>Ready for Analysis</p>
                <span>Click Analyze Activity</span>
              </div>
            )}

            {loading && (
              <div className="waiting">
                <div className="pulse"></div>

                <p>Analyzing behavioral patterns...</p>
              </div>
            )}

            {mlResult && !mlResult.error && (
              <div className="ml-result">
                <div className="risk-number">
                  {mlResult.risk_percentage}%
                  <span>BEHAVIORAL RISK</span>
                </div>

                <div className="info-row">
                  <span>Risk Level</span>
                  <strong>{mlResult.risk_level}</strong>
                </div>

                <div className="prediction">
                  <p>AEGIS DECISION</p>
                  <strong>{mlResult.decision}</strong>
                </div>
              </div>
            )}

            {mlResult?.error && (
              <div className="waiting">
                <p>{mlResult.error}</p>
              </div>
            )}

          </div>
        </div>

        {/* FINAL RESPONSE */}
        <section className="final-card">

          <div>
            <p>FINAL RECOMMENDED RESPONSE</p>

            <h2>
              {displayShadow.recommended_response.action}
            </h2>

            {mlResult && !mlResult.error && (
              <span className="containment">
                + AEGIS: {mlResult.decision}
              </span>
            )}
          </div>

          <div className="money">
            ₹
            {displayShadow.recommended_response.estimated_fraud_prevented.toLocaleString(
              "en-IN"
            )}

            <span>ESTIMATED FRAUD PREVENTED</span>
          </div>

        </section>
      </main>
    </div>
  );
}

export default App;