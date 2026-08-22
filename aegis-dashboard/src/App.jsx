import { useEffect, useMemo, useState } from "react";
import "./App.css";

const API_URL =
  import.meta.env.VITE_API_URL ||
  "http://127.0.0.1:5001";

const scenarios = [
  {
    id: "benign",
    label: "Normal Behaviour",
    shortLabel: "NORMAL",
    description:
      "Routine activity with minimal behavioral risk.",
    demo: "benign",
  },
  {
    id: "suspicious",
    label: "Suspicious Behaviour",
    shortLabel: "SUSPICIOUS",
    description:
      "Unusual behavior requiring analyst review.",
    demo: "suspicious",
  },
  {
    id: "coordinated",
    label: "Coordinated Fraud",
    shortLabel: "COORDINATED",
    description:
      "Multiple connected entities indicate coordinated activity.",
    demo: "coordinated",
  },
  {
    id: "malware",
    label: "Compromised Host",
    shortLabel: "MALWARE",
    description:
      "Memory and process behavior suggests compromise.",
    demo: "malware",
  },
];

const analysisStages = [
  "Transaction metadata",
  "Behavioral features",
  "ML classification",
  "Identity linkage",
  "SHADOWNET correlation",
  "Threat prediction",
  "Response simulation",
];

function formatNumber(value) {
  return Number(value || 0).toLocaleString("en-IN");
}

function getRiskClass(value) {
  const score = Number(value);

  if (!Number.isFinite(score)) {
    return "neutral";
  }

  if (score >= 75) return "critical";
  if (score >= 55) return "high";
  if (score >= 30) return "medium";

  return "low";
}

function getTransactionStatus(transaction) {
  const risk = Number(transaction?.base_risk);

  if (!Number.isFinite(risk)) {
    return "UNKNOWN";
  }

  if (risk >= 75) return "CRITICAL";
  if (risk >= 55) return "HIGH";
  if (risk >= 30) return "MEDIUM";

  return "LOW";
}

/*
 * Automatically select a transaction appropriate for the
 * selected scenario.
 *
 * The transaction's real Exasol BASE_RISK determines the
 * selection. We do not invent transaction IDs.
 */
function selectTransactionForScenario(
  scenarioId,
  transactions
) {
  if (!transactions?.length) {
    return null;
  }

  const sorted = [...transactions].sort(
    (a, b) =>
      Number(b.base_risk || 0) -
      Number(a.base_risk || 0)
  );

  const count = sorted.length;

  switch (scenarioId) {
    case "benign":
      // Lowest-risk transaction.
      return sorted[count - 1];

    case "suspicious":
      // Roughly middle of the risk distribution.
      return sorted[
        Math.floor((count - 1) * 0.55)
      ];

    case "coordinated":
      // High-risk transaction, but leave the absolute
      // highest one for the compromised-host scenario.
      return sorted[
        Math.min(
          Math.floor((count - 1) * 0.2),
          count - 1
        )
      ];

    case "malware":
      // Highest-risk transaction.
      return sorted[0];

    default:
      return sorted[0];
  }
}

function App() {
  const [
    selectedScenarioId,
    setSelectedScenarioId,
  ] = useState("coordinated");

  const [
    transactions,
    setTransactions,
  ] = useState([]);

  const [
    selectedTransactionId,
    setSelectedTransactionId,
  ] = useState("");

  const [
    mlResult,
    setMlResult,
  ] = useState(null);

  const [
    shadowData,
    setShadowData,
  ] = useState(null);

  const [
    combinedResult,
    setCombinedResult,
  ] = useState(null);

  const [
    transactionData,
    setTransactionData,
  ] = useState(null);

  const [
    loadingTransactions,
    setLoadingTransactions,
  ] = useState(true);

  const [
    loading,
    setLoading,
  ] = useState(false);

  const [
    analysisStage,
    setAnalysisStage,
  ] = useState(-1);

  const [
    analysisError,
    setAnalysisError,
  ] = useState("");

  const [
    selectedNode,
    setSelectedNode,
  ] = useState(null);

  const [
    showWhy,
    setShowWhy,
  ] = useState(false);

  const [
    containmentRunning,
    setContainmentRunning,
  ] = useState(false);

  const [
    contained,
    setContained,
  ] = useState(false);

  const selectedScenario =
    useMemo(
      () =>
        scenarios.find(
          (scenario) =>
            scenario.id ===
            selectedScenarioId
        ) || scenarios[0],
      [selectedScenarioId]
    );

  const selectedTransaction =
    useMemo(
      () =>
        transactions.find(
          (transaction) =>
            transaction.tx_id ===
            selectedTransactionId
        ) || null,
      [
        transactions,
        selectedTransactionId,
      ]
    );

  const graph =
    shadowData?.graph || {
      nodes: [],
      edges: [],
    };

  const networkRisk =
    shadowData?.network_risk ?? null;

  const riskPercentage =
    mlResult?.risk_percentage ?? null;

  const combinedRisk =
    combinedResult?.risk_percentage ?? null;

  const finalDecision =
    combinedResult?.decision || null;

  const analysisComplete =
    Boolean(
      mlResult &&
        shadowData &&
        combinedResult
    );

  /*
   * Keep the transaction feed sorted by actual Exasol
   * BASE_RISK, highest first.
   */
  const sortedTransactions =
    useMemo(
      () =>
        [...transactions].sort(
          (a, b) =>
            Number(b.base_risk || 0) -
            Number(a.base_risk || 0)
        ),
      [transactions]
    );

  // ==========================================================
  // LOAD REAL TRANSACTIONS
  // ==========================================================

  const loadTransactions =
    async () => {
      setLoadingTransactions(true);
      setAnalysisError("");

      try {
        const response =
          await fetch(
            `${API_URL}/transactions?limit=30`
          );

        const result =
          await response.json();

        if (
          !response.ok ||
          !result.success
        ) {
          throw new Error(
            result.error ||
              "Failed to load transactions."
          );
        }

        const received =
          Array.isArray(
            result.transactions
          )
            ? result.transactions
            : [];

        /*
         * Sort immediately after retrieving the
         * real database records.
         */
        const sorted = [
          ...received,
        ].sort(
          (a, b) =>
            Number(b.base_risk || 0) -
            Number(a.base_risk || 0)
        );

        setTransactions(sorted);

        /*
         * Automatically select the transaction that
         * corresponds to the initial scenario.
         */
        const initialTransaction =
          selectTransactionForScenario(
            selectedScenarioId,
            sorted
          );

        if (initialTransaction) {
          setSelectedTransactionId(
            initialTransaction.tx_id
          );
        }
      } catch (error) {
        console.error(
          "Transaction loading error:",
          error
        );

        setAnalysisError(
          error.message ||
            "Could not load transactions from Exasol."
        );
      } finally {
        setLoadingTransactions(false);
      }
    };

  useEffect(() => {
    loadTransactions();
  }, []);

  // ==========================================================
  // RESET ANALYSIS
  // ==========================================================

  const resetResults = () => {
    setMlResult(null);
    setShadowData(null);
    setCombinedResult(null);
    setTransactionData(null);

    setAnalysisStage(-1);
    setSelectedNode(null);
    setShowWhy(false);

    setContainmentRunning(false);
    setContained(false);
  };

  // ==========================================================
  // SCENARIO CHANGE
  // ==========================================================

  const handleScenarioChange = (
    scenarioId
  ) => {
    setSelectedScenarioId(
      scenarioId
    );

    /*
     * Automatically choose a real transaction whose
     * Exasol BASE_RISK matches the selected scenario.
     */
    const matchingTransaction =
      selectTransactionForScenario(
        scenarioId,
        transactions
      );

    if (matchingTransaction) {
      setSelectedTransactionId(
        matchingTransaction.tx_id
      );
    }

    resetResults();
  };

  // ==========================================================
  // MANUAL TRANSACTION CHANGE
  // ==========================================================

  const handleTransactionChange = (
    transactionId
  ) => {
    setSelectedTransactionId(
      transactionId
    );

    /*
     * Manual selection is still allowed.
     * The user can investigate any real transaction.
     */
    resetResults();
  };

  // ==========================================================
  // ANALYSIS ANIMATION
  // ==========================================================

  const runAnalysisAnimation =
    async () => {
      setAnalysisStage(0);

      for (
        let index = 1;
        index <
        analysisStages.length;
        index += 1
      ) {
        await new Promise(
          (resolve) =>
            setTimeout(
              resolve,
              300
            )
        );

        setAnalysisStage(index);
      }
    };

  // ==========================================================
  // ANALYZE
  // ==========================================================

  const analyzeActivity =
    async () => {
      if (
        !selectedTransactionId
      ) {
        setAnalysisError(
          "Select a transaction first."
        );

        return;
      }

      setLoading(true);

      setMlResult(null);
      setShadowData(null);
      setCombinedResult(null);
      setTransactionData(null);

      setSelectedNode(null);
      setShowWhy(false);
      setContained(false);
      setAnalysisError("");

      const animationPromise =
        runAnalysisAnimation();

      try {
        const response =
          await fetch(
            `${API_URL}/analyze`,
            {
              method: "POST",

              headers: {
                "Content-Type":
                  "application/json",
              },

              body: JSON.stringify({
                demo:
                  selectedScenario.demo,

                tx_id:
                  selectedTransactionId,
              }),
            }
          );

        const result =
          await response.json();

        await animationPromise;

        if (
          !response.ok ||
          !result.success
        ) {
          throw new Error(
            result.error ||
              `AEGIS API returned ${response.status}`
          );
        }

        setTransactionData(
          result.transaction ||
            null
        );

        setMlResult(
          result.ml || null
        );

        setShadowData(
          result.shadownet ||
            null
        );

        setCombinedResult(
          result.combined ||
            null
        );

        setAnalysisStage(
          analysisStages.length
        );
      } catch (error) {
        console.error(
          "AEGIS analysis error:",
          error
        );

        setAnalysisStage(-1);

        setAnalysisError(
          error.message ||
            "AEGIS analysis failed."
        );
      } finally {
        setLoading(false);
      }
    };

  // ==========================================================
  // CONTAINMENT
  // ==========================================================

  const simulateContainment =
    async () => {
      if (
        containmentRunning ||
        contained ||
        !analysisComplete ||
        finalDecision === "ALLOW"
      ) {
        return;
      }

      setContainmentRunning(
        true
      );

      await new Promise(
        (resolve) =>
          setTimeout(
            resolve,
            1200
          )
      );

      setContainmentRunning(
        false
      );

      setContained(true);
    };

  // ==========================================================
  // GRAPH POSITIONS
  // ==========================================================

  const positionedNodes =
    useMemo(() => {
      if (
        !graph.nodes?.length
      ) {
        return [];
      }

      const accounts =
        graph.nodes.filter(
          (node) =>
            node.type === "account"
        );

      const devices =
        graph.nodes.filter(
          (node) =>
            node.type === "device"
        );

      const transactionNodes =
        graph.nodes.filter(
          (node) =>
            node.type ===
            "transaction"
        );

      const others =
        graph.nodes.filter(
          (node) =>
            ![
              "account",
              "device",
              "transaction",
            ].includes(node.type)
        );

      const positions =
        new Map();

      accounts.forEach(
        (node, index) => {
          const count =
            accounts.length;

          const angle =
            count <= 1
              ? 0
              : (
                  index / count
                ) *
                  Math.PI *
                  2 -
                Math.PI / 2;

          const radius =
            count > 5
              ? 39
              : 34;

          positions.set(
            node.id,
            {
              x:
                50 +
                Math.cos(angle) *
                  radius,

              y:
                50 +
                Math.sin(angle) *
                  radius,
            }
          );
        }
      );

      devices.forEach(
        (node, index) => {
          positions.set(
            node.id,
            {
              x: 50,
              y:
                43 +
                index * 13,
            }
          );
        }
      );

      transactionNodes.forEach(
        (node, index) => {
          const count =
            transactionNodes.length;

          const x =
            count <= 1
              ? 50
              : 34 +
                (
                  index /
                  Math.max(
                    count - 1,
                    1
                  )
                ) *
                  32;

          positions.set(
            node.id,
            {
              x,
              y: 84,
            }
          );
        }
      );

      others.forEach(
        (node, index) => {
          positions.set(
            node.id,
            {
              x:
                15 +
                (index % 4) *
                  23,

              y:
                15 +
                Math.floor(
                  index / 4
                ) *
                  20,
            }
          );
        }
      );

      return graph.nodes.map(
        (node) => ({
          ...node,
          ...(positions.get(
            node.id
          ) || {
            x: 50,
            y: 50,
          }),
        })
      );
    }, [graph.nodes]);

  const positionedNodeMap =
    useMemo(
      () =>
        new Map(
          positionedNodes.map(
            (node) => [
              node.id,
              node,
            ]
          )
        ),
      [positionedNodes]
    );

  const getNodePosition = (
    nodeId
  ) => {
    const node =
      positionedNodeMap.get(
        nodeId
      );

    return node || {
      x: 50,
      y: 50,
    };
  };

  // ==========================================================
  // EXPLAINABILITY
  // ==========================================================

  const explainability =
    useMemo(() => {
      if (
        !shadowData?.signals
      ) {
        return [];
      }

      return [
        ...shadowData.signals,
      ].sort(
        (a, b) =>
          Number(b.impact) -
          Number(a.impact)
      );
    }, [shadowData]);

  // ==========================================================
  // RENDER
  // ==========================================================

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            A
          </div>

          <div>
            <h1>AEGIS</h1>

            <p>
              INTELLIGENT THREAT
              CONTAINMENT SYSTEM
            </p>
          </div>
        </div>

        <div className="system-status">
          <span className="status-dot"></span>

          <span>
            EXASOL CONNECTED
          </span>

          <span className="status-divider"></span>

          <span>
            ML ENGINE ONLINE
          </span>

          <span className="status-divider"></span>

          <span>
            SHADOWNET ACTIVE
          </span>
        </div>
      </header>

      <main className="dashboard">
        {/* ==================================================
            HERO
            ================================================== */}

        <section className="hero">
          <div className="hero-copy">
            <p className="eyebrow">
              REAL-TIME THREAT INVESTIGATION
            </p>

            <h2>
              Investigate the threat.
              <br />

              <span>
                Contain it before it spreads.
              </span>
            </h2>

            <p className="hero-description">
              AEGIS combines behavioral
              machine learning with
              Exasol-powered relationship
              intelligence to identify
              hidden threat networks and
              recommend containment actions.
            </p>
          </div>

          <div className="hero-metrics">
            <div className="metric-card">
              <span className="metric-label">
                EVENTS ANALYZED
              </span>

              <strong>
                12,481
              </strong>

              <small>
                +18.4% today
              </small>
            </div>

            <div className="metric-card">
              <span className="metric-label">
                THREAT CLUSTERS
              </span>

              <strong>
                286
              </strong>

              <small>
                31 newly detected
              </small>
            </div>

            <div className="metric-card">
              <span className="metric-label">
                ENGINE LATENCY
              </span>

              <strong>
                184ms
              </strong>

              <small>
                Exasol correlation
              </small>
            </div>
          </div>
        </section>

        {/* ==================================================
            SCENARIO + TRANSACTION FEED
            ================================================== */}

        <section className="control-panel">
          <div className="control-heading">
            <div>
              <p className="eyebrow">
                INTERACTIVE SIMULATION
              </p>

              <h3>
                Scenario determines the
                transaction risk profile
              </h3>
            </div>

            <div className="selected-indicator">
              <span className="status-dot"></span>

              {selectedScenario.shortLabel}
            </div>
          </div>

          <div className="scenario-grid">
            {scenarios.map(
              (scenario) => {
                const active =
                  scenario.id ===
                  selectedScenarioId;

                return (
                  <button
                    type="button"
                    key={scenario.id}
                    className={`scenario-button ${
                      active
                        ? "active"
                        : ""
                    }`}
                    onClick={() =>
                      handleScenarioChange(
                        scenario.id
                      )
                    }
                  >
                    <span className="scenario-topline">
                      <span>
                        {
                          scenario.shortLabel
                        }
                      </span>

                      {active && (
                        <span className="active-tag">
                          AUTO-MAPPED
                        </span>
                      )}
                    </span>

                    <strong>
                      {
                        scenario.label
                      }
                    </strong>

                    <small>
                      {
                        scenario.description
                      }
                    </small>
                  </button>
                );
              }
            )}
          </div>

          <div className="transaction-selector">
            <div>
              <span className="control-label">
                EXASOL TRANSACTION FEED
              </span>

              <strong>
                {loadingTransactions
                  ? "Loading..."
                  : selectedTransaction
                    ? `${selectedTransaction.tx_id} · ${selectedTransaction.device_id}`
                    : "No transaction available"}
              </strong>

              <small
                style={{
                  display:
                    "block",
                  marginTop:
                    "6px",
                  color:
                    "var(--muted)",
                  fontSize:
                    "8px",
                  fontFamily:
                    "var(--mono)",
                }}
              >
                ORDERED BY BASE RISK
              </small>
            </div>

            <div className="transaction-list">
              {loadingTransactions && (
                <div className="transaction-loading">
                  Loading real
                  transactions from
                  Exasol...
                </div>
              )}

              {!loadingTransactions &&
                sortedTransactions.length ===
                  0 && (
                  <div className="transaction-loading">
                    No transactions
                    available.
                  </div>
                )}

              {!loadingTransactions &&
                sortedTransactions.map(
                  (
                    transaction
                  ) => {
                    const active =
                      transaction.tx_id ===
                      selectedTransactionId;

                    const status =
                      getTransactionStatus(
                        transaction
                      );

                    return (
                      <button
                        type="button"
                        key={
                          transaction.tx_id
                        }
                        className={`transaction-chip ${
                          active
                            ? "selected"
                            : ""
                        }`}
                        onClick={() =>
                          handleTransactionChange(
                            transaction.tx_id
                          )
                        }
                      >
                        <span>
                          {
                            transaction.tx_id
                          }
                        </span>

                        <strong>
                          BASE RISK{" "}
                          {
                            transaction.base_risk
                          }
                          %
                        </strong>

                        <em
                          className={status.toLowerCase()}
                        >
                          {status}
                        </em>
                      </button>
                    );
                  }
                )}
            </div>
          </div>
        </section>

        {/* ==================================================
            SELECTED TRANSACTION
            ================================================== */}

        <section className="investigation-header">
          <div>
            <p className="eyebrow">
              SELECTED TRANSACTION
            </p>

            <h3>
              {selectedTransaction
                ? selectedTransaction.tx_id
                : "NO TRANSACTION"}
            </h3>

            <p>
              {selectedTransaction
                ? `Account ${selectedTransaction.account_id} · Device ${selectedTransaction.device_id} · Exasol Base Risk ${selectedTransaction.base_risk}%`
                : "Select a transaction from the Exasol feed."}
            </p>
          </div>

          <button
            type="button"
            className="analyze-button"
            onClick={analyzeActivity}
            disabled={
              loading ||
              loadingTransactions ||
              !selectedTransactionId
            }
          >
            <span className="button-pulse"></span>

            {loading
              ? "ANALYZING THREAT..."
              : "RUN AEGIS ANALYSIS"}
          </button>
        </section>

        {/* ==================================================
            PIPELINE
            ================================================== */}

        {loading && (
          <section className="analysis-progress">
            <div className="analysis-progress-header">
              <div>
                <span className="eyebrow">
                  AEGIS ANALYSIS PIPELINE
                </span>

                <strong>
                  Correlating threat signals...
                </strong>
              </div>

              <span>
                {Math.min(
                  analysisStage + 1,
                  analysisStages.length
                )}
                /
                {
                  analysisStages.length
                }
              </span>
            </div>

            <div className="stage-track">
              {analysisStages.map(
                (
                  stage,
                  index
                ) => (
                  <div
                    className={`stage ${
                      index <=
                      analysisStage
                        ? "complete"
                        : ""
                    } ${
                      index ===
                      analysisStage
                        ? "current"
                        : ""
                    }`}
                    key={stage}
                  >
                    <span className="stage-marker">
                      {index <
                      analysisStage
                        ? "✓"
                        : index + 1}
                    </span>

                    <span>
                      {stage}
                    </span>
                  </div>
                )
              )}
            </div>
          </section>
        )}

        {/* ==================================================
            ERROR
            ================================================== */}

        {analysisError && (
          <section className="error-panel">
            <strong>
              AEGIS ENGINE ERROR
            </strong>

            <p>
              {analysisError}
            </p>
          </section>
        )}

        {/* ==================================================
            MAIN ANALYSIS
            ================================================== */}

        <section className="main-grid">
          {/* =================================================
              SHADOWNET
              ================================================= */}

          <article className="card shadow-card">
            <div className="card-title">
              <div className="card-icon purple">
                ◈
              </div>

              <div>
                <p>
                  RELATIONSHIP INTELLIGENCE
                </p>

                <h3>
                  SHADOWNET
                </h3>
              </div>

              <span className="live-badge">
                LIVE
              </span>
            </div>

            <div className="network-summary">
              <div>
                <span>
                  NETWORK RISK
                </span>

                <strong
                  className={getRiskClass(
                    networkRisk
                  )}
                >
                  {networkRisk === null
                    ? "--"
                    : `${networkRisk}%`}
                </strong>
              </div>

              <div>
                <span>
                  LINKED ACCOUNTS
                </span>

                <strong>
                  {shadowData
                    ?.hidden_network
                    ?.linked_accounts ??
                    "--"}
                </strong>
              </div>

              <div>
                <span>
                  SHARED DEVICE
                </span>

                <strong>
                  {shadowData
                    ?.hidden_network
                    ?.shared_device ??
                    "--"}
                </strong>
              </div>
            </div>

            <div className="network-map">
              <div className="network-grid"></div>

              <svg
                className="network-svg"
                viewBox="0 0 100 100"
                preserveAspectRatio="none"
              >
                {graph.edges.map(
                  (edge) => {
                    const source =
                      getNodePosition(
                        edge.source
                      );

                    const target =
                      getNodePosition(
                        edge.target
                      );

                    return (
                      <line
                        key={edge.id}
                        x1={source.x}
                        y1={source.y}
                        x2={target.x}
                        y2={target.y}
                        className={`graph-edge ${
                          edge.relationship
                            ?.toLowerCase()
                            .replace(
                              /\s+/g,
                              "-"
                            ) || ""
                        }`}
                      />
                    );
                  }
                )}
              </svg>

              {positionedNodes.map(
                (node) => {
                  const selected =
                    selectedNode ===
                    node.id;

                  return (
                    <button
                      type="button"
                      key={node.id}
                      className={`network-node ${
                        node.type
                      } ${
                        selected
                          ? "selected"
                          : ""
                      }`}
                      style={{
                        left: `${node.x}%`,
                        top: `${node.y}%`,
                      }}
                      onClick={() =>
                        setSelectedNode(
                          node.id
                        )
                      }
                    >
                      <span className="node-pulse"></span>

                      <strong>
                        {
                          node.label
                        }
                      </strong>

                      <small>
                        {String(
                          node.type
                        ).toUpperCase()}
                      </small>
                    </button>
                  );
                }
              )}

              {!graph.nodes.length && (
                <div className="network-empty">
                  <div>
                    <strong>
                      SHADOWNET READY
                    </strong>

                    <span>
                      Run AEGIS analysis
                      to build the
                      relationship graph.
                    </span>
                  </div>
                </div>
              )}

              {graph.nodes.length >
                0 && (
                <div className="network-center-label">
                  LIVE THREAT CLUSTER
                </div>
              )}
            </div>

            {selectedNode && (
              <div className="node-details">
                <div>
                  <span>
                    ENTITY INTELLIGENCE
                  </span>

                  <strong>
                    {
                      selectedNode
                    }
                  </strong>
                </div>

                <button
                  type="button"
                  onClick={() =>
                    setSelectedNode(
                      null
                    )
                  }
                >
                  ×
                </button>

                <div className="node-stats">
                  <div>
                    <span>
                      TYPE
                    </span>

                    <strong>
                      {String(
                        positionedNodeMap.get(
                          selectedNode
                        )?.type ||
                          "UNKNOWN"
                      ).toUpperCase()}
                    </strong>
                  </div>

                  <div>
                    <span>
                      RELATIONSHIPS
                    </span>

                    <strong>
                      {
                        graph.edges.filter(
                          (edge) =>
                            edge.source ===
                              selectedNode ||
                            edge.target ===
                              selectedNode
                        ).length
                      }
                    </strong>
                  </div>

                  <div>
                    <span>
                      RISK
                    </span>

                    <strong>
                      {combinedRisk ===
                      null
                        ? "--"
                        : `${combinedRisk}%`}
                    </strong>
                  </div>
                </div>
              </div>
            )}

            <div className="prediction">
              <span>
                PREDICTED NEXT ACTION
              </span>

              <strong>
                {shadowData
                  ?.predicted_next_action ||
                  "Awaiting correlation analysis"}
              </strong>
            </div>
          </article>

          {/* =================================================
              ML ENGINE
              ================================================= */}

          <article className="card aegis-card">
            <div className="card-title">
              <div className="card-icon cyan">
                ◆
              </div>

              <div>
                <p>
                  BEHAVIORAL ANALYSIS
                </p>

                <h3>
                  AEGIS ML ENGINE
                </h3>
              </div>

              {analysisComplete && (
                <span className="model-badge">
                  MODEL ACTIVE
                </span>
              )}
            </div>

            {!mlResult &&
              !loading && (
                <div className="waiting">
                  <div className="waiting-orbit">
                    <span></span>
                    <span></span>
                    <span></span>
                  </div>

                  <p>
                    Ready for behavioral
                    analysis
                  </p>

                  <span>
                    The selected scenario
                    automatically maps to
                    the appropriate real
                    transaction risk profile.
                  </span>
                </div>
              )}

            {loading && (
              <div className="waiting">
                <div className="scanner"></div>

                <p>
                  Scanning behavioral
                  indicators...
                </p>

                <span>
                  Comparing process,
                  memory and relationship
                  signals.
                </span>
              </div>
            )}

            {mlResult &&
              !mlResult.error && (
                <div className="ml-result">
                  <div className="risk-hero">
                    <div>
                      <span>
                        BEHAVIORAL RISK
                      </span>

                      <strong
                        className={getRiskClass(
                          riskPercentage
                        )}
                      >
                        {riskPercentage}%
                      </strong>
                    </div>

                    <div
                      className={`risk-orb ${getRiskClass(
                        riskPercentage
                      )}`}
                    >
                      <span>
                        {
                          mlResult.risk_level
                        }
                      </span>
                    </div>
                  </div>

                  <div className="risk-meter">
                    <div
                      className={`risk-meter-fill ${getRiskClass(
                        riskPercentage
                      )}`}
                      style={{
                        width: `${Math.min(
                          100,
                          Math.max(
                            0,
                            Number(
                              riskPercentage
                            ) || 0
                          )
                        )}%`,
                      }}
                    ></div>
                  </div>

                  <div className="info-row">
                    <span>
                      Model Decision
                    </span>

                    <strong>
                      {
                        mlResult.decision
                      }
                    </strong>
                  </div>

                  <div className="info-row">
                    <span>
                      Exasol Base Risk
                    </span>

                    <strong>
                      {selectedTransaction
                        ? `${selectedTransaction.base_risk}%`
                        : "--"}
                    </strong>
                  </div>

                  <button
                    type="button"
                    className="why-button"
                    onClick={() =>
                      setShowWhy(
                        (value) =>
                          !value
                      )
                    }
                  >
                    {showWhy
                      ? "Hide reasoning"
                      : "Why did AEGIS flag this?"}

                    <span>
                      {showWhy
                        ? "↑"
                        : "→"}
                    </span>
                  </button>

                  {showWhy && (
                    <div className="explainability">
                      <div className="explainability-header">
                        <span>
                          CONTRIBUTING SIGNALS
                        </span>

                        <small>
                          AEGIS INTERPRETATION
                        </small>
                      </div>

                      {explainability.map(
                        (
                          item
                        ) => (
                          <div
                            className="feature-row"
                            key={
                              item.label
                            }
                          >
                            <div>
                              <span>
                                {
                                  item.label
                                }
                              </span>

                              <strong>
                                {Math.round(
                                  Number(
                                    item.impact
                                  ) || 0
                                )}
                              </strong>
                            </div>

                            <div className="feature-bar">
                              <div
                                style={{
                                  width: `${Math.min(
                                    100,
                                    Math.max(
                                      0,
                                      Number(
                                        item.impact
                                      ) || 0
                                    )
                                  )}%`,
                                }}
                              ></div>
                            </div>

                            <small
                              style={{
                                display:
                                  "block",
                                marginTop:
                                  "4px",
                                color:
                                  "var(--muted)",
                                fontSize:
                                  "8px",
                              }}
                            >
                              {
                                item.value
                              }
                            </small>
                          </div>
                        )
                      )}
                    </div>
                  )}

                  <div className="prediction cyan-prediction">
                    <span>
                      AEGIS ML DECISION
                    </span>

                    <strong>
                      {
                        mlResult.decision
                      }
                    </strong>
                  </div>
                </div>
              )}
          </article>
        </section>

        {/* ==================================================
            INTELLIGENCE
            ================================================== */}

        <section className="intelligence-grid">
          <article className="intel-card">
            <div className="intel-header">
              <div>
                <span className="eyebrow">
                  CORRELATION ENGINE
                </span>

                <h3>
                  Why this threat matters
                </h3>
              </div>

              <span
                className={`risk-pill ${getRiskClass(
                  combinedRisk
                )}`}
              >
                {combinedRisk === null
                  ? "--"
                  : `${combinedRisk}% RISK`}
              </span>
            </div>

            <div className="signal-list">
              <div className="signal-item">
                <span className="signal-icon">
                  01
                </span>

                <div>
                  <strong>
                    Shared infrastructure
                  </strong>

                  <p>
                    {shadowData
                      ?.hidden_network
                      ?.shared_device ||
                      "No device correlation yet."}
                  </p>
                </div>
              </div>

              <div className="signal-item">
                <span className="signal-icon">
                  02
                </span>

                <div>
                  <strong>
                    Account clustering
                  </strong>

                  <p>
                    {
                      shadowData
                        ?.hidden_network
                        ?.linked_accounts ??
                      0
                    }{" "}
                    account(s) share the
                    observed infrastructure.
                  </p>
                </div>
              </div>

              <div className="signal-item">
                <span className="signal-icon">
                  03
                </span>

                <div>
                  <strong>
                    Behavioral anomaly
                  </strong>

                  <p>
                    ML behavioral risk:
                    {" "}
                    {riskPercentage ===
                    null
                      ? "--"
                      : `${riskPercentage}%`}
                  </p>
                </div>
              </div>

              <div className="signal-item">
                <span className="signal-icon">
                  04
                </span>

                <div>
                  <strong>
                    Threat sequence
                  </strong>

                  <p>
                    {shadowData
                      ?.threat_sequence ||
                      "No sequence correlated yet."}
                  </p>
                </div>
              </div>
            </div>
          </article>

          <article className="intel-card timeline-card">
            <div className="intel-header">
              <div>
                <span className="eyebrow">
                  INVESTIGATION TIMELINE
                </span>

                <h3>
                  Threat progression
                </h3>
              </div>

              <span className="timeline-status">
                {analysisComplete
                  ? "CORRELATED"
                  : "READY"}
              </span>
            </div>

            <div className="timeline">
              <div className="timeline-item complete">
                <span>
                  09:02
                </span>

                <div>
                  <strong>
                    Scenario selected
                  </strong>

                  <p>
                    {
                      selectedScenario.label
                    }
                  </p>
                </div>
              </div>

              <div className="timeline-item complete">
                <span>
                  09:03
                </span>

                <div>
                  <strong>
                    Risk-matched transaction
                  </strong>

                  <p>
                    {selectedTransaction
                      ? `${selectedTransaction.tx_id} · ${selectedTransaction.base_risk}% base risk`
                      : "Awaiting transaction"}
                  </p>
                </div>
              </div>

              <div
                className={`timeline-item ${
                  transactionData
                    ? "complete"
                    : ""
                }`}
              >
                <span>
                  09:04
                </span>

                <div>
                  <strong>
                    Device fingerprint matched
                  </strong>

                  <p>
                    {
                      transactionData
                        ?.device_id ||
                      "Awaiting transaction lookup"
                    }
                  </p>
                </div>
              </div>

              <div
                className={`timeline-item ${
                  mlResult
                    ? "complete"
                    : ""
                }`}
              >
                <span>
                  09:07
                </span>

                <div>
                  <strong>
                    Behavioral model scored event
                  </strong>

                  <p>
                    {riskPercentage ===
                    null
                      ? "Waiting for ML execution"
                      : `${riskPercentage}% behavioral risk`}
                  </p>
                </div>
              </div>

              <div
                className={`timeline-item ${
                  shadowData
                    ? "complete"
                    : ""
                }`}
              >
                <span>
                  09:08
                </span>

                <div>
                  <strong>
                    SHADOWNET correlated entities
                  </strong>

                  <p>
                    {
                      shadowData
                        ?.hidden_network
                        ?.linked_accounts ??
                      0
                    }{" "}
                    linked account(s)
                  </p>
                </div>
              </div>

              <div
                className={`timeline-item ${
                  combinedResult
                    ? "complete"
                    : ""
                }`}
              >
                <span>
                  09:09
                </span>

                <div>
                  <strong>
                    AEGIS generated decision
                  </strong>

                  <p>
                    {
                      finalDecision ||
                      "Awaiting combined risk"
                    }
                  </p>
                </div>
              </div>

              <div
                className={`timeline-item ${
                  contained
                    ? "complete"
                    : ""
                }`}
              >
                <span>
                  09:10
                </span>

                <div>
                  <strong>
                    {contained
                      ? "Containment executed"
                      : "Containment ready"}
                  </strong>

                  <p>
                    {contained
                      ? "Threat cluster isolated"
                      : "Awaiting analyst action"}
                  </p>
                </div>
              </div>
            </div>
          </article>
        </section>

        {/* ==================================================
            FINAL RESPONSE
            ================================================== */}

        <section
          className={`final-card ${
            contained
              ? "contained"
              : ""
          }`}
        >
          <div className="final-copy">
            <span className="eyebrow">
              FINAL AEGIS RESPONSE
            </span>

            <h2>
              {contained
                ? "THREAT CONTAINED"
                : finalDecision ||
                  "AWAITING ANALYSIS"}
            </h2>

            <p>
              {contained
                ? "AEGIS has simulated containment across the detected threat cluster."
                : shadowData
                    ?.recommended_response
                    ?.collateral_impact ||
                  "Run AEGIS analysis to generate a response recommendation."}
            </p>

            {mlResult && (
              <span className="containment">
                BASE RISK:{" "}
                {selectedTransaction
                  ? `${selectedTransaction.base_risk}%`
                  : "--"}
                {" · "}
                ML:{" "}
                {
                  mlResult.decision
                }
                {" · "}
                NETWORK:{" "}
                {networkRisk ===
                null
                  ? "--"
                  : `${networkRisk}%`}
              </span>
            )}
          </div>

          <div className="response-action">
            <div className="money">
              ₹
              {formatNumber(
                shadowData
                  ?.recommended_response
                  ?.estimated_fraud_prevented ||
                  0
              )}

              <span>
                DATABASE RESPONSE ESTIMATE
              </span>
            </div>

            <button
              type="button"
              className={`contain-button ${
                contained
                  ? "done"
                  : ""
              }`}
              disabled={
                !analysisComplete ||
                containmentRunning ||
                contained ||
                finalDecision ===
                  "ALLOW"
              }
              onClick={
                simulateContainment
              }
            >
              {containmentRunning
                ? "CONTAINING..."
                : contained
                  ? "THREAT CONTAINED ✓"
                  : finalDecision ===
                      "ALLOW"
                    ? "NO CONTAINMENT REQUIRED"
                    : "SIMULATE CONTAINMENT"}
            </button>
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;