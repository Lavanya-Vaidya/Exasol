import os
import re
from pathlib import Path

import joblib
import pandas as pd
import pyexasol
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS


# ============================================================
# ENVIRONMENT
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")


# ============================================================
# CONFIGURATION
# ============================================================

EXASOL_DSN = os.getenv("EXASOL_DSN")
EXASOL_USER = os.getenv("EXASOL_USER")
EXASOL_PASSWORD = os.getenv("EXASOL_PASSWORD")
EXASOL_SCHEMA = os.getenv("EXASOL_SCHEMA", "SHADOWNET")

AEGIS_HOST = os.getenv("AEGIS_HOST", "127.0.0.1")
AEGIS_PORT = int(os.getenv("AEGIS_PORT", "5001"))
CORS_ORIGIN = os.getenv(
    "CORS_ORIGIN",
    "http://localhost:5173",
)


if not EXASOL_DSN:
    raise RuntimeError(
        "EXASOL_DSN is missing from aegis-ml/.env"
    )

if not EXASOL_USER:
    raise RuntimeError(
        "EXASOL_USER is missing from aegis-ml/.env"
    )

if not EXASOL_PASSWORD:
    raise RuntimeError(
        "EXASOL_PASSWORD is missing from aegis-ml/.env"
    )


# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/*": {
            "origins": CORS_ORIGIN
        }
    },
)


# ============================================================
# ML FILES
# ============================================================

MODEL_PATH = BASE_DIR / "model.pkl"
FEATURES_PATH = BASE_DIR / "features.pkl"
DATASET_PATH = BASE_DIR / "MalMem2022.csv"

TX_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]{1,128}$"
)


# ============================================================
# LOAD ML ASSETS
# ============================================================

try:
    model = joblib.load(MODEL_PATH)
    feature_names = joblib.load(FEATURES_PATH)
    df = pd.read_csv(DATASET_PATH)

except Exception as exc:
    raise RuntimeError(
        f"Failed to load AEGIS ML assets: {exc}"
    ) from exc


# ============================================================
# VALIDATE DATASET
# ============================================================

if "Class" not in df.columns:
    raise RuntimeError(
        "MalMem2022.csv does not contain a 'Class' column."
    )


missing_features = [
    feature
    for feature in feature_names
    if feature not in df.columns
]

if missing_features:
    raise RuntimeError(
        "The ML dataset is missing required features: "
        + ", ".join(missing_features)
    )


# ============================================================
# PREPARE ML SAMPLES
# ============================================================

class_series = (
    df["Class"]
    .astype(str)
    .str.lower()
)

benign_rows = df[
    class_series == "benign"
]

malware_rows = df[
    class_series == "malware"
]

if benign_rows.empty:
    raise RuntimeError(
        "No Benign sample found in MalMem2022.csv."
    )

if malware_rows.empty:
    raise RuntimeError(
        "No Malware sample found in MalMem2022.csv."
    )


benign_sample = (
    benign_rows.iloc[0][feature_names]
    .apply(pd.to_numeric, errors="coerce")
    .fillna(0)
)

malware_sample = (
    malware_rows.iloc[0][feature_names]
    .apply(pd.to_numeric, errors="coerce")
    .fillna(0)
)


# ============================================================
# HELPERS
# ============================================================

def clamp(
    value,
    minimum=0.0,
    maximum=100.0,
):
    try:
        value = float(value)
    except (TypeError, ValueError):
        value = minimum

    return max(
        minimum,
        min(maximum, value),
    )


def clean_number(
    value,
    default=0.0,
):
    try:
        number = float(value)

        if pd.isna(number):
            return float(default)

        return number

    except (TypeError, ValueError):
        return float(default)


def validate_tx_id(tx_id):
    return (
        isinstance(tx_id, str)
        and bool(
            TX_ID_PATTERN.fullmatch(tx_id)
        )
    )


def sql_escape(value):
    return str(value).replace(
        "'",
        "''",
    )


# ============================================================
# EXASOL CONNECTION
# ============================================================

def get_exasol_connection():
    return pyexasol.connect(
        dsn=EXASOL_DSN,
        user=EXASOL_USER,
        password=EXASOL_PASSWORD,
        websocket_sslopt={
            "cert_reqs": 0
        },
    )


# ============================================================
# TRANSACTIONS
# ============================================================

def fetch_transactions(limit=25):
    """
    Get real transaction records from Exasol.
    """

    conn = get_exasol_connection()

    try:
        conn.execute(
            f"OPEN SCHEMA {EXASOL_SCHEMA}"
        )

        query = f"""
            SELECT
                TX_ID,
                ACCOUNT_ID,
                DEVICE_ID,
                BASE_RISK
            FROM ACTIVITIES
            ORDER BY BASE_RISK DESC
            LIMIT {int(limit)}
        """

        result = conn.execute(query)
        rows = result.fetchall()

        return [
            {
                "tx_id": str(row[0]),
                "account_id": str(row[1]),
                "device_id": str(row[2]),
                "base_risk": round(
                    clean_number(row[3]),
                    2,
                ),
            }
            for row in rows
        ]

    finally:
        conn.close()


def fetch_transaction(tx_id):
    safe_tx_id = sql_escape(tx_id)

    conn = get_exasol_connection()

    try:
        conn.execute(
            f"OPEN SCHEMA {EXASOL_SCHEMA}"
        )

        query = f"""
            SELECT
                TX_ID,
                ACCOUNT_ID,
                DEVICE_ID,
                BASE_RISK
            FROM ACTIVITIES
            WHERE TX_ID = '{safe_tx_id}'
            LIMIT 1
        """

        result = conn.execute(query)

        return result.fetchone()

    finally:
        conn.close()


# ============================================================
# SHADOWNET DATA
# ============================================================

def fetch_network(tx_id):
    safe_tx_id = sql_escape(tx_id)

    conn = get_exasol_connection()

    try:
        conn.execute(
            f"OPEN SCHEMA {EXASOL_SCHEMA}"
        )

        selected_query = f"""
            SELECT
                TX_ID,
                ACCOUNT_ID,
                DEVICE_ID,
                BASE_RISK
            FROM ACTIVITIES
            WHERE TX_ID = '{safe_tx_id}'
            LIMIT 1
        """

        selected_result = conn.execute(
            selected_query
        )

        selected = selected_result.fetchone()

        if not selected:
            return None

        selected_tx = str(selected[0])
        selected_account = str(selected[1])
        selected_device = str(selected[2])

        device_safe = sql_escape(
            selected_device
        )

        network_query = f"""
            SELECT
                TX_ID,
                ACCOUNT_ID,
                DEVICE_ID,
                BASE_RISK
            FROM ACTIVITIES
            WHERE DEVICE_ID = '{device_safe}'
            ORDER BY BASE_RISK DESC
            LIMIT 50
        """

        result = conn.execute(
            network_query
        )

        rows = result.fetchall()

        return {
            "selected_tx": selected_tx,
            "selected_account": selected_account,
            "selected_device": selected_device,
            "rows": rows,
        }

    finally:
        conn.close()


def fetch_threat_patterns():
    conn = get_exasol_connection()

    try:
        conn.execute(
            f"OPEN SCHEMA {EXASOL_SCHEMA}"
        )

        result = conn.execute(
            """
            SELECT
                SEQUENCE_TYPE,
                THREAT_MULTIPLIER
            FROM THREAT_PATTERNS
            ORDER BY THREAT_MULTIPLIER DESC
            LIMIT 5
            """
        )

        return result.fetchall()

    finally:
        conn.close()


def fetch_sandbox_response():
    """
    The current SANDBOX_LOGS query is intentionally generic
    because the verified schema does not contain a transaction
    identifier.
    """

    conn = get_exasol_connection()

    try:
        conn.execute(
            f"OPEN SCHEMA {EXASOL_SCHEMA}"
        )

        result = conn.execute(
            """
            SELECT
                SIMULATED_ACTION,
                FRAUD_PREVENTED_EST,
                COLLATERAL_IMPACT
            FROM SANDBOX_LOGS
            ORDER BY FRAUD_PREVENTED_EST DESC
            LIMIT 1
            """
        )

        return result.fetchone()

    finally:
        conn.close()


# ============================================================
# GRAPH
# ============================================================

def build_graph(network):
    selected_tx = network["selected_tx"]
    selected_account = network["selected_account"]
    selected_device = network["selected_device"]
    rows = network["rows"]

    nodes = []
    edges = []

    node_ids = set()
    edge_ids = set()

    def add_node(
        node_id,
        node_type,
    ):
        node_id = str(node_id)

        if node_id in node_ids:
            return

        node_ids.add(node_id)

        nodes.append(
            {
                "id": node_id,
                "type": node_type,
                "label": node_id,
            }
        )

    def add_edge(
        source,
        target,
        relationship,
    ):
        edge_id = (
            f"{source}|"
            f"{target}|"
            f"{relationship}"
        )

        if edge_id in edge_ids:
            return

        edge_ids.add(edge_id)

        edges.append(
            {
                "id": edge_id,
                "source": str(source),
                "target": str(target),
                "relationship": relationship,
            }
        )

    add_node(
        selected_tx,
        "transaction",
    )

    add_node(
        selected_account,
        "account",
    )

    add_node(
        selected_device,
        "device",
    )

    add_edge(
        selected_account,
        selected_tx,
        "INITIATED",
    )

    add_edge(
        selected_account,
        selected_device,
        "USES",
    )

    for row in rows:
        row_tx = str(row[0])
        row_account = str(row[1])
        row_device = str(row[2])

        add_node(
            row_tx,
            "transaction",
        )

        add_node(
            row_account,
            "account",
        )

        add_node(
            row_device,
            "device",
        )

        add_edge(
            row_account,
            row_tx,
            "INITIATED",
        )

        add_edge(
            row_account,
            row_device,
            "USES",
        )

    return {
        "nodes": nodes,
        "edges": edges,
    }


# ============================================================
# ML
# ============================================================

def get_malware_probability(probabilities):
    if not hasattr(
        model,
        "classes_"
    ):
        return clean_number(
            probabilities[1]
            if len(probabilities) > 1
            else probabilities[0]
        )

    classes = list(
        model.classes_
    )

    possible_labels = [
        "malware",
        "Malware",
        1,
        "1",
    ]

    for label in possible_labels:
        if label in classes:
            index = classes.index(
                label
            )

            return clean_number(
                probabilities[index]
            )

    if len(probabilities) >= 2:
        return clean_number(
            probabilities[1]
        )

    return clean_number(
        probabilities[0]
    )


def build_scenario_sample(
    scenario
):
    scenario = str(
        scenario or "benign"
    ).lower()

    weights = {
        "benign": 0.0,
        "suspicious": 0.30,
        "coordinated": 0.65,
        "malware": 1.0,
    }

    malware_weight = weights.get(
        scenario,
        0.0,
    )

    return (
        benign_sample
        * (1.0 - malware_weight)
        +
        malware_sample
        * malware_weight
    )


def run_ml_analysis(
    scenario
):
    sample = build_scenario_sample(
        scenario
    )

    X = pd.DataFrame(
        [sample.values],
        columns=feature_names,
    )

    probabilities = (
        model.predict_proba(X)[0]
    )

    malware_probability = (
        get_malware_probability(
            probabilities
        )
    )

    risk_percentage = round(
        clamp(
            malware_probability * 100
        ),
        2,
    )

    if risk_percentage < 30:
        risk_level = "LOW"
        decision = "ALLOW"

    elif risk_percentage < 55:
        risk_level = "MEDIUM"
        decision = "MONITOR"

    elif risk_percentage < 75:
        risk_level = "HIGH"
        decision = "SANDBOX"

    else:
        risk_level = "CRITICAL"
        decision = "BLOCK"

    return {
        "risk_score": round(
            malware_probability,
            4,
        ),
        "risk_percentage": risk_percentage,
        "risk_level": risk_level,
        "decision": decision,
        "scenario": scenario,
    }


# ============================================================
# SHADOWNET ANALYSIS
# ============================================================

def build_shadownet_result(
    network,
    ml_result,
    threat_patterns,
    sandbox_response,
):
    rows = network["rows"]

    linked_accounts = len(
        {
            str(row[1])
            for row in rows
        }
    )

    linked_transactions = len(
        {
            str(row[0])
            for row in rows
        }
    )

    base_risks = [
        clean_number(row[3])
        for row in rows
    ]

    max_base_risk = (
        max(base_risks)
        if base_risks
        else 0.0
    )

    account_component = min(
        linked_accounts * 10,
        45,
    )

    transaction_component = min(
        max(
            linked_transactions - 1,
            0,
        )
        * 4,
        20,
    )

    network_risk = clamp(
        max_base_risk
        + account_component
        + transaction_component
    )

    if threat_patterns:
        strongest = max(
            threat_patterns,
            key=lambda row:
                clean_number(row[1]),
        )

        threat_sequence = str(
            strongest[0]
        )

        threat_multiplier = clean_number(
            strongest[1],
            1.0,
        )

    else:
        threat_sequence = (
            "NO KNOWN SEQUENCE"
        )

        threat_multiplier = 1.0

    if linked_accounts >= 5:
        predicted_next_action = (
            "Move funds through linked account cluster"
        )

    elif linked_accounts >= 3:
        predicted_next_action = (
            "Attempt transfer through secondary linked account"
        )

    elif ml_result["risk_percentage"] >= 75:
        predicted_next_action = (
            "Repeat transaction from compromised endpoint"
        )

    elif ml_result["risk_percentage"] >= 50:
        predicted_next_action = (
            "Probe account for additional suspicious activity"
        )

    else:
        predicted_next_action = (
            "No suspicious continuation detected"
        )

    sandbox_action = (
        "ALLOW TRANSACTION"
    )

    sandbox_prevented = 0.0
    sandbox_collateral = "None"

    if sandbox_response:
        sandbox_action = str(
            sandbox_response[0]
        )

        sandbox_prevented = clean_number(
            sandbox_response[1]
        )

        sandbox_collateral = str(
            sandbox_response[2]
        )

    combined_risk = (
        ml_result["risk_percentage"]
        * 0.6
        + network_risk * 0.4
    )

    if combined_risk >= 75:
        sandbox_action = (
            "BLOCK TRANSACTION"
        )

    elif combined_risk >= 55:
        sandbox_action = (
            "MONITOR TRANSACTION"
        )

    signals = [
        {
            "label": "Shared infrastructure",
            "value": network[
                "selected_device"
            ],
            "impact": round(
                account_component,
                2,
            ),
        },
        {
            "label": "Linked-account density",
            "value": (
                f"{linked_accounts} account(s)"
            ),
            "impact": round(
                clamp(
                    linked_accounts * 18
                ),
                2,
            ),
        },
        {
            "label": "Transaction cluster",
            "value": (
                f"{linked_transactions} transaction(s)"
            ),
            "impact": round(
                transaction_component,
                2,
            ),
        },
        {
            "label": "Behavioral anomaly",
            "value": (
                f"{ml_result['risk_percentage']}%"
            ),
            "impact": round(
                ml_result[
                    "risk_percentage"
                ],
                2,
            ),
        },
    ]

    return {
        "tx_id": network[
            "selected_tx"
        ],

        "network_risk": round(
            network_risk,
            2,
        ),

        "hidden_network": {
            "shared_device": network[
                "selected_device"
            ],
            "linked_accounts":
                linked_accounts,
            "linked_transactions":
                linked_transactions,
        },

        "predicted_next_action":
            predicted_next_action,

        "threat_sequence":
            threat_sequence,

        "threat_multiplier":
            round(
                threat_multiplier,
                3,
            ),

        "signals":
            signals,

        "graph":
            build_graph(network),

        "recommended_response": {
            "action":
                sandbox_action,

            "estimated_fraud_prevented":
                round(
                    sandbox_prevented,
                    2,
                ),

            "collateral_impact":
                sandbox_collateral,
        },
    }


# ============================================================
# ROUTES
# ============================================================

@app.route(
    "/",
    methods=["GET"],
)
def home():
    return jsonify(
        {
            "service": "AEGIS",
            "status": "online",
            "message":
                "AEGIS ML + SHADOWNET API is running",
        }
    )


@app.route(
    "/health",
    methods=["GET"],
)
def health():
    return jsonify(
        {
            "status": "ok",
            "model_loaded":
                model is not None,
            "feature_count":
                len(feature_names),
            "dataset_rows":
                len(df),
            "exasol_configured":
                True,
        }
    )


# ============================================================
# NEW: REAL TRANSACTION FEED
# ============================================================

@app.route(
    "/transactions",
    methods=["GET"],
)
def transactions():
    try:
        limit_value = request.args.get(
            "limit",
            "25",
        )

        try:
            limit = int(
                limit_value
            )
        except ValueError:
            limit = 25

        limit = max(
            1,
            min(limit, 100),
        )

        data = fetch_transactions(
            limit
        )

        return jsonify(
            {
                "success": True,
                "count": len(data),
                "transactions": data,
            }
        )

    except Exception as exc:
        app.logger.exception(
            "Transaction retrieval failed"
        )

        return jsonify(
            {
                "success": False,
                "error_code":
                    "TRANSACTION_LIST_FAILED",
                "error":
                    "Could not retrieve transactions from Exasol.",
                "details": str(exc),
            }
        ), 500


# ============================================================
# ANALYZE
# ============================================================

@app.route(
    "/analyze",
    methods=["POST"],
)
def analyze():
    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    tx_id = data.get(
        "tx_id"
    )

    scenario = str(
        data.get(
            "demo",
            "benign",
        )
    ).lower()

    if not validate_tx_id(
        tx_id
    ):
        return jsonify(
            {
                "success": False,
                "error_code":
                    "INVALID_TX_ID",
                "error":
                    "A valid transaction ID is required.",
            }
        ), 400

    allowed_scenarios = {
        "benign",
        "suspicious",
        "coordinated",
        "malware",
    }

    if scenario not in allowed_scenarios:
        return jsonify(
            {
                "success": False,
                "error_code":
                    "INVALID_SCENARIO",
                "error":
                    f"Unsupported scenario: {scenario}",
            }
        ), 400

    # --------------------------------------------------------
    # ML
    # --------------------------------------------------------

    try:
        ml_result = run_ml_analysis(
            scenario
        )

    except Exception as exc:
        app.logger.exception(
            "ML analysis failed"
        )

        return jsonify(
            {
                "success": False,
                "error_code":
                    "ML_ANALYSIS_FAILED",
                "error":
                    "AEGIS ML analysis failed.",
                "details": str(exc),
            }
        ), 500

    # --------------------------------------------------------
    # TRANSACTION
    # --------------------------------------------------------

    try:
        transaction = fetch_transaction(
            tx_id
        )

    except Exception as exc:
        app.logger.exception(
            "Transaction lookup failed"
        )

        return jsonify(
            {
                "success": False,
                "error_code":
                    "TRANSACTION_LOOKUP_FAILED",
                "error":
                    "Could not retrieve transaction from Exasol.",
                "details": str(exc),
                "ml": ml_result,
            }
        ), 500

    if not transaction:
        return jsonify(
            {
                "success": False,
                "error_code":
                    "TRANSACTION_NOT_FOUND",
                "error":
                    f"Transaction {tx_id} was not found.",
                "ml": ml_result,
            }
        ), 404

    # --------------------------------------------------------
    # SHADOWNET
    # --------------------------------------------------------

    try:
        network = fetch_network(
            tx_id
        )

        if not network:
            return jsonify(
                {
                    "success": False,
                    "error_code":
                        "SHADOWNET_DATA_NOT_FOUND",
                    "error":
                        "No SHADOWNET relationship data found.",
                    "ml": ml_result,
                }
            ), 404

    except Exception as exc:
        app.logger.exception(
            "SHADOWNET lookup failed"
        )

        return jsonify(
            {
                "success": False,
                "error_code":
                    "SHADOWNET_UNAVAILABLE",
                "error":
                    "SHADOWNET correlation failed.",
                "details": str(exc),
                "ml": ml_result,
            }
        ), 500

    # --------------------------------------------------------
    # THREATS
    # --------------------------------------------------------

    try:
        threat_patterns = (
            fetch_threat_patterns()
        )

    except Exception as exc:
        app.logger.warning(
            "Threat pattern lookup failed: %s",
            exc,
        )

        threat_patterns = []

    # --------------------------------------------------------
    # SANDBOX
    # --------------------------------------------------------

    try:
        sandbox_response = (
            fetch_sandbox_response()
        )

    except Exception as exc:
        app.logger.warning(
            "Sandbox lookup failed: %s",
            exc,
        )

        sandbox_response = None

    # --------------------------------------------------------
    # BUILD RESULT
    # --------------------------------------------------------

    shadownet_result = (
        build_shadownet_result(
            network=network,
            ml_result=ml_result,
            threat_patterns=threat_patterns,
            sandbox_response=sandbox_response,
        )
    )

    combined_risk = round(
        (
            ml_result[
                "risk_percentage"
            ]
            * 0.6
        )
        +
        (
            shadownet_result[
                "network_risk"
            ]
            * 0.4
        ),
        2,
    )

    if combined_risk >= 75:
        final_decision = "BLOCK"

    elif combined_risk >= 55:
        final_decision = "MONITOR"

    elif combined_risk >= 30:
        final_decision = "REVIEW"

    else:
        final_decision = "ALLOW"

    return jsonify(
        {
            "success": True,

            "transaction": {
                "tx_id":
                    transaction[0],
                "account_id":
                    transaction[1],
                "device_id":
                    transaction[2],
                "base_risk":
                    clean_number(
                        transaction[3]
                    ),
            },

            "ml":
                ml_result,

            "shadownet":
                shadownet_result,

            "combined": {
                "risk_percentage":
                    combined_risk,
                "decision":
                    final_decision,
            },
        }
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    app.run(
        host=AEGIS_HOST,
        port=AEGIS_PORT,
        debug=False,
    )