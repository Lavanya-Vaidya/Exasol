from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import pyexasol

app = Flask(__name__)
CORS(app)


# -------------------------------
# LOAD ML MODEL
# -------------------------------

model = joblib.load("model.pkl")
feature_names = joblib.load("features.pkl")

# Dataset for ML demo samples
df = pd.read_csv("MalMem2022.csv")


# -------------------------------
# EXASOL CONNECTION FUNCTION
# -------------------------------

def get_exasol_connection():
    return pyexasol.connect(
        dsn="13.233.255.53:8563",
        user="sys",
        password="exasol",
        websocket_sslopt={
            "cert_reqs": 0
        }
    )


# -------------------------------
# HOME
# -------------------------------

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "AEGIS ML + SHADOWNET API is running"
    })


# -------------------------------
# COMBINED ANALYSIS
# -------------------------------

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json() or {}

    # ==================================
    # AEGIS ML ANALYSIS
    # ==================================

    if data.get("demo") == "malware":

        sample = df[df["Class"] == "Malware"].iloc[0]

        features = {
            feature: float(sample[feature])
            for feature in feature_names
        }

    elif data.get("demo") == "benign":

        sample = df[df["Class"] == "Benign"].iloc[0]

        features = {
            feature: float(sample[feature])
            for feature in feature_names
        }

    else:

        features = {
            feature: data.get(feature, 0)
            for feature in feature_names
        }

    X = pd.DataFrame([features])

    risk_score = float(model.predict_proba(X)[0][1])

    if risk_score < 0.30:
        decision = "ALLOW"
        risk_level = "LOW"

    elif risk_score < 0.60:
        decision = "MONITOR"
        risk_level = "MEDIUM"

    else:
        decision = "SANDBOX"
        risk_level = "HIGH"


    # ==================================
    # LIVE EXASOL SHADOWNET ANALYSIS
    # ==================================

    conn = get_exasol_connection()

    try:
        conn.execute("OPEN SCHEMA shadownet")

        tx_id = data.get("tx_id", "T1")

        # Transaction + shared device analysis
        result = conn.execute(f"""
            SELECT
                A.TX_ID,
                A.DEVICE_ID,
                A.BASE_RISK,
                COUNT(DISTINCT B.ACCOUNT_ID) AS LINKED_ACCOUNTS
            FROM ACTIVITIES A
            JOIN ACTIVITIES B
                ON A.DEVICE_ID = B.DEVICE_ID
            WHERE A.TX_ID = '{tx_id}'
            GROUP BY
                A.TX_ID,
                A.DEVICE_ID,
                A.BASE_RISK
        """)

        transaction = result.fetchone()

        # Highest threat pattern
        result = conn.execute("""
            SELECT
                SEQUENCE_TYPE,
                THREAT_MULTIPLIER
            FROM THREAT_PATTERNS
            ORDER BY THREAT_MULTIPLIER DESC
            LIMIT 1
        """)

        threat = result.fetchone()

        # Recommended response
        result = conn.execute("""
            SELECT
                SIMULATED_ACTION,
                FRAUD_PREVENTED_EST,
                COLLATERAL_IMPACT
            FROM SANDBOX_LOGS
            LIMIT 1
        """)

        sandbox = result.fetchone()

    finally:
        conn.close()


    # ==================================
    # COMBINED RESPONSE
    # ==================================

    return jsonify({

        # AEGIS ML
        "ml": {
            "risk_score": round(risk_score, 4),
            "risk_percentage": round(risk_score * 100, 2),
            "risk_level": risk_level,
            "decision": decision
        },

        # SHADOWNET / EXASOL
        "shadownet": {
            "tx_id": transaction[0],
            "network_risk": float(transaction[2]),
            "hidden_network": {
                "shared_device": transaction[1],
                "linked_accounts": int(transaction[3])
            },
            "predicted_next_action": threat[0],
            "threat_multiplier": float(threat[1]),
            "recommended_response": {
                "action": sandbox[0],
                "estimated_fraud_prevented": float(sandbox[1]),
                "collateral_impact": sandbox[2]
            }
        }
    })


# -------------------------------
# RUN SERVER
# -------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5001,
        debug=True
    )