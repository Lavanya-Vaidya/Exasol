# AEGIS

## Adaptive Engine for Guarding, Intelligence & Security

> **An interactive threat intelligence and containment platform powered by Machine Learning, Exasol, and relationship intelligence.**

AEGIS is designed to investigate suspicious activity beyond a single event.

Instead of asking only:

> **"Is this transaction risky?"**

AEGIS asks:

> **"What does this activity connect to, how is the threat likely to evolve, and what should we do next?"**

It combines behavioural machine learning, Exasol-powered transaction intelligence, and SHADOWNET relationship analysis into a single interactive investigation console.

---

# Overview

Fraud and cyber threats rarely exist as isolated events.

A transaction may appear harmless on its own while its surrounding infrastructure reveals:

- multiple connected accounts
- shared devices
- repeated transaction behaviour
- abnormal behavioural patterns
- suspicious threat sequences

AEGIS connects these signals into a unified investigation.

```text
                 TRANSACTION
                      │
                      ▼
              ┌───────────────┐
              │    EXASOL     │
              │ Transaction   │
              │ Intelligence │
              └───────┬───────┘
                      │
              ┌───────┴────────┐
              │                │
              ▼                ▼
       ┌─────────────┐   ┌──────────────┐
       │  AEGIS ML   │   │  SHADOWNET   │
       │ Behavioural │   │ Relationship │
       │   Analysis  │   │ Intelligence │
       └──────┬──────┘   └──────┬───────┘
              │                 │
              └────────┬────────┘
                       ▼
               ┌──────────────┐
               │ AEGIS FUSION │
               │    ENGINE    │
               └──────┬───────┘
                      │
                      ▼
              ┌──────────────┐
              │ Risk + Threat│
              │  Prediction  │
              └──────┬───────┘
                      │
                      ▼
              ┌──────────────┐
              │  RESPONSE /  │
              │ CONTAINMENT  │
              └──────────────┘
```

---

# Core Features

## 1. Behavioural Threat Detection

The AEGIS ML engine evaluates behavioural characteristics and provides a threat score.

The platform supports multiple investigation scenarios:

| Scenario | Purpose |
|---|---|
| Normal Behaviour | Routine activity with low behavioural risk |
| Suspicious Behaviour | Potential anomaly requiring investigation |
| Coordinated Fraud | Connected activity across multiple entities |
| Compromised Host | Behaviour associated with endpoint compromise |

The selected scenario automatically maps to an appropriate real transaction from the Exasol transaction feed.

---

## 2. Exasol-Powered Transaction Intelligence

AEGIS retrieves real transaction records from the Exasol `ACTIVITIES` table.

Transactions are ordered by their actual database risk:

```text
BASE_RISK DESC
```

The transaction feed exposes:

```text
Transaction ID
Account ID
Device ID
Base Risk
```

This keeps the investigation grounded in the underlying database instead of relying on fabricated transaction identifiers.

---

## 3. SHADOWNET Relationship Intelligence

SHADOWNET reveals hidden relationships surrounding a selected transaction.

It correlates entities such as:

```text
ACCOUNT
   │
   ├──────── USES ──────── DEVICE
   │
   └──── INITIATED ───── TRANSACTION
```

This allows AEGIS to identify clusters that may not be obvious from an isolated transaction.

The graph is generated from the selected transaction's relationship data.

---

## 4. AEGIS Fusion Engine

AEGIS combines behavioural and relationship intelligence into a single risk assessment.

```text
Behavioural ML Risk      × 60%
SHADOWNET Network Risk   × 40%
                            │
                            ▼
                     AEGIS Final Risk
```

The resulting risk drives the final response:

```text
LOW        → ALLOW
MEDIUM     → REVIEW
HIGH       → MONITOR
CRITICAL   → BLOCK
```

---

## 5. Threat Prediction

AEGIS goes beyond detection.

The platform also predicts what could happen next based on the observed transaction cluster and behavioural signals.

Examples include:

```text
Move funds through linked account cluster
```

```text
Attempt transfer through secondary linked account
```

```text
Repeat transaction from compromised endpoint
```

```text
Probe account for additional suspicious activity
```

This shifts the workflow from reactive detection toward proactive threat intelligence.

---

## 6. Explainable Investigation

AEGIS exposes the signals contributing to its assessment.

Analysts can inspect:

- behavioural risk
- shared infrastructure
- linked-account density
- transaction clustering
- threat sequence
- SHADOWNET relationships
- combined AEGIS risk

The interface also allows individual graph entities to be selected for deeper inspection.

---

## 7. Interactive Containment

Once the threat has been evaluated, AEGIS provides a response recommendation.

The investigation flow becomes:

```text
DETECT
   ↓
INVESTIGATE
   ↓
CORRELATE
   ↓
PREDICT
   ↓
RESPOND
   ↓
CONTAIN
```

The dashboard includes a containment simulation to demonstrate how the platform transitions from intelligence to action.

---

# Investigation Flow

```text
1. Select Threat Scenario
          ↓
2. Automatically Select Risk-Matched Transaction
          ↓
3. Retrieve Transaction from Exasol
          ↓
4. Analyse Behaviour
          ↓
5. Run ML Classification
          ↓
6. Correlate Accounts & Devices
          ↓
7. Build SHADOWNET
          ↓
8. Identify Threat Pattern
          ↓
9. Predict Next Action
          ↓
10. Fuse ML + Network Intelligence
          ↓
11. Generate Final Decision
          ↓
12. Simulate Containment
```

---

# Technology Stack

## Frontend

- React
- Vite
- JavaScript
- CSS
- SVG-based interactive relationship visualization

## Backend

- Python
- Flask
- Flask-CORS
- pyExasol
- python-dotenv

## Machine Learning

- scikit-learn
- pandas
- NumPy
- joblib

## Data Platform

- Exasol

## Intelligence Layer

- AEGIS ML Engine
- SHADOWNET
- Threat Pattern Analysis
- Response Simulation

---

# Architecture

```text
┌───────────────────────────────────────────────────────────┐
│                    AEGIS DASHBOARD                        │
│                                                           │
│  Scenario Control   Transaction Feed   SHADOWNET Graph   │
│        │                  │                   │            │
└────────┼──────────────────┼───────────────────┼───────────┘
         │                  │                   │
         └──────────────────┼───────────────────┘
                            ▼
                     ┌─────────────┐
                     │ Flask API   │
                     │ /analyze    │
                     │ /transactions│
                     │ /health     │
                     └──────┬──────┘
                            │
                ┌───────────┴───────────┐
                │                       │
                ▼                       ▼
        ┌──────────────┐        ┌───────────────┐
        │  ML Engine   │        │    Exasol     │
        │ model.pkl    │        │   SHADOWNET   │
        │ features.pkl │        │ Relationships │
        └──────────────┘        └───────────────┘
```

---

# Project Structure

```text
Exasol/
│
├── aegis-dashboard/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   └── index.css
│   │
│   ├── package.json
│   └── .env
│
├── aegis-ml/
│   ├── app.py
│   ├── test_exasol.py
│   ├── requirements.txt
│   ├── model.pkl
│   ├── features.pkl
│   ├── MalMem2022.csv
│   └── .env
│
├── docs/
│   └── screenshots/
│
├── .gitignore
└── README.md
```

---

# Getting Started

## 1. Clone the Repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd Exasol
```

---

## 2. Backend Setup

```powershell
cd aegis-ml
python -m venv venv
```

Activate the environment on Windows:

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

---

## 3. Configure Exasol

Create:

```text
aegis-ml/.env
```

Add:

```env
EXASOL_DSN=YOUR_EXASOL_DSN
EXASOL_USER=YOUR_EXASOL_USER
EXASOL_PASSWORD=YOUR_EXASOL_PASSWORD
EXASOL_SCHEMA=SHADOWNET

AEGIS_HOST=127.0.0.1
AEGIS_PORT=5001

CORS_ORIGIN=http://localhost:5173
```

The real `.env` file should never be committed to GitHub.

---

## 4. Start the Backend

From `aegis-ml`:

```powershell
python app.py
```

The API runs on:

```text
http://127.0.0.1:5001
```

Health check:

```text
http://127.0.0.1:5001/health
```

Transaction feed:

```text
http://127.0.0.1:5001/transactions
```

---

## 5. Frontend Setup

Open another terminal:

```powershell
cd aegis-dashboard
npm install
```

Create:

```text
aegis-dashboard/.env
```

Add:

```env
VITE_API_URL=http://127.0.0.1:5001
```

Start the dashboard:

```powershell
npm run dev
```

Open the Vite URL shown in the terminal.

---

# API

## `GET /`

Returns service status.

---

## `GET /health`

Returns backend and ML health information.

Example:

```json
{
  "status": "ok",
  "model_loaded": true,
  "feature_count": 12,
  "dataset_rows": 10000,
  "exasol_configured": true
}
```

---

## `GET /transactions`

Returns real transaction records from Exasol.

Example:

```json
{
  "success": true,
  "count": 4,
  "transactions": [
    {
      "tx_id": "T4",
      "account_id": "A4",
      "device_id": "D20",
      "base_risk": 85
    }
  ]
}
```

Transactions are ordered by `BASE_RISK` in descending order.

---

## `POST /analyze`

Runs the complete AEGIS investigation for a selected transaction and threat scenario.

Example request:

```json
{
  "demo": "coordinated",
  "tx_id": "T4"
}
```

The response contains:

- transaction information
- ML risk
- network risk
- SHADOWNET graph
- linked accounts
- linked transactions
- threat sequence
- predicted next action
- recommended response
- combined AEGIS risk
- final decision

---

# Example Investigation

## Compromised Host

```text
Scenario
   ↓
Compromised Host
   ↓
Highest-risk transaction
   ↓
Behavioural ML
   ↓
SHADOWNET
   ↓
AEGIS Fusion
   ↓
Critical Risk
   ↓
BLOCK
```

The scenario controls the behavioural analysis while the transaction itself comes from the actual Exasol transaction feed.

---

# Risk Model

AEGIS separates three different signals.

### Exasol Base Risk

The risk stored against the transaction in the database.

### Behavioural ML Risk

The output generated by the trained machine-learning model.

### SHADOWNET Network Risk

The risk derived from connected accounts, devices, and transaction relationships.

The final AEGIS assessment combines the latter two intelligence layers:

```text
ML Risk × 0.60
+
SHADOWNET Risk × 0.40
=
AEGIS Risk
```

The Exasol Base Risk remains visible as an underlying transaction-level signal.

---

# Security

Sensitive configuration should never be committed.

Ignored files include:

```text
.env
venv/
node_modules/
dist/
__pycache__/
```

For production deployment:

- disable Flask debug mode
- restrict CORS
- use secure database credentials
- rotate exposed credentials
- enable HTTPS
- use a production WSGI server
- protect the Exasol connection
- avoid exposing internal exception details

---

# Future Roadmap

Potential extensions include:

- live event streaming
- real-time Exasol monitoring
- graph-based anomaly detection
- historical threat replay
- transaction amount intelligence
- automated alerting
- analyst case management
- advanced explainable ML
- automated containment integrations
- real-time threat feeds
- persistent investigation history

---

# The Core Idea

AEGIS is built around a simple principle:

> **A threat is rarely visible in a single event. It becomes visible when you connect the events around it.**

AEGIS transforms:

```text
EVENT
```

into:

```text
CONTEXT
```

and transforms:

```text
CONTEXT
```

into:

```text
ACTION
```

The goal is not simply to detect suspicious activity.

The goal is to understand:

- **why it matters**
- **what it connects to**
- **what could happen next**
- **how to respond**

---

# Demo Assets

Screenshots and other visual assets can be stored under:

```text
docs/screenshots/
```

Recommended files:

```text
docs/screenshots/
├── dashboard.png
├── investigation.png
├── shadownet.png
├── risk-analysis.png
└── containment.png
```

---

# Team

Built as an intelligent threat investigation and containment platform combining:

**Machine Learning + Exasol + Relationship Intelligence**

---

# License

Add your preferred license here.
