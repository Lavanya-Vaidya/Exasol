# AEGIS

## Adaptive Engine for Guarding, Intelligence & Security

**AEGIS is an interactive threat intelligence and containment platform that combines Machine Learning, Exasol, and relationship intelligence to detect, investigate, predict, and respond to suspicious activity.**

---

# Problem

Fraud and cyber threats rarely appear as isolated events.

A single transaction may look normal when evaluated independently. However, the activity around it can reveal a much larger threat:

- multiple accounts sharing the same device
- suspicious transaction clusters
- abnormal behavioural patterns
- repeated activity from compromised infrastructure
- coordinated movement across related entities

Traditional detection systems often stop at:

> **"Is this transaction suspicious?"**

The bigger question is:

> **"What is this transaction connected to, what is likely to happen next, and what should we do about it?"**

AEGIS is built to answer that question.

---

# Solution

AEGIS combines three layers of intelligence:

```text
                 TRANSACTION
                      │
                      ▼
              ┌───────────────┐
              │    EXASOL     │
              │ Transaction   │
              │ Intelligence  │
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
               RISK + PREDICTION
                      │
                      ▼
                  RESPONSE
                      │
                      ▼
                 CONTAINMENT
```

The result is an investigation workflow rather than a simple fraud score.

---

# What AEGIS Does

## 1. Behavioural Threat Detection

The AEGIS ML engine evaluates behavioural characteristics and produces a threat assessment.

The dashboard supports four investigation scenarios:

| Scenario | Purpose |
|---|---|
| **Normal Behaviour** | Routine activity with low behavioural risk |
| **Suspicious Behaviour** | Potential anomaly requiring investigation |
| **Coordinated Fraud** | Connected activity across multiple entities |
| **Compromised Host** | Behaviour associated with endpoint compromise |

The selected scenario automatically maps to an appropriate transaction from the real Exasol transaction feed.

---

## 2. Exasol Transaction Intelligence

AEGIS retrieves transaction data from the Exasol `ACTIVITIES` table.

The transaction feed contains:

```text
Transaction ID
Account ID
Device ID
Base Risk
```

Transactions are ordered by their actual database risk:

```text
BASE_RISK DESC
```

This means the dashboard works with real transaction records and their real database-level risk rather than hard-coded demo transactions.

---

## 3. SHADOWNET Relationship Intelligence

SHADOWNET correlates entities surrounding the selected transaction.

For example:

```text
ACCOUNT A1
    │
    ├──────── USES ──────── DEVICE D19
    │
    └──── INITIATED ───── TRANSACTION T3
                               │
ACCOUNT A2 ───── USES ─────────┘
                               │
ACCOUNT A3 ───── USES ─────────┘
```

This exposes relationships that may not be obvious from a single transaction.

The dashboard turns those relationships into an interactive graph.

---

## 4. Threat Prediction

AEGIS does not stop at detection.

Based on the observed transaction cluster and behavioural intelligence, it predicts a possible next action.

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

This allows the system to move from reactive detection toward proactive threat intelligence.

---

## 5. AEGIS Fusion Engine

AEGIS combines behavioural and relationship intelligence into a final assessment.

```text
Behavioural ML Risk      × 60%
SHADOWNET Network Risk   × 40%
                            │
                            ▼
                     AEGIS Final Risk
```

The resulting risk drives the response:

```text
LOW        → ALLOW
MEDIUM     → REVIEW
HIGH       → MONITOR
CRITICAL   → BLOCK
```

The Exasol `BASE_RISK` remains visible as a separate transaction-level signal.

---

## 6. Explainable Investigation

AEGIS exposes the signals that contribute to the investigation.

Analysts can inspect:

- behavioural risk
- Exasol base risk
- shared infrastructure
- linked-account density
- transaction clustering
- threat sequence
- SHADOWNET relationships
- combined AEGIS risk

Entities in the SHADOWNET graph can also be selected to inspect their relationships.

---

## 7. Interactive Containment

AEGIS connects detection directly to response.

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

The dashboard provides a containment simulation to demonstrate the final response stage.

---

# Why Exasol?

Exasol is used as the **transaction intelligence and relationship analysis layer** of AEGIS.

Instead of treating the ML model as the entire system, AEGIS uses Exasol to hold and query the structured investigation data around an event.

In this project, Exasol is responsible for:

1. Storing transaction activity.
2. Storing account and device relationships.
3. Retrieving real transactions for investigation.
4. Correlating transactions that share infrastructure.
5. Providing threat-pattern information.
6. Providing response simulation data.
7. Feeding structured intelligence into the AEGIS API.

The application connects to Exasol from Python using `pyexasol`.

---

# How Exasol Personal Is Used

AEGIS uses **Exasol Personal** as the database environment for the project.

Exasol Personal is Exasol's free, single-user edition for personal use and development. It provides the same Exasol database engine used for analytics workloads and can run in an individual's own environment or supported cloud infrastructure. citeturn281745search0turn281745search9

For AEGIS, the Exasol Personal instance hosts the project's `SHADOWNET` schema and its investigation data.

### Data stored in Exasol

The AEGIS backend works with tables including:

```text
SHADOWNET
│
├── ACTIVITIES
│   ├── TX_ID
│   ├── ACCOUNT_ID
│   ├── DEVICE_ID
│   └── BASE_RISK
│
├── THREAT_PATTERNS
│   ├── SEQUENCE_TYPE
│   └── THREAT_MULTIPLIER
│
└── SANDBOX_LOGS
    ├── SIMULATED_ACTION
    ├── FRAUD_PREVENTED_EST
    └── COLLATERAL_IMPACT
```

### Application flow

```text
Exasol Personal
      │
      │ SQL queries
      ▼
Python / Flask API
      │
      ├───────────────┐
      ▼               ▼
AEGIS ML          SHADOWNET
      │               │
      └───────┬───────┘
              ▼
        React Dashboard
```

The backend connects to Exasol using environment variables:

```env
EXASOL_DSN=YOUR_EXASOL_DSN
EXASOL_USER=YOUR_EXASOL_USER
EXASOL_PASSWORD=YOUR_EXASOL_PASSWORD
EXASOL_SCHEMA=SHADOWNET
```

This keeps database configuration outside the source code.

Exasol's current documentation describes Exasol Personal as a free, single-user edition and provides quick-start guidance for connecting and loading data. citeturn281745search1turn281745search4

---

# Architecture

```text
┌────────────────────────────────────────────────────────────┐
│                     AEGIS DASHBOARD                        │
│                                                            │
│ Scenario Control │ Transaction Feed │ SHADOWNET │ Action  │
└────────┬─────────┴─────────┬────────┴──────┬────┴─────────┘
         │                   │               │
         └───────────────────┼───────────────┘
                             ▼
                    ┌─────────────────┐
                    │    Flask API    │
                    │                 │
                    │ /health         │
                    │ /transactions   │
                    │ /analyze        │
                    └────────┬────────┘
                             │
                 ┌───────────┴───────────┐
                 │                       │
                 ▼                       ▼
        ┌────────────────┐      ┌─────────────────┐
        │  AEGIS ML      │      │ Exasol Personal │
        │                │      │                 │
        │ model.pkl      │      │ SHADOWNET       │
        │ features.pkl   │      │ ACTIVITIES      │
        └────────────────┘      │ THREAT_PATTERNS │
                                │ SANDBOX_LOGS    │
                                └─────────────────┘
```

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
- SVG-based interactive graph

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

## Database

- Exasol Personal

## Intelligence

- AEGIS ML Engine
- SHADOWNET
- Threat Pattern Analysis
- Response Simulation

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

# Setup

## Prerequisites

You need:

- Python 3
- Node.js and npm
- access to your Exasol Personal database
- the AEGIS repository

For Exasol Personal, follow the current official Exasol Personal deployment/quick-start documentation for your environment. citeturn281745search1turn281745search2

---

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

Never commit the real `.env` file.

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

Check the backend:

```text
http://127.0.0.1:5001/health
```

Check the Exasol transaction feed:

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

Start the frontend:

```powershell
npm run dev
```

Open the Vite URL displayed in the terminal.

---

# API

## `GET /`

Returns service status.

---

## `GET /health`

Returns backend and ML status.

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

Returns real transactions from Exasol.

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

Transactions are returned in descending `BASE_RISK` order.

---

## `POST /analyze`

Runs the complete AEGIS investigation.

Example:

```json
{
  "demo": "coordinated",
  "tx_id": "T4"
}
```

The response contains:

- transaction intelligence
- ML risk
- SHADOWNET network risk
- graph nodes
- graph edges
- linked entities
- threat sequence
- predicted next action
- recommended response
- combined AEGIS risk
- final decision

---

# Example Investigation

## Compromised Host

```text
Compromised Host
        │
        ▼
Highest-risk transaction
        │
        ▼
Behavioural ML
        │
        ▼
SHADOWNET correlation
        │
        ▼
AEGIS Fusion
        │
        ▼
Critical Risk
        │
        ▼
BLOCK
```

The transaction itself is selected from Exasol rather than being hard-coded into the scenario.

---

# Risk Model

AEGIS exposes three different risk concepts:

### Exasol Base Risk

The database-level risk associated with the transaction.

### Behavioural ML Risk

The threat score produced by the trained AEGIS ML model.

### SHADOWNET Network Risk

The risk derived from relationships between accounts, devices, and transactions.

The AEGIS fusion score is:

```text
AEGIS Risk
=
(ML Risk × 0.60)
+
(SHADOWNET Risk × 0.40)
```

The final response is then derived from the combined score.

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
*.pyc
```

Before publishing the repository, verify that no real database password or credential has been committed.

For production deployment:

- disable Flask debug mode
- restrict CORS to the actual frontend origin
- use secure database credentials
- enable HTTPS
- use a production WSGI server
- avoid returning internal exception details
- rotate credentials if they were ever exposed

---

# Future Improvements

Potential extensions include:

- live event streaming
- real-time Exasol monitoring
- graph-based anomaly detection
- transaction amount intelligence
- historical threat replay
- automated alerts
- analyst case management
- advanced ML explainability
- automated containment integrations
- persistent investigation history
- real-time threat feeds

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

**why it matters, what it connects to, what could happen next, and how to respond.**

---

# Demo Screenshots

Store project screenshots under:

```text
docs/screenshots/
```

Recommended filenames:

```text
dashboard.png
investigation.png
shadownet.png
risk-analysis.png
containment.png
```

They can be added to this README later without changing the application.

---

# Team

Built as an intelligent threat investigation and containment platform combining:

**Machine Learning + Exasol + Relationship Intelligence**

---

# License

Add your preferred license here.
