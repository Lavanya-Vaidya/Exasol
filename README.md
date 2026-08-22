# AEGIS

## Adaptive Engine for Guarding, Intelligence & Security

**AEGIS is an interactive threat investigation and containment platform combining Machine Learning, Exasol, and SHADOWNET relationship intelligence.**

## Problem

A suspicious transaction may look harmless on its own, while related accounts, devices, and behavioural patterns reveal a larger threat.

Traditional detection asks:

> **Is this transaction suspicious?**

AEGIS asks:

> **What is it connected to, what happens next, and what should we do?**

## Solution

AEGIS combines:

```text
Transaction
    ↓
Exasol Intelligence
    ↓
┌───────────────┬───────────────┐
│   AEGIS ML    │   SHADOWNET   │
│ Behaviour Risk│ Network Risk  │
└───────┬───────┴───────┬───────┘
        └───────┬───────┘
                ↓
         AEGIS Fusion
                ↓
       Risk + Prediction
                ↓
           Response
```

## Key Features

- **Behavioural ML** — detects suspicious behavioural patterns.
- **Exasol Intelligence** — retrieves and ranks real transactions from `ACTIVITIES`.
- **SHADOWNET** — connects accounts, devices, and transactions.
- **Threat Prediction** — estimates the next likely action.
- **Risk Fusion** — combines ML and network intelligence.
- **Explainability** — shows the signals behind a decision.
- **Containment Simulation** — moves from detection to response.

### Investigation Scenarios

| Scenario | Purpose |
|---|---|
| Normal Behaviour | Low-risk routine activity |
| Suspicious Behaviour | Anomalous activity |
| Coordinated Fraud | Connected fraud behaviour |
| Compromised Host | Possible endpoint compromise |

## How Exasol Personal Is Used

Exasol Personal is the data and analytics layer of AEGIS.

It stores the `SHADOWNET` schema and provides the structured data used during investigation:

```text
ACTIVITIES
├── TX_ID
├── ACCOUNT_ID
├── DEVICE_ID
└── BASE_RISK

THREAT_PATTERNS
├── SEQUENCE_TYPE
└── THREAT_MULTIPLIER

SANDBOX_LOGS
├── SIMULATED_ACTION
├── FRAUD_PREVENTED_EST
└── COLLATERAL_IMPACT
```

The backend uses `pyexasol` to query Exasol and sends the results to the React dashboard.

```text
Exasol Personal
      ↓
Python / Flask
      ↓
AEGIS ML + SHADOWNET
      ↓
React Dashboard
```

Transactions are ordered by:

```text
BASE_RISK DESC
```

The application reads Exasol credentials from `.env`.

## Risk Model

AEGIS keeps three signals visible:

```text
Exasol Base Risk
        +
Behavioural ML Risk
        +
SHADOWNET Network Risk
```

The final AEGIS score is:

```text
ML Risk × 60%
+
SHADOWNET Risk × 40%
=
AEGIS Risk
```

Decision levels:

```text
LOW        → ALLOW
MEDIUM     → REVIEW
HIGH       → MONITOR
CRITICAL   → BLOCK
```

## Architecture

```text
┌──────────────────────────────────────┐
│          AEGIS React Dashboard       │
│ Scenario │ Transactions │ SHADOWNET │
└───────────────────┬──────────────────┘
                    ↓
             ┌─────────────┐
             │  Flask API  │
             └──────┬──────┘
                    ↓
        ┌───────────┴───────────┐
        ↓                       ↓
   AEGIS ML               Exasol Personal
   model.pkl              SHADOWNET schema
        └───────────┬───────────┘
                    ↓
             Final Decision
```

## Setup

### 1. Clone

```bash
git clone <YOUR_REPOSITORY_URL>
cd Exasol
```

### 2. Backend

```powershell
cd aegis-ml
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Create `aegis-ml/.env`:

```env
EXASOL_DSN=YOUR_EXASOL_DSN
EXASOL_USER=YOUR_EXASOL_USER
EXASOL_PASSWORD=YOUR_EXASOL_PASSWORD
EXASOL_SCHEMA=SHADOWNET

AEGIS_HOST=127.0.0.1
AEGIS_PORT=5001
CORS_ORIGIN=http://localhost:5173
```

Start:

```powershell
python app.py
```

### 3. Frontend

```powershell
cd aegis-dashboard
npm install
```

Create `aegis-dashboard/.env`:

```env
VITE_API_URL=http://127.0.0.1:5001
```

Start:

```powershell
npm run dev
```

## API

### Health

```text
GET /health
```

### Transactions

```text
GET /transactions
```

Returns real Exasol transactions ordered by `BASE_RISK`.

### Analysis

```text
POST /analyze
```

Example:

```json
{
  "demo": "coordinated",
  "tx_id": "T4"
}
```

Returns transaction intelligence, ML risk, SHADOWNET graph data, prediction, response recommendation, and final AEGIS risk.

## Project Structure

```text
Exasol/
├── aegis-dashboard/
│   └── src/
│       ├── App.jsx
│       ├── App.css
│       └── index.css
│
├── aegis-ml/
│   ├── app.py
│   ├── test_exasol.py
│   ├── requirements.txt
│   ├── model.pkl
│   ├── features.pkl
│   └── MalMem2022.csv
│
├── docs/
│   └── screenshots/
│
├── .gitignore
└── README.md
```

## Security

Do not commit:

```text
.env
venv/
node_modules/
dist/
__pycache__/
```

Keep Exasol credentials only in environment variables.

## Future

- real-time event streaming
- advanced graph anomaly detection
- historical threat replay
- automated alerts
- automated containment
- persistent analyst investigations

## Core Idea

> **A threat is rarely visible in a single event. It becomes visible when you connect the events around it.**

AEGIS turns:

```text
EVENT → CONTEXT → PREDICTION → ACTION
```

## Team

Built using:

**Machine Learning + Exasol + SHADOWNET**
