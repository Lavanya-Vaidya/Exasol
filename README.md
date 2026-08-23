# AEGIS

## Adaptive Engine for Guarding, Intelligence & Security

AEGIS is an interactive threat investigation and containment platform combining **Machine Learning, Exasol, and SHADOWNET relationship intelligence**.

## Problem

A suspicious transaction may look harmless on its own, while related accounts, devices, and behavioural patterns reveal a larger threat.

Traditional detection asks:

> **Is this transaction suspicious?**

AEGIS asks:

> **What is it connected to, what happens next, and what should we do?**

## Solution

AEGIS combines transaction intelligence, behavioural ML, and SHADOWNET network intelligence to move from detection to investigation, prediction, and response.

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
- **Exasol Intelligence** — retrieves and ranks transaction data from Exasol.
- **SHADOWNET** — connects accounts, devices, and transactions.
- **Threat Prediction** — estimates the next likely action.
- **Risk Fusion** — combines ML and network intelligence.
- **Explainability** — shows the signals behind a decision.
- **Containment Simulation** — recommends a response.

### Investigation Scenarios

| Scenario | Purpose |
|---|---|
| Normal Behaviour | Low-risk routine activity |
| Suspicious Behaviour | Anomalous activity |
| Coordinated Fraud | Connected fraud behaviour |
| Compromised Host | Possible endpoint compromise |

## How Exasol Personal Is Used

Exasol Personal is the data and analytics layer of AEGIS.

It stores the `SHADOWNET` schema and provides the structured data used during investigation.

### `ACTIVITIES`

```text
TX_ID
ACCOUNT_ID
DEVICE_ID
BASE_RISK
```

### `THREAT_PATTERNS`

```text
SEQUENCE_TYPE
THREAT_MULTIPLIER
```

### `SANDBOX_LOGS`

```text
SIMULATED_ACTION
FRAUD_PREVENTED_EST
COLLATERAL_IMPACT
```

Transactions are ranked by:

```text
BASE_RISK DESC
```

The backend connects to Exasol using `pyexasol`.

```text
Exasol Personal
      ↓
Python / Flask
      ↓
AEGIS ML + SHADOWNET
      ↓
React Dashboard
```

## Risk Model

AEGIS uses three signals:

```text
Exasol Base Risk
        +
Behavioural ML Risk
        +
SHADOWNET Network Risk
```

Final score:

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
git clone https://github.com/Lavanya-Vaidya/Exasol.git
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

Start the backend:

```powershell
python app.py
```

### 3. Frontend

Open a new terminal:

```powershell
cd aegis-dashboard
npm install
```

Create `aegis-dashboard/.env`:

```env
VITE_API_URL=http://127.0.0.1:5001
```

Start the frontend:

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

Returns Exasol transactions ordered by `BASE_RISK`.

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

Returns transaction intelligence, ML risk, SHADOWNET data, prediction, response recommendation, and final AEGIS risk.

## Demo

[Watch the AEGIS Demo](https://drive.google.com/file/d/1WpnuUuCr9cKryRO1KakOo7IsnMcWY2WG/view?usp=sharing)

## Pitch Deck

The pitch deck will be added to the repository before final submission.

Expected location:

```text
docs/AEGIS_Pitch_Deck.pdf
```

## Project Structure

```text
Exasol/
├── aegis-dashboard/
│   ├── public/
│   ├── src/
│   │   ├── assets/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── index.css
│   │   └── main.jsx
│   ├── .gitignore
│   ├── .oxlintrc.json
│   ├── README.md
│   ├── index.html
│   ├── package.json
│   ├── package-lock.json
│   └── vite.config.js
│
├── aegis-ml/
│   ├── MalMem2022.csv
│   ├── Output1.csv
│   ├── Output2.csv
│   ├── Output3.csv
│   ├── app.py
│   ├── check_classes.py
│   ├── check_labels.py
│   ├── features.pkl
│   ├── inspect_data.py
│   ├── inspect_full_data.py
│   ├── model.pkl
│   ├── requirements.txt
│   ├── test_api.py
│   ├── test_exasol.py
│   └── train.py
│
├── .gitignore
├── README.md
└── pitchdeck.pptx
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

Keep Exasol credentials in environment variables.
