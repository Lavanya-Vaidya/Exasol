import os
import re

import pyexasol


# ============================================================
# CONFIGURATION
# ============================================================

EXASOL_DSN = os.getenv("EXASOL_DSN", "13.233.255.53:8563")
EXASOL_USER = os.getenv("EXASOL_USER")
EXASOL_PASSWORD = os.getenv("EXASOL_PASSWORD")
EXASOL_SCHEMA = os.getenv("EXASOL_SCHEMA", "SHADOWNET")

TX_ID = "T4"

TX_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


# ============================================================
# VALIDATION
# ============================================================

if not TX_ID_PATTERN.fullmatch(TX_ID):
    raise ValueError(f"Invalid transaction ID: {TX_ID}")


if not EXASOL_USER or not EXASOL_PASSWORD:
    raise RuntimeError(
        "Missing Exasol credentials.\n\n"
        "Set them in PowerShell before running this script:\n"
        '$env:EXASOL_USER="sys"\n'
        '$env:EXASOL_PASSWORD="your-password"'
    )


# ============================================================
# CONNECTION
# ============================================================

print("\nConnecting to Exasol...")

conn = pyexasol.connect(
    dsn=EXASOL_DSN,
    user=EXASOL_USER,
    password=EXASOL_PASSWORD,
    websocket_sslopt={
        "cert_reqs": 0
    }
)

print("✓ Connected")


try:
    conn.execute(
        f"OPEN SCHEMA {EXASOL_SCHEMA}"
    )

    print(f"✓ Schema: {EXASOL_SCHEMA}")

    # ========================================================
    # TRANSACTION + SHARED DEVICE
    # ========================================================

    result = conn.execute(
        """
        SELECT
            A.TX_ID,
            A.DEVICE_ID,
            A.BASE_RISK,
            COUNT(DISTINCT B.ACCOUNT_ID) AS LINKED_ACCOUNTS
        FROM ACTIVITIES A
        JOIN ACTIVITIES B
            ON A.DEVICE_ID = B.DEVICE_ID
        WHERE A.TX_ID = '{}'
        GROUP BY
            A.TX_ID,
            A.DEVICE_ID,
            A.BASE_RISK
        """.format(
            TX_ID.replace("'", "''")
        )
    )

    transaction = result.fetchone()

    print("\n" + "=" * 60)
    print("TRANSACTION ANALYTICS")
    print("=" * 60)

    if transaction:
        tx_id, device_id, base_risk, linked_accounts = transaction

        print(f"Transaction ID : {tx_id}")
        print(f"Device ID      : {device_id}")
        print(f"Base Risk      : {base_risk}")
        print(f"Linked Accounts: {linked_accounts}")

    else:
        print(f"No transaction found for {TX_ID}")

    # ========================================================
    # THREAT PATTERN
    # ========================================================

    result = conn.execute(
        """
        SELECT
            SEQUENCE_TYPE,
            THREAT_MULTIPLIER
        FROM THREAT_PATTERNS
        ORDER BY THREAT_MULTIPLIER DESC
        LIMIT 1
        """
    )

    threat = result.fetchone()

    print("\n" + "=" * 60)
    print("THREAT PATTERN")
    print("=" * 60)

    if threat:
        sequence_type, threat_multiplier = threat

        print(f"Sequence Type   : {sequence_type}")
        print(f"Threat Multiplier: {threat_multiplier}")

    else:
        print("No threat pattern found.")

    # ========================================================
    # SANDBOX RESPONSE
    # ========================================================

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

    response = result.fetchone()

    print("\n" + "=" * 60)
    print("SANDBOX RESPONSE")
    print("=" * 60)

    if response:
        action, fraud_prevented, collateral = response

        print(f"Action              : {action}")
        print(f"Fraud Prevented Est.: ₹{fraud_prevented}")
        print(f"Collateral Impact   : {collateral}")

    else:
        print("No sandbox response found.")

finally:
    conn.close()
    print("\n✓ Connection closed")