import pyexasol

conn = pyexasol.connect(
    dsn="13.233.255.53:8563",
    user="sys",
    password="exasol",
    websocket_sslopt={
        "cert_reqs": 0
    }
)

conn.execute("OPEN SCHEMA shadownet")

tx_id = "T1"

# Get transaction and shared device information
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

print("\nTRANSACTION ANALYTICS:")
print(transaction)

# Get highest threat pattern
result = conn.execute("""
    SELECT
        SEQUENCE_TYPE,
        THREAT_MULTIPLIER
    FROM THREAT_PATTERNS
    ORDER BY THREAT_MULTIPLIER DESC
    LIMIT 1
""")

threat = result.fetchone()

print("\nTHREAT PATTERN:")
print(threat)

# Get recommended sandbox response
result = conn.execute("""
    SELECT
        SIMULATED_ACTION,
        FRAUD_PREVENTED_EST,
        COLLATERAL_IMPACT
    FROM SANDBOX_LOGS
    LIMIT 1
""")

response = result.fetchone()

print("\nSANDBOX RESPONSE:")
print(response)

conn.close()