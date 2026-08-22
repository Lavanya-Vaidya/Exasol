import pandas as pd
import requests
import joblib

# Load dataset
df = pd.read_csv("MalMem2022.csv")

# Load the exact 55 features expected by the model
feature_names = joblib.load("features.pkl")

# -------- TEST 1: BENIGN --------
sample = df[df["Class"] == "Benign"].iloc[0]

data = {
    feature: float(sample[feature])
    for feature in feature_names
}

response = requests.post(
    "http://127.0.0.1:5001/analyze",
    json=data
)

print("\n===== BENIGN TEST =====")
print("Actual Class:", sample["Class"])
print("Actual Category:", sample["Category"])
print("API Response:", response.json())


# -------- TEST 2: MALWARE --------
sample = df[df["Class"] == "Malware"].iloc[0]

data = {
    feature: float(sample[feature])
    for feature in feature_names
}

response = requests.post(
    "http://127.0.0.1:5001/analyze",
    json=data
)

print("\n===== MALWARE TEST =====")
print("Actual Class:", sample["Class"])
print("Actual Category:", sample["Category"])
print("API Response:", response.json())