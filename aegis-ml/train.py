import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# Load dataset
df = pd.read_csv("MalMem2022.csv")

# Convert labels:
# Benign = 0
# Malware = 1
df["label"] = df["Class"].map({
    "Benign": 0,
    "Malware": 1
})

# Remove non-numeric / metadata columns
X = df.drop(columns=[
    "Class",
    "Category",
    "Filename",
    "label"
])

# Target
y = df["label"]

print("Features shape:", X.shape)
print("Target distribution:")
print(y.value_counts())

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", X_train.shape)
print("Testing samples:", X_test.shape)

# Create model
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1
)

# Train
print("\nTraining Random Forest...")
model.fit(X_train, y_train)

# Predict
y_pred = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, y_pred)

print("\nModel Accuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "model.pkl")

# Save feature names
joblib.dump(X.columns.tolist(), "features.pkl")

print("\nModel saved as model.pkl")
print("Feature names saved as features.pkl")