import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib


BASE_DIR = Path(__file__).resolve().parent.parent

DATASET_PATH = BASE_DIR / "data" / ".old.arff"
MODEL_PATH = BASE_DIR / "models" / "phishing_model.pkl"


# Load dataset
from scipy.io import arff

data, meta = arff.loadarff(DATASET_PATH)

df = pd.DataFrame(data)


# Convert byte values
for column in df.columns:
    if df[column].dtype == object:
        df[column] = df[column].apply(
            lambda value: value.decode("utf-8")
            if isinstance(value, bytes)
            else value
        )

        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )


# Remove invalid rows
df = df.dropna()


# Features that can be used for live URL analysis
feature_columns = [
    "URL_Length",
    "having_At_Symbol",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "having_IP_Address",
    "Shortining_Service",
    "HTTPS_token"
]


# Check required columns
missing_columns = [
    column
    for column in feature_columns
    if column not in df.columns
]

if missing_columns:
    print("Missing columns:", missing_columns)
    raise ValueError("Required dataset columns are missing.")


X = df[feature_columns]

y = df["Result"]


# Convert target
# 1  = phishing
# -1 = safe
y = y.map({
    1: 1,
    -1: 0
})


# Remove invalid target rows
valid_rows = y.notna()

X = X[valid_rows]
y = y[valid_rows]


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# Create model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)


# Train
model.fit(X_train, y_train)


# Test
predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)


# Save model
joblib.dump(
    model,
    MODEL_PATH
)


print("\nModel training completed!")

print("Features used:")
for feature in feature_columns:
    print("-", feature)

print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))

print(
    f"Model accuracy: {accuracy * 100:.2f}%"
)

print(
    "Model saved at:",
    MODEL_PATH
)