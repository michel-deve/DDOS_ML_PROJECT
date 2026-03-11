import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import joblib

# Load dataset
df = pd.read_csv("dataset/ddos.csv")

# Clean column names
df.columns = df.columns.str.strip()

# Convert labels
df['Label'] = df['Label'].map({'BENIGN': 0, 'DDoS': 1})

# Keep only numeric columns

df = df.select_dtypes(include=['number'])

# Remove infinity and NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)


# Split features and target
X = df.drop('Label', axis=1)
y = df['Label']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# Test model
y_pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "model/ddos_rf_model.pkl")
# Save feature names
joblib.dump(X.columns.tolist(), "model/feature_names.pkl")

print("Model saved successfully")
