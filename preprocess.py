import pandas as pd
import numpy as np

# -------------------------------
# Load Dataset
# -------------------------------
df = pd.read_csv("dataset/ddos.csv")

print("Dataset loaded successfully")

# -------------------------------
# Clean Column Names
# -------------------------------
df.columns = df.columns.str.strip()

# -------------------------------
# Convert Label to Binary
# 0 -> Normal (BENIGN)
# 1 -> DDoS
# -------------------------------
df['Label'] = df['Label'].map({
    'BENIGN': 0,
    'DDoS': 1
})

print("Label conversion done")

# -------------------------------
# Keep Only Numeric Columns
# -------------------------------
df = df.select_dtypes(include=['number'])

# -------------------------------
# Handle Infinite and NaN Values
# -------------------------------
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

print("NaN and infinite values removed")

# -------------------------------
# Split Features and Target
# -------------------------------
X = df.drop('Label', axis=1)
y = df['Label']

print("Preprocessing completed successfully")
print("Feature shape:", X.shape)
print("Label shape:", y.shape)
