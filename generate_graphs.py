import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report
import os

# Create static directory for images if it doesn't exist
if not os.path.exists('static'):
    os.makedirs('static')

def generate_graphs():
    print("Loading resources...")
    try:
        model = joblib.load("model/ddos_rf_model.pkl")
        feature_names = joblib.load("model/feature_names.pkl")
        
        # Load a sample portion of the dataset for visualization
        print("Loading dataset...")
        # Try finding the dataset, handle case if not found
        if not os.path.exists("dataset/ddos.csv"):
            print("dataset/ddos.csv not found. Cannot generate graphs.")
            return

        df = pd.read_csv("dataset/ddos.csv", nrows=5000) 
        
        # Strip whitespace from column names
        df.columns = df.columns.str.strip()
        
        # Handle infinite values
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        
        # Basic preprocessing to match training
        if 'Label' in df.columns:
            # Force conversion to string then map, to be safe
            df['Label'] = df['Label'].astype(str)
            y = df['Label'].apply(lambda x: 1 if x.lower() in ['ddos', 'attack'] else 0)
            
            # Prepare X
            # Ensure all feature columns exist, fill missing with 0
            for col in feature_names:
                if col not in df.columns:
                    df[col] = 0
            X = df[feature_names]
            
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # 1. Feature Importance
            print("Generating Feature Importance Graph...")
            importances = model.feature_importances_
            indices = np.argsort(importances)[::-1]
            
            plt.figure(figsize=(10, 6))
            plt.title("Feature Importance - Random Forest")
            plt.bar(range(X.shape[1]), importances[indices], align="center")
            plt.xticks(range(X.shape[1]), [feature_names[i] for i in indices], rotation=90)
            plt.tight_layout()
            plt.savefig('static/feature_importance.png')
            print("Saved feature_importance.png")
            
            # 2. Confusion Matrix
            print("Generating Confusion Matrix...")
            y_pred = model.predict(X_test)
            cm = confusion_matrix(y_test, y_pred)
            
            fig, ax = plt.subplots(figsize=(6, 5))
            cax = ax.matshow(cm, cmap='Blues')
            fig.colorbar(cax)
            
            # Add counts to the heatmap cells
            for (i, j), z in np.ndenumerate(cm):
                ax.text(j, i, '{:d}'.format(z), ha='center', va='center', color='black')
                
            plt.title("Confusion Matrix")
            plt.ylabel('Actual Label')
            plt.xlabel('Predicted Label')
            # Set ticks
            ax.set_xticks([0, 1])
            ax.set_yticks([0, 1])
            ax.set_xticklabels(['Normal', 'DDoS'])
            ax.set_yticklabels(['Normal', 'DDoS'])
            
            plt.tight_layout()
            plt.savefig('static/confusion_matrix.png')
            print("Saved confusion_matrix.png")

            # 3. Classification Report (Text)
            print("Generating Classification Report...")
            report = classification_report(y_test, y_pred)
            with open('static/classification_report.txt', 'w') as f:
                f.write(report)
            print("Saved classification_report.txt")
            
        else:
            print("Label column not found in dataset. Skipping confusion matrix.")
            
    except Exception as e:
        print(f"Error generating graphs: {e}")

if __name__ == "__main__":
    generate_graphs()
