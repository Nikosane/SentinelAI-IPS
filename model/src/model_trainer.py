import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle

def train_anomaly_detector(data_path, model_path):
    try:
        data = pd.read_csv(data_path)

        X = data[["size", "protocol"]] 

        model = IsolationForest(random_state=42)
        model.fit(X)

        with open(model_path, "wb") as f:
            pickle.dump(model, f)
        print(f"Anomaly detection model saved to {model_path}")
    except Exception as e:
        print(f"Error training anomaly detector: {e}")

def train_attack_classifier(data_path, model_path):
    try:
        data = pd.read_csv(data_path)

        X = data[["size", "protocol"]]
        y = data["label"] 

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        model = RandomForestClassifier(random_state=42)
        model.fit(X_train, y_train)

        with open(model_path, "wb") as f:
            pickle.dump(model, f)
        print(f"Attack classification model saved to {model_path}")
    except Exception as e:
        print(f"Error training attack classifier: {e}")

if __name__ == "__main__":
    processed_data_path = "../data/processed_data.csv"
    anomaly_model_path = "../models/anomaly_detector.pkl"
    classifier_model_path = "../models/attack_classifier.pkl"

    train_anomaly_detector(processed_data_path, anomaly_model_path)
    train_attack_classifier(processed_data_path, classifier_model_path)
