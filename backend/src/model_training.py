import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier


def preprocess_data(df):

    # Drop duplicate rows
    df = df.drop_duplicates()

    # Convert status column to label (1 = legitimate, 0 = phishing)
    if "status" in df.columns:
        df["label"] = df["status"].apply(lambda x: 1 if str(x).lower() == "legitimate" else 0)
        df = df.drop(columns=["status"])

    return df


def train_model(df):

    print("Preprocessing dataset...")

    df = preprocess_data(df)

    if "label" not in df.columns:
        print("Dataset must contain label column!")
        return

    X = df.drop(columns=["label", "url"], errors="ignore")
    y = df["label"]

    X = X.fillna(0)

    print("\nClass distribution:")
    print(y.value_counts())

    if len(y.unique()) < 2:
        print("Dataset must contain at least 2 classes!")
        return

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    model = XGBClassifier(
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42
    )

    print("Training model...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("\n===== Classification Report =====")
    print(classification_report(y_test, y_pred))

    accuracy = accuracy_score(y_test, y_pred)
    print("Accuracy:", accuracy)

    os.makedirs("models", exist_ok=True)

    joblib.dump(model, "models/phishing_model.pkl")
    joblib.dump(scaler, "models/scaler.pkl")

    print("\nModel saved successfully in models/ folder")

    return model


if __name__ == "__main__":

    dataset_path = "data/phishing_large.csv"

    if not os.path.exists(dataset_path):
        print("Dataset not found:", dataset_path)
        exit()

    df = pd.read_csv(dataset_path)

    print("Dataset loaded successfully")
    print("Total records:", len(df))

    train_model(df)