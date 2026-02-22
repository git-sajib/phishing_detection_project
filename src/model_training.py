import joblib
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

def train_model(df):

    X = df.drop("label", axis=1)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    model = XGBClassifier(use_label_encoder=False, eval_metric="logloss")

    param_grid = {
        "n_estimators": [200, 500],
        "max_depth": [4, 6],
        "learning_rate": [0.01, 0.1]
    }

    grid = GridSearchCV(model, param_grid, cv=3, scoring="f1")
    grid.fit(X_train, y_train)

    best_model = grid.best_estimator_

    y_pred = best_model.predict(X_test)

    print("Classification Report:")
    print(classification_report(y_test, y_pred))

    accuracy = accuracy_score(y_test, y_pred)
    print("Accuracy:", accuracy)

    joblib.dump(best_model, "models/phishing_model.pkl")
    joblib.dump(scaler, "models/scaler.pkl")

    return best_model