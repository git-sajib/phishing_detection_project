from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import shap
import numpy as np
from src.feature_extraction import extract_url_features

app = Flask(__name__)
CORS(app)

# Load model and scaler
try:
    model = joblib.load("models/phishing_model.pkl")
    scaler = joblib.load("models/scaler.pkl")
except Exception as e:
    model = None
    scaler = None
    print("Model load error:", e)


@app.route("/")
def home():
    return jsonify({"message": "Phishing Detection API is running"})


@app.route("/predict", methods=["POST"])
def predict():
    if model is None or scaler is None:
        return jsonify({"error": "Model not loaded"}), 500

    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "URL required"}), 400

    url = data.get("url")

    try:
        features = extract_url_features(url)
        df = pd.DataFrame([features])

        df_scaled = scaler.transform(df)

        proba = model.predict_proba(df_scaled)[0]

        try:
            legit_index = list(model.classes_).index(1)
        except:
            legit_index = 1

        # convert numpy float to python float
        legitimate_percentage = float(round(proba[legit_index] * 100, 2))

        result = "Legitimate" if legitimate_percentage >= 50 else "Phishing"

        # SHAP explainability (optional)
        shap_data = None
        try:
            explainer = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(df_scaled)

            feature_names = list(features.keys())

            # convert numpy values to python floats
            shap_importance = [float(x) for x in np.abs(shap_values).mean(axis=0)]

            shap_data = {
                "features": feature_names,
                "importance": shap_importance
            }
        except:
            shap_data = None

        return jsonify({
            "result": result,
            "legitimate_percentage": legitimate_percentage,
            "shap": shap_data
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)