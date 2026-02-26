from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
import os

app = Flask(__name__)
CORS(app)

# ---------------------------
# Load model and scaler
# ---------------------------
try:
    model = joblib.load("models/phishing_model.pkl")
    scaler = joblib.load("models/scaler.pkl")
    print("Model loaded successfully")
except Exception as e:
    model = None
    scaler = None
    print("Model load error:", e)


# ---------------------------
# Feature Extraction
# ---------------------------
def extract_features(url):
    parsed = urlparse(url)
    features = {}

    # IMPORTANT: DO NOT include "url" column (caused your error)
    features["length_url"] = len(url)
    features["length_hostname"] = len(parsed.hostname) if parsed.hostname else 0
    features["ip"] = 1 if re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url) else 0

    features["nb_dots"] = url.count(".")
    features["nb_hyphens"] = url.count("-")
    features["nb_at"] = url.count("@")
    features["nb_qm"] = url.count("?")
    features["nb_and"] = url.count("&")
    features["nb_or"] = 0
    features["nb_eq"] = url.count("=")
    features["nb_underscore"] = url.count("_")
    features["nb_tilde"] = url.count("~")
    features["nb_percent"] = url.count("%")
    features["nb_slash"] = url.count("/")
    features["nb_star"] = url.count("*")
    features["nb_colon"] = url.count(":")
    features["nb_comma"] = url.count(",")
    features["nb_semicolumn"] = url.count(";")
    features["nb_dollar"] = url.count("$")
    features["nb_space"] = url.count(" ")
    features["nb_www"] = 1 if "www." in url else 0
    features["nb_com"] = 1 if ".com" in url else 0
    features["nb_dslash"] = 1 if "//" in url else 0

    features["http_in_path"] = 1 if "http" in url else 0
    features["https_token"] = 1 if "https" in url else 0

    digits = sum(c.isdigit() for c in url)
    features["ratio_digits_url"] = digits / len(url) if len(url) > 0 else 0
    features["ratio_digits_host"] = (
        digits / len(parsed.hostname) if parsed.hostname else 0
    )

    features["punycode"] = 1 if "xn--" in url else 0
    features["port"] = parsed.port if parsed.port else 0
    features["tld_in_path"] = 1 if re.search(r"\.(com|net|org|info|biz)", parsed.path) else 0
    features["tld_in_subdomain"] = 1 if re.search(r"\.(com|net|org)", parsed.hostname or "") else 0
    features["abnormal_subdomain"] = 0
    features["nb_subdomains"] = (
        parsed.hostname.count(".") - 1 if parsed.hostname else 0
    )

    features["prefix_suffix"] = 1 if "-" in (parsed.hostname or "") else 0
    features["random_domain"] = 0
    features["shortening_service"] = 1 if any(s in url for s in ["bit.ly", "tinyurl"]) else 0
    features["path_extension"] = 1 if re.search(r"\.(php|html|js)$", parsed.path) else 0
    features["nb_redirection"] = url.count("//") - 1
    features["nb_external_redirection"] = 0

    features["length_words_raw"] = len(url.split())
    features["char_repeat"] = max(
        [len(m.group(0)) for m in re.finditer(r"(.)\1*", url)],
        default=0
    )

    words = re.split(r"\W+", url)
    features["shortest_words_raw"] = min([len(w) for w in words if w]) if words else 0
    features["shortest_word_host"] = len(parsed.hostname) if parsed.hostname else 0
    features["shortest_word_path"] = len(parsed.path) if parsed.path else 0

    features["longest_words_raw"] = max([len(w) for w in words if w]) if words else 0
    features["longest_word_host"] = len(parsed.hostname) if parsed.hostname else 0
    features["longest_word_path"] = len(parsed.path) if parsed.path else 0

    features["avg_words_raw"] = (
        sum(len(w) for w in words) / len(words) if words else 0
    )
    features["avg_word_host"] = len(parsed.hostname) if parsed.hostname else 0
    features["avg_word_path"] = len(parsed.path) if parsed.path else 0

    features["phish_hints"] = 1 if any(h in url for h in ["login", "verify", "secure"]) else 0

    # Remaining static features
    static_features = [
        "domain_in_brand","brand_in_subdomain","brand_in_path","suspecious_tld",
        "statistical_report","nb_hyperlinks","ratio_intHyperlinks",
        "ratio_extHyperlinks","ratio_nullHyperlinks","nb_extCSS",
        "ratio_intRedirection","ratio_extRedirection","ratio_intErrors",
        "ratio_extErrors","login_form","external_favicon","links_in_tags",
        "submit_email","ratio_intMedia","ratio_extMedia","sfh","iframe",
        "popup_window","safe_anchor","onmouseover","right_clic",
        "empty_title","domain_in_title","domain_with_copyright",
        "whois_registered_domain","domain_registration_length",
        "domain_age","web_traffic","dns_record","google_index","page_rank"
    ]

    for f in static_features:
        features[f] = 0

    return features


# ---------------------------
# Routes
# ---------------------------
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

    url = data["url"]

    try:
        features = extract_features(url)
        df = pd.DataFrame([features])

        # Ensure same column order as training
        df = df[scaler.feature_names_in_]

        df_scaled = scaler.transform(df)

        proba = model.predict_proba(df_scaled)[0]
        legit_percentage = round(float(proba[1]) * 100, 2)

        result = "legitimate" if legit_percentage >= 50 else "phishing"

        return jsonify({
            "result": result,
            "legitimate_percentage": legit_percentage
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)