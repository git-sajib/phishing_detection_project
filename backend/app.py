from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# Load model and scaler
try:
    model = joblib.load("models/phishing_model.pkl")
    scaler = joblib.load("models/scaler.pkl")
    print("Model loaded successfully")
except Exception as e:
    model = None
    scaler = None
    print("Model load error:", e)


def extract_features(url):

    parsed = urlparse(url)

    features = {}

    features["url"] = url
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
    features["ratio_digits_host"] = digits / len(parsed.hostname) if parsed.hostname else 0

    features["punycode"] = 1 if "xn--" in url else 0
    features["port"] = parsed.port if parsed.port else 0
    features["tld_in_path"] = 1 if re.search(r"\.(com|net|org|info|biz)", parsed.path) else 0
    features["tld_in_subdomain"] = 1 if re.search(r"\.(com|net|org)", parsed.hostname or "") else 0
    features["abnormal_subdomain"] = 0
    features["nb_subdomains"] = (parsed.hostname.count(".") - 1) if parsed.hostname else 0

    features["prefix_suffix"] = 1 if "-" in (parsed.hostname or "") else 0
    features["random_domain"] = 0
    features["shortening_service"] = 1 if any(s in url for s in ["bit.ly", "tinyurl"]) else 0
    features["path_extension"] = 1 if re.search(r"\.(php|html|js)$", parsed.path) else 0
    features["nb_redirection"] = url.count("//") - 1
    features["nb_external_redirection"] = 0

    features["length_words_raw"] = len(url.split())
    features["char_repeat"] = max([len(m.group(0)) for m in re.finditer(r"(.)\1*", url)], default=0)

    words = re.split(r"\W+", url)
    features["shortest_words_raw"] = min([len(w) for w in words if w]) if words else 0
    features["shortest_word_host"] = len(parsed.hostname) if parsed.hostname else 0
    features["shortest_word_path"] = len(parsed.path) if parsed.path else 0

    features["longest_words_raw"] = max([len(w) for w in words if w]) if words else 0
    features["longest_word_host"] = len(parsed.hostname) if parsed.hostname else 0
    features["longest_word_path"] = len(parsed.path) if parsed.path else 0

    features["avg_words_raw"] = sum(len(w) for w in words) / len(words) if words else 0
    features["avg_word_host"] = len(parsed.hostname) if parsed.hostname else 0
    features["avg_word_path"] = len(parsed.path) if parsed.path else 0

    features["phish_hints"] = 1 if any(h in url for h in ["login", "verify", "secure"]) else 0
    features["domain_in_brand"] = 0
    features["brand_in_subdomain"] = 0
    features["brand_in_path"] = 0
    features["suspecious_tld"] = 0
    features["statistical_report"] = 0

    features["nb_hyperlinks"] = 0
    features["ratio_intHyperlinks"] = 0
    features["ratio_extHyperlinks"] = 0
    features["ratio_nullHyperlinks"] = 0
    features["nb_extCSS"] = 0
    features["ratio_intRedirection"] = 0
    features["ratio_extRedirection"] = 0
    features["ratio_intErrors"] = 0
    features["ratio_extErrors"] = 0

    features["login_form"] = 1 if "login" in url else 0
    features["external_favicon"] = 0
    features["links_in_tags"] = 0
    features["submit_email"] = 0
    features["ratio_intMedia"] = 0
    features["ratio_extMedia"] = 0

    features["sfh"] = 0
    features["iframe"] = 0
    features["popup_window"] = 0
    features["safe_anchor"] = 0
    features["onmouseover"] = 0
    features["right_clic"] = 0
    features["empty_title"] = 0
    features["domain_in_title"] = 0
    features["domain_with_copyright"] = 0

    features["whois_registered_domain"] = 0
    features["domain_registration_length"] = 0
    features["domain_age"] = 0
    features["web_traffic"] = 0
    features["dns_record"] = 0
    features["google_index"] = 1
    features["page_rank"] = 0

    return features


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

        df_scaled = scaler.transform(df)

        proba = model.predict_proba(df_scaled)[0]
        legit_percentage = round(proba[1] * 100, 2)
        result = "legitimate" if legit_percentage >= 50 else "phishing"

        return jsonify({
            "result": result,
            "legitimate_percentage": legit_percentage
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)