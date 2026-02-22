import shap
import matplotlib.pyplot as plt


def explain_model(model, X):

    # TreeExplainer for tree-based models (XGBoost)
    explainer = shap.TreeExplainer(model)

    # Calculate SHAP values
    shap_values = explainer.shap_values(X)

    # Summary plot (global feature importance)
    shap.summary_plot(shap_values, X)

    # Optional: return shap values (useful for API)
    return shap_values


def save_shap_plot(model, X, path="models/shap_summary.png"):

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X)

    shap.summary_plot(shap_values, X, show=False)
    plt.savefig(path)
    plt.close()

    return path