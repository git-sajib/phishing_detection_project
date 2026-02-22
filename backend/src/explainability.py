import shap
import matplotlib.pyplot as plt

def explain_model(model, X):

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X)

    shap.summary_plot(shap_values, X)