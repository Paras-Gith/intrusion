"""Explainability layer: TreeSHAP (global + local), LIME, latency and fidelity tests.

Run from the project root:  python src/explain.py
The functions here are reused later by the Flask app and by rules.py.
"""
from time import perf_counter

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap
from lime.lime_tabular import LimeTabularExplainer

from config import (
    DATA_PROCESSED, FIGURES_DIR, MODELS_DIR, PREPROCESSOR_FILE, RANDOM_STATE,
    SCALE_COLS,
)

CLASS_NAMES = ["Normal", "Attack"]


# ---------- Loading ----------
def load_artifacts():
    """Return (model, preprocessor artifacts, TreeSHAP explainer)."""
    model = joblib.load(MODELS_DIR / "xgboost.joblib")
    prep = joblib.load(PREPROCESSOR_FILE)
    return model, prep, shap.TreeExplainer(model)


def display_data(X, prep):
    """Undo the scaling so plots/alerts show real values (e.g. src_bytes = 491)."""
    D = X.copy()
    D[SCALE_COLS] = prep["scaler"].inverse_transform(X[SCALE_COLS])
    return D


# ---------- TreeSHAP ----------
def shap_values_for(explainer, X):
    """SHAP values for the Attack class, shape (n_rows, n_features)."""
    sv = explainer.shap_values(X)
    if isinstance(sv, list):          # older shap versions return one array per class
        sv = sv[-1]
    return np.asarray(sv)


def base_value(explainer):
    return float(np.ravel(explainer.expected_value)[-1])


def save_waterfall(sv_row, base, disp_row, path):
    exp = shap.Explanation(
        values=sv_row, base_values=base,
        data=disp_row.values, feature_names=list(disp_row.index),
    )
    plt.figure()
    shap.plots.waterfall(exp, max_display=10, show=False)
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close("all")


def explain_flow(model, explainer, prep, x_row, top_k=5, plot_path=None):
    """Explain ONE preprocessed flow (a 1-row DataFrame).

    Returns prediction, attack probability and the top_k features with their
    real (unscaled) value and SHAP contribution (log-odds; + pushes to Attack).
    """
    proba = float(model.predict_proba(x_row)[0, 1])
    sv = shap_values_for(explainer, x_row)[0]
    disp = display_data(x_row, prep).iloc[0]
    order = np.argsort(-np.abs(sv))[:top_k]
    top = [
        {"feature": x_row.columns[i], "value": float(disp.iloc[i]), "shap": float(sv[i])}
        for i in order
    ]
    if plot_path is not None:
        save_waterfall(sv, base_value(explainer), disp, plot_path)
    return {
        "prediction": CLASS_NAMES[int(proba >= 0.5)],
        "attack_probability": proba,
        "top_features": top,
    }


def global_plots(explainer, X_sample):
    """Global explanation: beeswarm summary + mean |SHAP| bar chart."""
    sv = shap_values_for(explainer, X_sample)
    plt.figure()
    shap.summary_plot(sv, X_sample, max_display=15, show=False)
    plt.savefig(FIGURES_DIR / "shap_summary.png", dpi=150, bbox_inches="tight")
    plt.close("all")
    plt.figure()
    shap.summary_plot(sv, X_sample, plot_type="bar", max_display=15, show=False)
    plt.savefig(FIGURES_DIR / "shap_bar.png", dpi=150, bbox_inches="tight")
    plt.close("all")


# ---------- LIME ----------
def build_lime(X_train):
    return LimeTabularExplainer(
        X_train.values, feature_names=list(X_train.columns),
        class_names=CLASS_NAMES, mode="classification",
        discretize_continuous=True, random_state=RANDOM_STATE,
    )


def lime_flow(lime_explainer, model, x_row, num_features=6, num_samples=1000):
    """Return [(rule, weight), ...]; positive weight supports 'Attack'."""
    cols = list(x_row.columns)

    def predict(arr):
        return model.predict_proba(pd.DataFrame(arr, columns=cols))

    exp = lime_explainer.explain_instance(
        x_row.values[0], predict, num_features=num_features, num_samples=num_samples
    )
    return exp.as_list()


# ---------- Evaluation of the explanations ----------
def time_treeshap(explainer, X, n=200):
    """Average TreeSHAP time per single flow, in milliseconds."""
    rows = [X.iloc[[i]] for i in range(min(n, len(X)))]
    explainer.shap_values(rows[0])  # warm-up
    start = perf_counter()
    for r in rows:
        explainer.shap_values(r)
    return (perf_counter() - start) / len(rows) * 1000


def fidelity_test(model, explainer, X_train, y_train, X_test, y_test, n=200, k=3):
    """Mask each attack's top-k attack-pushing features (set to the median of
    normal training traffic). Returns the share of detections that flip to Normal."""
    cols = list(X_test.columns)
    normal_median = X_train[y_train == 0].median().values
    Xa = X_test[y_test == 1]
    Xa = Xa[model.predict(Xa) == 1].head(n)  # correctly detected attacks only
    sv = shap_values_for(explainer, Xa)
    masked = Xa.values.copy()
    for r in range(len(masked)):
        top = np.argsort(-sv[r])[:k]
        masked[r, top] = normal_median[top]
    flipped = model.predict(pd.DataFrame(masked, columns=cols)) == 0
    return float(flipped.mean()), len(Xa)


# ---------- Demo / report figures ----------
def main():
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    model, prep, explainer = load_artifacts()
    X_train = pd.read_csv(DATA_PROCESSED / "X_train.csv")
    y_train = pd.read_csv(DATA_PROCESSED / "y_train.csv")["is_attack"]
    X_test = pd.read_csv(DATA_PROCESSED / "X_test.csv")
    y_test = pd.read_csv(DATA_PROCESSED / "y_test.csv")["is_attack"]

    print("Global explanation (TreeSHAP on 1000 test flows)...")
    global_plots(explainer, X_test.sample(min(1000, len(X_test)), random_state=RANDOM_STATE))

    # One correctly detected attack as the worked example
    idx = X_test.index[(y_test == 1) & (model.predict(X_test) == 1)][0]
    x_row = X_test.iloc[[idx]]
    result = explain_flow(
        model, explainer, prep, x_row, top_k=5,
        plot_path=FIGURES_DIR / "shap_waterfall_example.png",
    )
    print(f"\nExample flow #{idx}: {result['prediction']} "
          f"(attack probability {result['attack_probability']:.3f})")
    for f in result["top_features"]:
        print(f"  {f['feature']:<28} value={f['value']:>10.3f}  SHAP={f['shap']:+.3f}")

    print("\nLIME on the same flow:")
    for rule, weight in lime_flow(build_lime(X_train), model, x_row):
        print(f"  {rule:<45} {weight:+.3f}")

    ms = time_treeshap(explainer, X_test)
    rate, n = fidelity_test(model, explainer, X_train, y_train, X_test, y_test)
    print(f"\nTreeSHAP latency: {ms:.2f} ms per flow (single-row calls)")
    print(f"Fidelity: masking the top 3 SHAP features flipped {rate:.1%} "
          f"of {n} detected attacks to Normal")
    print(f"Figures saved to {FIGURES_DIR}")


if __name__ == "__main__":
    main()