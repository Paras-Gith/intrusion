"""Evaluate the trained models on the held-out test split.

Metrics: Accuracy, Precision, Recall, F1, False Positive Rate, prediction time.
Run from the project root:  python src/evaluate.py
"""
from time import perf_counter

import joblib
import matplotlib

matplotlib.use("Agg")  # no display needed (works in Codespaces / servers)
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import (
    ConfusionMatrixDisplay, accuracy_score, confusion_matrix, f1_score,
    precision_score, recall_score,
)

from config import DATA_PROCESSED, FIGURES_DIR, MODELS_DIR

TARGET = "is_attack"
MODEL_NAMES = ["decision_tree", "logistic_regression", "random_forest", "xgboost"]


def evaluate_model(name, model, X, y):
    start = perf_counter()
    pred = model.predict(X)
    ms_per_flow = (perf_counter() - start) / len(X) * 1000

    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return pred, {
        "model": name,
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred),
        "recall": recall_score(y, pred),
        "f1": f1_score(y, pred),
        "fpr": fp / (fp + tn),            # false alarms among normal traffic
        "predict_ms_per_flow": ms_per_flow,
    }


def save_confusion_matrix(name, y, pred):
    fig, ax = plt.subplots(figsize=(4.5, 4))
    ConfusionMatrixDisplay.from_predictions(
        y, pred, display_labels=["Normal", "Attack"], cmap="Blues", ax=ax
    )
    ax.set_title(f"Confusion matrix: {name}")
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / f"confusion_{name}.png", dpi=150)
    plt.close(fig)


def main():
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    X_test = pd.read_csv(DATA_PROCESSED / "X_test.csv")
    y_test = pd.read_csv(DATA_PROCESSED / "y_test.csv")[TARGET]

    rows = []
    for name in MODEL_NAMES:
        model = joblib.load(MODELS_DIR / f"{name}.joblib")
        pred, metrics = evaluate_model(name, model, X_test, y_test)
        rows.append(metrics)
        save_confusion_matrix(name, y_test, pred)

    table = pd.DataFrame(rows).set_index("model")
    table.to_csv(FIGURES_DIR / "metrics_table.csv")
    print(table.round(4).to_string())
    print(f"\nSaved metrics_table.csv and confusion matrices to {FIGURES_DIR}")


if __name__ == "__main__":
    main()