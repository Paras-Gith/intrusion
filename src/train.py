"""Train the classifiers on the preprocessed NSL-KDD training split.

Target: is_attack (0 = Normal, 1 = Attack).
Run from the project root:  python src/train.py
"""
import time

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

from config import DATA_PROCESSED, MODELS_DIR, RANDOM_STATE

TARGET = "is_attack"


def get_models():
    """Decision Tree = baseline, Logistic Regression = linear reference (Table II)."""
    return {
        "decision_tree": DecisionTreeClassifier(random_state=RANDOM_STATE),
        "logistic_regression": LogisticRegression(max_iter=2000),
        "random_forest": RandomForestClassifier(
            n_estimators=100, n_jobs=-1, random_state=RANDOM_STATE
        ),
        "xgboost": XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            eval_metric="logloss", random_state=RANDOM_STATE, n_jobs=-1,
        ),
    }


def main():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    X_train = pd.read_csv(DATA_PROCESSED / "X_train.csv")
    y_train = pd.read_csv(DATA_PROCESSED / "y_train.csv")[TARGET]
    print(f"Training on {X_train.shape[0]} rows, {X_train.shape[1]} features\n")

    for name, model in get_models().items():
        start = time.time()
        model.fit(X_train, y_train)
        path = MODELS_DIR / f"{name}.joblib"
        joblib.dump(model, path)
        print(f"{name:<20} trained in {time.time() - start:5.1f}s -> {path.name}")


if __name__ == "__main__":
    main()