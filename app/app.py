"""Flask SOC dashboard: upload flows -> predict -> explain -> plain-English alerts.

Run from the project root:  python app/app.py   (then open http://127.0.0.1:5000)
"""
import sys
import threading
import uuid
from collections import Counter
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

import numpy as np
import pandas as pd
from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_from_directory, url_for)

import database as db
from config import FEATURE_NAMES, FIGURES_DIR
from explain import load_artifacts
from preprocess import transform_new
from rules import alert_for_flow
MAX_ROWS = 300      # flows analysed per upload
MAX_PLOTS = 10      # waterfall plots drawn per upload (highest-confidence attacks)
PLOTS_DIR = BASE_DIR / "app" / "static" / "plots"
GLOBAL_FIGURES = ["shap_summary.png", "shap_bar.png"]

app = Flask(__name__)
app.secret_key = "change-me-for-real-deployments"
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload cap

model, prep, explainer = load_artifacts()
db.init_db()
PLOTS_DIR.mkdir(parents=True, exist_ok=True)
_lock = threading.Lock()  # matplotlib/SHAP plotting is not thread-safe


@app.route("/")
def index():
    return render_template("index.html", runs=db.list_runs()[:5])


@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files.get("file")
    if not file or not file.filename.lower().endswith(".csv"):
        flash("Please choose a .csv file.", "danger")
        return redirect(url_for("index"))

    try:
        raw = pd.read_csv(file)
    except Exception:
        flash("Could not read that file as a CSV.", "danger")
        return redirect(url_for("index"))

    missing = [c for c in FEATURE_NAMES if c not in raw.columns]
    if missing:
        shown = ", ".join(missing[:5]) + (" ..." if len(missing) > 5 else "")
        flash(f"Missing columns: {shown}. The CSV needs a header row with the "
              f"41 NSL-KDD feature names.", "danger")
        return redirect(url_for("index"))
    if raw.empty:
        flash("The CSV has no rows.", "danger")
        return redirect(url_for("index"))

    raw = raw.head(MAX_ROWS).reset_index(drop=True)
    try:
        X = transform_new(raw, prep)
    except Exception:
        flash("Some columns contain values the model cannot read "
              "(check for text in numeric columns).", "danger")
        return redirect(url_for("index"))

    with _lock:
        proba = model.predict_proba(X)[:, 1]
        top_attacks = [i for i in np.argsort(-proba)[:MAX_PLOTS] if proba[i] >= 0.5]
        token = uuid.uuid4().hex[:8]
        rows = []
        for i in range(len(X)):
            plot_rel = plot_path = None
            if i in top_attacks:
                plot_rel = f"plots/{token}_row{i + 1}.png"
                plot_path = BASE_DIR / "app" / "static" / plot_rel
            alert = alert_for_flow(model, explainer, prep, X.iloc[[i]], plot_path=plot_path)
            rows.append({
                "row_num": i + 1,
                "true_label": str(raw["label"].iloc[i]) if "label" in raw.columns else None,
                "prediction": alert["prediction"],
                "probability": alert["attack_probability"],
                "severity": alert["severity"],
                "summary": alert["summary"],
                "plot_file": plot_rel,
            })

    run_id = db.save_run(file.filename, rows)
    return redirect(url_for("results", run_id=run_id))


@app.route("/results/<int:run_id>")
def results(run_id):
    run = db.get_run(run_id)
    if run is None:
        abort(404)
    only_attacks = request.args.get("only") == "attacks"
    dets = db.get_detections(run_id, only_attacks=only_attacks)
    all_dets = dets if not only_attacks else db.get_detections(run_id)
    sev = Counter(d["severity"] for d in all_dets)
    return render_template("results.html", run=run, dets=dets, sev=sev,
                           only_attacks=only_attacks, max_plots=MAX_PLOTS)


@app.route("/history")
def history():
    return render_template("history.html", runs=db.list_runs())


@app.route("/global")
def global_view():
    available = [f for f in GLOBAL_FIGURES if (FIGURES_DIR / f).exists()]
    return render_template("global.html", available=available)


@app.route("/figures/<name>")
def figures(name):
    if name not in GLOBAL_FIGURES:
        abort(404)
    return send_from_directory(FIGURES_DIR, name)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)