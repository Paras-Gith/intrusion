"""Natural-language rule extractor: SHAP attributions -> plain-English SOC alerts.

The alert's REASONS come straight from TreeSHAP (top features pushing the
decision). The "pattern hint" is a simple threshold heuristic on the flow's real
values, NOT a model output: the classifier itself is binary (Normal / Attack).

Run a demo from the project root:  python src/rules.py
"""
import pandas as pd

from config import DATA_PROCESSED, FIGURES_DIR
from latency.explain import display_data, explain_flow, load_artifacts

# feature -> (human label, kind); kind controls how the value is written
FEATURES = {
    "duration": ("connection duration (s)", "count"),
    "src_bytes": ("bytes sent by the source", "count"),
    "dst_bytes": ("bytes returned by the destination", "count"),
    "land": ("source and destination address/port identical", "binary"),
    "wrong_fragment": ("wrong fragments", "count"),
    "urgent": ("urgent packets", "count"),
    "hot": ("'hot' indicators (sensitive-system accesses)", "count"),
    "num_failed_logins": ("failed login attempts", "count"),
    "logged_in": ("successful login", "binary"),
    "num_compromised": ("compromised conditions", "count"),
    "root_shell": ("root shell obtained", "binary"),
    "su_attempted": ("'su root' attempted", "binary"),
    "num_root": ("root accesses", "count"),
    "num_file_creations": ("file creations", "count"),
    "num_shells": ("shell prompts", "count"),
    "num_access_files": ("access-control file operations", "count"),
    "num_outbound_cmds": ("outbound commands", "count"),
    "is_host_login": ("host login", "binary"),
    "is_guest_login": ("guest login", "binary"),
    "count": ("connections to the same host in the last 2 s", "count"),
    "srv_count": ("connections to the same service in the last 2 s", "count"),
    "serror_rate": ("SYN error rate (same host)", "rate"),
    "srv_serror_rate": ("SYN error rate (same service)", "rate"),
    "rerror_rate": ("REJ error rate (same host)", "rate"),
    "srv_rerror_rate": ("REJ error rate (same service)", "rate"),
    "same_srv_rate": ("connections to the same service", "rate"),
    "diff_srv_rate": ("connections to different services", "rate"),
    "srv_diff_host_rate": ("connections to different hosts (same service)", "rate"),
    "dst_host_count": ("connections to the destination host", "count"),
    "dst_host_srv_count": ("connections to the destination host's service", "count"),
    "dst_host_same_srv_rate": ("destination host: same-service rate", "rate"),
    "dst_host_diff_srv_rate": ("destination host: different-service rate", "rate"),
    "dst_host_same_src_port_rate": ("destination host: same-source-port rate", "rate"),
    "dst_host_srv_diff_host_rate": ("destination host: different-host rate", "rate"),
    "dst_host_serror_rate": ("destination host: SYN error rate", "rate"),
    "dst_host_srv_serror_rate": ("destination host: service SYN error rate", "rate"),
    "dst_host_rerror_rate": ("destination host: REJ error rate", "rate"),
    "dst_host_srv_rerror_rate": ("destination host: service REJ error rate", "rate"),
}


def describe(feature, value, prep=None):
    """One feature + its real value -> a short readable phrase."""
    value = 0.0 if abs(value) < 1e-6 else value  # clean up -0.000 from unscaling

    if feature.startswith("protocol_type_"):
        proto = feature[len("protocol_type_"):].upper()
        return f"protocol is {proto}" if value >= 0.5 else f"protocol is not {proto}"
    if feature.startswith("flag_"):
        flag = feature[len("flag_"):]
        return f"connection flag is {flag}" if value >= 0.5 else f"connection flag is not {flag}"
    if feature == "service":
        code = int(round(value))
        if prep is not None:
            cats = prep["service_encoder"].categories_[0]
            if 0 <= code < len(cats):
                return f"service is '{cats[code]}'"
            return "service is unseen in training"
        return f"service code = {code}"

    label, kind = FEATURES.get(feature, (feature.replace("_", " "), "count"))
    if kind == "rate":
        return f"{label} = {value * 100:.0f}%"
    if kind == "binary":
        return f"{label}: {'yes' if value >= 0.5 else 'no'}"
    return f"{label} = {value:,.0f}"


def pattern_hint(v):
    """Heuristic attack-family hint from real flow values (dict). May be None."""
    if v.get("serror_rate", 0) >= 0.8 and v.get("count", 0) >= 50:
        return "SYN-flood-like traffic (DoS family)"
    if v.get("protocol_type_icmp", 0) >= 0.5 and v.get("count", 0) >= 200:
        return "ICMP-flood-like traffic (DoS family)"
    if v.get("diff_srv_rate", 0) >= 0.5 or v.get("srv_diff_host_rate", 0) >= 0.5:
        return "scanning-like traffic across services or hosts (Probe family)"
    if v.get("num_failed_logins", 0) >= 1:
        return "repeated failed logins (R2L family)"
    if v.get("root_shell", 0) >= 0.5 or v.get("su_attempted", 0) >= 0.5 or v.get("num_root", 0) > 0:
        return "privilege-escalation signs (U2R family)"
    return None


def build_alert(result, flow_values, prep=None, top_n=3):
    """result = explain_flow() output; flow_values = dict of the flow's real values."""
    p = result["attack_probability"]
    is_attack = result["prediction"] == "Attack"
    sign = 1 if is_attack else -1

    # Reasons = top features pushing TOWARD the predicted class
    reasons = [
        {
            "text": describe(f["feature"], f["value"], prep),
            "shap": f["shap"],
        }
        for f in result["top_features"]
        if f["shap"] * sign > 0
    ][:top_n]

    if is_attack:
        severity = "High" if p >= 0.9 else "Medium" if p >= 0.7 else "Low"
        headline = f"ATTACK DETECTED ({p:.1%} confidence)"
        hint = pattern_hint(flow_values)
    else:
        severity, hint = "None", None
        headline = f"Normal traffic ({1 - p:.1%} confidence)"

    parts = [headline + "."]
    if hint:
        parts.append(f"Pattern hint: {hint}.")
    if reasons:
        joined = "; ".join(r["text"] for r in reasons)
        lead = "Main reasons" if is_attack else "Looks normal because"
        parts.append(f"{lead}: {joined}.")

    return {
        "severity": severity,
        "headline": headline,
        "pattern_hint": hint,
        "reasons": reasons,
        "summary": " ".join(parts),
    }


def alert_for_flow(model, explainer, prep, x_row, plot_path=None, top_n=3):
    """Full path used by the dashboard: explain one flow, then write the alert."""
    result = explain_flow(model, explainer, prep, x_row, top_k=10, plot_path=plot_path)
    values = display_data(x_row, prep).iloc[0].to_dict()
    alert = build_alert(result, values, prep, top_n)
    alert["attack_probability"] = result["attack_probability"]
    alert["prediction"] = result["prediction"]
    return alert


# ---------- Demo ----------
def main():
    model, prep, explainer = load_artifacts()
    X_test = pd.read_csv(DATA_PROCESSED / "X_test.csv")
    y_test = pd.read_csv(DATA_PROCESSED / "y_test.csv")
    pred = model.predict(X_test)

    print("Example alerts (one correctly classified flow per class)\n")
    for cls in ["normal", "dos", "probe", "r2l", "u2r"]:
        hits = y_test.index[(y_test["attack_class"] == cls) & (pred == (cls != "normal"))]
        if len(hits) == 0:
            print(f"[{cls.upper()}] no correctly classified example in the test split\n")
            continue
        i = hits[0]
        alert = alert_for_flow(model, explainer, prep, X_test.iloc[[i]])
        print(f"[true label: {y_test.loc[i, 'label']} / {cls.upper()}]")
        print(f"  {alert['summary']}\n")


if __name__ == "__main__":
    main()