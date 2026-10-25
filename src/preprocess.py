"""Load NSL-KDD, encode, scale, split 80/20 (stratified) and save everything.

Run from the project root:  python src/preprocess.py
"""
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OrdinalEncoder, StandardScaler

from config import (
    ATTACK_TO_CLASS, CLASS_IDS, DATA_PROCESSED, FEATURE_NAMES, FLAGS,
    MODELS_DIR, PREPROCESSOR_FILE, PROTOCOLS, RANDOM_STATE, RAW_COLUMNS,
    RAW_FILE, SCALE_COLS, TEST_SIZE,
)


def load_raw():
    """Read the headerless file, name the columns, drop the difficulty level."""
    df = pd.read_csv(RAW_FILE, header=None, names=RAW_COLUMNS)
    df["label"] = df["label"].astype(str).str.strip()
    return df.drop(columns=["difficulty"])


def add_targets(df):
    """Add binary (is_attack) and 5-class (attack_class, class_id) targets."""
    df = df.copy()
    df["attack_class"] = df["label"].map(ATTACK_TO_CLASS)
    unknown = df.loc[df["attack_class"].isna(), "label"].unique()
    if len(unknown):
        raise ValueError(f"Attack names missing from ATTACK_TO_CLASS: {unknown}")
    df["class_id"] = df["attack_class"].map(CLASS_IDS)
    df["is_attack"] = (df["label"] != "normal").astype(int)  # 0 Normal, 1 Attack
    return df


def encode(X_raw, service_enc):
    """Label-encode service, one-hot protocol_type and flag (fixed categories)."""
    X = X_raw.copy()
    X["service"] = service_enc.transform(X[["service"]]).ravel()
    for p in PROTOCOLS:
        X[f"protocol_type_{p}"] = (X["protocol_type"] == p).astype(int)
    for f in FLAGS:
        X[f"flag_{f}"] = (X["flag"] == f).astype(int)
    return X.drop(columns=["protocol_type", "flag"])


def scale(X, scaler, fit=False):
    """StandardScaler on the count/size columns only."""
    X = X.copy()
    X[SCALE_COLS] = X[SCALE_COLS].astype(float)
    if fit:
        X[SCALE_COLS] = scaler.fit_transform(X[SCALE_COLS])
    else:
        X[SCALE_COLS] = scaler.transform(X[SCALE_COLS])
    return X


def transform_new(X_raw, artifacts):
    """Apply the saved preprocessing to new raw rows (used later by Flask)."""
    X = encode(X_raw[FEATURE_NAMES], artifacts["service_encoder"])
    X = scale(X, artifacts["scaler"])
    return X[artifacts["feature_columns"]]


def main():
    DATA_PROCESSED.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    df = add_targets(load_raw())
    print(f"Loaded {df.shape[0]} rows, {len(FEATURE_NAMES)} features")
    print(df["attack_class"].value_counts().to_string(), "\n")

    # Stratify on the 5-class label so rare classes (U2R) appear in both splits
    train_df, test_df = train_test_split(
        df, test_size=TEST_SIZE, stratify=df["class_id"],
        random_state=RANDOM_STATE,
    )

    # Fit encoders/scaler on TRAIN only to avoid leakage into the test set
    service_enc = OrdinalEncoder(
        handle_unknown="use_encoded_value", unknown_value=-1
    ).fit(train_df[["service"]])
    scaler = StandardScaler()

    X_train = scale(encode(train_df[FEATURE_NAMES], service_enc), scaler, fit=True)
    X_test = scale(encode(test_df[FEATURE_NAMES], service_enc), scaler)

    target_cols = ["label", "attack_class", "class_id", "is_attack"]
    X_train.reset_index(drop=True).to_csv(DATA_PROCESSED / "X_train.csv", index=False)
    X_test.reset_index(drop=True).to_csv(DATA_PROCESSED / "X_test.csv", index=False)
    train_df[target_cols].reset_index(drop=True).to_csv(DATA_PROCESSED / "y_train.csv", index=False)
    test_df[target_cols].reset_index(drop=True).to_csv(DATA_PROCESSED / "y_test.csv", index=False)
    # Raw (unencoded) test rows, handy for dashboard upload samples later
    test_df[FEATURE_NAMES + ["label"]].reset_index(drop=True).to_csv(
        DATA_PROCESSED / "test_raw.csv", index=False
    )

    joblib.dump(
        {
            "service_encoder": service_enc,
            "scaler": scaler,
            "feature_columns": list(X_train.columns),
        },
        PREPROCESSOR_FILE,
    )

    print(f"X_train: {X_train.shape}   X_test: {X_test.shape}")
    print(f"Train attack share: {train_df['is_attack'].mean():.3f}   "
          f"Test attack share: {test_df['is_attack'].mean():.3f}")
    print(f"Saved CSVs to {DATA_PROCESSED}")
    print(f"Saved preprocessor to {PREPROCESSOR_FILE}")


if __name__ == "__main__":
    main()