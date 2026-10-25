"""Cut small CSVs from the raw test split for trying the dashboard upload.

Run from the project root:  python src/make_samples.py
"""
import pandas as pd

from config import DATA_PROCESSED, DATA_SAMPLES, RANDOM_STATE


def main():
    DATA_SAMPLES.mkdir(parents=True, exist_ok=True)
    raw = pd.read_csv(DATA_PROCESSED / "test_raw.csv")
    y = pd.read_csv(DATA_PROCESSED / "y_test.csv")  # same row order as test_raw

    mixed = raw.sample(min(100, len(raw)), random_state=RANDOM_STATE)
    attacks = raw[y["is_attack"] == 1].sample(30, random_state=RANDOM_STATE)
    normal = raw[y["is_attack"] == 0].sample(30, random_state=RANDOM_STATE)
    # up to 10 flows from each attack family (DoS, Probe, R2L, U2R)
    by_type = pd.concat(
        [raw[y["attack_class"] == c].head(10) for c in ["dos", "probe", "r2l", "u2r"]]
    )

    files = {
        "sample_mixed_100.csv": mixed,
        "sample_attacks_30.csv": attacks,
        "sample_normal_30.csv": normal,
        "sample_attack_types.csv": by_type,
    }
    for name, df in files.items():
        df.to_csv(DATA_SAMPLES / name, index=False)
        print(f"{name:<26} {len(df)} rows")


if __name__ == "__main__":
    main()