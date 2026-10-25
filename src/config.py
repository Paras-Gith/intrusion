"""Central settings for the intrusion project: paths, column names, label maps."""
from pathlib import Path

# ---------- Paths ----------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_RAW = BASE_DIR / "data" / "raw"
DATA_PROCESSED = BASE_DIR / "data" / "processed"
DATA_SAMPLES = BASE_DIR / "data" / "samples"
MODELS_DIR = BASE_DIR / "models"
FIGURES_DIR = BASE_DIR / "reports" / "figures"

RAW_FILE = DATA_RAW / "KDDTrain+_20Percent.txt"
PREPROCESSOR_FILE = MODELS_DIR / "preprocessor.joblib"

RANDOM_STATE = 42
TEST_SIZE = 0.2

# ---------- Columns ----------
# The raw NSL-KDD file has no header: 41 features + label + difficulty level.
FEATURE_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]
RAW_COLUMNS = FEATURE_NAMES + ["label", "difficulty"]

# Categorical features
PROTOCOLS = ["icmp", "tcp", "udp"]                      # one-hot encoded
FLAGS = ["OTH", "REJ", "RSTO", "RSTOS0", "RSTR", "S0",  # one-hot encoded
         "S1", "S2", "S3", "SF", "SH"]
# "service" has ~70 values, so it is label (ordinal) encoded instead.

# Count/size columns that get StandardScaler (rates and 0/1 flags are left as is)
SCALE_COLS = [
    "duration", "src_bytes", "dst_bytes", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "num_compromised", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "count", "srv_count", "dst_host_count",
    "dst_host_srv_count",
]

# ---------- Labels ----------
CLASS_IDS = {"normal": 0, "dos": 1, "probe": 2, "r2l": 3, "u2r": 4}

ATTACK_TO_CLASS = {"normal": "normal"}
for _name in ["neptune", "smurf", "back", "teardrop", "pod", "land",
              "apache2", "udpstorm", "processtable", "mailbomb"]:
    ATTACK_TO_CLASS[_name] = "dos"
for _name in ["satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"]:
    ATTACK_TO_CLASS[_name] = "probe"
for _name in ["guess_passwd", "ftp_write", "imap", "phf", "multihop",
              "warezmaster", "warezclient", "spy", "xlock", "xsnoop",
              "snmpguess", "snmpgetattack", "httptunnel", "sendmail",
              "named", "worm"]:
    ATTACK_TO_CLASS[_name] = "r2l"
for _name in ["buffer_overflow", "loadmodule", "rootkit", "perl",
              "sqlattack", "xterm", "ps"]:
    ATTACK_TO_CLASS[_name] = "u2r"