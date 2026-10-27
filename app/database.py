"""SQLite helpers: one row per upload (runs) and one per analysed flow (detections)."""
import sqlite3
from contextlib import closing
from datetime import datetime

from config import BASE_DIR

DB_PATH = BASE_DIR / "app" / "nids.db"


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with closing(_conn()) as conn, conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                total INTEGER NOT NULL,
                attacks INTEGER NOT NULL,
                high INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL REFERENCES runs(id),
                row_num INTEGER NOT NULL,
                true_label TEXT,
                prediction TEXT NOT NULL,
                probability REAL NOT NULL,
                severity TEXT NOT NULL,
                summary TEXT NOT NULL,
                plot_file TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_det_run ON detections(run_id);
            """
        )


def save_run(filename, rows):
    """Insert a run and all its detections in one transaction; return run id."""
    attacks = sum(r["prediction"] == "Attack" for r in rows)
    high = sum(r["severity"] == "High" for r in rows)
    with closing(_conn()) as conn, conn:
        cur = conn.execute(
            "INSERT INTO runs (filename, uploaded_at, total, attacks, high) "
            "VALUES (?, ?, ?, ?, ?)",
            (filename, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             len(rows), attacks, high),
        )
        run_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO detections (run_id, row_num, true_label, prediction, "
            "probability, severity, summary, plot_file) VALUES (?,?,?,?,?,?,?,?)",
            [
                (run_id, r["row_num"], r["true_label"], r["prediction"],
                 r["probability"], r["severity"], r["summary"], r["plot_file"])
                for r in rows
            ],
        )
    return run_id


def get_run(run_id):
    with closing(_conn()) as conn:
        return conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()


def get_detections(run_id, only_attacks=False):
    sql = "SELECT * FROM detections WHERE run_id = ?"
    if only_attacks:
        sql += " AND prediction = 'Attack'"
    sql += " ORDER BY (prediction = 'Attack') DESC, probability DESC, row_num"
    with closing(_conn()) as conn:
        return conn.execute(sql, (run_id,)).fetchall()


def list_runs():
    with closing(_conn()) as conn:
        return conn.execute("SELECT * FROM runs ORDER BY id DESC").fetchall()