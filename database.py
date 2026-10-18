"""
SENTRIX — AI-Powered URL Threat Intelligence
Database Management Module (SQLite)

Provides thread-safe persistent scan history, statistics calculation,
search & filtering, and CSV export capabilities.
"""

import os
import sqlite3
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
import pandas as pd

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "data", "scan_history.db")


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Creates a connection to the SQLite database."""
    target_path = db_path or DEFAULT_DB_PATH
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    conn = sqlite3.connect(target_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Initializes the database tables and indices if they do not exist."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                prediction TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                model_confidence REAL,
                indicators_json TEXT,
                threat_intel_status TEXT,
                threat_intel_details TEXT,
                source TEXT DEFAULT 'SINGLE_SCAN',
                explanation_summary TEXT,
                explanation_json TEXT
            )
            """
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp DESC)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_prediction ON scans (prediction)"
        )

        # Non-destructive migrations for existing tables
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN explanation_summary TEXT")
        except sqlite3.OperationalError:
            pass

        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN explanation_json TEXT")
        except sqlite3.OperationalError:
            pass

        conn.commit()
    finally:
        conn.close()


def insert_scan(
    url: str,
    prediction: str,
    risk_score: int,
    model_confidence: Optional[float] = None,
    indicators: Optional[List[Dict[str, Any]]] = None,
    threat_intel_status: str = "NOT_CONFIGURED",
    threat_intel_details: str = "Threat intelligence lookup was not performed.",
    source: str = "SINGLE_SCAN",
    explanation_summary: Optional[str] = None,
    explanation_json: Optional[str] = None,
    timestamp: Optional[str] = None,
    db_path: Optional[str] = None
) -> int:
    """
    Inserts a newly completed scan record into the persistent history.
    Returns the inserted record's row ID.
    """
    init_db(db_path)
    now_ts = timestamp or datetime.now().isoformat()
    indicators_str = json.dumps(indicators or [])
    
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (
                url, timestamp, prediction, risk_score, model_confidence,
                indicators_json, threat_intel_status, threat_intel_details, source,
                explanation_summary, explanation_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                url.strip(),
                now_ts,
                prediction.upper(),
                int(risk_score),
                float(model_confidence) if model_confidence is not None else None,
                indicators_str,
                threat_intel_status,
                threat_intel_details,
                source,
                explanation_summary,
                explanation_json
            )
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_stats(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Computes summary metrics for the live cybersecurity dashboard:
    total scans, safe/suspicious/malicious breakdown, avg risk score, and latest timestamp.
    """
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM scans WHERE UPPER(prediction) = 'SAFE'")
        safe_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM scans WHERE UPPER(prediction) = 'SUSPICIOUS'")
        suspicious_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM scans WHERE UPPER(prediction) = 'MALICIOUS'")
        malicious_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT AVG(risk_score) FROM scans")
        avg_risk = cursor.fetchone()[0]
        
        cursor.execute("SELECT timestamp FROM scans ORDER BY id DESC LIMIT 1")
        latest_row = cursor.fetchone()
        latest_timestamp = latest_row[0] if latest_row else None
    finally:
        conn.close()

    return {
        "total_scans": total_scans,
        "safe_count": safe_count,
        "suspicious_count": suspicious_count,
        "malicious_count": malicious_count,
        "avg_risk_score": round(avg_risk, 1) if avg_risk is not None else 0.0,
        "latest_timestamp": latest_timestamp
    }


def get_recent_scans(limit: int = 10, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves the N most recent scans as dictionaries."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, url, timestamp, prediction, risk_score, model_confidence,
                   indicators_json, threat_intel_status, threat_intel_details, source,
                   explanation_summary, explanation_json
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        rows = cursor.fetchall()

        results = []
        for r in rows:
            results.append({
                "id": r["id"],
                "url": r["url"],
                "timestamp": r["timestamp"],
                "prediction": r["prediction"],
                "risk_score": r["risk_score"],
                "model_confidence": r["model_confidence"],
                "indicators": json.loads(r["indicators_json"] or "[]"),
                "threat_intel_status": r["threat_intel_status"],
                "threat_intel_details": r["threat_intel_details"],
                "source": r["source"],
                "explanation_summary": r["explanation_summary"] if "explanation_summary" in r.keys() else "",
                "explanation_json": json.loads(r["explanation_json"]) if "explanation_json" in r.keys() and r["explanation_json"] else None
            })
        return results
    finally:
        conn.close()


def get_filtered_history_df(
    category: Optional[str] = None,
    search_query: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 500,
    db_path: Optional[str] = None
) -> pd.DataFrame:
    """
    Retrieves filtered scan history formatted as a pandas DataFrame for UI tables and CSV exports.
    """
    init_db(db_path)
    query = (
        "SELECT id, url, timestamp, prediction, risk_score, model_confidence, "
        "threat_intel_status, explanation_summary, source FROM scans WHERE 1=1"
    )
    params: List[Any] = []

    if category and category.upper() != "ALL":
        query += " AND UPPER(prediction) = ?"
        params.append(category.upper())

    if search_query and search_query.strip():
        query += " AND url LIKE ?"
        params.append(f"%{search_query.strip()}%")

    if start_date:
        query += " AND timestamp >= ?"
        params.append(start_date)

    if end_date:
        query += " AND timestamp <= ?"
        params.append(end_date)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    conn = get_connection(db_path)
    try:
        df = pd.read_sql_query(query, conn, params=params)
        return df
    finally:
        conn.close()


def clear_history(db_path: Optional[str] = None) -> bool:
    """Clears all records in the scans table."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans")
        conn.commit()
    finally:
        conn.close()
    return True
