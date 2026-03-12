# logs/logger.py
# Persistent detection logger.
# Saves every NEW/REMOVED/CHANGED alert to a JSON log file with timestamps.
# Used by the Logs page and PDF/CSV export.

import os
import json
import threading
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(__file__), "detections.json")
_lock    = threading.Lock()


def _load():
    """Load existing log entries from disk."""
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save(entries):
    """Save log entries to disk."""
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)


def log_alert(alert):
    """
    Logs a single alert dict to the JSON log file.
    Adds a timestamp automatically.
    """
    with _lock:
        entries = _load()
        entry   = {
            "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type":       alert.get("type", ""),
            "name":       alert.get("name", ""),
            "path":       alert.get("path", ""),
            "location":   alert.get("location", ""),
            "risk_score": alert.get("risk_score", 0),
            "risk_level": alert.get("risk_level", ""),
            "reasons":    alert.get("reasons", []),
            "message":    alert.get("message", ""),
        }
        entries.append(entry)
        # Keep last 500 entries only
        entries = entries[-500:]
        _save(entries)


def get_logs(limit=200):
    """Returns the most recent log entries (newest first)."""
    with _lock:
        entries = _load()
    return list(reversed(entries[-limit:]))


def clear_logs():
    """Clears all log entries."""
    with _lock:
        _save([])


def get_stats():
    """Returns summary stats from the log."""
    with _lock:
        entries = _load()
    return {
        "total":   len(entries),
        "high":    sum(1 for e in entries if e.get("risk_level") == "High"),
        "medium":  sum(1 for e in entries if e.get("risk_level") == "Medium"),
        "low":     sum(1 for e in entries if e.get("risk_level") == "Low"),
        "new":     sum(1 for e in entries if e.get("type") == "NEW"),
        "removed": sum(1 for e in entries if e.get("type") == "REMOVED"),
    }