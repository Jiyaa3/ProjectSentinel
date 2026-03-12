# scanner/hash_checker.py
# SHA256 Hash Checker for persistence entries.
# First scan  → saves hashes to hashes.json
# Every scan  → compares current hash vs saved
# If changed  → flags as MODIFIED → instant High Risk boost

import os
import json
import hashlib
import threading
from datetime import datetime

HASH_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "hashes.json")
_lock     = threading.Lock()


def _load():
    try:
        with open(HASH_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data):
    try:
        os.makedirs(os.path.dirname(HASH_FILE), exist_ok=True)
        with open(HASH_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[HashChecker] Save error: {e}")


def sha256(filepath):
    """Compute SHA256 of a file. Returns hex string or None."""
    try:
        if not filepath or not os.path.exists(filepath):
            return None
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError):
        return None
    except Exception:
        return None


def check_entry(name, path):
    """
    Check a persistence entry's hash against stored baseline.
    Returns dict:
        hash_status : "New" | "Unchanged" | "MODIFIED" | "Missing" | "Unknown"
        current_hash: current SHA256 or None
        saved_hash  : previously stored hash or None
        first_seen  : timestamp when first detected
        flagged     : True if file was modified (should boost risk)
    """
    with _lock:
        store = _load()

    key          = f"{name}|{path}"
    current_hash = sha256(path)
    now          = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if key not in store:
        # First time seeing this entry — save it
        entry = {
            "name":       name,
            "path":       path,
            "hash":       current_hash,
            "first_seen": now,
            "last_seen":  now,
            "modified":   False,
        }
        with _lock:
            store = _load()
            store[key] = entry
            _save(store)
        return {
            "hash_status":   "New",
            "current_hash":  current_hash,
            "saved_hash":    None,
            "first_seen":    now,
            "flagged":       False,
        }

    saved        = store[key]
    saved_hash   = saved.get("hash")
    first_seen   = saved.get("first_seen", now)

    # Update last_seen
    with _lock:
        store = _load()
        if key in store:
            store[key]["last_seen"] = now

    if current_hash is None:
        _save(store)
        return {
            "hash_status":  "Missing",
            "current_hash": None,
            "saved_hash":   saved_hash,
            "first_seen":   first_seen,
            "flagged":      False,
        }

    if saved_hash is None:
        # Had no hash before, save now
        store[key]["hash"] = current_hash
        _save(store)
        return {
            "hash_status":  "Unknown",
            "current_hash": current_hash,
            "saved_hash":   None,
            "first_seen":   first_seen,
            "flagged":      False,
        }

    if current_hash != saved_hash:
        # FILE WAS MODIFIED
        store[key]["modified"]      = True
        store[key]["modified_at"]   = now
        store[key]["previous_hash"] = saved_hash
        store[key]["hash"]          = current_hash
        _save(store)
        return {
            "hash_status":  "MODIFIED",
            "current_hash": current_hash,
            "saved_hash":   saved_hash,
            "first_seen":   first_seen,
            "flagged":      True,
        }

    _save(store)
    return {
        "hash_status":  "Unchanged",
        "current_hash": current_hash,
        "saved_hash":   saved_hash,
        "first_seen":   first_seen,
        "flagged":      False,
    }


def get_all_hashes():
    """Returns all stored hash records."""
    with _lock:
        return _load()


def clear_hashes():
    """Reset all stored hashes (forces re-baseline on next scan)."""
    with _lock:
        _save({})