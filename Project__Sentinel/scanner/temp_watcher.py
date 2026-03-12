# scanner/temp_watcher.py
# Watches Temp + Downloads folders every 3 seconds.
# When ANY new file appears → scans it → pushes alert via SSE.

import os
import threading
import time
from datetime import datetime
from scanner.file_scanner import _scan_content, _score_file

_lock        = threading.Lock()
_alerts      = []
_seen_files  = set()

WATCH_DIRS = [
    os.environ.get("TEMP", ""),
    os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
    os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
]

SKIP_EXTS = {".log", ".tmp", ".etl", ".ini", ".dat", ".lock"}


def _push(entry):
    with _lock:
        _alerts.append(entry)


def get_temp_alerts():
    with _lock:
        alerts = list(_alerts)
        _alerts.clear()
    return alerts


def scan_watched_dirs():
    """Scan watched dirs and return all files with risk info."""
    results = []
    for d in WATCH_DIRS:
        if not d or not os.path.isdir(d):
            continue
        try:
            for fname in os.listdir(d):
                fpath = os.path.join(d, fname)
                if not os.path.isfile(fpath):
                    continue
                ext = os.path.splitext(fname)[1].lower()
                if ext in SKIP_EXTS:
                    continue
                try:
                    risk = _score_file(fpath, False)
                    is_mal, matches = _scan_content(fpath)
                    results.append({
                        "name":         fname,
                        "path":         fpath,
                        "status":       "In Watched Folder",
                        "process":      "—",
                        "pid":          0,
                        "risk_score":   risk["risk_score"],
                        "risk_level":   risk["risk_level"],
                        "is_malicious": is_mal,
                        "mal_matches":  matches[:3],
                        "reasons":      risk["reasons"][:3],
                        "scanned_at":   datetime.now().strftime("%H:%M:%S"),
                    })
                except Exception:
                    pass
        except Exception:
            pass
    results.sort(key=lambda x: (-int(x["is_malicious"]), -x["risk_score"]))
    return results


def _watch_loop():
    global _seen_files

    # Build baseline
    for d in WATCH_DIRS:
        if not d or not os.path.isdir(d):
            continue
        try:
            for f in os.listdir(d):
                _seen_files.add(os.path.join(d, f).lower())
        except Exception:
            pass

    print(f"[TempWatcher] Watching: {[d for d in WATCH_DIRS if d]}")

    while True:
        time.sleep(3)
        try:
            for d in WATCH_DIRS:
                if not d or not os.path.isdir(d):
                    continue
                for fname in os.listdir(d):
                    fpath      = os.path.join(d, fname)
                    fpath_low  = fpath.lower()
                    ext        = os.path.splitext(fname)[1].lower()

                    if fpath_low in _seen_files or ext in SKIP_EXTS:
                        continue
                    if not os.path.isfile(fpath):
                        continue

                    _seen_files.add(fpath_low)

                    try:
                        risk       = _score_file(fpath, False)
                        is_mal, matches = _scan_content(fpath)

                        # Only alert if risky
                        if risk["risk_score"] > 0 or is_mal:
                            _push({
                                "type":         "FILE_NEW",
                                "name":         fname,
                                "path":         fpath,
                                "risk_score":   risk["risk_score"],
                                "risk_level":   risk["risk_level"],
                                "is_malicious": is_mal,
                                "mal_matches":  matches[:3],
                                "reasons":      risk["reasons"][:3],
                                "message":      f"New file detected: {fname} [{risk['risk_level']}]",
                            })
                            print(f"[TempWatcher] {'🚨 MALICIOUS' if is_mal else '⚠️ Suspicious'}: {fname} score={risk['risk_score']}")
                    except Exception as e:
                        print(f"[TempWatcher] Scan error {fname}: {e}")
        except Exception as e:
            print(f"[TempWatcher] Loop error: {e}")


def start_temp_watcher():
    t = threading.Thread(target=_watch_loop, daemon=True, name="TempWatcher")
    t.start()
    print("[TempWatcher] 👁️  Watching Temp, Downloads, Desktop for new files")