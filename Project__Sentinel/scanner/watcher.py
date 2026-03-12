# scanner/watcher.py
# TRUE Real-Time Watcher
# ─────────────────────
# Monitors 3 sources LIVE:
#   1. Windows Registry Run keys  — via winreg polling (3s)
#   2. Startup Folder             — via os.listdir polling (3s)
#   3. Scheduled Tasks            — via schtasks polling (30s)
#
# ANY new entry triggers:
#   → Sound alert in browser
#   → Toast notification
#   → Table row flash
#   → Summary card update

import os
import time
import threading
import winreg

from scanner.registry_scan import scan_registry
from scanner.startup_scan  import scan_startup_folder
from scanner.task_scan     import scan_scheduled_tasks
from scanner.risk_engine   import score_risk
from scanner.notifier      import notify_new_threat, notify_removed, notify_startup
from logs.logger           import log_alert

# ── Shared state ─────────────────────────────────────────────
_lock           = threading.Lock()
_alerts         = []
_baseline       = {}      # key → entry dict
_task_baseline  = {}
_task_counter   = 0       # scan tasks every 10 cycles (30s)

POLL_INTERVAL   = 3       # seconds between registry+startup scans
TASK_EVERY_N    = 10      # scan tasks every N cycles


def _entry_key(entry):
    """Unique identity key for an entry."""
    return f"{entry['name'].strip()}|{entry['location'].strip()}"


def _score(entry):
    """Score a raw entry dict."""
    path = entry.get("path") or entry.get("full_path", "N/A")
    r    = score_risk(entry["name"], path, entry["location"])
    return {
        "name":       entry["name"],
        "path":       path,
        "location":   entry["location"],
        "risk_score": r["risk_score"],
        "risk_level": r["risk_level"],
        "reasons":    r.get("reasons", []),
    }


def _build_snapshot():
    """Scan registry + startup and return {key: scored_entry}."""
    snapshot = {}
    items    = []

    try:
        items += scan_registry()
    except Exception as e:
        print(f"[Watcher] Registry scan error: {e}")

    try:
        items += scan_startup_folder()
    except Exception as e:
        print(f"[Watcher] Startup scan error: {e}")

    for raw in items:
        scored = _score(raw)
        key    = _entry_key(scored)
        snapshot[key] = scored

    return snapshot


def _build_task_snapshot():
    """Scan scheduled tasks and return {key: scored_entry}."""
    snapshot = {}
    try:
        for raw in scan_scheduled_tasks():
            scored = _score(raw)
            key    = _entry_key(scored)
            snapshot[key] = scored
    except Exception as e:
        print(f"[Watcher] Task scan error: {e}")
    return snapshot


def _push_alert(alert_type, entry, extra=""):
    """Push a new alert into the queue for SSE delivery."""
    alert = {
            "type":       alert_type,   # "NEW" | "REMOVED" | "CHANGED"
            "name":       entry.get("name", ""),
            "path":       entry.get("path", ""),
            "location":   entry.get("location", ""),
            "risk_score": entry.get("risk_score", 0),
            "risk_level": entry.get("risk_level", "Low"),
            "reasons":    entry.get("reasons", []),
            "message":    extra or f"{alert_type}: {entry.get('name','')} [{entry.get('risk_level','')}]",
        }
    # Log to file
    try:
        log_alert(alert)
    except Exception:
        pass
    # Windows desktop notification
    try:
        if alert_type == "NEW":
            notify_new_threat(
                alert["name"], alert["location"],
                alert["risk_level"], alert["risk_score"]
            )
        elif alert_type == "REMOVED":
            notify_removed(alert["name"], alert["location"])
    except Exception:
        pass
    with _lock:
        _alerts.append(alert)


def _compare_and_alert(old_snapshot, new_snapshot):
    """Diff two snapshots and push alerts for any changes."""
    old_keys = set(old_snapshot.keys())
    new_keys = set(new_snapshot.keys())

    # New entries appeared
    for key in new_keys - old_keys:
        entry = new_snapshot[key]
        _push_alert("NEW", entry,
            f"NEW persistence entry: {entry['name']} — {entry['risk_level']} risk (score {entry['risk_score']})")
        print(f"[Watcher] 🚨 NEW: {entry['name']} | {entry['location']} | {entry['risk_level']}")

    # Entries were removed
    for key in old_keys - new_keys:
        entry = old_snapshot[key]
        _push_alert("REMOVED", entry,
            f"Entry removed: {entry['name']} from {entry['location']}")
        print(f"[Watcher] ✅ REMOVED: {entry['name']} | {entry['location']}")

    # Entries changed risk score
    for key in old_keys & new_keys:
        old = old_snapshot[key]
        new = new_snapshot[key]
        if new["risk_score"] != old["risk_score"] and new["risk_score"] > old["risk_score"]:
            _push_alert("CHANGED", new,
                f"Risk changed: {new['name']} — now {new['risk_level']} (score {new['risk_score']})")
            print(f"[Watcher] ⚠️  CHANGED: {new['name']} score {old['risk_score']} → {new['risk_score']}")


def _watcher_loop():
    """Main background loop — runs forever in a daemon thread."""
    global _baseline, _task_baseline, _task_counter

    print("[Watcher] 🟢 Building baseline scan...")
    _baseline      = _build_snapshot()
    _task_baseline = _build_task_snapshot()
    print(f"[Watcher] 🟢 Baseline: {len(_baseline)} registry/startup + {len(_task_baseline)} tasks")
    try:
        notify_startup()
    except Exception:
        pass

    while True:
        time.sleep(POLL_INTERVAL)
        _task_counter += 1

        try:
            # Always scan registry + startup every 3 seconds
            new_snapshot = _build_snapshot()
            _compare_and_alert(_baseline, new_snapshot)
            _baseline = new_snapshot

            # Scan tasks every 30 seconds (heavier operation)
            if _task_counter >= TASK_EVERY_N:
                _task_counter   = 0
                new_tasks       = _build_task_snapshot()
                _compare_and_alert(_task_baseline, new_tasks)
                _task_baseline  = new_tasks

        except Exception as e:
            print(f"[Watcher] Loop error: {e}")


def get_alerts():
    """
    Returns and clears all pending alerts.
    Called by Flask /stream SSE route every 3 seconds.
    """
    with _lock:
        alerts = list(_alerts)
        _alerts.clear()
    return alerts


def get_current_snapshot():
    """Returns the latest scanned snapshot for API use."""
    with _lock:
        return dict(_baseline)


def start_watcher():
    """Start the background watcher daemon thread."""
    t = threading.Thread(target=_watcher_loop, daemon=True, name="SentinelWatcher")
    t.start()
    print("[Watcher] 🛡️  Real-time monitor active — registry+startup every 3s, tasks every 30s")