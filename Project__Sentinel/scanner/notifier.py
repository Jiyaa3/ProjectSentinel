# scanner/notifier.py
# Windows Desktop Notifications — alerts appear outside the browser.
# Uses win10toast (install: pip install win10toast)
# Falls back gracefully if not installed.

import threading

def _send(title, message, risk_level="Low"):
    """Send a Windows toast notification in a background thread."""
    try:
        from win10toast import ToastNotifier
        icon_path = None  # Uses default Windows icon

        # Choose duration based on risk
        duration = 10 if risk_level == "High" else 5

        toaster = ToastNotifier()
        toaster.show_toast(
            title,
            message,
            duration    = duration,
            threaded    = True,
            icon_path   = icon_path
        )
    except ImportError:
        # win10toast not installed — silently skip
        print(f"[Notifier] Desktop notification (win10toast not installed): {title} — {message}")
    except Exception as e:
        print(f"[Notifier] Notification error: {e}")


def notify_new_threat(name, location, risk_level, risk_score):
    """Show a desktop alert for a newly detected persistence entry."""
    title   = f"🚨 Sentinel: New {risk_level} Risk Detected"
    message = f"{name} added to {location}\nRisk Score: {risk_score} [{risk_level}]"
    threading.Thread(target=_send, args=(title, message, risk_level), daemon=True).start()


def notify_removed(name, location):
    """Show a desktop alert when an entry is removed."""
    title   = "✅ Sentinel: Entry Removed"
    message = f"{name} was removed from {location}"
    threading.Thread(target=_send, args=(title, message, "Low"), daemon=True).start()


def notify_startup():
    """Show a notification when Sentinel starts monitoring."""
    title   = "🛡️ Project Sentinel Active"
    message = "Real-time persistence monitoring is running.\nOpen http://127.0.0.1:5000"
    threading.Thread(target=_send, args=(title, message, "Low"), daemon=True).start()