# simulation/real_bsod.py
# Stub to avoid missing import path and provide placeholder behavior.

import threading
import time


def trigger_bsod_delayed(delay_seconds=5):
    """Simulate a delayed BSOD trigger (no-op in stub)."""
    def _do():
        time.sleep(delay_seconds)
        # In a real implementation this would trigger a crash
        print(f"[real_bsod] delayed trigger ({delay_seconds}s) called (stub).")

    t = threading.Thread(target=_do, daemon=True)
    t.start()
    return True
