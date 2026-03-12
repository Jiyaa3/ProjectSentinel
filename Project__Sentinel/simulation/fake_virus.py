# simulation/fake_virus.py
# ============================================================
# FAKE VIRUS — 100% HARMLESS DEMO TOOL
# For educational use with Project Sentinel only.
# Does NOT damage, encrypt, steal, or transmit anything.
# ============================================================
# What it does when run:
#   1. Shows a popup  "You have been hacked! (Demo Only)"
#   2. Opens browser  "Sentinel Demo - Malware Detected" page
#   3. Opens browser  Fake Blue Screen of Death (HTML page)
#   4. Appears in     Dashboard table as HIGH RISK detected
# ============================================================

import os
import sys
import time
import webbrowser
import tkinter as tk
from tkinter import messagebox


def show_hacked_popup():
    """
    Effect 1 — Shows a dramatic 'You have been hacked!' popup.
    Completely harmless — just a tkinter messagebox.
    """
    root = tk.Tk()
    root.withdraw()  # Hide the empty root window

    messagebox.showwarning(
        title="⚠️  SYSTEM ALERT",
        message=(
            "🔴 YOU HAVE BEEN HACKED!\n\n"
            "All your files are being encrypted...\n"
            "Your webcam has been accessed...\n"
            "Your passwords are being stolen...\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "⚠️  DEMO ONLY — Project Sentinel\n"
            "This is a safe educational simulation.\n"
            "Nothing actually happened to your PC.\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━"
        )
    )
    root.destroy()


def open_hacked_page():
    """
    Effect 2 — Opens the 'Malware Detected' page in browser.
    Points to the local Flask server page.
    """
    webbrowser.open("http://127.0.0.1:5000/hacked")
    time.sleep(1)


def open_bsod_page():
    """
    Effect 3 — Opens a fake Blue Screen of Death in browser.
    Just a scary-looking HTML page — completely harmless.
    """
    webbrowser.open("http://127.0.0.1:5000/bsod")
    time.sleep(1)


# ── Run all effects in sequence ──────────────────────────────
if __name__ == "__main__":
    print("[fake_virus] Starting demo sequence...")

    # Effect 1 — Popup (blocks until user clicks OK)
    show_hacked_popup()

    # Effect 2 — Malware detected page
    open_hacked_page()

    # Effect 3 — Fake BSOD page
    open_bsod_page()

    print("[fake_virus] Demo complete. Everything is safe!")
    print("[fake_virus] Go to http://127.0.0.1:5000 to see it detected in Sentinel.")


def launch():
    """
    Called from simulate_attack.py — runs all effects in a background thread
    so Flask doesn't freeze waiting for tkinter popup.
    """
    import threading

    def _run():
        # Effect 1 — Scary popup
        try:
            show_hacked_popup()
        except Exception as e:
            print(f"[fake_virus] Popup error: {e}")

        # Effect 2 — Open hacked page
        try:
            open_hacked_page()
        except Exception as e:
            print(f"[fake_virus] Hacked page error: {e}")

        # Effect 3 — Open BSOD page
        try:
            open_bsod_page()
        except Exception as e:
            print(f"[fake_virus] BSOD page error: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()