# bsod_demo.py — Standalone Real BSOD Demo
# ══════════════════════════════════════════
# Run this SEPARATELY from Sentinel
# VM ONLY — Windows 7
# Run as Administrator!
# ══════════════════════════════════════════

import os
import sys
import time
import subprocess
import threading
import tkinter as tk
from tkinter import messagebox

# ── Check running as Admin ────────────────────────────────────
def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


# ── BSOD Methods ─────────────────────────────────────────────

def method_notmyfault():
    """Use NotMyFault by Sysinternals — cleanest method."""
    paths = [
        os.path.join(os.path.dirname(__file__), "notmyfault64.exe"),
        os.path.join(os.path.dirname(__file__), "notmyfault.exe"),
        r"C:\Tools\notmyfault64.exe",
    ]
    for p in paths:
        if os.path.exists(p):
            subprocess.Popen([p, "/crash"])
            return True
    return False


def method_csrss():
    """Kill csrss.exe — Windows 7 BSODs immediately."""
    try:
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq csrss.exe",
             "/FO", "CSV", "/NH"],
            capture_output=True, text=True
        )
        for line in result.stdout.strip().split("\n"):
            if "csrss.exe" in line.lower():
                pid = line.split(",")[1].strip().strip('"')
                subprocess.run(["taskkill", "/F", "/PID", pid])
                return True
    except Exception as e:
        print(f"csrss method failed: {e}")
    return False


def method_kernel():
    """Use Windows kernel NtRaiseHardError — works on Windows 7."""
    try:
        import ctypes
        ntdll = ctypes.windll.ntdll

        # Enable shutdown privilege
        prev = ctypes.c_ulong(0)
        ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(prev))

        # Trigger hard error → BSOD
        response = ctypes.c_ulong(0)
        ntdll.NtRaiseHardError(
            ctypes.c_ulong(0xC0000420),  # STATUS_ASSERTION_FAILURE
            0, 0, 0, 6,
            ctypes.byref(response)
        )
        return True
    except Exception as e:
        print(f"Kernel method failed: {e}")
        return False


# ── Countdown Window ──────────────────────────────────────────

def show_countdown(seconds, on_complete):
    """Shows a scary countdown window before BSOD."""
    root = tk.Tk()
    root.title("⚠️ SYSTEM CRASH IMMINENT")
    root.geometry("500x380")
    root.configure(bg="#0d0000")
    root.attributes("-topmost", True)
    root.resizable(False, False)

    BG   = "#0d0000"
    RED  = "#ff0000"
    ORNG = "#ff4500"

    tk.Label(root, text="☠️  CRITICAL SYSTEM ERROR  ☠️",
             font=("Segoe UI", 16, "bold"), bg=BG, fg=RED).pack(pady=(20,4))
    tk.Label(root, text="Windows will crash in:",
             font=("Segoe UI", 12), bg=BG, fg=ORNG).pack(pady=(0,8))

    count_var = tk.StringVar(value=str(seconds))
    tk.Label(root, textvariable=count_var,
             font=("Segoe UI", 72, "bold"), bg=BG, fg=RED).pack()

    tk.Label(root, text="This is a controlled demo\nVM will BSOD — restore snapshot after",
             font=("Segoe UI", 10), bg=BG, fg="#888888",
             justify="center").pack(pady=(8,4))

    # Progress bar
    progress_frame = tk.Frame(root, bg="#1a0000", height=12, width=440)
    progress_frame.pack(pady=8)
    progress_bar = tk.Frame(progress_frame, bg=RED, height=12,
                            width=440)
    progress_bar.place(x=0, y=0)

    def tick(remaining, total):
        if remaining <= 0:
            root.destroy()
            on_complete()
            return
        count_var.set(str(remaining))
        # Shrink progress bar
        new_width = int(440 * remaining / total)
        progress_bar.config(width=max(new_width, 0))
        root.after(1000, tick, remaining-1, total)

    root.after(1000, tick, seconds-1, seconds)
    root.mainloop()


# ── Main Demo ─────────────────────────────────────────────────

def run_bsod():
    """Try all methods in order."""
    print("[BSOD] Attempting real BSOD...")

    # Method 1 — Kernel call (most reliable)
    print("[BSOD] Trying kernel method...")
    if method_kernel():
        return

    # Method 2 — NotMyFault
    print("[BSOD] Trying NotMyFault...")
    if method_notmyfault():
        return

    # Method 3 — Kill csrss
    print("[BSOD] Trying csrss kill...")
    if method_csrss():
        return

    print("[BSOD] All methods failed")
    messagebox.showerror("Failed",
        "Could not trigger BSOD.\n\n"
        "Make sure you:\n"
        "1. Run as Administrator\n"
        "2. Are in a Windows 7 VM\n"
        "3. Have NotMyFault in simulation folder")


def main():
    # Admin check
    if not is_admin():
        messagebox.showerror(
            "Admin Required",
            "This must be run as Administrator!\n\n"
            "Right-click → Run as Administrator"
        )
        sys.exit(1)

    # Warning popup
    root = tk.Tk()
    root.withdraw()
    confirm = messagebox.askyesno(
        "⚠️ REAL BSOD DEMO — VM ONLY",
        "This will trigger a REAL Blue Screen of Death!\n\n"
        "✅ Only run this inside a Windows 7 VM\n"
        "✅ Make sure you took a VirtualBox snapshot\n"
        "✅ Run as Administrator\n\n"
        "VM will crash and reboot.\n"
        "Restore snapshot afterwards.\n\n"
        "Are you ready to proceed?"
    )
    root.destroy()

    if not confirm:
        print("[BSOD] Cancelled by user.")
        sys.exit(0)

    # Countdown then BSOD
    show_countdown(seconds=5, on_complete=run_bsod)


if __name__ == "__main__":
    main()