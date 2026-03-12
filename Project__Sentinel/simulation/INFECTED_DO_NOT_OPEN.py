# INFECTED_DO_NOT_OPEN.py
# ══════════════════════════════════════════════
# FAKE MALWARE — 100% HARMLESS DEMO FILE
# Shows a scary warning when opened.
# Contains real malware signatures so Sentinel
# detects it as HIGH RISK + MALICIOUS.
# ══════════════════════════════════════════════

# Embedded signatures (strings only — do NOTHING):
SIGNATURES = """
VirtualAllocEx WriteProcessMemory CreateRemoteThread
SetWindowsHookEx GetAsyncKeyState keylogger
reverse_shell shellcode msfvenom metasploit
powershell -enc powershell -nop DownloadString
DownloadFile CryptEncrypt ransom bitcoin
net user /add reg add schtasks /create
invoke-expression iex( FromBase64String bypass
"""

import tkinter as tk
from tkinter import messagebox
import threading
import time
import os
import sys

def flash_warning(root, label, colors, idx=0):
    label.config(fg=colors[idx % len(colors)])
    root.after(400, flash_warning, root, label, colors, idx+1)

def show_warning():
    root = tk.Tk()
    root.title("⚠️ SECURITY ALERT — Project Sentinel")
    root.geometry("620x560")
    root.resizable(False, False)
    root.configure(bg="#0d0000")
    root.attributes("-topmost", True)

    BG      = "#0d0000"
    CARD    = "#1a0000"
    RED     = "#ff0000"
    ORANGE  = "#ff4500"
    YELLOW  = "#ffc107"
    WHITE   = "#ffffff"
    GRAY    = "#aaaaaa"

    # Flashing skull header
    skull = tk.Label(root, text="☠️  CRITICAL THREAT DETECTED  ☠️",
                     font=("Segoe UI", 15, "bold"), bg=BG, fg=RED)
    skull.pack(pady=(18, 2))
    flash_warning(root, skull, [RED, ORANGE, YELLOW])

    # File name
    filepath = os.path.abspath(__file__)
    fname    = os.path.basename(filepath)
    tk.Label(root, text=f"FILE:  {fname}",
             font=("Courier New", 10, "bold"), bg=BG, fg=ORANGE).pack(pady=(4,2))
    tk.Label(root, text=filepath, font=("Courier New", 8),
             bg=BG, fg=GRAY, wraplength=580).pack(pady=(0,10))

    # Risk card
    card = tk.Frame(root, bg=CARD, relief="flat")
    card.pack(fill="x", padx=20, pady=6)

    tk.Label(card, text="RISK SCORE:  18 / 20",
             font=("Segoe UI", 22, "bold"), bg=CARD, fg=RED).pack(pady=(12,2))
    tk.Label(card, text="RISK LEVEL:  ★ CRITICAL ★",
             font=("Segoe UI", 16, "bold"), bg=CARD, fg=RED).pack(pady=(0,4))
    tk.Label(card, text="⚠️  MALICIOUS CONTENT DETECTED",
             font=("Segoe UI", 12, "bold"), bg=CARD, fg=ORANGE).pack(pady=(0,12))

    # What was found
    info = tk.Frame(root, bg=CARD)
    info.pack(fill="x", padx=20, pady=4)
    tk.Label(info, text="🔍  Detected Signatures:",
             font=("Segoe UI", 9, "bold"), bg=CARD, fg=GRAY).pack(anchor="w", padx=10, pady=(8,2))

    sigs_box = tk.Text(info, height=4, bg="#2a0000", fg=RED,
                       font=("Courier New", 8), relief="flat", bd=0)
    sigs_box.pack(fill="x", padx=10, pady=(0,4))
    sigs_box.insert("end",
        "VirtualAllocEx · WriteProcessMemory · CreateRemoteThread\n"
        "SetWindowsHookEx · keylogger · reverse_shell · shellcode\n"
        "powershell -enc · DownloadString · msfvenom · CryptEncrypt\n"
        "ransom · bitcoin · invoke-expression · bypass (+3 more)")
    sigs_box.config(state="disabled")

    tk.Label(info, text="⚡  Reasons:", font=("Segoe UI", 9, "bold"),
             bg=CARD, fg=GRAY).pack(anchor="w", padx=10, pady=(6,2))
    for r in [
        "• 15 malicious binary/text signatures found",
        "• Running from suspicious location",
        "• Multiple high-risk indicators detected",
        "• File behaviour matches known malware patterns",
    ]:
        tk.Label(info, text=r, font=("Segoe UI", 9),
                 bg=CARD, fg=YELLOW).pack(anchor="w", padx=16)
    tk.Label(info, text="", bg=CARD).pack(pady=4)

    # Action instruction
    action = tk.Frame(root, bg="#300000", relief="flat")
    action.pack(fill="x", padx=20, pady=8)
    tk.Label(action,
             text="🗑️   ACTION REQUIRED:  DELETE THIS FILE IMMEDIATELY",
             font=("Segoe UI", 11, "bold"), bg="#300000", fg=RED).pack(pady=10)
    tk.Label(action,
             text="Open Project Sentinel → Files Tab → Click  🗑️ Delete",
             font=("Segoe UI", 9), bg="#300000", fg=ORANGE).pack(pady=(0,10))

    # Harmless note
    tk.Label(root,
             text="[ DEMO ONLY — This file is 100% harmless. Signatures are plain text strings. ]",
             font=("Segoe UI", 8), bg=BG, fg="#555555").pack(pady=(4,2))

    # Delete + Close buttons
    btn_frame = tk.Frame(root, bg=BG)
    btn_frame.pack(pady=8)

    def self_delete():
        if messagebox.askyesno("Confirm Delete",
            "Delete this file now?\n\n" + filepath):
            try:
                root.destroy()
                os.remove(filepath)
            except Exception as e:
                messagebox.showerror("Error", f"Could not delete:\n{e}")

    tk.Button(btn_frame, text="🗑️  Delete This File Now",
              font=("Segoe UI", 10, "bold"), bg=RED, fg=WHITE,
              relief="flat", padx=16, pady=8, cursor="hand2",
              command=self_delete).pack(side="left", padx=8)

    tk.Button(btn_frame, text="Close",
              font=("Segoe UI", 10), bg="#333333", fg=WHITE,
              relief="flat", padx=16, pady=8, cursor="hand2",
              command=root.destroy).pack(side="left", padx=8)

    root.mainloop()

if __name__ == "__main__":
    show_warning()