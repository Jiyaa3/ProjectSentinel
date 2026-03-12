# simulation/simulate_attack.py
# Simulates ALL 3 persistence types:
#   1. Registry Run key  (HKCU)
#   2. Startup folder entry
#   3. Scheduled task

import os
import sys
import subprocess
import winreg

SIM_NAME     = "SentinelTest_virus"
SIM_EXE      = r"C:\Windows\System32\calc.exe"   # harmless real exe
STARTUP_PATH = os.path.join(
    os.environ.get("APPDATA", ""),
    r"Microsoft\Windows\Start Menu\Programs\Startup",
    f"{SIM_NAME}.lnk"
)
TASK_NAME    = "SentinelTest_Task"

_sim_active  = False


def is_simulation_active():
    return _sim_active


# ── 1. Registry Run ───────────────────────────────────────────

def simulate_add():
    global _sim_active
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Run",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, SIM_NAME, 0, winreg.REG_SZ, SIM_EXE)
        winreg.CloseKey(key)
        _sim_active = True
        return True
    except Exception as e:
        print(f"[Sim] Registry add failed: {e}")
        return False


def simulate_remove():
    global _sim_active
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Run",
                             0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, SIM_NAME)
        winreg.CloseKey(key)
        _sim_active = False
        return True
    except FileNotFoundError:
        _sim_active = False
        return False
    except Exception as e:
        print(f"[Sim] Registry remove failed: {e}")
        return False


# ── 2. Startup Folder ────────────────────────────────────────

def simulate_startup_add():
    """Create a .lnk shortcut in the Startup folder."""
    try:
        # Use PowerShell to create a shortcut (no extra libs needed)
        ps = f"""
$ws  = New-Object -ComObject WScript.Shell
$lnk = $ws.CreateShortcut('{STARTUP_PATH}')
$lnk.TargetPath = '{SIM_EXE}'
$lnk.Description = 'SentinelTest Startup Entry'
$lnk.Save()
"""
        subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, timeout=10)
        return os.path.exists(STARTUP_PATH)
    except Exception as e:
        print(f"[Sim] Startup add failed: {e}")
        return False


def simulate_startup_remove():
    """Remove the startup folder shortcut."""
    try:
        if os.path.exists(STARTUP_PATH):
            os.remove(STARTUP_PATH)
            return True
        return False
    except Exception as e:
        print(f"[Sim] Startup remove failed: {e}")
        return False


def is_startup_active():
    return os.path.exists(STARTUP_PATH)


# ── 3. Scheduled Task ─────────────────────────────────────────

def simulate_task_add():
    """Create a fake scheduled task."""
    try:
        cmd = [
            "schtasks", "/create",
            "/tn", TASK_NAME,
            "/tr", SIM_EXE,
            "/sc", "onlogon",
            "/f"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except Exception as e:
        print(f"[Sim] Task add failed: {e}")
        return False


def simulate_task_remove():
    """Delete the fake scheduled task."""
    try:
        cmd = ["schtasks", "/delete", "/tn", TASK_NAME, "/f"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except Exception as e:
        print(f"[Sim] Task remove failed: {e}")
        return False


def is_task_active():
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/tn", TASK_NAME],
            capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


# ── Launch fake virus page ─────────────────────────────────────

def launch_fake_virus():
    try:
        from simulation.fake_virus import launch
        launch()
    except Exception as e:
        print(f"[Sim] Launch failed: {e}")