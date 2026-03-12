# scanner/live_monitor.py
# Live Process Monitor — shows ONLY truly running processes
# Accurate risk: Windows/McAfee/AV = Low, suspicious = High

import os
import threading
import time
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None

_lock           = threading.Lock()
_process_alerts = []
_seen_pids      = set()
_process_cache  = {}

# ══════════════════════════════════════════════════════════════
# WHITELIST — always Low risk
# ══════════════════════════════════════════════════════════════
WHITELIST = {
    # Windows core
    "system", "system idle process", "registry", "smss.exe",
    "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe",
    "taskhostw.exe", "sihost.exe", "ctfmon.exe", "fontdrvhost.exe",
    "runtimebroker.exe", "searchindexer.exe", "searchhost.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "applicationframehost.exe", "textinputhost.exe",
    "securityhealthsystray.exe", "securityhealthservice.exe",
    "spoolsv.exe", "audiodg.exe", "wuauclt.exe", "usoclient.exe",
    "trustedinstaller.exe", "tiworker.exe", "wudfhost.exe",
    "wsappx.exe", "sppsvc.exe", "sppextcomobj.exe", "sedsvc.exe",
    "waasmedicagent.exe", "mousocoreworker.exe", "msiexec.exe",
    "conhost.exe", "dllhost.exe", "wermgr.exe", "werfault.exe",
    "msdtc.exe", "vssvc.exe", "dismhost.exe", "cleanmgr.exe",
    # Antivirus / Security
    "mcshield.exe", "mcscancheck.exe", "mcuicnt.exe",        # McAfee
    "mcafee.exe", "mfefire.exe", "mfemms.exe", "mfevtps.exe",
    "masvc.exe", "macompatsvc.exe",                           # McAfee
    "mbam.exe", "mbamservice.exe", "mbamdaemon.exe",          # Malwarebytes
    "avgui.exe", "avgsvca.exe", "avgsvc.exe",                 # AVG
    "avastui.exe", "avastsvc.exe",                            # Avast
    "egui.exe", "ekrn.exe",                                   # ESET
    "bdagent.exe", "bdservicehost.exe",                       # Bitdefender
    "msmpeng.exe", "nissrv.exe", "mssense.exe",               # Windows Defender
    "sense.exe", "windefend.exe",
    # Browsers
    "chrome.exe", "msedge.exe", "firefox.exe",
    "brave.exe", "opera.exe", "vivaldi.exe",
    # Common apps
    "discord.exe", "spotify.exe", "steam.exe",
    "onedrive.exe", "teams.exe", "slack.exe",
    "zoom.exe", "skype.exe", "telegram.exe",
    "code.exe", "notepad.exe", "notepad++.exe",
    "calc.exe", "mspaint.exe", "wordpad.exe",
    # GPU / drivers
    "nvtray.exe", "nvdisplay.container.exe", "nvcontainer.exe",
    "igfxtray.exe", "igfxem.exe", "igfxhk.exe",
    "amdow.exe", "atieclxx.exe", "atiesrxx.exe",
    # Python / dev tools (for our own tool)
    "python.exe", "pythonw.exe", "flask.exe",
}

# Suspicious keywords — only flag if NOT in trusted path
SUSPICIOUS_KEYWORDS = [
    ("virus",       8), ("malware",    8), ("payload",  7),
    ("hack",        6), ("exploit",    6), ("keylog",   7),
    ("ransom",      7), ("backdoor",   7), ("trojan",   7),
    ("inject",      6), ("shellcode",  6), ("crypter",  6),
    ("sentineltest",6), ("fake_virus", 7), ("mshta",    4),
    ("wscript",     3), ("cscript",    3), ("certutil", 4),
]

SUSPICIOUS_PATHS = [
    ("\\appdata\\local\\temp\\", 6),
    ("\\temp\\",                 5),
    ("\\tmp\\",                  5),
    ("\\downloads\\",            4),
    ("\\desktop\\",              3),
    ("\\public\\",               3),
]

TRUSTED_PATHS = [
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\windowsapps\\",
]

SUSPICIOUS_CMDFLAGS = [
    ("-enc ",      4), ("-nop ",        3), ("-w hidden",   4),
    ("-bypass",    4), ("downloadstring",5), ("frombase64", 4),
    ("iex(",       5), ("invoke-expression", 5),
]


def _analyze(proc):
    """Analyze a single running process. Returns scored dict."""
    try:
        info = proc.as_dict(attrs=[
            "pid","name","exe","cmdline",
            "username","status","create_time","cpu_percent"
        ])
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

    name    = (info.get("name") or "").strip()
    exe     = (info.get("exe")  or "")
    cmdline = " ".join(info.get("cmdline") or [])
    status  = info.get("status") or "unknown"

    # Only include truly running/sleeping processes
    if status not in ("running", "sleeping", "disk-sleep", "idle"):
        return None

    name_lower = name.lower()
    exe_lower  = exe.lower()

    # Start time
    try:
        started = datetime.fromtimestamp(info["create_time"]).strftime("%H:%M:%S")
    except Exception:
        started = "N/A"

    # CPU
    try:
        cpu = round(proc.cpu_percent(interval=None), 1)
    except Exception:
        cpu = 0.0

    # ── Whitelist check — instant Low ──
    if name_lower in WHITELIST:
        return {
            "pid": info["pid"], "name": name, "exe": exe or "N/A",
            "cmdline": cmdline[:80] or "N/A", "username": info.get("username","N/A"),
            "status": status, "start_time": started, "cpu_pct": cpu,
            "risk_score": 0, "risk_level": "Low",
            "reasons": ["Trusted system/AV process"],
            "is_malicious": False,
        }

    # Trusted path check
    in_trusted = any(tp in exe_lower for tp in TRUSTED_PATHS)
    if in_trusted:
        return {
            "pid": info["pid"], "name": name, "exe": exe or "N/A",
            "cmdline": cmdline[:80] or "N/A", "username": info.get("username","N/A"),
            "status": status, "start_time": started, "cpu_pct": cpu,
            "risk_score": 0, "risk_level": "Low",
            "reasons": ["Located in trusted system path"],
            "is_malicious": False,
        }

    score   = 0
    reasons = []

    # Suspicious path
    for loc, pts in SUSPICIOUS_PATHS:
        if loc in exe_lower:
            score += pts
            reasons.append(f"Running from: {loc.strip(chr(92))}")
            break

    # Suspicious name keywords
    for kw, pts in SUSPICIOUS_KEYWORDS:
        if kw in name_lower or kw in exe_lower:
            score += pts
            reasons.append(f"Suspicious name: {kw}")

    # Suspicious cmdline
    for flag, pts in SUSPICIOUS_CMDFLAGS:
        if flag in cmdline.lower():
            score += pts
            reasons.append(f"Suspicious flag: {flag.strip()}")

    # Hidden exe
    if exe and os.path.exists(exe):
        try:
            import ctypes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(exe)
            if attrs != -1 and (attrs & 2):
                score += 5
                reasons.append("Hidden executable attribute")
        except Exception:
            pass

    score = max(score, 0)
    if score <= 2:   level = "Low"
    elif score <= 5: level = "Medium"
    else:            level = "High"

    if not reasons:
        reasons = ["No suspicious indicators"]

    return {
        "pid":          info["pid"],
        "name":         name,
        "exe":          exe or "N/A",
        "cmdline":      cmdline[:80] or "N/A",
        "username":     (info.get("username") or "N/A"),
        "status":       status,
        "start_time":   started,
        "cpu_pct":      cpu,
        "risk_score":   score,
        "risk_level":   level,
        "reasons":      reasons[:3],
        "is_malicious": False,
        "scanned_at":   datetime.now().strftime("%H:%M:%S"),
    }


def get_all_processes():
    """Returns ALL running processes scored and analyzed."""
    if psutil is None:
        return []
    results = []
    for proc in psutil.process_iter():
        try:
            data = _analyze(proc)
            if data:
                results.append(data)
        except Exception:
            continue
    results.sort(key=lambda x: (-x["risk_score"], x["name"].lower()))
    return results


def get_new_process_alerts():
    with _lock:
        alerts = list(_process_alerts)
        _process_alerts.clear()
    return alerts


def _monitor_loop():
    global _seen_pids
    if psutil is None:
        return
    for proc in psutil.process_iter(["pid"]):
        try:
            _seen_pids.add(proc.pid)
        except Exception:
            pass
    print(f"[LiveMonitor] Baseline: {len(_seen_pids)} processes")

    while True:
        time.sleep(3)
        try:
            current_pids = set()
            for proc in psutil.process_iter(["pid"]):
                try: current_pids.add(proc.pid)
                except: pass

            for pid in current_pids - _seen_pids:
                try:
                    proc = psutil.Process(pid)
                    data = _analyze(proc)
                    if data and data["risk_score"] > 0:
                        with _lock:
                            _process_alerts.append({
                                "type":       "PROCESS_NEW",
                                "pid":        data["pid"],
                                "name":       data["name"],
                                "exe":        data["exe"],
                                "risk_score": data["risk_score"],
                                "risk_level": data["risk_level"],
                                "reasons":    data["reasons"],
                                "is_malicious": False,
                                "message": f"New process: {data['name']} [{data['risk_level']}]"
                            })
                except Exception:
                    pass

            _seen_pids = current_pids
        except Exception as e:
            print(f"[LiveMonitor] Error: {e}")


def start_live_monitor():
    t = threading.Thread(target=_monitor_loop, daemon=True, name="LiveMonitor")
    t.start()
    print("[LiveMonitor] Live process scanner active")