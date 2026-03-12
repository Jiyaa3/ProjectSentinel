# scanner/process_map.py
# Process Map — matches persistence entries to currently RUNNING processes.
# Shows which startup entries are actively running right now.
# Uses psutil (pip install psutil)

import os

def get_running_processes():
    """
    Returns a dict of {exe_name_lower: [pid, pid, ...]} for all running processes.
    """
    processes = {}
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'status']):
            try:
                name = (proc.info['name'] or '').lower()
                pid  = proc.info['pid']
                exe  = (proc.info['exe'] or '').lower()
                if name:
                    processes.setdefault(name, []).append({
                        "pid":    pid,
                        "exe":    exe,
                        "status": proc.info['status']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except ImportError:
        print("[ProcessMap] psutil not installed. Run: pip install psutil")
    return processes


def map_processes_to_entries(entries):
    """
    Takes a list of persistence entry dicts and enriches each with:
        - is_running  (bool)   : Is the process currently running?
        - pids        (list)   : PIDs of matching processes
        - proc_status (str)    : Process status if running

    Args:
        entries (list): List of scored entry dicts from scanners

    Returns:
        list: Same entries with process info added
    """
    running = get_running_processes()
    result  = []

    for entry in entries:
        enriched = dict(entry)

        # Extract exe name from path
        path     = entry.get("path", "")
        exe_name = os.path.basename(path.strip('"').split('"')[0]).lower()

        if exe_name and exe_name in running:
            procs = running[exe_name]
            enriched["is_running"]  = True
            enriched["pids"]        = [p["pid"] for p in procs]
            enriched["proc_status"] = procs[0]["status"] if procs else "unknown"

            # Bump risk score if a suspicious process is actively running
            if entry.get("risk_level") == "High":
                enriched["running_note"] = "⚠️ ACTIVE — running right now"
            else:
                enriched["running_note"] = "✅ Running"
        else:
            enriched["is_running"]   = False
            enriched["pids"]         = []
            enriched["proc_status"]  = "not running"
            enriched["running_note"] = "—"

        result.append(enriched)

    return result


def get_all_suspicious_processes():
    """
    Scans ALL running processes and flags any that look suspicious.
    Returns list of flagged process dicts.
    """
    suspicious = []
    SUSPICIOUS_NAMES = [
        "powershell", "cmd", "wscript", "cscript", "mshta",
        "certutil", "regsvr32", "rundll32", "bitsadmin",
        "virus", "malware", "payload", "hack", "inject",
        "sentineltest", "fake_virus",
    ]

    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
            try:
                name    = (proc.info['name'] or '').lower()
                exe     = (proc.info['exe'] or '').lower()
                cmdline = ' '.join(proc.info['cmdline'] or []).lower()

                for sus in SUSPICIOUS_NAMES:
                    if sus in name or sus in exe:
                        suspicious.append({
                            "pid":      proc.info['pid'],
                            "name":     proc.info['name'],
                            "exe":      proc.info['exe'] or "N/A",
                            "cmdline":  cmdline[:120],
                            "username": proc.info['username'] or "N/A",
                            "reason":   f"Suspicious process name: {sus}"
                        })
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except ImportError:
        print("[ProcessMap] psutil not installed. Run: pip install psutil")

    return suspicious