# scanner/file_scanner.py
# File Scanner — shows files currently OPEN by running processes.
# Different from process monitor — shows FILES not executables.
# Scans content for malicious signatures.

import os
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None

MALICIOUS_BYTES = [
    b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
    b"SetWindowsHookEx", b"GetAsyncKeyState", b"keylogger",
    b"reverse_shell", b"shellcode", b"msfvenom", b"metasploit",
    b"powershell -enc", b"powershell -nop", b"DownloadString",
    b"DownloadFile", b"CryptEncrypt", b"ransom", b"bitcoin",
]

MALICIOUS_TEXT = [
    "invoke-expression", "iex(", "downloadstring", "frombase64string",
    "shellcode", "reverse_shell", "payload", "exploit", "keylog",
    "ransomware", "bitcoin", "powershell -", "wscript.shell",
    "createobject(", "net user /add", "reg add", "schtasks /create",
    "bypass", "-w hidden", "-noprofile",
]

SCRIPT_EXTS  = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".py"}

# File types worth scanning
SCAN_EXTS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
    ".js",  ".hta", ".scr", ".pif", ".com", ".py",
    ".jar", ".sh",  ".php", ".asp", ".aspx",
    # Also scan media/doc formats for embedded signatures
    ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".mp3", ".mp4", ".avi", ".wav", ".mkv",
    ".docx", ".xlsx", ".pdf", ".zip", ".rar",
}

TRUSTED_DIRS = [
    "\\windows\\system32\\", "\\windows\\syswow64\\",
    "\\program files\\microsoft\\", "\\program files\\windows",
    "\\windows\\winsxs\\", "\\windowsapps\\",
]

# File extensions to SKIP (not worth scanning)
SKIP_EXTS = {
    ".log", ".ini", ".cfg",
    # .txt kept for scanning — can contain signatures
    ".ico", ".svg",
    ".ttf", ".otf", ".woff", ".woff2",
    ".sqlite", ".db", ".ldb",
}


def _is_trusted(path):
    p = path.lower()
    return any(td in p for td in TRUSTED_DIRS)


def _scan_content(filepath):
    """Returns (is_malicious, matches)"""
    if not os.path.exists(filepath):
        return False, []
    if _is_trusted(filepath):
        return False, []

    ext     = os.path.splitext(filepath)[1].lower()
    matches = []

    if ext in SKIP_EXTS:
        return False, []

    try:
        if ext in SCRIPT_EXTS:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(256_000).lower()
            for sig in MALICIOUS_TEXT:
                if sig in content:
                    matches.append(sig)
        elif ext in SCAN_EXTS or ext == ".exe":
            with open(filepath, "rb") as f:
                content = f.read(256_000)
            for sig in MALICIOUS_BYTES:
                if sig in content:
                    matches.append(sig.decode(errors="ignore"))
    except (PermissionError, OSError):
        return False, []
    except Exception:
        return False, []

    return bool(matches), matches[:4]


def _score_file(path, status):
    """Score a file for risk."""
    score   = 0
    reasons = []
    p       = path.lower()

    if _is_trusted(path):
        return {"risk_score": 0, "risk_level": "Low",
                "is_malicious": False, "mal_matches": [],
                "reasons": ["Trusted system file"]}

    # Suspicious locations
    sus_locs = [
        ("\\appdata\\local\\temp\\", 6),
        ("\\temp\\", 5), ("\\tmp\\", 5),
        ("\\downloads\\", 4), ("\\desktop\\", 3),
        ("\\public\\", 3), ("\\appdata\\roaming\\", 2),
    ]
    for loc, pts in sus_locs:
        if loc in p:
            score += pts
            reasons.append(f"Suspicious location: {loc.strip(chr(92))}")
            break

    # Extension
    ext = os.path.splitext(p)[1]
    ext_pts = {".vbs":5,".hta":5,".scr":5,".ps1":4,
               ".bat":4,".cmd":4,".js":3,".exe":1,".py":1}
    if ext in ext_pts:
        score += ext_pts[ext]
        if ext_pts[ext] >= 4:
            reasons.append(f"High-risk file type: {ext}")

    # Content scan
    is_mal, matches = _scan_content(path)
    if is_mal:
        score += 6 if len(matches) >= 3 else 3
        reasons += [f"Signature: {m}" for m in matches[:2]]

    # Currently executing = more risky if already suspicious
    if status == "Running" and score > 2:
        score += 2
        reasons.append("Currently executing")

    score = max(score, 0)
    if score <= 2:   level = "Low"
    elif score <= 5: level = "Medium"
    else:            level = "High"

    if not reasons:
        reasons = ["No suspicious indicators"]

    return {
        "risk_score":   score,
        "risk_level":   level,
        "is_malicious": is_mal,
        "mal_matches":  matches[:3],
        "reasons":      reasons[:3],
    }


def get_all_open_files():
    """
    Returns files currently OPEN by running processes.
    Excludes system DLLs, fonts, and other noise.
    Shows actual user/app files with risk scoring.
    """
    if psutil is None:
        return []

    seen         = {}   # filepath_lower → entry
    running_exes = set()

    # Collect running exes first
    for proc in psutil.process_iter(["exe"]):
        try:
            exe = proc.info.get("exe") or ""
            if exe:
                running_exes.add(exe.lower())
        except Exception:
            continue

    # Collect open file handles
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            proc_name = proc.info.get("name") or ""
            try:
                for f in proc.open_files():
                    fp  = f.path
                    fpl = fp.lower()

                    # Skip system noise
                    ext = os.path.splitext(fpl)[1]
                    if ext in {".dll", ".mui", ".ttf", ".otf",
                               ".nls", ".dat", ".sys", ".drv"}:
                        continue

                    # Skip windows internal paths
                    if ("\\windows\\system32\\" in fpl or
                        "\\windows\\syswow64\\" in fpl or
                        "\\windows\\winsxs\\"   in fpl):
                        continue

                    if fpl not in seen:
                        is_running = fpl in running_exes
                        seen[fpl] = {
                            "path":      fp,
                            "name":      os.path.basename(fp),
                            "status":    "Running" if is_running else "Open",
                            "process":   proc_name,
                            "pid":       proc.info["pid"],
                        }
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        except Exception:
            continue

    # Score each file
    results = []
    for _, entry in seen.items():
        risk = _score_file(entry["path"], entry["status"])

        # Only include files that are either risky or running
        # Skip low-risk idle files to reduce noise
        if risk["risk_score"] == 0 and entry["status"] == "Open":
            continue

        results.append({
            "name":         entry["name"],
            "path":         entry["path"],
            "status":       entry["status"],
            "process":      entry["process"],
            "pid":          entry["pid"],
            "risk_score":   risk["risk_score"],
            "risk_level":   risk["risk_level"],
            "is_malicious": risk["is_malicious"],
            "mal_matches":  risk["mal_matches"],
            "reasons":      risk["reasons"],
            "scanned_at":   datetime.now().strftime("%H:%M:%S"),
        })

    # Sort: malicious → high → running → by score
    results.sort(key=lambda x: (
        -int(x["is_malicious"]),
        -x["risk_score"],
        x["status"] != "Running"
    ))
    return results