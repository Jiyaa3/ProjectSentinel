# scanner/risk_engine.py
# LEGITIMATE Dynamic Risk Engine
# Accurately scores persistence entries — minimizes false positives.
# Trusted apps like Chrome, Discord, Spotify score LOW.
# Real threats like scripts in Temp, hidden exes score HIGH.

import os


# ══════════════════════════════════════════════════════════════
# WHITELIST — These are always LOW risk regardless of path
# ══════════════════════════════════════════════════════════════
WHITELIST = [
    # Microsoft
    "msedge.exe", "msedgewebview2.exe", "onedrive.exe", "teams.exe",
    "outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe",
    "skype.exe", "lync.exe", "ms-teams.exe",
    "ctfmon.exe", "sihost.exe", "taskhostw.exe", "runtimebroker.exe",
    "searchindexer.exe", "explorer.exe", "notepad.exe", "calc.exe",
    "wuauclt.exe", "usoclient.exe", "trustedinstaller.exe", "tiworker.exe",
    "wudfhost.exe", "wsappx.exe", "sppsvc.exe", "sppextcomobj.exe",
    "sedsvc.exe", "waasmedicagent.exe", "mousocoreworker.exe",
    # Browsers
    "chrome.exe", "firefox.exe", "opera.exe", "brave.exe", "vivaldi.exe",
    # Common apps
    "discord.exe", "spotify.exe", "steam.exe", "epicgameslauncher.exe",
    "dropbox.exe", "googledrivefs.exe", "box.exe", "slack.exe",
    "zoom.exe", "webexmta.exe", "acrord32.exe",
    # GPU / hardware drivers
    "nvtray.exe", "nvcplui.exe", "nvdisplay.container.exe",
    "igfxtray.exe", "igfxem.exe", "igfxhk.exe", "amdow.exe",
    "radeoninstaller.exe", "atieclxx.exe",
    # Antivirus / security
    "mbam.exe", "mbamdaemon.exe", "avgui.exe", "avastui.exe",
    "egui.exe", "bdagent.exe", "mcuicnt.exe",
    # System utilities
    "ccleaner.exe", "ccleaner64.exe", "everything.exe",
]

# Trusted publisher paths — anything here is Low risk
TRUSTED_PATHS = [
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\",
    "\\program files\\microsoft\\",
    "\\program files (x86)\\microsoft\\",
    "\\program files\\google\\",
    "\\program files\\mozilla firefox\\",
    "\\program files\\discord\\",
    "\\program files\\spotify\\",
    "\\program files\\steam\\",
    "\\windowsapps\\",
    "\\winsxs\\",
    "\\program files\\",
    "\\program files (x86)\\",
]

# Trusted Microsoft keywords in name/path
TRUSTED_KEYWORDS = [
    "hotpatch", "windowsupdate", "windows update", "microsoftupdate",
    "wuauclt", "usoclient", "trustedinstaller", "tiworker",
    "wudfhost", "wsappx", "sppsvc", "sppextcomobj",
    "sedsvc", "waasmedicagent", "mousocoreworker",
    "nvtray", "igfxtray", "amdow",
    "edgeupdate", "googleupdate", "adobearm",
    "dropbox", "googledrivefs",
]

# ══════════════════════════════════════════════════════════════
# SUSPICIOUS INDICATORS — add points
# ══════════════════════════════════════════════════════════════

# High-risk path locations
SUSPICIOUS_PATHS = [
    ("\\appdata\\local\\temp\\",  +6),
    ("\\temp\\",                  +5),
    ("\\tmp\\",                   +5),
    ("\\appdata\\roaming\\",      +2),
    ("\\appdata\\local\\",        +1),
    ("\\downloads\\",             +4),
    ("\\desktop\\",               +3),
    ("\\public\\",                +3),
    ("\\programdata\\",           +1),
]

# High-risk file types
SUSPICIOUS_EXTENSIONS = [
    (".vbs",  +5),   # VBScript
    (".hta",  +5),   # HTML Application
    (".scr",  +5),   # Screensaver (classic malware)
    (".pif",  +5),   # Program Info File
    (".ps1",  +4),   # PowerShell script
    (".bat",  +4),   # Batch file
    (".cmd",  +4),   # Command script
    (".js",   +3),   # JavaScript
    (".jar",  +3),   # Java
    (".com",  +3),   # Old executable
    (".exe",  +1),   # Executable (mild)
    (".lnk",  +1),   # Shortcut
]

# Suspicious name keywords
SUSPICIOUS_NAMES = [
    ("virus",       +8),
    ("malware",     +8),
    ("payload",     +7),
    ("inject",      +6),
    ("hack",        +6),
    ("exploit",     +6),
    ("backdoor",    +7),
    ("trojan",      +7),
    ("keylog",      +7),
    ("ransom",      +7),
    ("crypter",     +6),
    ("sentineltest",+6),   # Our simulation
    ("fake_virus",  +7),   # Our simulation script
    # Masquerading names (only suspicious outside System32)
    ("svchost",     +4),
    ("lsass",       +5),
    ("winlogon",    +4),
    ("csrss",       +4),
    ("mshta",       +4),
    ("wscript",     +3),
    ("cscript",     +3),
    ("certutil",    +4),
    ("regsvr32",    +3),
    ("rundll32",    +2),
]


def _clean_path(path):
    """Extract actual exe path, removing quotes and arguments."""
    p = path.strip().strip('"')
    # Handle: "C:\path\file.exe" -args
    if '"' in path:
        parts = path.split('"')
        for part in parts:
            if part.strip() and ('\\' in part or '/' in part):
                p = part.strip()
                break
    # Handle: C:\path\file.exe -args
    elif ' -' in p or ' /' in p:
        p = p.split(' -')[0].split(' /')[0].strip()
    return p


def check_file_live(raw_path):
    """
    Live checks on the actual file on disk.
    Returns (score_delta, list_of_reasons).
    """
    score   = 0
    reasons = []
    path    = _clean_path(raw_path)

    if not path or path == "N/A":
        return 0, []

    if not os.path.exists(path):
        # Missing file is suspicious — planted then hidden/deleted
        score += 3
        reasons.append("File not found on disk (hidden or deleted)")
        return score, reasons

    try:
        size = os.path.getsize(path)
        if size == 0:
            score += 4
            reasons.append("Zero-byte file (suspicious)")
        elif size < 1024:
            score += 3
            reasons.append(f"Tiny file size ({size} bytes)")
        elif size < 10240:
            score += 1
    except Exception:
        pass

    # Hidden file attribute check (Windows only)
    try:
        import ctypes
        attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
        if attrs != -1 and (attrs & 2):  # FILE_ATTRIBUTE_HIDDEN
            score += 5
            reasons.append("File is hidden (Windows hidden attribute set)")
    except Exception:
        pass

    return score, reasons


def score_risk(name, path, location):
    """
    Accurately scores any persistence entry.

    Returns:
        dict with risk_score (int), risk_level (str), reasons (list)
    """
    score   = 0
    reasons = []

    path_lower = path.lower()
    name_lower = name.lower()
    exe_name   = os.path.basename(_clean_path(path_lower))

    # ══════════════════════════════════════════════════════════
    # STEP 1 — Whitelist check (instant Low if matched)
    # ══════════════════════════════════════════════════════════
    if exe_name in [w.lower() for w in WHITELIST]:
        return {
            "risk_score": 0,
            "risk_level": "Low",
            "reasons":    [f"Whitelisted known-safe application: {exe_name}"]
        }

    # Trusted Microsoft/system keywords
    for kw in TRUSTED_KEYWORDS:
        if kw in name_lower or kw in path_lower:
            return {
                "risk_score": 0,
                "risk_level": "Low",
                "reasons":    [f"Trusted system component: {kw}"]
            }

    # ══════════════════════════════════════════════════════════
    # STEP 2 — Trusted path bonus (subtract points)
    # ══════════════════════════════════════════════════════════
    in_trusted_path = False
    for tp in TRUSTED_PATHS:
        if tp in path_lower:
            score -= 3
            in_trusted_path = True
            reasons.append(f"Located in trusted path")
            break

    # ══════════════════════════════════════════════════════════
    # STEP 3 — Suspicious path scoring
    # ══════════════════════════════════════════════════════════
    if not in_trusted_path:
        for keyword, points in SUSPICIOUS_PATHS:
            if keyword in path_lower:
                score += points
                reasons.append(f"Suspicious location: {keyword.strip(chr(92))}")
                break

    # ══════════════════════════════════════════════════════════
    # STEP 4 — File extension scoring
    # ══════════════════════════════════════════════════════════
    ext = os.path.splitext(path_lower)[1].split('"')[0]
    for suspicious_ext, points in SUSPICIOUS_EXTENSIONS:
        if ext == suspicious_ext:
            if points >= 3:
                reasons.append(f"High-risk file type: {suspicious_ext}")
            score += points
            break

    # ══════════════════════════════════════════════════════════
    # STEP 5 — Suspicious name keywords
    # Only flag svchost/lsass etc if NOT in System32
    # ══════════════════════════════════════════════════════════
    system32_names = {"svchost", "lsass", "winlogon", "csrss"}
    for keyword, points in SUSPICIOUS_NAMES:
        if keyword in name_lower or keyword in path_lower:
            if keyword in system32_names and "system32" in path_lower:
                continue  # Legitimate location — skip
            score += points
            reasons.append(f"Suspicious keyword detected: {keyword}")

    # ══════════════════════════════════════════════════════════
    # STEP 6 — Location-based scoring
    # ══════════════════════════════════════════════════════════
    location_scores = {
        "HKCU Run":        +1,
        "HKLM Run":        +0,
        "Startup Folder":  +1,
        "Scheduled Tasks": +0,
    }
    score += location_scores.get(location, 0)

    # ══════════════════════════════════════════════════════════
    # STEP 7 — Live file checks
    # ══════════════════════════════════════════════════════════
    live_score, live_reasons = check_file_live(path)
    score   += live_score
    reasons += live_reasons

    # ══════════════════════════════════════════════════════════
    # STEP 8 — Multi-flag penalty
    # ══════════════════════════════════════════════════════════
    if score >= 8:
        score += 2
        reasons.append("Multiple risk indicators — elevated threat")

    # ══════════════════════════════════════════════════════════
    # FINAL — Clamp and determine level
    # ══════════════════════════════════════════════════════════
    score = max(score, 0)

    if score == 0:
        risk_level = "Low"
    elif score <= 3:
        risk_level = "Low"
    elif score <= 6:
        risk_level = "Medium"
    else:
        risk_level = "High"

    if not reasons:
        reasons = ["No suspicious indicators found"]

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "reasons":    reasons
    }


# ── Standalone test ──────────────────────────────────────────
if __name__ == "__main__":
    tests = [
        ("SentinelTest",         r'pythonw "C:\Project_Sentinel\simulation\fake_virus.py"', "HKCU Run"),
        ("OneDrive",             r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",        "HKCU Run"),
        ("chrome",               r"C:\Program Files\Google\Chrome\Application\chrome.exe",   "HKCU Run"),
        ("Discord",              r"C:\Users\Asus\AppData\Local\Discord\app-1.0.9\Discord.exe","HKCU Run"),
        ("Spotify",              r"C:\Users\Asus\AppData\Roaming\Spotify\Spotify.exe",        "HKCU Run"),
        ("updater",              r"C:\Users\Asus\AppData\Local\Temp\updater.exe",             "HKCU Run"),
        ("helper.vbs",           r"C:\Users\Asus\Downloads\helper.vbs",                       "Startup Folder"),
        ("svchost_fake",         r"C:\Users\Asus\AppData\Roaming\svchost.exe",                "HKCU Run"),
        ("svchost_real",         r"C:\Windows\System32\svchost.exe",                          "HKLM Run"),
        ("ctfmon",               r"C:\Windows\System32\ctfmon.exe",                           "HKCU Run"),
        ("waasmedicagent",       r"C:\Windows\System32\waasmedicagent.exe",                   "HKLM Run"),
        ("MalwareDropper",       r"C:\Users\Asus\AppData\Roaming\MalwareDropper.exe",         "Startup Folder"),
    ]

    print(f"\n{'Name':<25} {'Score':>5}  {'Level':<10}  Reason")
    print("─" * 80)
    for name, path, loc in tests:
        r = score_risk(name, path, loc)
        print(f"{name:<25} {r['risk_score']:>5}  {r['risk_level']:<10}  {r['reasons'][0]}")