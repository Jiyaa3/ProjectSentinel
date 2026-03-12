# 🛡️ Project Sentinel
**Offline Windows Persistence Analyzer — Educational Security Tool**

> Detect, simulate, and understand how malware survives reboots on Windows.
> Built with Python + Flask. 100% offline. 100% safe.

---

## What It Does
Project Sentinel scans your Windows PC for **persistence mechanisms** — the techniques malware uses to survive a reboot:

| Source | What it scans |
|---|---|
| 🔑 Registry Run Keys | `HKCU\...\Run` and `HKLM\...\Run` |
| 📁 Startup Folder | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` |
| ⏰ Scheduled Tasks | All tasks via `schtasks /query` |

Every entry is **risk-scored** (Low / Medium / High) and shown in a live Bootstrap dashboard.

---

## Demo — Full Attack Lifecycle
Click **"Launch Full Attack Demo"** to see all 4 effects at once:

1. 💬 **Popup** — "You have been hacked!" warning dialog
2. 🔴 **Malware Page** — Dramatic red detection page in browser
3. 💀 **Fake BSOD** — Blue Screen of Death in browser
4. 📊 **Dashboard** — `virus.exe` appears as HIGH RISK in the table

Then click **"Remove & Clean Up"** to remediate — exactly like an antivirus would.

---

## Installation

### Requirements
- Windows 10 / 11
- Python 3.8+

### Setup
```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/Project_Sentinel.git
cd Project_Sentinel

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# 3. Install dependencies
pip install flask

# 4. Run
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

---

## Optional: Compile virus.exe
To use a real `.exe` in the demo instead of a `.py` script:
```bash
pip install pyinstaller
build_exe.bat
```
This creates `simulation\virus.exe` — still 100% harmless.

---

## Folder Structure
```
Project_Sentinel/
├── app.py                        # Flask backend + all routes
├── build_exe.bat                 # Compiles fake_virus.py → virus.exe
├── scanner/
│   ├── __init__.py
│   ├── registry_scan.py          # Scans HKCU + HKLM Run keys
│   ├── startup_scan.py           # Scans Startup folder
│   ├── task_scan.py              # Lists scheduled tasks
│   └── risk_engine.py            # Scores Low / Medium / High
├── simulation/
│   ├── simulate_attack.py        # Inject / remove / launch fake virus
│   └── fake_virus.py             # 4 harmless demo effects
├── templates/
│   ├── dashboard.html            # Main Bootstrap dashboard
│   ├── hacked.html               # Red malware detected page
│   └── bsod.html                 # Fake Blue Screen of Death
├── static/
│   └── style.css                 # Dark theme styles
└── logs/                         # (reserved for future logging)
```

---

## ⚠️ Disclaimer
This tool is for **educational purposes only**.
- No real malware is created or deployed
- All simulations use `notepad.exe` or a harmless popup script
- No data is collected, transmitted, or stored
- Only affects the current Windows user (`HKCU`)

---

## Built With
- Python 3 — `winreg`, `subprocess`, `os`
- Flask — web framework
- Bootstrap 5 — dashboard UI
- PyInstaller — optional `.exe` compilation

---

*Made for learning how Windows persistence works — and how to detect it.*