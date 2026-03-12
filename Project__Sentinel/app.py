# app.py — Project Sentinel Flask Backend
# pip install flask psutil win10toast reportlab
# python app.py → http://127.0.0.1:5000

import sys, os, json, time, csv, io
from datetime import datetime
sys.path.insert(0, os.path.dirname(__file__))

from flask import (Flask, render_template, redirect, url_for,
                   flash, Response, stream_with_context, request)

from scanner.registry_scan import scan_registry
from scanner.startup_scan  import scan_startup_folder
from scanner.task_scan     import scan_scheduled_tasks
from scanner.risk_engine   import score_risk
from scanner.watcher       import start_watcher, get_alerts
from scanner.live_monitor  import start_live_monitor, get_all_processes, get_new_process_alerts
from scanner.file_scanner  import get_all_open_files
from scanner.temp_watcher      import start_temp_watcher, get_temp_alerts, scan_watched_dirs

try:
    from scanner.network_discovery import start_discovery, get_machines, add_manual_machine, get_machine_count, fetch_machine_scan
except ImportError:
    def start_discovery():
        return False
    def get_machines():
        return []
    def add_manual_machine(ip):
        return None
    def get_machine_count():
        return 0
    def fetch_machine_scan(ip):
        return {}

try:
    from scanner.drive_scanner     import start_drive_scan_async, get_drive_scan_results, get_drive_scan_status
except ImportError:
    def start_drive_scan_async():
        return False
    def get_drive_scan_results():
        return {"status": "unavailable"}
    def get_drive_scan_status():
        return {"status": "unavailable"}

from logs.logger           import log_alert, get_logs, clear_logs, get_stats
from scanner.hash_checker  import check_entry, get_all_hashes, clear_hashes
from simulation.simulate_attack import (
    simulate_add, simulate_remove, is_simulation_active, launch_fake_virus,
    simulate_startup_add, simulate_startup_remove, is_startup_active,
    simulate_task_add, simulate_task_remove, is_task_active
)

app = Flask(__name__)
app.secret_key = "sentinel-secret-key"

SIMULATION_THREATS = [
    {
        "name": "BSOD_Attack.exe",
        "path": r"C:\Users\Asus\AppData\Local\Temp\BSOD_Attack.exe",
        "location": "HKCU Run", "risk_score": 15, "risk_level": "High",
        "reasons": ["Fake BSOD payload", "Suspicious Temp path", "Simulation active"],
    },
    {
        "name": "MalwareDropper.exe",
        "path": r"C:\Users\Asus\AppData\Roaming\MalwareDropper.exe",
        "location": "Startup Folder", "risk_score": 18, "risk_level": "High",
        "reasons": ["Malware dropper", "AppData persistence", "Simulation active"],
    },
]


def run_all_scanners():
    all_entries = []

    for item in scan_registry():
        risk = score_risk(item["name"], item["path"], item["location"])
        h    = check_entry(item["name"], item["path"])
        if h["flagged"]: risk["risk_score"] += 5; risk["reasons"].insert(0, "⚠️ File hash MODIFIED since last scan")
        if risk["risk_score"] > 6: risk["risk_level"] = "High"
        all_entries.append({"name": item["name"], "path": item["path"],
                            "location": item["location"], **risk, **{"hash_status": h["hash_status"], "first_seen": h["first_seen"]}})

    for item in scan_startup_folder():
        risk = score_risk(item["name"], item["full_path"], item["location"])
        h    = check_entry(item["name"], item["full_path"])
        if h["flagged"]: risk["risk_score"] += 5; risk["reasons"].insert(0, "⚠️ File hash MODIFIED since last scan")
        if risk["risk_score"] > 6: risk["risk_level"] = "High"
        all_entries.append({"name": item["name"], "path": item["full_path"],
                            "location": item["location"], **risk, **{"hash_status": h["hash_status"], "first_seen": h["first_seen"]}})

    for item in scan_scheduled_tasks():
        path = item.get("path", "N/A")
        risk = score_risk(item["name"], path, item["location"])
        h    = check_entry(item["name"], path)
        if h["flagged"]: risk["risk_score"] += 5; risk["reasons"].insert(0, "⚠️ File hash MODIFIED since last scan")
        if risk["risk_score"] > 6: risk["risk_level"] = "High"
        all_entries.append({"name": item["name"], "path": path,
                            "location": item["location"], **risk, **{"hash_status": h["hash_status"], "first_seen": h["first_seen"]}})

    if is_simulation_active():
        for t in SIMULATION_THREATS:
            t["hash_status"] = "New"; t["first_seen"] = "—"
            all_entries.append(t)

    all_entries.sort(key=lambda x: x["risk_score"], reverse=True)
    return all_entries


# ── Dashboard ─────────────────────────────────────────────────

@app.route("/")
def dashboard():
    entries     = run_all_scanners()
    high_risk   = sum(1 for e in entries if e["risk_level"] == "High")
    medium_risk = sum(1 for e in entries if e["risk_level"] == "Medium")
    low_risk    = sum(1 for e in entries if e["risk_level"] == "Low")
    return render_template("dashboard.html",
        entries=entries, total=len(entries),
        high_risk=high_risk, medium_risk=medium_risk, low_risk=low_risk,
        sim_active=is_simulation_active())


# ── Simulation ────────────────────────────────────────────────

@app.route("/simulate/add", methods=["POST"])
def sim_add():
    if simulate_add():
        flash("🔴 virus.exe injected into HKCU Run!", "danger")
    else:
        flash("❌ Injection failed. Try as Administrator.", "danger")
    return redirect(url_for("dashboard"))


@app.route("/simulate/remove", methods=["POST"])
def sim_remove():
    if simulate_remove():
        flash("✅ virus.exe removed. Registry is clean.", "success")
    else:
        flash("⚠️ Entry not found.", "secondary")
    return redirect(url_for("dashboard"))


@app.route("/simulate/launch", methods=["POST"])
def sim_launch():
    simulate_add()
    launch_fake_virus()
    flash("💀 Full attack demo launched!", "danger")
    return redirect(url_for("dashboard"))


@app.route("/hacked")
def hacked():
    return render_template("hacked.html")


@app.route("/bsod")
def bsod():
    return render_template("bsod.html")


# ── SSE Stream ────────────────────────────────────────────────

@app.route("/stream")
def stream():
    def event_stream():
        while True:
            for alert in get_alerts():
                yield "data: " + json.dumps(alert) + "\n\n"
            for alert in get_new_process_alerts():
                yield "data: " + json.dumps(alert) + "\n\n"
            for alert in get_temp_alerts():
                yield "data: " + json.dumps(alert) + "\n\n"
            yield "data: " + json.dumps({"type": "heartbeat"}) + "\n\n"
            time.sleep(3)
    return Response(stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── API endpoints ─────────────────────────────────────────────

@app.route("/api/scan")
def api_scan():
    return Response(json.dumps(run_all_scanners()), mimetype="application/json")


@app.route("/api/processes")
def api_processes():
    try:
        return Response(json.dumps(get_all_processes()), mimetype="application/json")
    except Exception as e:
        return Response(json.dumps([]), mimetype="application/json")


@app.route("/api/files")
def api_files():
    try:
        # Combine open files + files found in watched dirs
        open_files    = get_all_open_files()
        watched_files = scan_watched_dirs()
        # Merge — avoid duplicates by path
        seen_paths = {f["path"].lower() for f in open_files}
        for f in watched_files:
            if f["path"].lower() not in seen_paths:
                open_files.append(f)
        open_files.sort(key=lambda x: (-int(x["is_malicious"]), -x["risk_score"]))
        return Response(json.dumps(open_files), mimetype="application/json")
    except Exception as e:
        print(f"[API/files] {e}")
        return Response(json.dumps([]), mimetype="application/json")



# ── Simulate Startup Folder ───────────────────────────────────

@app.route("/simulate/startup/add", methods=["POST"])
def sim_startup_add():
    if simulate_startup_add():
        flash("🔴 Startup folder entry created — SentinelTest_virus.lnk", "danger")
    else:
        flash("❌ Startup simulation failed. Try as Administrator.", "danger")
    return redirect(url_for("dashboard"))


@app.route("/simulate/startup/remove", methods=["POST"])
def sim_startup_remove():
    if simulate_startup_remove():
        flash("✅ Startup folder entry removed.", "success")
    else:
        flash("⚠️ Startup entry not found.", "secondary")
    return redirect(url_for("dashboard"))


# ── Simulate Scheduled Task ───────────────────────────────────

@app.route("/simulate/task/add", methods=["POST"])
def sim_task_add():
    if simulate_task_add():
        flash("🔴 Scheduled task created — SentinelTest_Task", "danger")
    else:
        flash("❌ Task simulation failed. Try as Administrator.", "danger")
    return redirect(url_for("dashboard"))


@app.route("/simulate/task/remove", methods=["POST"])
def sim_task_remove():
    if simulate_task_remove():
        flash("✅ Scheduled task removed.", "success")
    else:
        flash("⚠️ Task not found.", "secondary")
    return redirect(url_for("dashboard"))


# ── Hash checker routes ───────────────────────────────────────

@app.route("/api/hashes")
def api_hashes():
    return Response(json.dumps(get_all_hashes()), mimetype="application/json")


@app.route("/hashes/clear", methods=["POST"])
def hashes_clear():
    clear_hashes()
    flash("✅ Hash baseline cleared — next scan will rebuild it.", "success")
    return redirect(url_for("dashboard"))


# ── API: simulation status ────────────────────────────────────

@app.route("/api/sim_status")
def api_sim_status():
    return Response(json.dumps({
        "registry": is_simulation_active(),
        "startup":  is_startup_active(),
        "task":     is_task_active(),
    }), mimetype="application/json")

# ── Real BSOD Demo ───────────────────────────────────────────

@app.route("/simulate/realbsod", methods=["POST"])
def sim_real_bsod():
    """
    Step 1 — Injects virus into registry (Sentinel detects in 3s)
    Step 2 — Waits 5 seconds
    Step 3 — Triggers real BSOD
    VM ONLY — do not run on real PC
    """
    trigger_bsod_delayed = None
    try:
        from simulation.real_bsod import trigger_bsod_delayed
    except ImportError:
        try:
            from simulation.bsod_demo import run_bsod as trigger_bsod_delayed
        except ImportError:
            trigger_bsod_delayed = None

    if callable(trigger_bsod_delayed):
        try:
            simulate_add()   # inject registry entry first
            try:
                trigger_bsod_delayed(delay_seconds=5)
            except TypeError:
                trigger_bsod_delayed()
            flash("💀 Real BSOD triggered! Sentinel will detect virus in 3s, BSOD in 5s. Watch the dashboard!", "danger")
        except Exception as e:
            flash(f"❌ BSOD trigger failed: {e} — Run as Administrator", "danger")
    else:
        flash("⚠️ BSOD simulation module not available. Install the simulation package or use /simulate/attack demo instead.", "danger")

    return redirect(url_for("dashboard"))


# ── ACTION: Drop fake malware demo files ─────────────────────

@app.route("/simulate/drop_fake", methods=["POST"])
def drop_fake_malware():
    """
    Copies fake_malware_demo files into Temp folder
    so the Files scanner detects them as MALICIOUS.
    Completely harmless — just strings inside a file.
    """
    import shutil
    sim_dir = os.path.join(os.path.dirname(__file__), "simulation")
    temp    = os.environ.get("TEMP", os.path.expanduser("~"))
    files   = [
        "fake_malware_demo.py",
        "fake_malware_demo.bat",
        "fake_malware_demo.txt",
        "fake_malware_demo.ps1",
        "fake_malware_demo.vbs",
    ]
    dropped = []
    for src in [os.path.join(sim_dir, f) for f in files]:
        if os.path.exists(src):
            dst = os.path.join(temp, os.path.basename(src))
            shutil.copy2(src, dst)
            dropped.append(os.path.basename(src))

    if dropped:
        flash(f"🦠 Fake malware dropped into Temp: {', '.join(dropped)} — open Files tab to see DETECTED!", "danger")
    else:
        flash("❌ Source files not found in simulation folder.", "danger")
    return redirect(url_for("dashboard"))


@app.route("/simulate/remove_fake", methods=["POST"])
def remove_fake_malware():
    """Remove the fake malware demo files from Temp."""
    import glob
    temp  = os.environ.get("TEMP", os.path.expanduser("~"))
    files = ["fake_malware_demo.py", "fake_malware_demo.bat"]
    temp  = os.environ.get("TEMP", os.path.expanduser("~"))
    files = [
        "fake_malware_demo.py",  "fake_malware_demo.bat",
        "fake_malware_demo.txt", "fake_malware_demo.ps1",
        "fake_malware_demo.vbs",
    ]
    removed = []
    for f in files:
        path = os.path.join(temp, f)
        if os.path.exists(path):
            os.remove(path)
            removed.append(f)
    if removed:
        flash(f"✅ Fake malware removed: {', '.join(removed)}", "success")
    else:
        flash("⚠️ No fake malware files found in Temp.", "secondary")
    return redirect(url_for("dashboard"))


# ── ACTION: Kill Process ──────────────────────────────────────

@app.route("/action/kill/<int:pid>", methods=["POST"])
def kill_process(pid):
    try:
        import psutil
        proc = psutil.Process(pid)
        name = proc.name()
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        return Response(json.dumps({
            "success": True,
            "message": f"Process '{name}' (PID {pid}) terminated."
        }), mimetype="application/json")
    except ImportError:
        return Response(json.dumps({"success": False,
            "message": "psutil not installed."}), mimetype="application/json")
    except psutil.NoSuchProcess:
        return Response(json.dumps({"success": False,
            "message": f"PID {pid} not found — already exited."}), mimetype="application/json")
    except psutil.AccessDenied:
        return Response(json.dumps({"success": False,
            "message": "Access denied — run Sentinel as Administrator."}), mimetype="application/json")
    except Exception as e:
        return Response(json.dumps({"success": False,
            "message": str(e)}), mimetype="application/json")


# ── ACTION: Delete File ───────────────────────────────────────

@app.route("/action/delete", methods=["POST"])
def delete_file():
    data     = request.get_json() or {}
    filepath = data.get("path", "").strip()

    if not filepath:
        return Response(json.dumps({"success": False,
            "message": "No file path provided."}), mimetype="application/json")

    # Safety — never delete system files
    fp_lower = filepath.lower()
    PROTECTED = ["\\windows\\system32\\", "\\windows\\syswow64\\",
                 "\\program files\\windows", "\\windowsapps\\"]
    for p in PROTECTED:
        if p in fp_lower:
            return Response(json.dumps({"success": False,
                "message": "Cannot delete protected system file."}), mimetype="application/json")

    if not os.path.exists(filepath):
        return Response(json.dumps({"success": False,
            "message": "File not found on disk."}), mimetype="application/json")
    try:
        os.remove(filepath)
        return Response(json.dumps({"success": True,
            "message": f"Deleted: {os.path.basename(filepath)}"}), mimetype="application/json")
    except PermissionError:
        return Response(json.dumps({"success": False,
            "message": "Permission denied — file may be in use or needs Admin rights."}), mimetype="application/json")
    except Exception as e:
        return Response(json.dumps({"success": False,
            "message": str(e)}), mimetype="application/json")


# ── ACTION: Open File Location ────────────────────────────────

@app.route("/action/locate", methods=["POST"])
def locate_file():
    import subprocess
    data     = request.get_json() or {}
    filepath = data.get("path", "").strip()

    if not filepath:
        return Response(json.dumps({"success": False,
            "message": "No path provided."}), mimetype="application/json")
    try:
        if os.path.exists(filepath):
            subprocess.Popen(["explorer", "/select,", filepath])
        else:
            folder = os.path.dirname(filepath)
            if os.path.exists(folder):
                subprocess.Popen(["explorer", folder])
            else:
                return Response(json.dumps({"success": False,
                    "message": "Path not found."}), mimetype="application/json")
        return Response(json.dumps({"success": True,
            "message": "Opened in Windows Explorer."}), mimetype="application/json")
    except Exception as e:
        return Response(json.dumps({"success": False,
            "message": str(e)}), mimetype="application/json")


# ── Pages ─────────────────────────────────────────────────────

@app.route("/live")
@app.route("/processes")
def live_monitor():
    return render_template("live_monitor.html")


@app.route("/files")
def files_page():
    return render_template("files.html")


@app.route("/logs")
def logs_page():
    logs  = get_logs(200)
    stats = get_stats()
    return render_template("logs.html", logs=logs, stats=stats)


@app.route("/logs/clear", methods=["POST"])
def logs_clear():
    clear_logs()
    flash("✅ Logs cleared.", "success")
    return redirect(url_for("logs_page"))


# ── Export ────────────────────────────────────────────────────

@app.route("/export/csv")
def export_csv():
    entries = run_all_scanners()
    output  = io.StringIO()
    writer  = csv.writer(output)
    writer.writerow(["#","Name","Path","Location","Score","Level","Reasons","Timestamp"])
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for i, e in enumerate(entries, 1):
        writer.writerow([i, e["name"], e["path"], e["location"],
                         e["risk_score"], e["risk_level"],
                         "; ".join(e.get("reasons", [])), ts])
    output.seek(0)
    fname = f"sentinel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(output.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.route("/export/pdf")
def export_pdf():
    entries = run_all_scanners()
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib           import colors
        from reportlab.lib.units     import mm
        from reportlab.platypus      import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles    import getSampleStyleSheet

        buf    = io.BytesIO()
        doc    = SimpleDocTemplate(buf, pagesize=A4,
                     leftMargin=15*mm, rightMargin=15*mm,
                     topMargin=15*mm, bottomMargin=15*mm)
        styles = getSampleStyleSheet()
        elems  = []

        elems.append(Paragraph("Project Sentinel — Persistence Report", styles["Title"]))
        elems.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
        elems.append(Spacer(1, 8*mm))

        high   = sum(1 for e in entries if e["risk_level"] == "High")
        medium = sum(1 for e in entries if e["risk_level"] == "Medium")
        low    = sum(1 for e in entries if e["risk_level"] == "Low")
        elems.append(Paragraph(
            f"Total: {len(entries)}  |  High: {high}  |  Medium: {medium}  |  Low: {low}",
            styles["Normal"]))
        elems.append(Spacer(1, 8*mm))

        data = [["#","Name","Location","Score","Level","Top Reason"]]
        for i, e in enumerate(entries, 1):
            data.append([str(i), e["name"][:30], e["location"],
                         str(e["risk_score"]), e["risk_level"],
                         e.get("reasons",["—"])[0][:50]])

        t = Table(data, colWidths=[10*mm,55*mm,35*mm,18*mm,22*mm,None])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), colors.HexColor("#161b22")),
            ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
            ("FONTSIZE",      (0,0),(-1,0), 10),
            ("FONTSIZE",      (0,1),(-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),
             [colors.HexColor("#f9f9f9"), colors.white]),
            ("GRID",          (0,0),(-1,-1), 0.3, colors.grey),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ]))
        for i, e in enumerate(entries, 1):
            if e["risk_level"] == "High":
                t.setStyle(TableStyle([("BACKGROUND",(0,i),(-1,i),colors.HexColor("#ffe0e0"))]))
            elif e["risk_level"] == "Medium":
                t.setStyle(TableStyle([("BACKGROUND",(0,i),(-1,i),colors.HexColor("#fff8e0"))]))
        elems.append(t)
        doc.build(elems)
        buf.seek(0)
        fname = f"sentinel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return Response(buf.getvalue(), mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={fname}"})
    except ImportError:
        flash("❌ reportlab not installed. Run: pip install reportlab", "danger")
        return redirect(url_for("dashboard"))


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════
# MACHINES — Multi-host network scanning
# ══════════════════════════════════════════════════════════════

@app.route("/machines")
def machines():
    return render_template("machines.html")


@app.route("/api/machines")
def api_machines():
    data = get_machines()
    return Response(json.dumps(data), mimetype="application/json")


@app.route("/api/machines/add", methods=["POST"])
def api_machines_add():
    ip = (request.json or {}).get("ip", "").strip()
    if not ip:
        return Response(json.dumps({"success": False}), mimetype="application/json")
    info = add_manual_machine(ip)
    if info:
        return Response(json.dumps({"success": True, "info": info}), mimetype="application/json")
    return Response(json.dumps({"success": False}), mimetype="application/json")


@app.route("/api/machine_scan/<ip>")
def api_machine_scan(ip):
    data = fetch_machine_scan(ip)
    return Response(json.dumps(data), mimetype="application/json")


@app.route("/api/local_info")
def api_local_info():
    import socket, platform
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"
    return Response(json.dumps({
        "ip":       local_ip,
        "os":       platform.system() + " " + platform.release(),
        "hostname": socket.gethostname(),
    }), mimetype="application/json")


@app.route("/api/drive_scan/start", methods=["POST"])
def api_drive_scan_start():
    started = start_drive_scan_async()
    return Response(json.dumps({"started": started}), mimetype="application/json")


@app.route("/api/drive_scan/status")
def api_drive_scan_status():
    return Response(json.dumps(get_drive_scan_status()), mimetype="application/json")


@app.route("/api/drive_scan/results")
def api_drive_scan_results():
    return Response(json.dumps(get_drive_scan_results()), mimetype="application/json")


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    start_watcher()
    start_live_monitor()
    start_temp_watcher()
    start_discovery()
    print("\n" + "="*52)
    print("  🛡️  Project Sentinel — All Systems Active")
    print("  📡  Watcher + Live Monitor: RUNNING")
    print("  🌐  Open: http://127.0.0.1:5000")
    print("="*52 + "\n")
    app.run(debug=False, host="127.0.0.1", port=5000, threaded=True)