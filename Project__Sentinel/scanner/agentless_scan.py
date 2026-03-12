# scanner/agentless_scan.py
# ══════════════════════════════════════════════════════════════
# Agentless scanner — scan ANY machine by IP
# No agent required. Port scan + banner grab + vuln detection.
# Works on Metasploitable, Windows, Linux, anything on LAN.
# ══════════════════════════════════════════════════════════════

import socket
import threading
import time
import concurrent.futures

# ── Well-known ports + service names ─────────────────────────
PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    111:   "RPCBind",
    135:   "MS-RPC",
    139:   "NetBIOS",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    512:   "Rexec",
    513:   "Rlogin",
    514:   "RSH",
    1099:  "Java-RMI",
    1524:  "Ingreslock-Backdoor",
    2049:  "NFS",
    2121:  "FTP-Alt",
    3306:  "MySQL",
    3389:  "RDP",
    4444:  "Metasploit-Handler",
    4848:  "GlassFish",
    5432:  "PostgreSQL",
    5900:  "VNC",
    5985:  "WinRM",
    6000:  "X11",
    6667:  "IRC",
    8009:  "AJP",
    8080:  "HTTP-Alt",
    8180:  "Tomcat",
    8443:  "HTTPS-Alt",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

# ── Vulnerability database ────────────────────────────────────
VULN_DB = {
    "FTP": [
        {"name": "FTP Cleartext Auth",
         "severity": "High",
         "cve": "N/A",
         "desc": "FTP transmits credentials in plaintext — sniffable on network",
         "fix": "Replace with SFTP or FTPS"},
        {"name": "Possible Anonymous FTP",
         "severity": "High",
         "cve": "N/A",
         "desc": "FTP may allow anonymous login — attacker can read/write files",
         "fix": "Disable anonymous FTP login"},
    ],
    "Telnet": [
        {"name": "Telnet Enabled",
         "severity": "Critical",
         "cve": "CVE-1999-0619",
         "desc": "Telnet sends ALL data including passwords in cleartext",
         "fix": "Disable Telnet, use SSH instead"},
    ],
    "SMB": [
        {"name": "SMB Exposed",
         "severity": "High",
         "cve": "CVE-2017-0144",
         "desc": "SMB open — EternalBlue/MS17-010 ransomware vector",
         "fix": "Block port 445 at firewall, patch Windows"},
    ],
    "NetBIOS": [
        {"name": "NetBIOS Information Leak",
         "severity": "Medium",
         "cve": "CVE-1999-0621",
         "desc": "NetBIOS leaks hostname, domain, username to unauthenticated users",
         "fix": "Disable NetBIOS over TCP/IP"},
    ],
    "MySQL": [
        {"name": "MySQL Exposed to Network",
         "severity": "High",
         "cve": "N/A",
         "desc": "MySQL accessible from network — should be localhost only",
         "fix": "Bind MySQL to 127.0.0.1 in my.cnf"},
    ],
    "PostgreSQL": [
        {"name": "PostgreSQL Exposed to Network",
         "severity": "High",
         "cve": "N/A",
         "desc": "PostgreSQL accessible remotely — database at risk",
         "fix": "Restrict pg_hba.conf to localhost"},
    ],
    "VNC": [
        {"name": "VNC Remote Desktop Open",
         "severity": "High",
         "cve": "CVE-2006-2369",
         "desc": "VNC gives full graphical remote access — often weak/no password",
         "fix": "Disable VNC or require strong password + firewall"},
    ],
    "RDP": [
        {"name": "RDP Exposed",
         "severity": "High",
         "cve": "CVE-2019-0708",
         "desc": "RDP open — BlueKeep/DejaBlue vulnerable versions common",
         "fix": "Patch Windows, use NLA, restrict with firewall"},
    ],
    "Rexec": [
        {"name": "Rexec Service Running",
         "severity": "Critical",
         "cve": "CVE-1999-0618",
         "desc": "Legacy remote exec daemon — no encryption, easily exploited",
         "fix": "Disable rexecd immediately"},
    ],
    "Rlogin": [
        {"name": "Rlogin Service Running",
         "severity": "Critical",
         "cve": "CVE-1999-0651",
         "desc": "Legacy rlogin — trust-based auth, no encryption",
         "fix": "Disable rlogind immediately"},
    ],
    "RSH": [
        {"name": "RSH Remote Shell",
         "severity": "Critical",
         "cve": "CVE-1999-0651",
         "desc": "Remote Shell — unauthenticated execution via .rhosts",
         "fix": "Disable rshd immediately"},
    ],
    "Ingreslock-Backdoor": [
        {"name": "INGRESLOCK BACKDOOR (Port 1524)",
         "severity": "Critical",
         "cve": "N/A",
         "desc": "Port 1524 — classic Metasploitable backdoor shell, gives root",
         "fix": "Rebuild system — this is a deliberate backdoor"},
    ],
    "Java-RMI": [
        {"name": "Java RMI Remote Code Execution",
         "severity": "High",
         "cve": "CVE-2011-3556",
         "desc": "Java RMI — remote code execution possible via deserialization",
         "fix": "Disable RMI or restrict access with firewall"},
    ],
    "NFS": [
        {"name": "NFS Share Exposed",
         "severity": "High",
         "cve": "CVE-1999-0170",
         "desc": "NFS may allow unauthenticated access to filesystem",
         "fix": "Restrict exports in /etc/exports"},
    ],
    "IRC": [
        {"name": "IRC / UnrealIRCd Backdoor",
         "severity": "Critical",
         "cve": "CVE-2010-2075",
         "desc": "UnrealIRCd 3.2.8.1 has a backdoor — direct RCE as root",
         "fix": "Remove IRC service"},
    ],
    "Tomcat": [
        {"name": "Apache Tomcat Exposed",
         "severity": "High",
         "cve": "CVE-2019-0232",
         "desc": "Tomcat manager likely uses default creds (admin:admin)",
         "fix": "Change default credentials, restrict manager app"},
    ],
    "HTTP": [
        {"name": "HTTP Unencrypted Web Server",
         "severity": "Low",
         "cve": "N/A",
         "desc": "Web server on HTTP — traffic unencrypted",
         "fix": "Enable HTTPS"},
    ],
    "HTTP-Alt": [
        {"name": "HTTP Alternate Port",
         "severity": "Low",
         "cve": "N/A",
         "desc": "Web server on alternate port — check for admin panels",
         "fix": "Review what service is exposed"},
    ],
    "SSH": [
        {"name": "SSH Service",
         "severity": "Info",
         "cve": "N/A",
         "desc": "SSH open — check for weak credentials or outdated version",
         "fix": "Use key-based auth, disable root login"},
    ],
    "RPCBind": [
        {"name": "RPCBind Exposed",
         "severity": "Medium",
         "cve": "CVE-2010-2060",
         "desc": "RPC portmapper — used to enumerate NFS/NIS services",
         "fix": "Block port 111 at firewall"},
    ],
    "Metasploit-Handler": [
        {"name": "Metasploit Listener Active",
         "severity": "Critical",
         "cve": "N/A",
         "desc": "Port 4444 open — active Metasploit handler or backdoor shell",
         "fix": "Investigate immediately"},
    ],
    "X11": [
        {"name": "X11 Display Server Exposed",
         "severity": "High",
         "cve": "CVE-1999-0526",
         "desc": "X11 open — attacker can capture screen, inject keystrokes",
         "fix": "Disable X11 TCP, use xauth"},
    ],
    "GlassFish": [
        {"name": "GlassFish Admin Console",
         "severity": "High",
         "cve": "CVE-2011-1511",
         "desc": "GlassFish admin console exposed — default creds often unchanged",
         "fix": "Restrict admin console access"},
    ],
    "AJP": [
        {"name": "AJP Ghostcat Vulnerability",
         "severity": "Critical",
         "cve": "CVE-2020-1938",
         "desc": "Ghostcat — AJP connector allows file read and possible RCE",
         "fix": "Disable AJP connector in Tomcat"},
    ],
    "MongoDB": [
        {"name": "MongoDB No Authentication",
         "severity": "Critical",
         "cve": "N/A",
         "desc": "MongoDB with no auth — entire database readable/writable",
         "fix": "Enable MongoDB authentication"},
    ],
    "Elasticsearch": [
        {"name": "Elasticsearch No Authentication",
         "severity": "Critical",
         "cve": "N/A",
         "desc": "Elasticsearch open — all indexed data accessible",
         "fix": "Enable X-Pack security"},
    ],
}

SEVERITY_SCORE  = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Info": 0}
SEVERITY_ORDER  = ["Critical", "High", "Medium", "Low", "Info"]


def _scan_port(ip, port, timeout=1.2):
    """Returns (port, open, banner)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) == 0:
            banner = ""
            try:
                s.settimeout(1.5)
                if port in (80, 8080, 8180, 8443):
                    s.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                else:
                    s.send(b"\r\n")
                raw = s.recv(256)
                banner = raw.decode("utf-8", errors="replace").strip()[:150]
            except Exception:
                pass
            s.close()
            return (port, True, banner)
        s.close()
    except Exception:
        pass
    return (port, False, "")


def scan_machine(ip, timeout=1.2, on_progress=None):
    """Full agentless scan. Returns structured result dict."""
    open_ports  = []
    vulns       = []
    total_score = 0
    ports_list  = list(PORTS.keys())

    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
        futures = {ex.submit(_scan_port, ip, p, timeout): p for p in ports_list}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner = future.result()
            done += 1
            if on_progress:
                on_progress(done, len(ports_list))
            if is_open:
                service = PORTS.get(port, f"Unknown-{port}")
                open_ports.append({
                    "port": port, "service": service,
                    "banner": banner, "open": True,
                })
                for v in VULN_DB.get(service, []):
                    sc = SEVERITY_SCORE.get(v["severity"], 0)
                    total_score += sc
                    vulns.append({
                        "port": port, "service": service,
                        "name": v["name"], "severity": v["severity"],
                        "cve":  v["cve"],  "desc":     v["desc"],
                        "fix":  v["fix"],  "score":    sc,
                    })

    open_ports.sort(key=lambda x: x["port"])
    vulns.sort(key=lambda x: -SEVERITY_SCORE.get(x["severity"], 0))

    if   total_score >= 25: risk_level = "Critical"
    elif total_score >= 12: risk_level = "High"
    elif total_score >= 5:  risk_level = "Medium"
    else:                   risk_level = "Low"

    summary = {
        "open_ports":  len(open_ports),
        "total_vulns": len(vulns),
        "critical": len([v for v in vulns if v["severity"] == "Critical"]),
        "high":     len([v for v in vulns if v["severity"] == "High"]),
        "medium":   len([v for v in vulns if v["severity"] == "Medium"]),
        "low":      len([v for v in vulns if v["severity"] == "Low"]),
    }

    return {
        "ip":         ip,
        "scanned_at": time.strftime("%H:%M:%S"),
        "open_ports": open_ports,
        "vulns":      vulns,
        "risk_score": total_score,
        "risk_level": risk_level,
        "summary":    summary,
    }


# ── Background scan cache ─────────────────────────────────────
_cache      = {}   # ip → result
_status     = {}   # ip → status dict
_cache_lock = threading.Lock()


def start_agentless_scan(ip):
    with _cache_lock:
        if _status.get(ip, {}).get("running"):
            return False
        _status[ip] = {"running": True, "progress": 0,
                        "total": len(PORTS), "started": time.strftime("%H:%M:%S")}

    def _run():
        def progress(done, total):
            with _cache_lock:
                _status[ip]["progress"] = done
                _status[ip]["total"]    = total
        result = scan_machine(ip, on_progress=progress)
        with _cache_lock:
            _cache[ip]  = result
            _status[ip] = {"running": False, "progress": len(PORTS),
                           "total": len(PORTS), "done": True,
                           "completed": time.strftime("%H:%M:%S")}
        print(f"[AgentlessScan] ✅ {ip} — {len(result['open_ports'])} open ports  "
              f"score={result['risk_score']} ({result['risk_level']})")

    threading.Thread(target=_run, daemon=True).start()
    return True


def get_agentless_result(ip):
    with _cache_lock:
        return _cache.get(ip)


def get_agentless_status(ip):
    with _cache_lock:
        return _status.get(ip, {"running": False, "progress": 0, "total": len(PORTS)})
