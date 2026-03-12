# scanner/task_scan.py
# Lists Windows Scheduled Tasks using the built-in schtasks command.
# Parses task name, status, and the executable path (if available).
#
# Example usage:
#   from scanner.task_scan import scan_scheduled_tasks
#   tasks = scan_scheduled_tasks()
#   for t in tasks:
#       print(t)

import subprocess


def scan_scheduled_tasks():
    """
    Queries all scheduled tasks using: schtasks /query /fo LIST /v

    Returns:
        list of dict: Each dict has:
            - name     : Task name (e.g. "\\Microsoft\\Windows\\SomeTask")
            - status   : Task status (e.g. "Ready", "Running", "Disabled")
            - path     : Executable path if found, else "N/A"
            - location : Always "Scheduled Tasks"
    """
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "LIST", "/v"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )
    except FileNotFoundError:
        print("[!] schtasks command not found. Are you running on Windows?")
        return []

    tasks   = []
    current = {}

    for line in result.stdout.splitlines():
        line = line.strip()

        if line.startswith("TaskName:"):
            current["name"] = line.split(":", 1)[1].strip()

        elif line.startswith("Status:"):
            current["status"] = line.split(":", 1)[1].strip()

        elif line.startswith("Task To Run:"):
            current["path"] = line.split(":", 1)[1].strip()

        # Once we have at least a name and status, save the task
        if "name" in current and "status" in current and "path" in current:
            tasks.append({
                "name":     current["name"],
                "status":   current["status"],
                "path":     current.get("path", "N/A"),
                "location": "Scheduled Tasks"
            })
            current = {}

    return tasks


# --- Standalone test ---
if __name__ == "__main__":
    tasks = scan_scheduled_tasks()
    print(f"Found {len(tasks)} scheduled tasks:\n")
    for task in tasks:
        print(f"  Name    : {task['name']}")
        print(f"  Status  : {task['status']}")
        print(f"  Path    : {task['path']}")
        print(f"  Location: {task['location']}")
        print()