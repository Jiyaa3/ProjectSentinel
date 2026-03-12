# scanner/startup_scan.py
# Scans the Windows Startup folder for the current user.
# Any file placed here is automatically run when the user logs in.
#
# Example usage:
#   from scanner.startup_scan import scan_startup_folder
#   entries = scan_startup_folder()
#   for e in entries:
#       print(e)

import os


def scan_startup_folder():
    """
    Scans the current user's Windows Startup folder.

    Startup folder path:
        %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup

    Returns:
        list of dict: Each dict has:
            - name      : Filename (e.g. "MyApp.lnk")
            - full_path : Complete path to the file
            - location  : Always "Startup Folder"
    """
    # Build the path using the APPDATA environment variable
    startup_path = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "Windows", "Start Menu", "Programs", "Startup"
    )

    results = []

    # Check the folder actually exists before scanning
    if not os.path.exists(startup_path):
        print(f"[!] Startup folder not found: {startup_path}")
        return results

    # Loop through every file in the startup folder
    for filename in os.listdir(startup_path):
        full_path = os.path.join(startup_path, filename)

        # Only include files, not subfolders
        if os.path.isfile(full_path):
            results.append({
                "name":      filename,
                "full_path": full_path,
                "location":  "Startup Folder"
            })

    return results


# --- Standalone test ---
if __name__ == "__main__":
    entries = scan_startup_folder()
    print(f"Found {len(entries)} startup folder entries:\n")
    for entry in entries:
        print(f"  Name     : {entry['name']}")
        print(f"  Full Path: {entry['full_path']}")
        print(f"  Location : {entry['location']}")
        print()