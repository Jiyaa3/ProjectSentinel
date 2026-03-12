# scanner/registry_scan.py
# Scans Windows Registry Run keys for persistence entries.
# Checks both HKCU (current user) and HKLM (all users / system-wide).
#
# Example usage:
#   from scanner.registry_scan import scan_registry
#   entries = scan_registry()
#   for e in entries:
#       print(e)

import winreg

# The two Run key locations we want to scan
RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run",  "HKCU Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run",  "HKLM Run"),
]


def scan_registry():
    """
    Scans HKCU and HKLM Run registry keys for startup entries.

    Returns:
        list of dict: Each dict has:
            - name     : Registry value name (the label for the entry)
            - path     : The executable path stored in the registry
            - location : Which hive it came from (e.g. "HKCU Run")
    """
    results = []

    for hive, key_path, location_label in RUN_KEYS:
        try:
            # Open the key in read-only mode
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        except FileNotFoundError:
            # Key doesn't exist on this machine — skip it
            continue
        except PermissionError:
            # HKLM may require admin rights — skip gracefully
            print(f"[!] Permission denied reading: {location_label}")
            continue

        # Loop through all values in the key
        index = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, index)
                results.append({
                    "name":     name,
                    "path":     value,
                    "location": location_label
                })
                index += 1
            except OSError:
                # No more values to read
                break

        winreg.CloseKey(key)

    return results


# --- Standalone test ---
if __name__ == "__main__":
    entries = scan_registry()
    print(f"Found {len(entries)} registry Run entries:\n")
    for entry in entries:
        print(f"  Name    : {entry['name']}")
        print(f"  Path    : {entry['path']}")
        print(f"  Location: {entry['location']}")
        print()