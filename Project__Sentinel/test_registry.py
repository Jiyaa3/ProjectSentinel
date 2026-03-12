from registry_scan import scan_run_keys

entries = scan_run_keys()

for item in entries:
    print(item)