from .registry_scan  import scan_registry
from .startup_scan   import scan_startup_folder
from .task_scan      import scan_scheduled_tasks
from .risk_engine    import score_risk
from .watcher        import start_watcher, get_alerts
from .notifier       import notify_new_threat, notify_removed, notify_startup
from .process_map    import map_processes_to_entries, get_all_suspicious_processes

from .live_monitor   import start_live_monitor, get_all_processes, get_new_process_alerts
from .temp_watcher import start_temp_watcher, get_temp_alerts, scan_watched_dirs