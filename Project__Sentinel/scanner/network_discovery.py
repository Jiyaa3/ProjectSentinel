# scanner/network_discovery.py
# Stub implementation for missing network discovery features.

def start_discovery():
    """No-op discovery when module is unavailable"""
    return False

def get_machines():
    """Return empty machine list"""
    return []

def add_manual_machine(ip):
    """No-op add machine"""
    return None

def get_machine_count():
    """Return default machine count"""
    return 0

def fetch_machine_scan(ip):
    """Return empty scan results"""
    return {}
