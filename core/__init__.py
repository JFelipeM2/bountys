"""
core/__init__.py
----------------
Paquete principal de asset-sentinel.
Expone los modulos publicos del core para importacion simplificada.
"""

from core.scanner import discover_subdomains, filter_live_hosts, run_nuclei_scan
from core.triage import analyze_vulnerability
from core.notifier import send_telegram_notification, send_scan_start_notification, send_scan_summary_notification

__all__ = [
    "discover_subdomains",
    "filter_live_hosts",
    "run_nuclei_scan",
    "analyze_vulnerability",
    "send_telegram_notification",
    "send_scan_start_notification",
    "send_scan_summary_notification",
]
