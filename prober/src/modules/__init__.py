"""
SSH Honeypot Detection Modules
This package contains modules for detecting and analyzing SSH honeypots.

Modules:
    - scanner: Network scanning functionality using nmap
    - capture: Packet capture functionality using tcpdump
    - ssh_analyzer: SSH protocol analysis and authentication
    - prober: Main probing functionality for SSH servers
"""

from .scanner import run_nmap_scan
from .capture import start_packet_capture, stop_packet_capture
from .ssh_analyzer import (
    analyze_pcap,
    try_ssh_auth,
    password_auth,
    public_key_auth
)
from .prober import probe_ssh_server
from .utils import clean_ansi_escape_codes

__all__ = [
    'run_nmap_scan',
    'start_packet_capture',
    'stop_packet_capture',
    'analyze_pcap',
    'try_ssh_auth',
    'password_auth',
    'public_key_auth',
    'probe_ssh_server',
    'clean_ansi_escape_codes'
] 