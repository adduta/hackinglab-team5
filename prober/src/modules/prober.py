import time
from .capture import start_packet_capture, stop_packet_capture
from .ssh_analyzer import try_ssh_auth, password_auth, analyze_pcap

def probe_ssh_server(host, port, username, password, pcap_file, interface):
    """Probe the SSH server and print the result"""
    print(f"Probing {host}:{port} with {username}@{password}")
    capture_proc = start_packet_capture(pcap_file, interface, port=port)
    time.sleep(5)
    try_ssh_auth(host, port, username, password_auth, password)
    time.sleep(5)
    stop_packet_capture(capture_proc)
    analyze_pcap(pcap_file) 