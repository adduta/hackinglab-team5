import time
from .capture import start_packet_capture, stop_packet_capture
from .honeypot_fingerprinter import HoneypotFingerprinter
from .ssh_analyzer import try_ssh_auth, password_auth, analyze_pcap

def probe_ssh_server(host, port, username, password, pcap_file, interface,commands):
    """Probe the SSH server and print the result"""
    print(f"Probing {host}:{port} with {username}:{password}")
    capture_proc = start_packet_capture(pcap_file, interface, port=port)
    time.sleep(5)
    cmd_results, auth_output = try_ssh_auth(host, port, username, password_auth, password,commands)
    time.sleep(3)
    stop_packet_capture(capture_proc)
    fingerprinter = HoneypotFingerprinter(
        results=cmd_results,
        auth_output=auth_output,
        pcap_file=pcap_file
    )
    time.sleep(5)
    fingerprinter.analyze_all_responses()
    time.sleep(5)
    analyze_pcap(pcap_file)

