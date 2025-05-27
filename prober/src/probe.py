#!/usr/bin/env python3
"""
SSH Honeypot Detection Script
This script probes SSH servers to detect potential honeypots by analyzing their behavior,
protocol implementations, and responses to various authentication attempts.
"""

from modules import run_nmap_scan, probe_ssh_server


def main():
    """Main execution function for the SSH honeypot detection script."""
    # 1. Run Nmap scan to discover SSH servers and their configurations
    nmap_output_file = "/prober/src/nmap_results.txt"
    targets = run_nmap_scan(nmap_output_file)
    # 2. Create commands you want to run in each container
    commands = {"whoami": "whoami", "ls": "ls -la", "ps": "ps aux", "uname": "uname -a"}
    # 3. Probe each target
    interface = "eth0"
    for target in targets:
        pcap_file = f"ssh_probe_{target['name']}.pcap"
        print(f"\n[*] Probing {target['name']} at {target['ip']}:{target['port']}")
        probe_ssh_server(
            target["ip"],
            target["port"],
            "root",
            "admin",
            pcap_file,
            interface,
            commands=commands,
        )


if __name__ == "__main__":
    main()
