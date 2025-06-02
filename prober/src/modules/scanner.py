import subprocess
import socket
import paramiko
import time

def run_nmap_scan(output_file):
    """Run nmap scan on the network to find SSH servers and save the results to a file"""
    # Known targets from our network
    known_targets = [
        {"ip": "192.168.125.30", "port": 2222, "name": "cowrie"},
        {"ip": "192.168.125.40", "port": 2022, "name": "sshesame"},
        {"ip": "192.168.125.44", "port": 8022, "name": "honeytrap"},
        {"ip": "192.168.125.42", "port": 22, "name": "heralding"}
        #{"ip": "192.168.125.90", "port": 2224, "name": "debian"},
    ]
    
    try:
        cmd = [
            "nmap", "-O", "-sV", "--script", "ssh2-enum-algos",
            "-p22,2022,2222,2223", "192.168.125.0/24",
            "-oN", output_file,
            "-T4"
        ]
        return known_targets
        print("[*] Running nmap scan...")
        subprocess.run(cmd, check=True)
        print(f"[+] Nmap scan completed successfully. Results saved to {output_file}")
    except subprocess.TimeoutExpired:
        print("[!] Nmap scan timed out")
        print("[+] Proceeding with known targets")
    except subprocess.CalledProcessError as e:
        print(f"[!] Nmap scan failed: {e}")
        print("[+] Proceeding with known targets")
    except Exception as e:
        print(f"[!] Unexpected error during nmap scan: {e}")
        print("[+] Proceeding with known targets")
    
    return known_targets
