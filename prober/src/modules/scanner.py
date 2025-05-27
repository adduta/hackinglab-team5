import subprocess
import os
import socket
import paramiko
import time


def run_zmap_scan(port, subnet, output_file):
    gw_mac = os.getenv("GATEWAY_MAC", "aa:bb:cc:dd:ee:ff")
    cmd = [
        "zmap",
        "-G", gw_mac,
        "-i", "eth0",
        "-p", str(port),
        subnet,
        "--blacklist-file=/dev/null",
        "-o", output_file
    ]
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if proc.returncode != 0:
        print(f"[!] ZMap failed on port {port} (exit {proc.returncode}):")
        print(proc.stderr.strip())
        return None
    return output_file


def run_nmap_scan(output_file):
    """Run nmap scan on the network to find SSH servers and save the results to a file"""
    # Known targets from our network
    known_targets = [
        {"ip": "192.168.125.30", "port": 2222, "name": "cowrie"},
        {"ip": "192.168.125.40", "port": 2022, "name": "sshesame"},
        # {"ip": "192.168.125.90", "port": 2224, "name": "debian"},
        # {"ip": "192.168.125.20", "port": 2223, "name": "sshhipot"}
    ]

    subnet = "192.168.125.0/24"
    ports = [22, 2022, 2222, 2223]
    zmap_results = []

    try:
        for port in ports:
            zmap_output = f"zmap_port_{port}.txt"
            print(f"[*] Running ZMap scan on port {port}...")
            run_zmap_scan(port, subnet, zmap_output)
            print(
                f"[+] ZMap scan on port {port} completed. Results saved to {zmap_output}"
            )

            with open(zmap_output, "r") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        zmap_results.append({"ip": ip, "port": port})
            os.remove(zmap_output)

        if not zmap_results:
            print("[!] No hosts found via ZMap. Proceeding with known targets.")
            return known_targets

        nmap_ips = list(set([result["ip"] for result in zmap_results]))
        nmap_ports = ",".join(str(port) for port in ports)
        cmd = [
            "nmap",
            "-O",
            "-sV",
            "--script",
            "ssh2-enum-algos",
            "-p",
            nmap_ports,
            "-oN",
            output_file,
            "-T4",
        ] + nmap_ips

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
