import concurrent.futures as cf
import subprocess
import os
import re
import time

ZMAP_REGEX = re.compile(r"\bsend:\s+(\d+)\b")


def run_zmap_scan(port, subnet, output_file):
    gw_mac = os.getenv("GATEWAY_MAC", "aa:bb:cc:dd:ee:ff")

    cmd = [
        "zmap",
        "-G",
        gw_mac,
        "-i",
        "eth0",
        "-p",
        str(port),
        "--blacklist-file=/dev/null",
        "-r",
        "100000",
        "--cooldown-time",
        "0",
        "-o",
        output_file,
        "-f",
        "saddr",
        subnet,
    ]
    start = time.perf_counter_ns()
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    delta = time.perf_counter_ns() - start
    print(f"ZMap scan on port {port} took {delta} ns WOWOWOWOWO.")

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
        start = time.perf_counter_ns()
        zmap_files = [f"zmap_port_{p}.txt" for p in ports]
        with cf.ThreadPoolExecutor() as ex:
            futures = [
                ex.submit(run_zmap_scan, p, subnet, fname)
                for p, fname in zip(ports, zmap_files)
            ]
            for f in futures:
                f.result()
        delta = time.perf_counter_ns() - start
        print(f"ZMAP total process took: {delta} ns.")

        live_ips = set()
        for path in zmap_files:
            if os.path.exists(path):
                with open(path) as f:
                    for ip in f:
                        ip = ip.strip()
                        if ip:
                            live_ips.add(ip)
                os.remove(path)

        if not live_ips:
            print("[!] No hosts found via ZMap. Proceeding with known targets.")
            return known_targets

        nmap_ips = list(set([result["ip"] for result in zmap_results]))
        nmap_ports = ",".join(str(port) for port in ports)
        cmd = [
            "nmap",
            "-Pn",
            "-n",
            "-sS",
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

        print("[*] Running nmap scan...")
        start = time.perf_counter_ns()
        subprocess.run(
            cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        delta = time.perf_counter_ns() - start
        print(f"NMAP scan on all ports took {delta} ns wow.")
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
