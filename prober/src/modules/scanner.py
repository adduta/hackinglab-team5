import concurrent.futures as cf
import subprocess
import os
import re
import time

ZMAP_REGEX = re.compile(r"\bsend:\s+(\d+)\b")
# Toggle RUNNING_IN_DOCKER to False if conducting an actual network scan
RUNNING_IN_DOCKER = True
# Change the parameter HOST_SUBNET if conducting an actual network scan.
HOST_SUBNET = "192.168.1.0/24"
DOCKER_SUBNET = "192.168.125.0/24"


def run_zmap_scan(port, subnet, output_file):
    """Runs Zmap scan to provide Nmap with live host IPs if an actual network scan is perfomed."""
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
        "1",
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
    print(f"ZMap scan on port {port} took {delta} ns.", flush=True)

    if proc.returncode != 0:
        print(f"[!] ZMap failed on port {port} (exit {proc.returncode}):", flush=True)
        print(proc.stderr.strip())
        return None

    return output_file


def run_nmap_scan(output_file):
    """Runs nmap scan on the network to find SSH servers and saves the results to a file."""
    # Known targets from our network
    known_targets = [
        {"ip": "192.168.125.30", "port": 2222, "name": "cowrie"},
        {"ip": "192.168.125.40", "port": 2022, "name": "sshesame"},
        {"ip": "192.168.125.44", "port": 8022, "name": "honeytrap"},
        {"ip": "192.168.125.42", "port": 22, "name": "heralding"},
        {"ip": "192.168.125.90", "port": 2224, "name": "debian"},
    ]

    known_tuples = {(t["ip"], t["port"]) for t in known_targets}
    known_ips = [obj["ip"] for obj in known_targets]
    print(f"IPs known to be live: {known_ips}", flush=True)
    ports = [22, 2022, 2222, 2223, 2224, 8022]

    subnet = DOCKER_SUBNET if RUNNING_IN_DOCKER else HOST_SUBNET

    try:
        live_ips = set()
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
        print(f"ZMap total process took: {delta} ns.", flush=True)

        # Add found hosts for NMap scan.
        for port, path in zip(ports, zmap_files):
            if not os.path.exists(path):
                continue

            with open(path) as fh:
                for ip in map(str.strip, fh):
                    if not ip:
                        continue

                    live_ips.add(ip)
                    if (ip, port) in known_tuples:
                        continue

                    known_targets.append({"ip": ip, "port": port, "name": "zmap"})
                    known_tuples.add((ip, port))

        os.remove(path)

        if not live_ips:
            print("[!] No hosts found via ZMap. Proceeding with known targets.")
        else:
            print(f"IPs ZMap found: {live_ips}", flush=True)

        nmap_ips = list(live_ips) + known_ips
        print(f"IPs NMap will scan: {nmap_ips}", flush=True)
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

        print("[*] Running NMap scan...", flush=True)
        start = time.perf_counter_ns()
        subprocess.run(
            cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        delta = time.perf_counter_ns() - start
        print(f"NMap scan on all ports took {delta} ns.", flush=True)
        print(f"[+] NMap scan completed successfully. Results saved to {output_file}")
    except subprocess.TimeoutExpired:
        print("[!] NMap scan timed out")
        print("[+] Proceeding with known targets")
    except subprocess.CalledProcessError as e:
        print(f"[!] NMap scan failed: {e}")
        print("[+] Proceeding with known targets")
    except Exception as e:
        print(f"[!] Unexpected error during NMap scan: {e}")
        print("[+] Proceeding with known targets")

    return known_targets
