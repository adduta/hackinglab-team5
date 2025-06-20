import subprocess
import tempfile
import os
from typing import Dict
import json
from datetime import datetime

def run_canary_methods(host, port, output_dir="/prober/results"):
    results = {}
    print("\n=== Canary Probes ===")

    # 1. Try root public key
    results["root_key_auth"] = try_publickey_auth("root", host, port)

    # 2. Try admin public key
    results["admin_key_auth"] = try_publickey_auth("admin", host, port)

    # 3. Try RSA key with ssh-rsa HostKeyAlgorithms
    results["rsa_key_auth"] = try_publickey_auth("root", host, port, force_rsa=True)

    # 4. Fake user auth
    results["fake_user_auth"] = try_publickey_auth("notarealuser", host, port)

    # 5. Bogus banner test
    # banner_cmd = f"SSH-2.0-OpenSSH_8.4p1 FakeEdition\r\n"
    # results["bogus_banner_response"] = send_custom_banner(host, port, banner_cmd)

    
    fake_version_cmd = f"SSH-3.14159-BogusBanner\\r\\n"
    results["bogus_banner"] = send_custom_banner(host, port, fake_version_cmd)


    # 6. CRLF ping
    crlf_cmd = f"\\r\\n"
    results["crlf_response"] = send_custom_banner(host, port, crlf_cmd)

    # Save as JSON
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"canary_results_{host.replace('.', '_')}_{port}.json")
    with open(out_path, "w") as f:
        json.dump({
            "timestamp": datetime.utcnow().isoformat(),
            "target": f"{host}:{port}",
            "results": results
        }, f, indent=2)
    print(f"Canary results saved to: {out_path}")
    return results

def try_publickey_auth(username: str, host: str, port: int, force_rsa: bool = False) -> str:
    """Attempt public key authentication with a temp key."""
    import os
    import tempfile

    fd, key_path = tempfile.mkstemp()
    os.close(fd)
    os.remove(key_path)  # Remove the empty file so ssh-keygen can create it

    try:
        ssh_keygen_cmd = ['ssh-keygen', '-q', '-t', 'rsa', '-f', key_path, '-N', '']
        subprocess.run(ssh_keygen_cmd, check=True)

        ssh_cmd = [
            "ssh",
            "-vvv",
            "-tt",
            "-o", "StrictHostKeyChecking=no",
            "-o", "PreferredAuthentications=publickey",
            "-i", key_path,  # if you're using a key
        ]

        if force_rsa:
            ssh_cmd += ['-o', 'HostKeyAlgorithms=+ssh-rsa']
        ssh_cmd += ['-p', str(port), f'{username}@{host}']

        result = subprocess.run(ssh_cmd, capture_output=True, timeout=10, text=True)

        return result.stderr + result.stdout
    except Exception as e:
        return f"Error during SSH auth for {username}: {str(e)}"
    finally:
        try:
            os.remove(key_path)
            os.remove(key_path + ".pub")
        except FileNotFoundError:
            pass


def send_custom_banner(host: str, port: int, banner: str) -> str:
    """Send a custom string to the SSH port and return the response."""
    try:
        cmd = f"printf '{banner}' | nc -v -w 3 {host} {port}"
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=6).decode()
    except subprocess.TimeoutExpired:
        return "Timeout"
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode(errors='ignore')}"


def generate_temp_key(key_type="rsa"):
    # Create a temporary file path for the key (no file created yet)
    key_fd, key_path = tempfile.mkstemp()
    os.close(key_fd)
    os.unlink(key_path)  # Ensure ssh-keygen can write to it

    try:
        subprocess.run(
            ['ssh-keygen', '-q', '-t', key_type, '-f', key_path, '-N', ''],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return key_path
    except subprocess.CalledProcessError as e:
        print(f"[!] ssh-keygen failed: {e.stderr.decode()}")
        return None