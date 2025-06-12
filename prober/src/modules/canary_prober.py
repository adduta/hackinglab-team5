import tempfile
import subprocess
import os

def run_canary_methods(host, port):
    results = {}

    # 1. Send a fake public key
    key_path = generate_temp_key()
    cmd = [
        "ssh",
        "-i", key_path,
        "-o", "PreferredAuthentications=publickey",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=3",
        f"notarealuser@{host}",
        "-p", str(port)
    ]
    results["fake_key_response"] = run_ssh_command(cmd)

    # 2. Send a bogus SSH version banner
    banner_cmd = f"echo -e 'SSH-3.14159-BogusBanner\\r\\n' | nc -w 2 {host} {port}"
    results["bogus_banner_response"] = run_shell_command(banner_cmd)

    # 3. Send only CRLF (empty handshake)
    crlf_cmd = f"echo -e '\\r\\n' | nc -v -w 2 {host} {port}"
    results["crlf_response"] = run_shell_command(crlf_cmd)

    os.remove(key_path)
    return results

def generate_temp_key():
    key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAw1vLEnqVWgz+rHb3xKMuTOFh...FAKEKEY
-----END RSA PRIVATE KEY-----"""
    key_file = tempfile.NamedTemporaryFile(delete=False)
    key_file.write(key.encode())
    key_file.close()
    os.chmod(key_file.name, 0o600)
    return key_file.name

def run_ssh_command(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=10).decode()
    except subprocess.CalledProcessError as e:
        return e.output.decode()

def run_shell_command(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5).decode()
    except subprocess.CalledProcessError as e:
        return e.output.decode()
