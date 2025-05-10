import paramiko
import subprocess
import pyshark
import time

def start_packet_capture(output_file, interface='eth0', port=22):
    cmd = [
        'tcpdump', '-i', interface, 'port', str(port),
        '-w', output_file, '-s', '0'
    ]
    proc = subprocess.Popen(cmd)
    return proc

def stop_packet_capture(proc):
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()

def analyze_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter='ssh')
    print("\n=== SSH Packet Analysis ===")
    for pkt in cap:
        try:
            if hasattr(pkt, 'ssh'):
                print(f"Time: {pkt.sniff_time}, Type: {pkt.ssh.get_field_value('message_code')}, Info: {pkt.ssh.get_field_value('message')}")
        except Exception as e:
            print(f"Packet parsing error: {e}")
    cap.close()


def try_ssh_auth(host, port, username, auth_func, auth_arg):
    transport = paramiko.Transport((host, port))
    try:
        transport.start_client(timeout=5)

        print(f"[+] SSH Banner: {transport.remote_version}")

        auth_func(transport, username, auth_arg)
        if transport.is_authenticated():
            print(f"[+] Auth succeeded for {username}@{host}")
        else:
            print(f"[-] Auth failed for {username}@{host}")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        transport.close()

def password_auth(transport, username, password):
    transport.auth_password(username, password)

def public_key_auth(transport, username, key_path):
    key = paramiko.RSAKey.from_private_key_file(key_path)
    transport.auth_publickey(username, key)


if __name__ == '__main__':
    pcap_file = 'ssh_probe_cowrie.pcap'
    interface = 'eth0'
    ssh_port = 2222

    capture_proc = start_packet_capture(pcap_file, interface, port=ssh_port)
    time.sleep(2)

    try_ssh_auth("192.168.125.30", ssh_port, "root", password_auth, "password")

    time.sleep(2)
    stop_packet_capture(capture_proc)
    analyze_pcap(pcap_file)