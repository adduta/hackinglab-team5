import pyshark
import paramiko

def analyze_pcap(pcap_file):
    """Analyze the pcap file and print the SSH packet details"""
    print(f"Analyzing {pcap_file}")
    cap = pyshark.FileCapture(pcap_file, display_filter='ssh')
    print("\n=== SSH Packet Analysis ===")
    for pkt in cap:
        try:
            if hasattr(pkt, 'ssh'):
                print(f"Time: {pkt.sniff_time} Type: {pkt.ssh.get_field_value('message_code')} Info: {pkt.ssh.get_field_value('message')}")
        except Exception as e:
            print(f"Packet parsing error: {e}")
    cap.close()

def try_ssh_auth(host, port, username, auth_func, auth_arg):
    """Try to authenticate to the SSH server and print the result"""
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
    """Authenticate using password"""
    transport.auth_password(username, password)

def public_key_auth(transport, username, key_path):
    """Authenticate using public key"""
    key = paramiko.RSAKey.from_private_key_file(key_path)
    transport.auth_publickey(username, key) 