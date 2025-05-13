import pyshark
import paramiko
import time 
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

def try_ssh_auth(host, port, username, auth_func, auth_arg,commands):
    """Try to authenticate to the SSH server and print the result"""
    transport = paramiko.Transport((host, port))
    try:
        transport.start_client(timeout=5)
        print(f"[+] SSH Banner: {transport.remote_version}")
        auth_func(transport, username, auth_arg)
        #execute commands if auth was successfull
        if transport.is_authenticated():
            print(f"[+] Auth succeeded for {username}@{host}")
            if commands: 
                session = transport.open_session()
                try:
                    session.get_pty()
                    session.invoke_shell()
                    session.send("whoami\n")
                    time.sleep(0.5)
                    output = b""
                    end_time = time.time() + 5
                    while time.time() < end_time:
                        if session.recv_ready():
                            output += session.recv(1024)
                        else:
                            time.sleep(0.2)
                    print(output.decode(errors="ignore"))
                except Exception as e :
                    print(f'error retrieving pty')
                session.close()
                
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