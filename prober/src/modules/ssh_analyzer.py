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
            results={}
            if commands: 
                session = transport.open_session()
                try:
                    session.get_pty()
                    session.invoke_shell()
                    for key in commands.keys(): 
                        # "test name : command "
                        command=commands.get(key)
                        session.send(command + "\n")
                        time.sleep(0.5)
                        output = b""
                        end_time = time.time() + 5
                        while time.time() < end_time:
                            if session.recv_ready():
                                output += session.recv(2048)
                            else:
                                time.sleep(0.2)
                        decoded = output.decode(errors='ignore')
                        clean_text=extract_command_output(decoded,command)
                        results[key] = clean_text
                except Exception as e :
                    print(f'{e}')
                print(f"RESULTS: {results}")
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
    
def extract_command_output(raw_output: str, command: str):
    """
    Extract the output of a command from a Cowrie shell-like response.
    """
    parts = raw_output.split(command, 1)
    if len(parts) < 2:
        return ""

    # Get everything after the command
    after_command = parts[1]

    # Strip the next prompt (e.g., root@svr04:~#) if present
    lines = after_command.strip().splitlines()

    # Return the content between the command and next prompt
    # (Assumes prompt looks like 'root@svr04:~#')
    clean_lines = []
    for line in lines:
        if line.strip().endswith("#") or line.strip().endswith("$"):
            break
        clean_lines.append(line.strip())
    return "\n".join(clean_lines)
