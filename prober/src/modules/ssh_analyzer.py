"""Module for SSH analysis and honeypot detection"""
import pyshark
import paramiko
import time
from typing import Dict, Tuple, Optional
from .credential_manager import CredentialManager
from .auth_tester import AuthTester, AuthTesterOutput
from .utils import clean_ansi_escape_codes

def analyze_pcap(pcap_file: str) -> None:
    """Analyze the pcap file and print the SSH packet details"""
    print(f"Analyzing {pcap_file}")
    cap = pyshark.FileCapture(pcap_file, display_filter='ssh')
    print("\n=== SSH Packet Analysis ===")
    for pkt in cap:
        try:
            if hasattr(pkt, 'ssh'):
                msg_type = pkt.ssh.get_field_value('message_code')
                msg_info = pkt.ssh.get_field_value('message')
                # Only print packets that have meaningful information
                if msg_type and msg_info and msg_info != 'None':
                    print(f"Time: {pkt.sniff_time} Type: {msg_type} Info: {msg_info}")
        except Exception as e:
            print(f"Packet parsing error: {e}")
    cap.close()

def execute_commands(session, commands: Dict[str, str]) -> Dict[str, str]:
    """Execute a list of commands and return their results"""
    results = {}
    try:
        session.get_pty()
        session.invoke_shell()
        motd_text = wait_for_output(session, "motd")
        results["motd"] = motd_text
        for key, command in commands.items():
            session.send(command + "\n")
            decoded = wait_for_output(session, command)
            clean_text = extract_command_output(decoded, command)
            results[key] = clean_text
    except Exception as e:
        print(f'Error executing commands: {e}', flush=True)
    return results

def wait_for_output(session, command):
    time.sleep(0.5)
    output = b""
    end_time = time.time() + 10
    while time.time() < end_time:
        if session.recv_ready():
            output += session.recv(2048)
        else:
            time.sleep(0.2)

    decoded = output.decode(errors="ignore")
    return decoded

def try_multiple_auth(host: str, port: int, auth_func, auth_arg, num_attempts: int = 10) -> AuthTesterOutput:
    """Try multiple authentication attempts with different credentials"""
    credential_manager = CredentialManager()
    auth_tester = AuthTester(
        credential_manager = credential_manager,
        host=host,
        port=port,
        auth_func=auth_func
    )
    return auth_tester.test_auth()

def conduct_honeypot_experiment(transport: paramiko.Transport, host: str, port: int, valid_username: str, valid_password: str, auth_func) -> str:
    """Conduct an experiment to detect if the system is a honeypot by checking file persistence."""
    test_filename = f"honeypot_test_{int(time.time())}.txt"
    test_content = "This is a test file for honeypot detection"
    
    # First connection - Create file
    session = transport.open_session()
    session.get_pty()
    session.invoke_shell()
    
    # Create file
    create_cmd = f"echo '{test_content}' > {test_filename}"
    session.send(create_cmd + "\n")
    time.sleep(1)
    #Discard output of echo command
    while session.recv_ready():
        session.recv(2048) 
    
    # Verify file creation
    verify_cmd = f"cat {test_filename}"
    session.send(verify_cmd + "\n")
    time.sleep(1)
    output = b""
    while session.recv_ready():
        output += session.recv(2048)
    first_verify = output.decode(errors='ignore')
    session.close()
    print(f"FIRST VERIFY CONTENT: {first_verify}")
    if test_content not in first_verify: 
        return "Experiment File Creation: Failed"
    # Disconnect and reconnect
    transport.close()
    time.sleep(2)  # Wait a bit before reconnecting
    
    # Second connection - Verify file persistence
    transport = paramiko.Transport((host, port))
    transport.start_client(timeout=5)
    auth_func(transport, valid_username, valid_password)
    
    if transport.is_authenticated():
        session = transport.open_session()
        session.get_pty()
        session.invoke_shell()
        
        # Check if file exists
        check_cmd = f"cat {test_filename}"
        session.send(check_cmd + "\n")
        time.sleep(1)
        output = b""
        while session.recv_ready():
            output += session.recv(2048)
        second_verify = output.decode(errors='ignore')
        
        # Clean up test file
        cleanup_cmd = f"rm {test_filename}"
        session.send(cleanup_cmd + "\n")
        time.sleep(1)
        session.close()
        
        # Determine if it's a honeypot
        is_honeypot = test_content in first_verify and test_content not in second_verify
        return f"Experiment File Creation: {is_honeypot}"
    
    return "Experiment File Creation: Failed"

def try_ssh_auth(host: str, port: int, username: str, auth_func, auth_arg, commands: Dict[str, str]) -> Tuple[Optional[Dict[str, str]], Optional[AuthTesterOutput]]:
    """Try to authenticate to the SSH server and print the result"""
    # First, perform multiple authentication attempts
    auth_output = try_multiple_auth(host, port, auth_func, auth_arg)
    
    if auth_output.success_patterns:
        valid_username, valid_password = next(iter(auth_output.success_patterns.keys())).split(":") # Grab whatever pair works
    else:
        valid_username = username
        valid_password = auth_arg
    
    # Now try the actual authentication for command execution
    transport = paramiko.Transport((host, port))
    try:
        transport.start_client(timeout=5)
        auth_func(transport, valid_username, valid_password)
        
        if transport.is_authenticated():
            print(f"[+] Auth succeeded for {valid_username}@{host}")
            if commands:
                session = transport.open_session()
                results = execute_commands(session, commands)
                # Format and print results nicely
                print("\n=== Command Results ===")
                for cmd, output in results.items():
                    print(f"\n--- {cmd} ---", flush=True)
                    formatted_output = format_command_output(cmd, output)
                    print(formatted_output)
                
                # Conduct honeypot detection experiment
                print("\n=== Conducting Honeypot Detection Experiment ===")
                try:
                    experiment_result = conduct_honeypot_experiment(transport, host, port, valid_username, valid_password, auth_func)
                    results["Experiment File Creation"] = experiment_result
                    print(f"\nExperiment Result: {experiment_result}")
                except Exception as e:
                    print(f"[-] Error conducting honeypot detection experiment: {e}")
                    results["Experiment File Creation"] = "Failed"
                
                session.close()
                return results, auth_output
        else:

            print(f"[-] Auth failed for {valid_username}@{host}", flush=True)
            return None, None
            
    except Exception as e:
        print(f"[!] Error: {e}")
        return None, auth_output
    finally:
        transport.close()

def password_auth(transport: paramiko.Transport, username: str, password: str) -> None:
    """Authenticate using password"""
    transport.auth_password(username, password)

def public_key_auth(transport: paramiko.Transport, username: str, key_path: str) -> None:
    """Authenticate using public key"""
    key = paramiko.RSAKey.from_private_key_file(key_path)
    transport.auth_publickey(username, key) 

def extract_command_output(raw_output: str, command: str) -> str:
    """Extract the output of a command from a shell-like response."""
    parts = raw_output.split(command, 1)
    if len(parts) < 2:
        return ""
    
    # Get everything after the command
    after_command = parts[1]

    # Strip the next prompt (e.g., root@svr04:~#) if present
    lines = after_command.strip().splitlines()

    # Return the content between the command and next prompt
    clean_lines = []
    for line in lines:
        if line.strip().endswith("#") or line.strip().endswith("$"):
            break
        clean_lines.append(line.strip())
    return "\n".join(clean_lines)

def format_command_output(command: str, output: str) -> str:
    """Format command output in a readable way"""
    cleaned_output = clean_ansi_escape_codes(output)
    
    # Format based on command type
    if command == 'ls':
        # Split into lines and format as a table
        lines = cleaned_output.strip().split('\n')
        if len(lines) > 0:
            # Skip the total line if presentf
            if lines[0].startswith('total'):
                lines = lines[1:]
            # Format each line
            formatted_lines = []
            for line in lines:
                parts = line.split()
                if len(parts) >= 9:
                    # Format: permissions size date time name
                    formatted_line = f"{parts[0]:<10} {parts[4]:>8} {parts[5]:<3} {parts[6]:<5} {parts[7]:<5} {' '.join(parts[8:])}"
                    formatted_lines.append(formatted_line)
            return '\n'.join(formatted_lines)
    
    elif command == 'ps':
        # Format ps output as a table
        lines = cleaned_output.strip().split('\n')
        if len(lines) > 0:
            # Get the header
            header = lines[0]
            # Format the data rows
            formatted_lines = [header]
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 11:
                    # Format: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
                    formatted_line = f"{parts[0]:<8} {parts[1]:>6} {parts[2]:>5} {parts[3]:>5} {parts[4]:>8} {parts[5]:>8} {parts[6]:<6} {parts[7]:<4} {parts[8]:<6} {' '.join(parts[9:])}"
                    formatted_lines.append(formatted_line)
            return '\n'.join(formatted_lines)
    
    elif command == 'uname':
        # Format uname output in a more readable way
        parts = cleaned_output.strip().split()
        if len(parts) >= 3:
            return f"OS: {parts[0]}\nHostname: {parts[1]}\nKernel: {' '.join(parts[2:])}"
    
    # Default formatting for other commands
    return cleaned_output.strip()
