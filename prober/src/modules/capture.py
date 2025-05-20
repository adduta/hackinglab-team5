import subprocess
import time

def start_packet_capture(output_file, interface='eth0', port=22):
    """Start packet capture using tcpdump"""
    print(f"Starting packet capture on {interface} port {port} to {output_file}")
    cmd = [
        'tcpdump', '-i', interface,
        f'port {port}',
        '-w', output_file,
        '-s', '0'
    ]
    proc = subprocess.Popen(cmd)
    print(f"Capture process started with PID {proc.pid}")
    return proc

def stop_packet_capture(proc):
    """Stop the packet capture process"""
    print(f"Stopping capture process with PID {proc.pid}")
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill() 