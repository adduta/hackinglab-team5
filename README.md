# SSH Honeypot Detection System

A sophisticated system for detecting SSH honeypots using multiple detection vectors and behavioral analysis.

## Features

### 1. Enhanced Scoring System
- Weighted scoring for different command types
- Pattern matching for suspicious responses
- Separate scoring for empty or no responses
- Comprehensive analysis combining multiple detection vectors

### 2. SSH Banner Analysis
- Detection of outdated SSH versions
- Scoring based on known honeypot banner patterns
- Regular expression matching for version analysis
- Common honeypot SSH banner identification

### 3. Authentication Pattern Analysis
- Tracking of successful authentication patterns
- Detection of suspicious root login allowance
- Identification of inconsistent authentication behaviors
- Analysis of username/password combinations

### 4. Command Response Analysis
Components analyzed:
- `whoami`: Detection of common honeypot user contexts
- `ps`: Analysis of process list completeness
- `ls`: Evaluation of file system structure
- `uname`: System information verification

Features:
- Empty or minimal response detection
- ANSI escape code cleaning
- Pattern matching for suspicious outputs
- Command-specific weight assignments

### 5. Detection Criteria

A system is flagged as a honeypot if any of these conditions are met:
- Total score ≥ 2.5 (comprehensive scoring)
- Empty response ratio ≥ 50%
- Authentication pattern score ≥ 0.8
- SSH banner score ≥ 0.4

## Usage

1. Clone the repository:
```bash
git clone [repository-url]
cd [repository-name]
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the docker containers
```bash
docker compose up --build -d
```

4. To see the results, look into the logs of the `prober` container.

## Project Structure

```
prober/
├── src/
│   ├── modules/
│   │   ├── auth_tester.py         # Authentication testing
│   │   ├── credential_manager.py  # Credential handling
│   │   ├── honeypot_fingerprinter.py  # Core detection logic
│   │   ├── scanner.py            # Network scanning
│   │   └── ssh_analyzer.py       # SSH response analysis
│   └── probe.py                  # Main entry point
```

## Detection Methods

1. **Banner Analysis**
   - Identifies outdated SSH versions
   - Detects known honeypot banner patterns
   - Scores based on version suspiciousness

2. **Authentication Testing**
   - Tracks success/failure patterns
   - Identifies suspicious root access
   - Detects inconsistent auth behaviors

3. **Command Response Analysis**
   - Evaluates response completeness
   - Checks for honeypot-specific patterns
   - Analyzes system information consistency

4. **System Behavior**
   - Empty or minimal response tracking
   - Process list analysis
   - File system structure verification

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

[Your License Here]

# hackinglab-team5
Detecting Honeypots in the wild

# Cloning
git clone --recurse-submodules  *< URL >*
# Initialization
git submodule update --init --recursive

# Recent Changes
## SSH Honeypot Detection
- Added Nmap scanning functionality to discover SSH servers
- Created modular code structure for better maintainability
- Added packet capture and analysis capabilities

# Port mapping summary
| Container   | Internal IP     | SSH Port |
|------------|-----------------|----------|
| sshesame   | 192.168.125.40  | 2022     |
| cowrie     | 192.168.125.30  | 2222     |
| debian_host| 192.168.125.90  | 22       |

## How the Prober Works

The `prober` is the core of the SSH honeypot detection system. It automates the process of discovering SSH servers, probing them, and analyzing their responses for honeypot characteristics. Here's a step-by-step breakdown of its operation:

### 1. SSH Target Discovery

- **File:** `prober/src/probe.py`, `prober/src/modules/scanner.py`
- The prober uses a function called `run_nmap_scan` to discover SSH servers on the network. This function is designed to run an Nmap scan, but in practice, it returns a hardcoded list of known targets (with their IPs, ports, and names) for reliability in lab environments.

### 2. Command Set Definition

- **File:** `prober/src/probe.py`
- A dictionary of commands is defined, including `whoami`, `ls -la`, `ps aux`, `uname -a`, `ping -c 1 google.com`, and `ifconfig`. These commands are chosen to elicit responses that can reveal honeypot behavior.

### 3. Probing Each Target

- **File:** `prober/src/probe.py`, `prober/src/modules/prober.py`
- For each discovered SSH server, the prober:
  - Starts a packet capture using `tcpdump` (via `start_packet_capture`).
  - Attempts SSH authentication using a set of credentials.
  - Executes the defined commands on the server if authentication succeeds.
  - Collects and prints the command outputs.
  - Stops the packet capture.

### 4. Authentication and Command Execution

- **File:** `prober/src/modules/ssh_analyzer.py`
- The `try_ssh_auth` function handles SSH authentication and command execution:
  - It first performs multiple authentication attempts using different credentials (via `try_multiple_auth`).
  - If authentication succeeds, it opens an SSH session and executes the predefined commands.
  - The command outputs are captured, cleaned (e.g., removing ANSI escape codes), and formatted for readability.

### 5. Packet Capture and Analysis

- **File:** `prober/src/modules/capture.py`, `prober/src/modules/ssh_analyzer.py`
- Packet capture is managed by `start_packet_capture` and `stop_packet_capture`, which use `tcpdump` to record SSH traffic.
- The captured packets are analyzed by `analyze_pcap`, which prints details of SSH packets (e.g., message codes and timestamps) to help identify suspicious behavior.

### 6. Honeypot Detection Logic

- **File:** `prober/src/modules/honeypot_fingerprinter.py`, `prober/src/modules/fingerprints/generic_fingerprinter.py`
- The `HoneypotFingerprinter` class orchestrates the detection process:
  - It uses a `GenericFingerprinter` to evaluate the target based on multiple criteria:
    - **Empty Response Ratio:** Checks if a high percentage of commands return empty or no responses.
    - **SSH Banner Analysis:** Detects outdated or suspicious SSH versions.
    - **Authentication Patterns:** Identifies suspicious behaviors, such as allowing root logins or inconsistent authentication success rates.
    - **Malformed Packets:** Checks if the target only exchanges malformed SSH packets.
  - The fingerprinting process assigns scores to each criterion, and the target is flagged as a honeypot if the total score exceeds a threshold (e.g., ≥ 2.5) or if specific criteria (e.g., empty response ratio ≥ 50%) are met.

### 7. Specific Honeypot Fingerprinting

- **File:** `prober/src/modules/fingerprints/cowrie_fingerprinter.py`, `prober/src/modules/fingerprints/sshesame_fingerprinter.py`
- The system also includes specific fingerprinters for known honeypots:
  - **Cowrie Fingerprinter:** Detects Cowrie honeypots by analyzing command outputs:
    - `ping` command: Returns 1.0 if google.com resolves to 29.89.32.244 (Cowrie's deterministic IP generation)
    - `ifconfig` command: Returns 0.8 if loopback shows exactly 110 packets with different byte counts
    - Maximum possible score: 1.8
    - Detection threshold: 1.35 (75% of maximum)
  - **SSHSame Fingerprinter:** Identifies SSHSame honeypots by checking for:
    - 100% authentication success rate (1.0)
    - All commands return empty responses (1.0)
    - Commands are logged but no output (1.0)
    - Maximum possible score: 3.0
    - Detection threshold: 2.25 (75% of maximum)

### 8. Output and Reporting

- The prober prints detailed logs of its operations, including:
  - SSH server discovery results.
  - Authentication attempts and outcomes.
  - Command execution results.
  - Packet analysis details.
  - Honeypot detection scores and conclusions.
