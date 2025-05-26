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

3. Run the detection system:
```bash
python prober/src/probe.py
```

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
| sshhipot   | 192.168.125.20  | 2223     |
| debian_host| 192.168.125.90  | 22       |
