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
