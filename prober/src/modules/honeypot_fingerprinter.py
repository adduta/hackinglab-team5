"""Module for analyzing SSH responses and detecting honeypots"""
import re
from typing import Dict

class HoneypotFingerprinter:
    """Class to analyze SSH responses and determine if a system is likely a honeypot"""
    
    def __init__(self):
        # Define command patterns and their weights for honeypot detection
        self.command_patterns = {
            'whoami': {
                'weight': 2.0,
                'honeypot_indicators': [
                    (r'root', 0.3),  # Most honeypots run as root
                    (r'admin', 0.2),  # Common honeypot username
                    (r'^root\s*$', 0.5),  # Exact match for just "root" (common in honeypots)
                ],
                'no_response_score': 0.8,  # High score for no response
                'empty_response_score': 0.6  # Score for empty response
            },
            'ls': {
                'weight': 1.5,
                'honeypot_indicators': [
                    (r'\.bash_history', 0.4),  # Empty or minimal bash history
                    (r'\.ssh', 0.3),  # Empty or minimal SSH directory
                    (r'\.bashrc', 0.2),  # Default bashrc
                    (r'^$', 0.8),  # Completely empty response (very suspicious)
                    (r'^\s*$', 0.7),  # Only whitespace response
                ],
                'no_response_score': 0.7,  # High score for no response
                'empty_response_score': 0.8  # Score for empty response
            },
            'uname': {
                'weight': 1.0,
                'honeypot_indicators': [
                    (r'Linux.*Debian', 0.3),  # Generic Debian response
                    (r'x86_64', 0.1),  # Generic architecture
                    (r'3\.2\.0-4-amd64', 0.4),  # Specific old kernel version (common in honeypots)
                    (r'#1 SMP', 0.2),  # Generic kernel build
                ],
                'no_response_score': 0.6,  # Medium score for no response
                'empty_response_score': 0.5  # Score for empty response
            },
            'ps': {
                'weight': 2.0,
                'honeypot_indicators': [
                    (r'few processes', 0.5),  # Minimal process list
                    (r'no processes', 0.4),  # No processes
                    (r'^USER\s+PID.*\n\s*$', 0.9),  # Only header, no processes (very suspicious)
                    (r'USER\s+PID.*START.*\n.*$', 0.4),  # Suspicious process format
                ],
                'no_response_score': 0.9,  # Very high score for no response
                'empty_response_score': 0.8  # Score for empty response
            }
        }
        
        # Common honeypot SSH banners and their scores
        self.ssh_banners = {
            r'SSH-2\.0-OpenSSH_6\.0p1 Debian-4\+deb7u\d+': 0.4,  # Old Debian version
            r'SSH-2\.0-OpenSSH_5\.\d+': 0.5,  # Very old OpenSSH
            r'SSH-2\.0-OpenSSH_[1-4]\.\d+': 0.8,  # Extremely old OpenSSH
        }
        
        # Track authentication attempts
        self.auth_attempts = 0
        self.auth_successes = 0
        self.auth_success_pattern = {}  # Track which credentials worked
        self.banner = None
        
    def set_banner(self, banner: str):
        """Set the SSH banner for analysis"""
        self.banner = banner
        
    def record_auth_attempt(self, success: bool, username: str = None, password: str = None):
        """Record an authentication attempt with credentials"""
        self.auth_attempts += 1
        if success:
            self.auth_successes += 1
            if username and password:
                key = f"{username}:{password}"
                self.auth_success_pattern[key] = True
    
    def get_auth_success_rate(self) -> float:
        """Calculate the authentication success rate"""
        if self.auth_attempts == 0:
            return 0.0
        return self.auth_successes / self.auth_attempts
    
    def analyze_auth_patterns(self) -> float:
        """Analyze authentication patterns for suspicious behavior"""
        score = 0.0
        
        # Check if root login was allowed (suspicious)
        root_logins = sum(1 for cred in self.auth_success_pattern if cred.startswith("root:"))
        if root_logins > 0:
            score += 0.5
        
        # Check if same username worked with different passwords (very suspicious)
        usernames = {}
        for cred in self.auth_success_pattern:
            username = cred.split(":")[0]
            usernames[username] = usernames.get(username, 0) + 1
            if usernames[username] > 1:
                score += 0.8
        
        return score
        
    def analyze_response(self, command: str, response: str) -> float:
        """Analyze a single command response and return a honeypot probability score"""
        if command not in self.command_patterns:
            return 0.0
            
        pattern_info = self.command_patterns[command]
        score = 0.0
        
        # Check for no response or empty response
        if not response:
            return pattern_info['no_response_score'] * pattern_info['weight']
        
        # Clean and check response
        cleaned_response = clean_ansi_escape_codes(response).strip()
        
        # Empty response check
        if not cleaned_response:
            return pattern_info['empty_response_score'] * pattern_info['weight']
        
        # Check for minimal response
        if len(cleaned_response) < 5:
            return pattern_info['empty_response_score'] * pattern_info['weight'] * 0.8
        
        # Check for pattern matches
        for pattern, weight in pattern_info['honeypot_indicators']:
            if re.search(pattern, cleaned_response, re.IGNORECASE | re.MULTILINE):
                score += weight
                
        return score * pattern_info['weight']
    
    def analyze_banner(self) -> float:
        """Analyze SSH banner for honeypot indicators"""
        if not self.banner:
            return 0.0
            
        score = 0.0
        for pattern, weight in self.ssh_banners.items():
            if re.search(pattern, self.banner, re.IGNORECASE):
                score += weight
        return score
    
    def analyze_all_responses(self, results: Dict[str, str]) -> Dict[str, float]:
        """Analyze all command responses and return detailed scores"""
        analysis = {
            'command_scores': {},
            'total_score': 0.0,
            'is_honeypot': False,
            'no_response_count': 0,
            'empty_response_count': 0,
            'total_commands': len(results),
            'auth_success_rate': self.get_auth_success_rate(),
            'banner_score': self.analyze_banner(),
            'auth_pattern_score': self.analyze_auth_patterns()
        }
        
        for command, response in results.items():
            score = self.analyze_response(command, response)
            analysis['command_scores'][command] = score
            analysis['total_score'] += score
            
            # Count empty and no responses
            if not response:
                analysis['no_response_count'] += 1
            elif not clean_ansi_escape_codes(response).strip():
                analysis['empty_response_count'] += 1
        
        # Add banner score
        analysis['total_score'] += analysis['banner_score']
        
        # Add authentication pattern score
        analysis['total_score'] += analysis['auth_pattern_score']
        
        # Calculate empty response ratio (including both no response and empty response)
        analysis['empty_response_ratio'] = (
            analysis['no_response_count'] + analysis['empty_response_count']
        ) / analysis['total_commands']
        
        # Consider it a honeypot if any of these conditions are met:
        analysis['is_honeypot'] = any([
            analysis['total_score'] >= 2.5,  # Lower threshold but more comprehensive scoring
            analysis['empty_response_ratio'] >= 0.5,  # 50% of commands gave empty/no response
            analysis['auth_pattern_score'] >= 0.8,  # Suspicious auth patterns
            analysis['banner_score'] >= 0.4  # Suspicious SSH banner
        ])
        
        return analysis

def clean_ansi_escape_codes(text: str) -> str:
    """Remove ANSI escape codes from text"""
    if not text:
        return ""
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    return ansi_escape.sub('', text) 