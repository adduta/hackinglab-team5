from typing import Dict

import re

from modules.auth_tester import AuthTesterOutput
from modules.fingerprints.base_fingerprinter import BaseFingerprinter, FingerprintRule
from modules.utils import clean_ansi_escape_codes


class GenericFingerprinter(BaseFingerprinter):
    """"
    Classifies a host as a honeypot or not, without focusing on a specific honeypot.
    """

    def __init__(self, results: Dict[str, str], canary_results: Dict[str, str], auth: AuthTesterOutput, pcap_file: str):
        rules = [
            FingerprintRule(
                id="empty_responses",
                name="High empty/no response ratio",
                evaluate = self.count_empty_responses
            ),
            FingerprintRule(
                id="banner",
                name="Old banner versions",
                evaluate=self.analyze_banner
            ),
            FingerprintRule(
                id="auth_patterns",
                name="Suspicious auth patterns",
                evaluate=self.analyze_auth_patterns
            ),
            # FingerprintRule(
            #     id="malformed_packets",
            #     name="Only exchanged malformed SSH packets",
            #     evaluate=self.check_malformed_packets,
            # ),
            FingerprintRule(
                id="bogus_banner",
                name="Accepted bogus SSH banner",
                evaluate=self.analyze_bogus_banner
            ),
            FingerprintRule(
                id="canary",
                name="Public key auth attempt",
                evaluate= self.analyze_canary 
            ),
            FingerprintRule(
                id="hostkey",
                name="Hostkey algorithm offer analysis",
                evaluate=self.analyze_hostkey_algorithms
            ),
            FingerprintRule(
                id="kex",
                name="KEX algorithm offers",
                evaluate=self.analyze_kex_algorithms
            )

        ]
        super().__init__(
            results=results,
            canary_results=canary_results,
            rules=rules,
            auth=auth,
            pcap_file=pcap_file,
            use_pkt_analysis=True
        )

    def compute_and_explain(self) -> bool:  
        score = super().get_score()

        is_honeypot = any([
            score >= 3.2,  # Lower threshold but more comprehensive scoring
            self._rule_score.get('empty_responses', 0) >= 0.5,  # 50% of commands gave empty/no response
            self._rule_score.get('auth_patterns', 0) >= 0.8,  # Suspicious auth patterns
            self._rule_score.get('banner', 0) >= 0.4  # Suspicious SSH banner
        ])
        print("\n=== Honeypot Analysis ===")
        print(f"Total Score: {score:.2f}")
        print(f"Is honeypot: {is_honeypot}")
        super().show_rules_overview()

        return is_honeypot

    def count_empty_responses(self):
        if self.results is None:
            return 1

        no_response_cnt = 0
        for command, response in self.results.items():
            # Count empty and no responses
            if not response or not clean_ansi_escape_codes(response).strip():
                no_response_cnt += 1

        return no_response_cnt / len(self.results)
        
    def analyze_canary(self):
        """
        Examine server response to a root public key authentication attempt.
        Real servers proceed to signature negotiation and then reject.
        Honeypots often short-circuit or reveal limitations in supported key types.
        """
        val = self.canary_results["root_key_auth"].lower()

        if "unable to negotiate" in val or "no matching host key type" in val:
            return 0.7  # Likely honeypot with broken/legacy crypto handling

        if "this is an ssh honeypot" in val:
            return 1.0  # Confirmed honeypot banner lol

        if "permission denied" in val:
            # Check if actual signature attempt occurred
            if "send_pubkey_test" in val and "no mutual signature algorithm" in val:
                return 0.0  # Expected failure
            if "no mutual" in val or "disable method" in val:
                return 0.4  # Incomplete key exchange
            
            return 0.0  # Fully handled rejection
        
        if not val.strip():
            return 0.6  # Silent or very incomplete behavior

        return 1.0  # Auth successful

    
    def analyze_bogus_banner(self):
        """Analyze response to made up ssh banner"""
        if not self.canary_results["bogus_banner"]:
            return 0.4
        val = self.canary_results["bogus_banner"].lower()

        # Expected error message from real SSH servers
        if "protocol major versions differ" in val:
            return 0.0

        # Suspicious: timeout, no output, or unclear response
        if "timeout" in val:
            return 0.4

        #any other response is highly unusual (heralding)
        return 0.8
    
    def analyze_hostkey_algorithms(self):
        if not self.canary_results["root_key_auth"]:
            return 1.0

        server_hostkey = []
        lines = self.canary_results["root_key_auth"].splitlines()
        for i, line in enumerate(lines):
            if 'peer server KEXINIT proposal' in line:
                # Expect the next relevant line to contain KEX algorithms
                for j in range(i+1, min(i+5, len(lines))):  # avoid index error
                    if 'host key algorithms:' in lines[j]:
                        server_hostkey = lines[j].split(':', 1)[-1].strip().split(',')
                        break

        num_hostkeys = len(server_hostkey)
        #print(server_hostkey)

        score = 0.0

        # Too few or too many host key algorithms is suspicious
        if num_hostkeys < 2 or num_hostkeys > 6:
            score += 0.5

        # Known suspicious or legacy hostkey types
        suspicious_keys = {
            'ssh-rsa': 0.3,
            'ssh-dss': 0.8,
            'ssh-rsa-sha224@ssh.com': 0.5,
            'rsa-sha2-256@ssh.com': 0.4,
            'x509v3-ssh-dss': 0.6
        }

        for alg in server_hostkey:
            if alg in suspicious_keys:
                score += suspicious_keys[alg]

        return min(score, 1.5)

    
    def analyze_kex_algorithms(self):

        if not self.canary_results["root_key_auth"]:
            return 1.0

        server_kex = []
        lines = self.canary_results["root_key_auth"].splitlines()
        for i, line in enumerate(lines):
            if 'peer server KEXINIT proposal' in line:
                # Expect the next relevant line to contain KEX algorithms
                for j in range(i+1, min(i+5, len(lines))):  # avoid index error
                    if 'KEX algorithms:' in lines[j]:
                        server_kex = lines[j].split(':', 1)[-1].strip().split(',')
                        break

        num_kex = len(server_kex)

        score = 0.0

        # Suspicious if fewer than 3 or more than 12 algorithms
        if num_kex < 3 or num_kex > 12:
            score += 0.5

        # Known suspicious/unusual KEX algorithms
        suspicious_kex = {
            'rsa2048-sha256': 0.6,
            'curve448-sha512': 0.4,
            'diffie-hellman-group1-sha1': 0.8,
            'diffie-hellman-group15-sha512': 0.4
        }

        for alg in server_kex:
            if alg in suspicious_kex:
                score += suspicious_kex[alg]

        return min(score, 1.5)



    def analyze_banner(self):
        """Analyze SSH banner for honeypot indicators"""
        if not self.auth or not self.auth.banner:
            return 0.0

        # Common honeypot SSH banners and their scores
        ssh_banners = {
            r'SSH-2\.0-OpenSSH_6\.0p1 Debian-4\+deb7u\d+': 0.4,  # Old Debian version
            r'SSH-2\.0-OpenSSH_5\.\d+': 0.5,  # Very old OpenSSH
            r'SSH-2\.0-OpenSSH_[1-4]\.\d+': 0.8,  # Extremely old OpenSSH
        }
        score = 0.0
        for pattern, weight in ssh_banners.items():
            if re.search(pattern, self.auth.banner, re.IGNORECASE):
                score += weight
        return score

    def analyze_auth_patterns(self):
        """Analyze authentication patterns for suspicious behavior"""
        score = 0.0
        if not self.auth: return 0.0
        # Check if root login was allowed (suspicious)
        root_logins = sum(1 for cred in self.auth.success_patterns if cred.startswith("root:"))
        if root_logins > 0:
            score += 0.5

        # Check if same username worked with different passwords (very suspicious)
        usernames = {}
        for cred in self.auth.success_patterns:
            username = cred.split(":")[0]
            usernames[username] = usernames.get(username, 0) + 1
            if usernames[username] > 1:
                score += 0.8

        return score
