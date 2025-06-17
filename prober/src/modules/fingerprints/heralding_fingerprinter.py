from typing import Dict
import pyshark
from modules.auth_tester import AuthTesterOutput
from .base_fingerprinter import BaseFingerprinter, FingerprintRule

class HeraldingFingerprinter(BaseFingerprinter):
    def __init__(self, results: Dict[str, str], canary_results: Dict[str, str], auth: AuthTesterOutput, pcap_file: str):
        self.use_pkt_analysis = True
        rules = [
            FingerprintRule(
                id="auth_rejection",
                name="All authentication attempts rejected",
                evaluate=self.check_auth_rejection
            ),
            FingerprintRule(
                id="bogus_banner_response",
                name="specific reply to made up banner",
                evaluate=self.check_banner_response
            ),
            FingerprintRule(
                id="kex_algs",
                name="specific kex algorithm",
                evaluate=self.check_kex
            ),
            FingerprintRule(
                id="hostkey_algs",
                name="specific host key algorithms",
                evaluate=self.check_hostkey
            )
        ]
        super().__init__(
            results=results,
            rules=rules,
            canary_results=canary_results,
            auth=auth,
            use_pkt_analysis=True,
            pcap_file=pcap_file
        )

    def compute_and_explain(self) -> bool:
        score = super().get_score()
        is_heralding = score >= 2.5  # Need at least 1.0 points to be considered Heralding
        
        print("\n=== Heralding Analysis ===")
        print(f"Total Score: {score:.2f}")
        print(f"Is Heralding: {is_heralding}")
        self.show_rules_overview()
        
        return is_heralding
    
    def check_banner_response(self):
        """Analyze response to made up ssh banner"""
        if not self.canary_results["bogus_banner"]:
            return 0.0
        val = self.canary_results["bogus_banner"].lower()

        # Expected error message from real SSH servers
        if "protocol major versions differ" in val:
            return 0.0

        # Suspicious: timeout, no output, or unclear response
        if "timeout" in val:
            return 0.0

        #any other response is highly unusual (heralding)
        return 1.0
    
    def check_kex(self):

        if not self.canary_results["root_key_auth"]:
            return 0.0

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
        if num_kex > 12:
            score += 0.3

        if 'rsa2048-sha256' in server_kex: 
            score += 0.7

        return score
    
    def check_hostkey(self):
        if not self.canary_results["root_key_auth"]:
            return 0.0

        server_hostkey = []
        lines = self.canary_results["root_key_auth"].splitlines()
        for i, line in enumerate(lines):
            if 'peer server KEXINIT proposal' in line:
                # Expect the next relevant line to contain KEX algorithms
                for j in range(i+1, min(i+5, len(lines))):  # avoid index error
                    if 'host key algorithms:' in lines[j]:
                        server_hostkey = lines[j].split(':', 1)[-1].strip().split(',')
                        break

        # Extract algorithm list
        num_hostkeys = len(server_hostkey)

        score = 0.0

        # Too few or too many host key algorithms is suspicious
        if num_hostkeys > 6:
            score += 0.2

        # Known suspicious or legacy hostkey types
        suspicious_keys = {
            'ssh-rsa': 0.1,
            'ssh-rsa-sha224@ssh.com': 0.3,
            'rsa-sha2-256@ssh.com': 0.2,
            'x509v3-ssh-dss': 0.4
        }

        for alg in server_hostkey:
            if alg in suspicious_keys:
                score += suspicious_keys[alg]

        return min(score, 1.0)


    def check_auth_rejection(self) -> float:
        """
        Check if all authentication attempts are rejected.
        Heralding honeypot rejects all authentication attempts.
        """

        #print(self.auth.attempts)
        if self.auth.attempts == 0:
            return 0.0
        
        success_rate = self.auth.get_success_rate()
        #print(success_rate)
        # Return 1.0 if all attempts failed (0% success rate)
        return 1.0 if success_rate == 0.0 else 0.0
