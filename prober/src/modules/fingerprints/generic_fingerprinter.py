from typing import Dict

import re

from modules.auth_tester import AuthTesterOutput
from modules.fingerprints.base_fingerprinter import BaseFingerprinter, FingerprintRule
from modules.utils import clean_ansi_escape_codes


class GenericFingerprinter(BaseFingerprinter):
    """"
    Classifies a host as a honeypot or not, without focusing on a specific honeypot.
    """

    def __init__(self, results: Dict[str, str], auth: AuthTesterOutput, pcap_file: str):
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
        ]
        super().__init__(
            results=results,
            rules=rules,
            auth=auth,
            pcap_file=pcap_file,
            use_pkt_analysis=True
        )

    def compute_and_explain(self) -> bool:  
        score = super().get_score()

        is_honeypot = any([
            score >= 2.5,  # Lower threshold but more comprehensive scoring
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

    def analyze_banner(self):
        """Analyze SSH banner for honeypot indicators"""
        if not self.auth.banner:
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
