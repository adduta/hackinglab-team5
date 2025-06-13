from typing import Dict
import pyshark
from modules.auth_tester import AuthTesterOutput
from .base_fingerprinter import BaseFingerprinter, FingerprintRule

class HeraldingFingerprinter(BaseFingerprinter):
    def __init__(self, results: Dict[str, str], auth: AuthTesterOutput, pcap_file: str):
        self.use_pkt_analysis = True
        rules = [
            FingerprintRule(
                id="auth_rejection",
                name="All authentication attempts rejected",
                evaluate=self.check_auth_rejection
            )
        ]
        super().__init__(
            results=results,
            rules=rules,
            auth=auth,
            use_pkt_analysis=True,
            pcap_file=pcap_file
        )

    def compute_and_explain(self) -> bool:
        score = super().get_score()
        is_heralding = score >= 1.0  # Need at least 1.0 points to be considered Heralding
        
        print("\n=== Heralding Analysis ===")
        print(f"Total Score: {score:.2f}")
        print(f"Is Heralding: {is_heralding}")
        self.show_rules_overview()
        
        return is_heralding

    def check_auth_rejection(self) -> float:
        """
        Check if all authentication attempts are rejected.
        Heralding honeypot rejects all authentication attempts.
        """

        print(self.auth.attempts)
        if self.auth.attempts == 0:
            return 0.0
        
        success_rate = self.auth.get_success_rate()
        print(success_rate)
        # Return 1.0 if all attempts failed (0% success rate)
        return 1.0 if success_rate == 0.0 else 0.0
