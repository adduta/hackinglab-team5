from typing import Dict
from modules.auth_tester import AuthTesterOutput
from .base_fingerprinter import BaseFingerprinter, FingerprintRule

class SSHSameFingerprinter(BaseFingerprinter):
    def __init__(self, results: Dict[str, str], auth: AuthTesterOutput):
        rules = [
            FingerprintRule(
                id="auth_success_rate",
                name="100% authentication success rate",
                evaluate=self.check_auth_success_rate
            ),
        ]
        super().__init__(
            results=results,
            rules=rules,
            auth=auth
        )

    def compute_and_explain(self) -> bool:
        score = super().get_score()
        is_sshesame = score >= 2.25  # 75% of max score (3.0)
        
        print("\n=== SSHSame Analysis ===")
        print(f"Total Score: {score:.2f}")
        print(f"Is SSHSame: {is_sshesame}")
        self.show_rules_overview()
        
        return is_sshesame

    def check_auth_success_rate(self) -> float:
        """
        Check if all authentication attempts succeeded.
        SSHesame has the default behavior of allowing all authentication attempts,
         and we have added 5 canary credentials made of randomly generated usernames and passwords, which the honeypot will always accept.
        """
        if self.auth.attempts == 0:
            return 0.0
        
        success_rate = self.auth.get_success_rate()
        if success_rate == 1.0:  # 100% success rate
            return 2.5
        return 0.0