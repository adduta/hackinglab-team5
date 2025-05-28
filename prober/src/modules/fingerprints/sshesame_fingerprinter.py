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
            FingerprintRule(
                id="empty_responses",
                name="All commands return empty responses",
                evaluate=self.check_empty_responses
            ),
            FingerprintRule(
                id="command_logging",
                name="Commands are logged but no output",
                evaluate=self.check_command_logging
            )
        ]
        super().__init__(
            results=results,
            rules=rules,
            auth=auth
        )

    def compute_and_explain(self) -> bool:
        score = super().get_score()
        is_sshesame = score >= 2.5  # Need at least 2.5 points to be considered SSHSame
        
        print("\n=== SSHSame Analysis ===")
        print(f"Total Score: {score:.2f}")
        print(f"Is SSHSame: {is_sshesame}")
        self.show_rules_overview()
        
        return is_sshesame

    def check_auth_success_rate(self) -> float:
        """Check if all authentication attempts succeeded"""
        if self.auth.attempts == 0:
            return 0.0
        
        success_rate = self.auth.get_success_rate()
        if success_rate == 1.0:  # 100% success rate
            return 1.0
        return 0.0

    def check_empty_responses(self) -> float:
        """Check if all commands return empty responses"""
        if not self.results:
            return 0.0
        
        empty_count = 0
        for command, response in self.results.items():
            if not response or not response.strip():
                empty_count += 1
        
        # If all responses are empty, return 1.0
        if empty_count == len(self.results):
            return 1.0
        return 0.0

    def check_command_logging(self) -> float:
        """Check if commands are logged but no output is returned"""
        if not self.results:
            return 0.0
        
        # SSHSame logs commands but returns no output
        # We can check if we have results for commands but they're all empty
        if len(self.results) > 0 and all(not response or not response.strip() for response in self.results.values()):
            return 1.0
        return 0.0 