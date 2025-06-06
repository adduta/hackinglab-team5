import re
from typing import Dict
from modules.auth_tester import AuthTesterOutput
from .base_fingerprinter import BaseFingerprinter, FingerprintRule

class HoneytrapFingerprinter(BaseFingerprinter):
    def __init__(self, results: Dict[str, str], auth: AuthTesterOutput):
        rules = [
            FingerprintRule(
                id="update_packages",
                name="524 packages can be updated",
                evaluate=self.check_package_updates
            ),
            FingerprintRule(
                id="security_updates",
                name="270 security updates",
                evaluate = self.check_security_updates
            ),
            FingerprintRule(
                id="ubuntu_version",
                name="ubuntu 16.04.1 LTS built 2016-12-10",
                evaluate=self.check_ubuntu_version
            ),
            FingerprintRule(
                id="last_login",
                name="last login 2017 on specific IP",
                evaluate=self.check_last_login
            )
        ]
        super().__init__(
            results = results,
            rules = rules,
            auth = auth
        )

    def compute_and_explain(self) -> bool | float:
        score = super().get_score()
        print("\n=== Honeytrap Analysis ===")
        print(f"Total Score: {score:.2f}")
        self.show_rules_overview()

        return score

    def check_package_updates(self) -> float:
        packages_match = re.search(r"(\d+)\s+packages can be updated", self.results["motd"])
        packages = int(packages_match.group(1)) if packages_match else None

        if packages == 524:
            return 0.5
        return 0

    def check_security_updates(self) -> float:
        security_match = re.search(r"(\d+)\s+updates are security updates", self.results["motd"])
        security_updates = int(security_match.group(1)) if security_match else None

        if security_updates == 270:
            return 0.5
        return 0


    def check_ubuntu_version(self) -> float:
        version_match = re.search(r"Ubuntu\s+([\d.]+ LTS).*built\s+([\d-]+)", self.results["motd"])
        version = version_match.group(1) if version_match else None
        build_date = version_match.group(2) if version_match else None

        if version == "16.04.1 LTS" and build_date == "2016-12-10":
            return 0.5
        return 0

    def check_last_login(self) -> float:
        login_match = re.search(r"last login:\s+(.+?) from ([\d.]+)", self.results["motd"])
        last_login = login_match.group(1) if login_match else None
        login_ip = login_match.group(2) if login_match else None

        if last_login == "Sun Nov 19 19:40:44 2017" and login_ip == "172.16.84.1":
            return 0.7
        return 0