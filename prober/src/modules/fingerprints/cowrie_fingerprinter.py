import re
from typing import Dict
from modules.auth_tester import AuthTesterOutput
from .base_fingerprinter import BaseFingerprinter, FingerprintRule

class CowrieFingerprinter(BaseFingerprinter):
    def __init__(self, results: Dict[str, str], canary_results: Dict[str, str], auth: AuthTesterOutput):
        rules = [
            FingerprintRule(
                id="ping",
                name="pinging google.com returns 29.89.32.244",
                evaluate=self.parse_ping
            ),
            FingerprintRule(
                id="ifconfig",
                name="ifconfig loopback shows 110 packets, but different bytes.",
                evaluate=self.parse_ifconfig
            ),
            FingerprintRule(
                id="file_persistence",
                name="File persistence test",
                evaluate=self.parse_file_persistence
            )
        ]
        super().__init__(
            results=results,
            canary_results=canary_results,
            rules=rules,
            auth=auth
        )

    def compute_and_explain(self) -> bool | float:
        score = super().get_score()
        print("\n=== Cowrie Analysis ===")
        print(f"Total Score: {score:.2f}")

        print(f"Is Cowrie: {score >= 1.35}")  # 75% of max score (1.8)

        self.show_rules_overview()

        return score

    def parse_ping(self) -> float:
        """
        For the ping command, Cowrie uses a deterministic way of generating links for a given hostname.
        It computes an MD5 hash and computes the IP based on the first 8 hex characters.
        Under this algorithm, google.com will resolve to 29.89.32.244.
        More information: https://github.com/cowrie/cowrie/blob/a4e8372a3c95819e8bd075e2da77486e03b6d020/src/cowrie/commands/ping.py#L83
        """
        output = self.results.get("ping")
        if output == None:
            return 0

        match = re.search(r'\((\d{1,3}(?:\.\d{1,3}){3})\)', output)
        if match:
            ip = match.group(1)
            if ip == "29.89.32.244": return 1
        return 0

    def parse_ifconfig(self) -> float:
        """
        When using ifconfig, Cowrie always shows loopback packets to be 110, but the number of bytes is different in two consecutive runs.
        Source code: https://github.com/cowrie/cowrie/blob/a4e8372a3c95819e8bd075e2da77486e03b6d020/src/cowrie/commands/ifconfig.py#L59
        """
        output = self.results.get("ifconfig")
        if output == None:
            return 0

        interfaces = output.split('\n\n')
        lo_blocks = [block for block in interfaces if block.strip().startswith('lo')]

        rx_packets = []
        rx_bytes = []

        for block in lo_blocks:
            match = re.search(r'RX packets:(\d+)', block)
            if match:
                rx_packets.append(int(match.group(1)))
            match = re.search(r'RX bytes:(\d+)', block)
            if match:
                rx_bytes.append(int(match.group(1)))

        if len(rx_packets) == 2 and len(rx_bytes) == 2:
            if rx_packets[0] == rx_packets[1] == 110 and rx_bytes[0] != rx_bytes[1]:
                return 0.8
        return 0

    def parse_file_persistence(self) -> float:
        """
        Check if the file persistence experiment indicates a honeypot.
        If the experiment result shows "True", it means the file was not persistent (honeypot behavior).
        """
        if "Experiment File Creation" not in self.results:
            return 0
            
        result = self.results["Experiment File Creation"]
        if "True" in result:  # File was not persistent (honeypot behavior)
            return 3.0
        return 0

