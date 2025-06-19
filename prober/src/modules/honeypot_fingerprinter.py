"""Module for analyzing SSH responses and detecting honeypots"""
import re
from typing import Dict

from .auth_tester import AuthTesterOutput
from .fingerprints.cowrie_fingerprinter import CowrieFingerprinter
from .fingerprints.generic_fingerprinter import GenericFingerprinter
from .fingerprints.honeytrap_fingerprinter import HoneytrapFingerprinter
from .fingerprints.sshesame_fingerprinter import SSHSameFingerprinter


class HoneypotFingerprinter:
    """Class to analyze SSH responses and determine if a system is likely a honeypot"""
    
    def __init__(self, results: Dict[str, str], auth_output: AuthTesterOutput, pcap_file: str):
        self.auth = auth_output
        self.results = results
        self.pcap_file = pcap_file

    def analyze_all_responses(self) -> Dict[str, bool | float]:
        generic_fingerprinter = GenericFingerprinter(results=self.results, auth=self.auth, pcap_file=self.pcap_file)
        honeypot_outcome = generic_fingerprinter.compute_and_explain()

        cowrie_fingerprinter = CowrieFingerprinter(results=self.results, auth=self.auth)
        cowrie_score = cowrie_fingerprinter.compute_and_explain()

        sshesame_fingerprinter = SSHSameFingerprinter(results=self.results, auth=self.auth)
        sshesame_score = sshesame_fingerprinter.compute_and_explain()

        honeytrap_fingerprinter = HoneytrapFingerprinter(results=self.results, auth=self.auth)
        honeytrap_score = honeytrap_fingerprinter.compute_and_explain()

        return {
            'is_honeypot': honeypot_outcome,
            'cowrie_score': cowrie_score,
            'sshesame_score': sshesame_score,
            'honeytrap_score': honeytrap_score,
        }