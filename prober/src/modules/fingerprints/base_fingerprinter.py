from abc import abstractmethod
from dataclasses import dataclass
from typing import List, Dict

import pyshark

from modules.auth_tester import AuthTesterOutput

@dataclass
class FingerprintRule:
    name: str
    id: str
    evaluate: callable

class BaseFingerprinter:
    def __init__(self, results: Dict[str, str], rules: List[FingerprintRule],
                 auth: AuthTesterOutput, pcap_file: str = None, use_pkt_analysis: bool = False) -> None:
        self.results = results
        self.auth = auth
        self.rules = rules

        self._rule_score = {}

        self._pcap_obj = None
        # load the packet file in memory only if any rule needs it.
        if use_pkt_analysis:
            self._pcap_obj = pyshark.FileCapture(pcap_file)

    def get_score(self):
        total_score = 0

        for rule in self.rules:
            try:
                score = rule.evaluate()
                total_score += score
                self._rule_score[rule.id] = score
            except Exception as e:
                print(f"Rule {rule.name} failed. Maybe you didn't enable packet analyis for this fingerprinter?\n Error: {e}")

        if self._pcap_obj is not None:
            self._pcap_obj.close()
        return total_score


    def show_rules_overview(self):
        print("==== Rules Overview === ")
        for rule in self.rules:
            print(f"{rule.name} - score: {self._rule_score[rule.id]}")

    @abstractmethod
    def compute_and_explain(self) -> bool | float:
        pass
