"""Module for testing SSH authentication"""
from dataclasses import dataclass

import paramiko
from .credential_manager import CredentialManager
@dataclass
class AuthTesterOutput:
    banner: str
    attempts: int
    successes: int
    success_patterns: dict

    def get_success_rate(self):
        if self.attempts == 0:
            return 0.0
        return self.successes / self.attempts


class AuthTester:
    """Handles SSH authentication testing"""
    
    def __init__(self, credential_manager: CredentialManager, host: str = None, port: int = 22, auth_func=None):
        self.credential_manager = credential_manager
        self.host = host
        self.port = port
        self.auth_func = auth_func
    
    def test_auth(self) -> AuthTesterOutput:
        """Perform multiple authentication attempts"""
        num_attempts = len(self.credential_manager.credentials)
        print(f"\n[*] Testing {num_attempts} authentication attempts on {self.host}:{self.port}")
        output = AuthTesterOutput(attempts=0, successes=0, success_patterns={}, banner="")

        for i, (username, password) in enumerate(self.credential_manager.credentials):
            transport = paramiko.Transport((self.host, self.port))
            success = False
            try:
                transport.start_client(timeout=5)
                if i == 0:  # Only print banner on first attempt
                    output.banner = transport.remote_version
                    print(f"[+] SSH Banner: {output.banner}", flush=True)
                
                self.auth_func(transport, username, password)
                success = transport.is_authenticated()
                if success:
                    print(f"[+] Auth succeeded for {username}@{self.host}")
                else:
                    print(f"[-] Auth failed for {username}@{self.host}")
                    
            except Exception as e:
                print(f"[!] Error during auth attempt {i+1}: {e}")
                success = False
            finally:
                output.attempts += 1
                if success:
                    output.successes += 1
                    if username and password:
                        key = f"{username}:{password}"
                        output.success_patterns[key] = True
                transport.close()

        self._print_auth_analysis(output)
        return output

    def _print_auth_analysis(self, output: AuthTesterOutput):
        """Print authentication analysis results"""
        auth_rate = output.get_success_rate()
        print(f"\n[*] Authentication Analysis:")
        print(f"    Success Rate: {auth_rate:.2%}")
        print(f"    Total Attempts: {output.attempts}")
        print(f"    Successful Attempts: {output.successes}")