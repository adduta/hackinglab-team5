"""Module for testing SSH authentication"""
import paramiko
from .credential_manager import CredentialManager
from .honeypot_fingerprinter import HoneypotFingerprinter

class AuthTester:
    """Handles SSH authentication testing"""
    
    def __init__(self, credential_manager: CredentialManager):
        self.credential_manager = credential_manager
        self.fingerprinter = HoneypotFingerprinter()
        self.banner = None
    
    def test_auth(self, host: str, port: int, auth_func, num_attempts: int = 10) -> HoneypotFingerprinter:
        """Perform multiple authentication attempts"""
        print(f"\n[*] Testing {num_attempts} authentication attempts on {host}:{port}")
        
        for i in range(num_attempts):
            username, password = self.credential_manager.get_credential(i)
            transport = paramiko.Transport((host, port))
            try:
                transport.start_client(timeout=5)
                if i == 0:  # Only print banner on first attempt
                    self.banner = transport.remote_version
                    self.fingerprinter.set_banner(self.banner)
                    print(f"[+] SSH Banner: {self.banner}")
                
                auth_func(transport, username, password)
                success = transport.is_authenticated()
                self.fingerprinter.record_auth_attempt(success, username, password)
                
                if success:
                    print(f"[+] Auth succeeded for {username}@{host}")
                else:
                    print(f"[-] Auth failed for {username}@{host}")
                    
            except Exception as e:
                print(f"[!] Error during auth attempt {i+1}: {e}")
                self.fingerprinter.record_auth_attempt(False, username, password)
            finally:
                transport.close()
        
        self._print_auth_analysis()
        return self.fingerprinter
    
    def _print_auth_analysis(self):
        """Print authentication analysis results"""
        auth_rate = self.fingerprinter.get_auth_success_rate()
        print(f"\n[*] Authentication Analysis:")
        print(f"    Success Rate: {auth_rate:.2%}")
        print(f"    Total Attempts: {self.fingerprinter.auth_attempts}")
        print(f"    Successful Attempts: {self.fingerprinter.auth_successes}") 