"""Module for managing SSH credentials for testing"""
import random
import string

class CredentialManager:
    """Manages SSH credentials for testing"""
    
    def __init__(self):
        self.credentials = []
        self._load_default_credentials()
        self._gen_canary_credentials()

    def _load_default_credentials(self):
        """Load default set of credentials"""
        self.credentials = [
            ("root", "admin"),
            ("admin", "admin"),
            ("root", "root"),
            ("admin", "password"),
            ("root", "password"),
            ("user", "user"),
            ("test", "test"),
            ("guest", "guest"),
            ("ubuntu", "ubuntu"),
            ("debian", "debian")
        ]

    def _gen_canary_credentials(self, count: int = 5):
        """
        Generate a specified number of random credential pairs and adds them to the canary credentials list.
        """
        for _ in range(count):
            username = ''.join(random.choices(string.ascii_lowercase, k=8))
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            self.add_credential(username, password)
    
    def add_credential(self, username: str, password: str):
        """Add a new credential pair"""
        self.credentials.append((username, password))
    
    def add_credentials(self, credentials: list):
        """Add multiple credential pairs"""
        self.credentials.extend(credentials)
