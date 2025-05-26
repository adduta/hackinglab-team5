"""Module for managing SSH credentials for testing"""

class CredentialManager:
    """Manages SSH credentials for testing"""
    
    def __init__(self):
        self.credentials = []
        self._load_default_credentials()
    
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
    
    def add_credential(self, username: str, password: str):
        """Add a new credential pair"""
        self.credentials.append((username, password))
    
    def add_credentials(self, credentials: list):
        """Add multiple credential pairs"""
        self.credentials.extend(credentials)
    
    def get_credential(self, index: int) -> tuple:
        """Get credential pair at specified index"""
        return self.credentials[index % len(self.credentials)]
    
    def get_credential_count(self) -> int:
        """Get total number of credentials"""
 