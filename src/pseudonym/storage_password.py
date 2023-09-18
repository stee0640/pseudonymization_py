from getpass import getpass
from .hasher import Hasher, Scrypt

# Helper class for deriving keys for encryption from passwords

class StoragePassword:
    def __init__(self, storage_key_salt: bytes, hasher: Hasher = Scrypt()):
        self.storage_key_salt: bytes = storage_key_salt
        self.hasher = hasher

    def derive_key(self, password: str) -> bytes:
        return self.hasher.hash(bytes(password, "utf-8"), self.storage_key_salt)

    def getpass_derive_key(self, typo_check: bool = False) -> bytes:
        password = getpass("Enter encryption password: ")
        if typo_check:
            password2 = getpass("Enter password again: ")
            if password != password2:
                raise ValueError(f"Passwords do not match: ")
        return self.derive_key(password)
