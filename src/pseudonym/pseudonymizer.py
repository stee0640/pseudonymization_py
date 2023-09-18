from .encrypted_salt import EncryptedSalt
from .normalizer import Normalizer, DefaultCprNormalizer
from .hasher import Hasher, Scrypt

# Class for producing pseudonyms given a Normalizer and HashingAlgorithm class. Defaults are a simple CPR-normalizer and Scrypt.


class Pseudonymizer:
    def __init__(
        self,
        serialized_encrypted_salt: str,
        storage_key: bytes,
        normalizer: Normalizer = DefaultCprNormalizer(),
        hasher: Hasher = Scrypt(),
    ):
        self.salt = EncryptedSalt().load(serialized_encrypted_salt).decrypt(storage_key)
        self.normalizer: Normalizer = normalizer
        self.hasher: Hasher = hasher

    def pseudonym(self, plaintext: str) -> bytes:
        pseudonym = self.hasher.hash(self.normalizer.transform(plaintext), self.salt)
        return pseudonym
