import secrets
from .encryption import AesGcm

# Crypto bit lengths. Beware om compatibility with other AES-GCM implementations. Tested in Python, C#, Java, TypeScript and Go
# The serialized encryption token is a hex value from a concatenation of a nonce (iv), the encrypted payload (salt) and an authentication tag.
NONCE_BYTES = 12
SECRET_SALT_BYTES = 16
TAG_BYTES = 16


class EncryptedSalt:
    def __init__(self):
        self.nonce = bytes(NONCE_BYTES)
        self.secret_salt = bytes(SECRET_SALT_BYTES)
        self.tag = bytes(TAG_BYTES)

    # Encryption:

    def encrypt(self, encryption_key: bytes, secret_salt: bytes):
        """
        Encrypt and store a new salt.

        :param encryption_key: the key used for encrypting the salt
        :param secret_salt: the salt to encrypt
        :return: the EncryptedSalt instance

        """
        self.nonce = secrets.token_bytes(NONCE_BYTES)
        self.secret_salt, self.tag = AesGcm(encryption_key, self.nonce).encrypt(secret_salt)
        return self

    def decrypt(self, encryption_key: bytes) -> bytes:
        """
        Decrypt a stored salt.

        :param encryption_key: the key used when the salt was encrypted
        :return: the decrypted salt stored in this EncryptedSalt instance
        
        """
        return AesGcm(encryption_key, self.nonce).decrypt(self.secret_salt, self.tag)

    def generate(self, encryption_key: bytes):
        """

        Generate, encrypt and store a new salt.

        :param encryption_key: the key used for encrypting the salt
        :return: the EncryptedSalt instance

        """
        secret_salt = secrets.token_bytes(SECRET_SALT_BYTES)
        self.encrypt(encryption_key, secret_salt)
        return self

    # Serialization:

    def dump(self) -> str:
        """
        Dump the EncryptedSalt instance as a hex string.

        :return: a hex string consisting of NONCE + ENCRYPTED_SALT + TAG

        """        
        combined_bytes: bytes = self.nonce + self.secret_salt + self.tag
        return combined_bytes.hex()

    def load(self, serialized_encrypted_salt: str):
        """
        Load the EncryptedSalt instance from a hex string.

        :param serialized_encrypted_salt: a hex string containing the encrypted salt as NONCE + ENCRYPTED_SALT + TAG
        :return: the EncryptedSalt instance

        """    
        encrypted_salt: bytes = bytes.fromhex(serialized_encrypted_salt)
        self.nonce = encrypted_salt[:NONCE_BYTES]
        self.secret_salt = encrypted_salt[NONCE_BYTES:-TAG_BYTES]
        self.tag = encrypted_salt[-TAG_BYTES:]
        return self

    def __repr__(self):
        return f"nonce: {self.nonce.hex()} secret_salt: {self.secret_salt.hex()} tag: {self.tag.hex()}"

    def __str__(self):
        return self.dump()
