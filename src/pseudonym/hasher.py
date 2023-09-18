import sys
from abc import ABC, abstractmethod
import hashlib
import hmac

class Hasher(ABC):
    @abstractmethod
    def hash(self, plaintext: bytes, salt: bytes) -> bytes:
        pass

if sys.version_info >= (3,8):       
    class Scrypt(Hasher):
        def hash(self, plaintext: bytes, salt: bytes) -> bytes:
            return hashlib.scrypt(
                plaintext,
                salt=salt,
                n=16384,
                r=8,
                p=1,
                dklen=32,
            )
else:
    from Crypto.Protocol.KDF import scrypt
    class Scrypt(Hasher):
        def hash(self, plaintext: bytes, salt: bytes) -> bytes:
            return scrypt(
                plaintext,
                salt=salt,
                N=16384,
                r=8,
                p=1,
                key_len=32,
            )

class Pbkdf2(Hasher):
    def hash(self, plaintext: bytes, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("SHA256", plaintext, salt, 100000)

class Hmac_SHA256(Hasher):
    def hash(self, plaintext: bytes, salt: bytes) -> bytes:
        return hmac.digest(salt, msg=plaintext, digest=hashlib.sha256)
    