import Crypto.Cipher.AES

class AesGcm:
    def __init__(self, key:bytes, iv: bytes):
        self.cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_GCM, nonce=iv)
        
    def encrypt(self, plaintext: bytes):
        ciphertext, tag = self.cipher.encrypt_and_digest(plaintext)
        return ciphertext, tag

    def decrypt(self, ciphertext: bytes, tag: bytes) -> bytes:
        plaintext = self.cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext