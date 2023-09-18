import unittest
from pseudonym.encrypted_salt import (
    EncryptedSalt,
    NONCE_BYTES,
    SECRET_SALT_BYTES,
    TAG_BYTES,
)


class TestEncryptedSalt(unittest.TestCase):
    def setUp(self):
        self.encryption_key_1 = b'\x99\xf3\xb4\xc9\xa0\x0c\x1f:\xb2\xbd7\t]\xb4\xe7\xf2\xb0E\xdc\x83\xcf\xa6aI\xd1\xc5]\x1b~\xd6\x8b\x98'
        self.encryption_key_2 = b'8\xc2M[N\xea\xc3\xe4\xcc\xf1\xd3>\xd7\xb9\x87\xadH\xc5VO\x93\xde\x06\xe0E\x10\x16o)\xc17\xed'
        self.fixed_secret_salt = b'<FQ\xfcf\x85\x85\x91\xdad\n\xf4\xdd\x0f]\xed'

    def tearDown(self):
        pass

    def test_init_encrypted_salt(self):
        self.encrypted_salt = EncryptedSalt()
        self.assertEqual(len(self.encrypted_salt.nonce), NONCE_BYTES)
        self.assertEqual(len(self.encrypted_salt.secret_salt), SECRET_SALT_BYTES)
        self.assertEqual(len(self.encrypted_salt.tag), TAG_BYTES)

    def test_encrypt_decrypt_encrypted_salt(self):
        encrypted_salt = EncryptedSalt()
        encrypted_salt.encrypt(self.encryption_key_1, self.fixed_secret_salt)
        secret_salt = encrypted_salt.decrypt(self.encryption_key_1)
        self.assertIsInstance(secret_salt, bytes)        
        self.assertEqual(secret_salt, self.fixed_secret_salt)

        encrypted_salt_1 = EncryptedSalt()
        encrypted_salt_1.encrypt(self.encryption_key_1, self.fixed_secret_salt)
        secret_salt_1 = encrypted_salt_1.decrypt(self.encryption_key_1)
        self.assertIsInstance(secret_salt_1, bytes)        

        encrypted_salt_2 = EncryptedSalt()
        encrypted_salt_2.encrypt(self.encryption_key_2, self.fixed_secret_salt)
        secret_salt_2 = encrypted_salt_2.decrypt(self.encryption_key_2)
        self.assertIsInstance(secret_salt_2, bytes)  

        self.assertIsInstance(encrypted_salt.nonce, bytes)  
        self.assertNotEqual(encrypted_salt.nonce, encrypted_salt_1.nonce)
        self.assertNotEqual(encrypted_salt.nonce, encrypted_salt_2.nonce)
        self.assertNotEqual(encrypted_salt_1.nonce, encrypted_salt_2.nonce)

        self.assertNotEqual(encrypted_salt.secret_salt, encrypted_salt_1.secret_salt)
        self.assertNotEqual(encrypted_salt_1.secret_salt, encrypted_salt_2.secret_salt)
        self.assertNotEqual(encrypted_salt.secret_salt, encrypted_salt_2.secret_salt)

        self.assertEqual(secret_salt, secret_salt_1)
        self.assertEqual(secret_salt, secret_salt_2)

    def test_generate_dump_load_encrypted_salt(self):
        generated_encrypted_salt = EncryptedSalt()
        generated_encrypted_salt.generate(self.encryption_key_1)
        secret_salt = generated_encrypted_salt.decrypt(self.encryption_key_1)
        self.assertIsInstance(secret_salt, bytes)        

        serialized_encrypted_salt = generated_encrypted_salt.dump()
        self.assertIsInstance(serialized_encrypted_salt, str)
        loaded_encrypted_salt = EncryptedSalt().load(serialized_encrypted_salt)
        self.assertIsInstance(loaded_encrypted_salt, EncryptedSalt)
        loaded_secret_salt = loaded_encrypted_salt.decrypt(self.encryption_key_1)
        self.assertEqual(secret_salt, loaded_secret_salt)



