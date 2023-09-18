# Pseudonymization_py

The pseudonyms are generated using the password-based key-derivation function `scrypt()`. The resulting pseudonyms are produced to length of 32 bytes.

The project specific salts are encrypted with AES-GCM and stored in the salts_repo as a 44 byte hex string. The first 12 bytes is a randomly generated nonce, the next 16 bytes is the encrypted project specific salt and the last 16 bytes is an authentication tag.

The storage_key used for AES-GCM encryption is derived from a password also using `scrypt()`. The length of the secret storage_key is 32 bytes with a 16 byte salt.\

The storage_key salt may be installed in a `salts_repo` JSON file along with the project salts.

