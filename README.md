# Module-4-Midterm-Build-a-Secure-Data-Transmission-App-with-Hashing-and-Encryption

A. Confidentiality, Integrity, and Availability (CIA)

Confidentiality: Upheld by AES-256 encryption. Only someone with the secret 32-byte key can decrypt the ciphertext and read the original_message.

Integrity: Guaranteed by SHA-256 hashing. The script calculates a hash of the input, and before finalizing decryption, re-hashes the output. If even one bit of the ciphertext is modified, the hash will not match, detecting tampering.

Availability: While the script itself is local, the design allows the ciphertext to be safely stored or transmitted. The use of standard pycryptodome libraries ensures the application remains functional.


B. Role of Entropy and Key Generation

Entropy (Randomness): In this implementation, a nonce (Number Used Once) is generated for AES-GCM using get_random_bytes(12). High entropy is crucial because if the nonce is predictable, an attacker can break the encryption.

Key Generation: AES-256 requires a 32-byte key. A strong key should be generated using a cryptographically secure random number generator, not a simple string, to prevent brute-force attacks.
