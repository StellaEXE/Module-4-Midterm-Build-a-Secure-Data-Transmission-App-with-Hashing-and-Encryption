import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def secure_vault():
    # 1. Key Generation & Entropy
    # We use os.urandom() for high entropy (randomness)
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12) 

    # 2. User Input
    message = input("Enter the message to secure: ").encode()

    # 3. Hashing (SHA-256) for Integrity
    original_hash = hashlib.sha256(message).hexdigest()
    print(f"\n[Original Hash]: {original_hash}")

    # 4. Encryption (Confidentiality)
    ciphertext = aesgcm.encrypt(nonce, message, None)
    print(f"[Encrypted Data]: {ciphertext.hex()}")

    # --- SIMULATING TRANSMISSION / STORAGE ---

    # 5. Decryption
    try:
        decrypted_message = aesgcm.decrypt(nonce, ciphertext, None)
        
        # 6. Integrity Verification
        new_hash = hashlib.sha256(decrypted_message).hexdigest()
        print(f"[Decrypted Message]: {decrypted_message.decode()}")
        print(f"[Verification Hash]: {new_hash}")

        if original_hash == new_hash:
            print("SUCCESS: Integrity verified. The message is untampered.")
        else:
            print("FAILURE: Integrity check failed!")

    except Exception as e:
        print(f"Decryption failed: {e}")

if __name__ == "__main__":
    secure_vault()
